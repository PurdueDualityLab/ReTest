"""Coverage-guided corpus for FuzzTest-style grammar fuzzing.

FuzzTest uses coverage feedback to guide generation:
1. Maintains corpus of inputs that discovered new coverage
2. Assigns "energy" to inputs based on coverage contribution
3. Preferentially selects high-energy inputs for mutation
4. Balances exploration (fresh generation) vs exploitation (corpus mutation)

Reference: Google FuzzTest's coverage-guided property-based testing approach.
"""

import random
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple


@dataclass
class CorpusEntry:
    """A corpus entry with coverage information.

    FuzzTest tracks which inputs led to new coverage and prioritizes them.
    """
    pattern: str
    new_edges_found: int  # Number of NEW edges discovered by this pattern
    generation: int  # Which generation/iteration this was added
    energy: float = 1.0  # Selection probability weight
    exec_count: int = 0  # How many times selected for mutation
    last_selected: float = 0.0  # Timestamp of last selection

    def __hash__(self):
        return hash(self.pattern)


class CoverageCorpus:
    """Coverage-guided corpus matching FuzzTest's approach.

    Key behaviors from FuzzTest:
    1. Add inputs that discover new coverage to corpus
    2. Assign energy based on:
       - New edges discovered (more = higher energy)
       - Recency (recently added = higher energy)
       - Execution count (less executed = higher energy for exploration)
    3. Probabilistic selection weighted by energy
    """

    # Corpus size limits (matching typical fuzzer behavior)
    MAX_CORPUS_SIZE = 10000
    MIN_CORPUS_SIZE = 100

    # Energy calculation parameters
    ENERGY_NEW_EDGE_WEIGHT = 2.0  # Bonus per new edge discovered
    ENERGY_RECENCY_WEIGHT = 0.5  # Bonus for recent additions
    ENERGY_EXPLORATION_WEIGHT = 0.3  # Bonus for less-executed entries
    ENERGY_MIN = 0.1  # Minimum energy to prevent starvation
    ENERGY_MAX = 100.0  # Cap to prevent runaway energy

    # Selection strategy weights
    CORPUS_MUTATION_PROBABILITY = 0.8  # 80% mutate corpus, 20% fresh generation

    def __init__(self, max_size: int = MAX_CORPUS_SIZE):
        """Initialize the corpus.

        Args:
            max_size: Maximum corpus size before culling
        """
        self.max_size = max_size
        self.entries: List[CorpusEntry] = []
        self.pattern_set: Set[str] = set()  # For O(1) duplicate checking

        # Statistics
        self.total_added = 0
        self.total_rejected = 0
        self.generation = 0
        self.total_edges_discovered = 0

    def add_if_new_coverage(
        self,
        pattern: str,
        new_edges_count: int,
    ) -> Tuple[bool, int]:
        """Add pattern to corpus if it discovers new coverage.

        This is the core FuzzTest behavior: only keep inputs that
        contribute new coverage.

        Args:
            pattern: The regex pattern
            new_edges_count: Number of new edges discovered by this pattern

        Returns:
            Tuple of (was_added, num_new_edges)
        """
        # Only add if new edges discovered
        if new_edges_count <= 0:
            self.total_rejected += 1
            return False, 0

        # Skip duplicates
        if pattern in self.pattern_set:
            return False, 0

        # Update stats
        self.total_edges_discovered += new_edges_count
        self.generation += 1

        # Create entry with energy based on new edges found
        entry = CorpusEntry(
            pattern=pattern,
            new_edges_found=new_edges_count,
            generation=self.generation,
            energy=self._calculate_initial_energy(new_edges_count),
        )

        self.entries.append(entry)
        self.pattern_set.add(pattern)
        self.total_added += 1

        # Cull if over size limit
        if len(self.entries) > self.max_size:
            self._cull_corpus()

        return True, new_edges_count

    def _calculate_initial_energy(self, new_edges: int) -> float:
        """Calculate initial energy for a new corpus entry.

        FuzzTest gives higher priority to inputs that discover more edges.
        """
        base_energy = 1.0
        edge_bonus = new_edges * self.ENERGY_NEW_EDGE_WEIGHT
        return min(base_energy + edge_bonus, self.ENERGY_MAX)

    def select_for_mutation(self) -> Optional[CorpusEntry]:
        """Select a corpus entry for mutation using energy-weighted sampling.

        FuzzTest uses coverage feedback to preferentially select inputs
        that are more likely to discover new coverage.

        Returns:
            Selected entry, or None if corpus is empty
        """
        if not self.entries:
            return None

        # Update energies before selection
        self._update_energies()

        # Energy-weighted random selection
        total_energy = sum(e.energy for e in self.entries)
        if total_energy <= 0:
            return random.choice(self.entries)

        # Weighted random selection
        r = random.uniform(0, total_energy)
        cumulative = 0.0
        for entry in self.entries:
            cumulative += entry.energy
            if cumulative >= r:
                entry.exec_count += 1
                entry.last_selected = time.time()
                return entry

        # Fallback (shouldn't reach here)
        return self.entries[-1]

    def _update_energies(self) -> None:
        """Update energy values for all corpus entries.

        Energy factors:
        1. New edges found (static, set at creation)
        2. Recency (dynamic, decays over time)
        3. Exploration bonus (less executed = higher energy)
        """
        if not self.entries:
            return

        current_time = time.time()
        max_gen = self.generation
        max_exec = max(e.exec_count for e in self.entries) or 1

        for entry in self.entries:
            # Base energy from new edges
            base = 1.0 + entry.new_edges_found * self.ENERGY_NEW_EDGE_WEIGHT

            # Recency bonus (newer entries get bonus)
            recency_factor = entry.generation / max_gen if max_gen > 0 else 1.0
            recency_bonus = recency_factor * self.ENERGY_RECENCY_WEIGHT

            # Exploration bonus (less executed = higher bonus)
            exec_factor = 1.0 - (entry.exec_count / max_exec) if max_exec > 0 else 1.0
            exploration_bonus = exec_factor * self.ENERGY_EXPLORATION_WEIGHT

            entry.energy = max(
                self.ENERGY_MIN,
                min(base + recency_bonus + exploration_bonus, self.ENERGY_MAX)
            )

    def _cull_corpus(self) -> None:
        """Remove low-value entries when corpus exceeds max size.

        FuzzTest keeps inputs that contribute unique coverage.
        We remove entries with lowest energy.
        """
        if len(self.entries) <= self.MIN_CORPUS_SIZE:
            return

        # Sort by energy (lowest first)
        self.entries.sort(key=lambda e: e.energy)

        # Remove lowest-energy entries until we're at 90% capacity
        target_size = int(self.max_size * 0.9)
        to_remove = len(self.entries) - target_size

        if to_remove > 0:
            # Remove the lowest-energy entries
            for entry in self.entries[:to_remove]:
                self.pattern_set.discard(entry.pattern)
            self.entries = self.entries[to_remove:]

        # Re-sort by generation for consistent ordering
        self.entries.sort(key=lambda e: e.generation)

    def should_use_corpus(self) -> bool:
        """Decide whether to mutate corpus or generate fresh.

        FuzzTest balances between:
        - Exploitation: Mutating known good inputs (corpus)
        - Exploration: Generating fresh random inputs

        Returns:
            True if should select from corpus, False if should generate fresh
        """
        if len(self.entries) < 10:
            # Not enough corpus entries, prefer fresh generation
            return False

        return random.random() < self.CORPUS_MUTATION_PROBABILITY

    def get_statistics(self) -> Dict:
        """Get corpus statistics."""
        return {
            "corpus_size": len(self.entries),
            "total_added": self.total_added,
            "total_rejected": self.total_rejected,
            "global_coverage": self.total_edges_discovered,  # Cumulative edges found
            "generation": self.generation,
            "avg_energy": sum(e.energy for e in self.entries) / len(self.entries) if self.entries else 0,
            "total_edges_discovered": self.total_edges_discovered,
        }

    def get_all_patterns(self) -> List[str]:
        """Get all patterns in corpus."""
        return [e.pattern for e in self.entries]

    def seed_corpus(self, patterns: List[str]) -> int:
        """Seed the corpus with initial patterns.

        Args:
            patterns: List of seed patterns

        Returns:
            Number of patterns added
        """
        added = 0
        for pattern in patterns:
            if pattern in self.pattern_set:
                continue

            # For seeds, add with minimal energy
            self.generation += 1
            entry = CorpusEntry(
                pattern=pattern,
                new_edges_found=0,
                generation=self.generation,
                energy=self.ENERGY_MIN,
            )
            self.entries.append(entry)
            self.pattern_set.add(pattern)
            added += 1

        return added
