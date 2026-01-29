"""Subtree pool for storing and managing AST subtrees with context.

This module implements the core subtree pool data structure that stores AST
subtrees organized by their type and context. The pool enables efficient
lookup of semantically compatible subtrees for grammar-aware mutations.

Following the Superion paper, context is defined as a 4-tuple:
[great-grandparent type, grandparent type, parent type, first sibling value/type]
"""

from __future__ import annotations

import random
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Optional

from loguru import logger


@dataclass(frozen=True, slots=True)
class SubtreeContext:
    """Context representation for an AST node.

    Context is defined as a 4-tuple following the paper:
    - great_grandparent_type: Type of node's great-grandparent (or None)
    - grandparent_type: Type of node's grandparent (or None)
    - parent_type: Type of node's parent (or None)
    - first_sibling: Value of first sibling if terminal, else type (or None)
    """
    great_grandparent_type: Optional[str]
    grandparent_type: Optional[str]
    parent_type: Optional[str]
    first_sibling: Optional[str]

    def to_tuple(self) -> tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
        """Convert context to tuple for use as dictionary key."""
        return (
            self.great_grandparent_type,
            self.grandparent_type,
            self.parent_type,
            self.first_sibling
        )


@dataclass
class SubtreeEntry:
    """Entry in the subtree pool containing the subtree and metadata."""
    subtree: Any  # AST node from yapp
    pattern_str: str  # String representation of the subtree
    byte_size: int  # Size in bytes
    frequency: int = 1  # Number of times this subtree has been seen


class SubtreePool:
    """Pool for storing and retrieving AST subtrees organized by type and context.

    The pool uses a two-level dictionary structure:
    - First level: node type (e.g., "Alternation", "Sequence", "Quantified")
    - Second level: context tuple
    - Value: list of SubtreeEntry objects

    This allows O(1) lookup of compatible subtrees for a given node type and context.

    Optimization: Uses hash-based duplicate detection for O(1) deduplication
    instead of O(n*m) linear string comparison.
    """

    def __init__(self, max_subtree_bytes: int = 200, max_pool_size: int = 100000):
        """Initialize the subtree pool.

        Args:
            max_subtree_bytes: Maximum size in bytes for a single subtree (default 200)
            max_pool_size: Maximum total number of subtrees in pool (default 100000)
        """
        # pool[node_type][context_tuple] = [SubtreeEntry, ...]
        self.pool: dict[str, dict[tuple, list[SubtreeEntry]]] = defaultdict(
            lambda: defaultdict(list)
        )
        self.max_subtree_bytes = max_subtree_bytes
        self.max_pool_size = max_pool_size
        self.total_subtrees = 0
        self._pool_full_warned = False

        # Hash-based duplicate tracking for O(1) deduplication
        # Maps (node_type, context_tuple, pattern_hash) -> index in entries list
        self._pattern_hashes: dict[tuple[str, tuple, int], int] = {}

        # Statistics
        self.stats = {
            "additions": 0,
            "rejections": 0,
            "lookups": 0,
            "hits": 0,
            "misses": 0,
            "duplicate_hits": 0,  # Track hash-based duplicate detection
            "hash_collisions": 0,  # Track hash collisions
        }

    def add_subtree(
        self,
        subtree: Any,
        node_type: str,
        context: SubtreeContext,
        pattern_str: str
    ) -> bool:
        """Add a subtree to the pool if it meets size requirements.

        Args:
            subtree: AST node to store
            node_type: Type of the AST node
            context: Context of the node in the original AST
            pattern_str: String representation of the subtree

        Returns:
            True if subtree was added, False if rejected
        """
        # Check size constraint
        byte_size = len(pattern_str.encode('utf-8'))
        if byte_size > self.max_subtree_bytes:
            self.stats["rejections"] += 1
            logger.debug(f"Rejecting subtree (size {byte_size} > {self.max_subtree_bytes})")
            return False

        # Check pool size limit
        if self.is_full():
            self.stats["rejections"] += 1
            if not self._pool_full_warned:
                logger.warning(f"Pool size limit reached ({self.max_pool_size})")
                self._pool_full_warned = True
            return False

        context_tuple = context.to_tuple()
        entries = self.pool[node_type][context_tuple]

        # O(1) hash-based duplicate check
        pattern_hash = hash(pattern_str)
        hash_key = (node_type, context_tuple, pattern_hash)

        if hash_key in self._pattern_hashes:
            # Potential duplicate found - verify with string comparison (handles hash collisions)
            entry_idx = self._pattern_hashes[hash_key]
            if entry_idx < len(entries) and entries[entry_idx].pattern_str == pattern_str:
                entries[entry_idx].frequency += 1
                self.stats["duplicate_hits"] += 1
                logger.debug(f"Incremented frequency for existing subtree (hash hit)")
                return True
            else:
                # Hash collision - need to do linear search
                self.stats["hash_collisions"] += 1
                for i, entry in enumerate(entries):
                    if entry.pattern_str == pattern_str:
                        entry.frequency += 1
                        # Update hash index to correct position
                        self._pattern_hashes[hash_key] = i
                        logger.debug(f"Incremented frequency for existing subtree (collision resolved)")
                        return True

        # Add new entry
        entry = SubtreeEntry(
            subtree=subtree,
            pattern_str=pattern_str,
            byte_size=byte_size
        )
        entries.append(entry)
        self._pattern_hashes[hash_key] = len(entries) - 1  # Track index for O(1) lookup
        self.total_subtrees += 1
        self.stats["additions"] += 1

        logger.debug(
            f"Added subtree: type={node_type}, context={context_tuple}, "
            f"size={byte_size}, pool_size={self.total_subtrees}"
        )
        return True

    def is_full(self) -> bool:
        """Return True if the pool reached its configured capacity."""
        return self.total_subtrees >= self.max_pool_size

    def get_subtree(self, node_type: str, context: SubtreeContext) -> Optional[Any]:
        """Retrieve a random subtree matching the given type and context.

        Args:
            node_type: Type of node to look up
            context: Context to match

        Returns:
            Random matching subtree or None if no matches found
        """
        self.stats["lookups"] += 1
        context_tuple = context.to_tuple()

        if node_type not in self.pool:
            self.stats["misses"] += 1
            return None

        if context_tuple not in self.pool[node_type]:
            self.stats["misses"] += 1
            return None

        entries = self.pool[node_type][context_tuple]
        if not entries:
            self.stats["misses"] += 1
            return None

        # Random selection (could be weighted by frequency in future)
        selected = random.choice(entries)
        self.stats["hits"] += 1

        logger.debug(
            f"Retrieved subtree: type={node_type}, context={context_tuple}, "
            f"hit_rate={self.stats['hits']}/{self.stats['lookups']}"
        )
        return selected.subtree

    def get_any_subtree_of_type(self, node_type: str) -> Optional[Any]:
        """Retrieve any random subtree of the given type, ignoring context.

        Args:
            node_type: Type of node to look up

        Returns:
            Random subtree of that type or None if no matches found
        """
        if node_type not in self.pool:
            return None

        # Collect all subtrees of this type across all contexts
        all_entries = []
        for context_entries in self.pool[node_type].values():
            all_entries.extend(context_entries)

        if not all_entries:
            return None

        # Return random subtree
        selected = random.choice(all_entries)
        logger.debug(f"Retrieved any subtree of type={node_type}")
        return selected.subtree

    def size(
        self,
        node_type: Optional[str] = None,
        context: Optional[SubtreeContext] = None
    ) -> int:
        """Get the number of subtrees in the pool.

        Args:
            node_type: If specified, count only subtrees of this type
            context: If specified (with node_type), count only subtrees with this context

        Returns:
            Number of subtrees matching the criteria
        """
        if node_type is None:
            return self.total_subtrees

        if node_type not in self.pool:
            return 0

        if context is None:
            # Count all subtrees of this type
            count = 0
            for entries_list in self.pool[node_type].values():
                count += len(entries_list)
            return count

        # Count subtrees of this type and context
        context_tuple = context.to_tuple()
        if context_tuple not in self.pool[node_type]:
            return 0

        return len(self.pool[node_type][context_tuple])

    def get_statistics(self) -> dict[str, Any]:
        """Get pool statistics for monitoring and debugging.

        Returns:
            Dictionary containing various statistics about pool usage
        """
        type_distribution = {}
        for node_type, contexts in self.pool.items():
            total_for_type = sum(len(entries) for entries in contexts.values())
            type_distribution[node_type] = total_for_type

        hit_rate = (
            self.stats["hits"] / self.stats["lookups"]
            if self.stats["lookups"] > 0
            else 0.0
        )

        return {
            "total_subtrees": self.total_subtrees,
            "unique_types": len(self.pool),
            "type_distribution": type_distribution,
            "additions": self.stats["additions"],
            "rejections": self.stats["rejections"],
            "lookups": self.stats["lookups"],
            "hits": self.stats["hits"],
            "misses": self.stats["misses"],
            "hit_rate": hit_rate,
            "duplicate_hits": self.stats["duplicate_hits"],
            "hash_collisions": self.stats["hash_collisions"],
            "hash_table_size": len(self._pattern_hashes),
        }

    def clear(self) -> None:
        """Clear all subtrees from the pool."""
        self.pool.clear()
        self._pattern_hashes.clear()  # Clear hash tracking
        self.total_subtrees = 0
        self._pool_full_warned = False
        self.stats = {
            "additions": 0,
            "rejections": 0,
            "lookups": 0,
            "hits": 0,
            "misses": 0,
            "duplicate_hits": 0,
            "hash_collisions": 0,
        }
        logger.info("Subtree pool cleared")

    # -------------------------------------------------------------------------
    # Methods for parallel pool synchronization
    # -------------------------------------------------------------------------

    def export_to_file(self, path: str) -> int:
        """Export pool entries to a JSONL file.

        Each line is a JSON object with pattern_str, node_type, and context.
        Only exports pattern strings (AST needs to be reparsed on import).

        Args:
            path: File path to write

        Returns:
            Number of entries exported
        """
        import json

        count = 0
        try:
            with open(path, "w") as f:
                for node_type, contexts in self.pool.items():
                    for context_tuple, entries in contexts.items():
                        for entry in entries:
                            record = {
                                "pattern": entry.pattern_str,
                                "type": node_type,
                                "context": list(context_tuple),
                            }
                            f.write(json.dumps(record) + "\n")
                            count += 1
        except Exception as e:
            logger.debug(f"Failed to export pool: {e}")
            return 0

        return count

    def import_from_file(self, path: str, parse_func=None) -> int:
        """Import pool entries from a JSONL file.

        Note: Since AST nodes can't be serialized easily, this import only
        reads pattern strings. The parse_func should be provided to convert
        patterns back to AST nodes if needed.

        Args:
            path: File path to read
            parse_func: Optional function to parse pattern strings to AST

        Returns:
            Number of entries imported
        """
        import json

        count = 0
        try:
            with open(path, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                        pattern = record.get("pattern", "")
                        node_type = record.get("type", "")
                        context_list = record.get("context", [None, None, None, None])

                        # Skip if we already have this pattern
                        pattern_hash = hash(pattern)
                        context_tuple = tuple(context_list)
                        hash_key = (node_type, context_tuple, pattern_hash)
                        if hash_key in self._pattern_hashes:
                            continue

                        # Parse if function provided, otherwise store None for subtree
                        subtree = None
                        if parse_func:
                            try:
                                subtree = parse_func(pattern)
                            except Exception:
                                pass

                        # Create entry
                        context = SubtreeContext(
                            context_list[0] if len(context_list) > 0 else None,
                            context_list[1] if len(context_list) > 1 else None,
                            context_list[2] if len(context_list) > 2 else None,
                            context_list[3] if len(context_list) > 3 else None,
                        )

                        entry = SubtreeEntry(
                            subtree=subtree,
                            pattern_str=pattern,
                            byte_size=len(pattern.encode("utf-8")),
                        )

                        # Add to pool
                        self.pool[node_type][context_tuple].append(entry)
                        self._pattern_hashes[hash_key] = len(self.pool[node_type][context_tuple]) - 1
                        self.total_subtrees += 1
                        count += 1

                        if self.total_subtrees >= self.max_pool_size:
                            break

                    except json.JSONDecodeError:
                        continue

        except FileNotFoundError:
            return 0
        except Exception as e:
            logger.debug(f"Failed to import pool: {e}")
            return 0

        if count > 0:
            logger.debug(f"Imported {count} entries from pool file")
        return count

    def get_export_size(self) -> int:
        """Get the current number of entries for delta export tracking.

        Returns:
            Current total subtrees count
        """
        return self.total_subtrees
