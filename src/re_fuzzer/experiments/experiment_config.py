"""Configuration dataclasses for baseline comparison experiments."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Literal, Optional


@dataclass
class ExperimentConfig:
    """Configuration for a single fuzzing experiment."""

    name: str
    strategy: Literal["naive", "grammar", "retest"]
    engine: Literal["pcre", "pcre2"]
    engine_version: str
    library_path: Path
    num_workers: int = 4
    duration_seconds: int = 10800  # 3 hours
    snapshot_interval_seconds: int = 60  # 1 minute (reduced from 600 to capture early growth)
    output_dir: Path = field(default_factory=lambda: Path("results"))

    # Seed corpus for fuzzing
    seed_file: Optional[Path] = None

    # Strategy-specific options
    mutation_probability: float = 0.8  # For ReTest
    max_pool_size: int = 100_000  # For ReTest
    dictionary_path: Optional[Path] = None  # For naive

    # Advanced generator options (for ReTest)
    advanced_generator_weight: float = 0.3  # 30% chance to use advanced pattern generation
    passive_pool_update_chance: float = 0.15  # Back to default

    # Seed corpus size (smaller = more gradual coverage growth)
    max_seed_size: int = 1000  # Balance between diversity and gradual discovery


@dataclass
class CoverageSnapshot:
    """A single coverage snapshot at a point in time."""

    timestamp: float
    elapsed_seconds: float
    unique_edges: int
    total_edges: int
    iterations: int
    crashes: int
    coverage_percent: float = 0.0
    total_mutations: int = 0  # Total mutations performed
    coverage_mutations: int = 0  # Mutations that increased coverage

    def __post_init__(self):
        if self.total_edges > 0 and self.coverage_percent == 0.0:
            self.coverage_percent = (self.unique_edges / self.total_edges) * 100


@dataclass
class BugInfo:
    """Information about a discovered bug."""

    pattern: str
    test_string: Optional[str]
    error_type: str  # "crash", "asan", "timeout", "semantic"
    error_message: str
    stack_trace: Optional[str] = None
    timestamp: float = 0.0


@dataclass
class ExperimentResult:
    """Results from a completed experiment."""

    config: ExperimentConfig
    snapshots: List[CoverageSnapshot] = field(default_factory=list)
    bugs: List[BugInfo] = field(default_factory=list)
    total_iterations: int = 0
    total_crashes: int = 0
    final_coverage: int = 0
    final_coverage_percent: float = 0.0
    duration_actual_seconds: float = 0.0

    def add_snapshot(self, snapshot: CoverageSnapshot) -> None:
        """Add a coverage snapshot."""
        self.snapshots.append(snapshot)

    def add_bug(self, bug: BugInfo) -> None:
        """Record a discovered bug."""
        self.bugs.append(bug)
        self.total_crashes += 1
