"""Experiments package for baseline comparison fuzzing experiments."""

from re_fuzzer.experiments.experiment_config import (
    BugInfo,
    CoverageSnapshot,
    ExperimentConfig,
    ExperimentResult,
)
from re_fuzzer.experiments.coverage_collector import (
    CoverageCollector,
    merge_coverage_bitmaps,
)
from re_fuzzer.experiments.chart_generator import ChartGenerator
from re_fuzzer.experiments.chart_monitor import ChartMonitor, start_chart_monitor
from re_fuzzer.experiments.bug_collector import BugCollector
from re_fuzzer.experiments.experiment_runner import (
    ExperimentOrchestrator,
    run_baseline_experiments,
)

__all__ = [
    # Config
    "BugInfo",
    "CoverageSnapshot",
    "ExperimentConfig",
    "ExperimentResult",
    # Coverage
    "CoverageCollector",
    "merge_coverage_bitmaps",
    # Charts
    "ChartGenerator",
    "ChartMonitor",
    "start_chart_monitor",
    # Bugs
    "BugCollector",
    # Runner
    "ExperimentOrchestrator",
    "run_baseline_experiments",
]
