"""Main orchestrator for running baseline comparison experiments.

This module coordinates running all 6 experiments (3 strategies x 2 engines)
in parallel, managing coverage collection, chart updates, and result aggregation.
"""

import concurrent.futures
import json
import os
import time
from pathlib import Path
from typing import Dict, List, Literal, Optional

from loguru import logger

from re_fuzzer.experiments.baselines.grammar_runner import GrammarAwareFuzzerRunner
from re_fuzzer.experiments.baselines.naive_runner import NaiveFuzzerRunner
from re_fuzzer.experiments.baselines.retest_runner import ReTestFuzzerRunner
from re_fuzzer.experiments.bug_collector import BugCollector
from re_fuzzer.experiments.chart_generator import ChartGenerator
from re_fuzzer.experiments.chart_monitor import start_chart_monitor
from re_fuzzer.experiments.experiment_config import (
    ExperimentConfig,
    ExperimentResult,
)


def create_runner(config: ExperimentConfig):
    """Create appropriate runner for experiment configuration.

    Args:
        config: Experiment configuration

    Returns:
        Runner instance (NaiveFuzzerRunner, GrammarAwareFuzzerRunner, or ReTestFuzzerRunner)
    """
    if config.strategy == "naive":
        return NaiveFuzzerRunner(config)
    elif config.strategy == "grammar":
        return GrammarAwareFuzzerRunner(config)
    elif config.strategy == "retest":
        return ReTestFuzzerRunner(config)
    else:
        raise ValueError(f"Unknown strategy: {config.strategy}")


def run_experiment(config: ExperimentConfig) -> tuple[str, ExperimentResult]:
    """Run a single experiment.

    This function is designed to be called in a process pool.

    Args:
        config: Experiment configuration

    Returns:
        Tuple of (experiment_name, result)
    """
    logger.info(f"Starting experiment: {config.name}")
    runner = create_runner(config)
    result = runner.run()
    logger.info(f"Completed experiment: {config.name}")
    return config.name, result


class ExperimentOrchestrator:
    """Orchestrates running multiple fuzzing experiments."""

    def __init__(
        self,
        output_dir: Path,
        pcre_library_path: Optional[Path] = None,
        pcre2_library_path: Optional[Path] = None,
        duration_seconds: int = 10800,  # 3 hours
        snapshot_interval_seconds: int = 600,  # 10 minutes
        num_workers_per_experiment: int = 4,
        seed_file: Optional[Path] = None,
        dictionary_path: Optional[Path] = None,
    ):
        """Initialize the orchestrator.

        Args:
            output_dir: Directory for all experiment outputs
            pcre_library_path: Path to instrumented PCRE library
            pcre2_library_path: Path to instrumented PCRE2 library
            duration_seconds: Duration per experiment
            snapshot_interval_seconds: Interval between coverage snapshots
            num_workers_per_experiment: Number of workers per experiment
            seed_file: Path to seed file for ReTest
            dictionary_path: Path to dictionary for naive fuzzer
        """
        self.output_dir = Path(output_dir)
        self.pcre_library_path = pcre_library_path
        self.pcre2_library_path = pcre2_library_path
        self.duration_seconds = duration_seconds
        self.snapshot_interval_seconds = snapshot_interval_seconds
        self.num_workers_per_experiment = num_workers_per_experiment
        self.seed_file = seed_file
        self.dictionary_path = dictionary_path

        self.results: Dict[str, ExperimentResult] = {}

    def create_experiment_configs(
        self,
        strategies: List[Literal["naive", "grammar", "retest"]] = None,
        engines: List[Literal["pcre", "pcre2"]] = None,
    ) -> List[ExperimentConfig]:
        """Create configurations for all experiments.

        Args:
            strategies: List of strategies to run (default: all)
            engines: List of engines to test (default: all)

        Returns:
            List of ExperimentConfig objects
        """
        if strategies is None:
            strategies = ["naive", "grammar", "retest"]
        if engines is None:
            engines = ["pcre", "pcre2"]

        configs = []

        for strategy in strategies:
            for engine in engines:
                # Skip if library path not available
                if engine == "pcre" and not self.pcre_library_path:
                    logger.warning(f"Skipping {strategy}_{engine}: PCRE library path not set")
                    continue
                if engine == "pcre2" and not self.pcre2_library_path:
                    logger.warning(f"Skipping {strategy}_{engine}: PCRE2 library path not set")
                    continue

                library_path = self.pcre_library_path if engine == "pcre" else self.pcre2_library_path
                engine_version = "8.45" if engine == "pcre" else "10.47"

                config = ExperimentConfig(
                    name=f"{strategy}_{engine}",
                    strategy=strategy,
                    engine=engine,
                    engine_version=engine_version,
                    library_path=library_path,
                    num_workers=self.num_workers_per_experiment,
                    duration_seconds=self.duration_seconds,
                    snapshot_interval_seconds=self.snapshot_interval_seconds,
                    output_dir=self.output_dir / "experiments",
                    seed_file=self.seed_file,
                    dictionary_path=self.dictionary_path,
                )
                configs.append(config)

        return configs

    def run_all(
        self,
        max_parallel_experiments: int = 6,
    ) -> Dict[str, ExperimentResult]:
        """Run all configured experiments.

        Args:
            max_parallel_experiments: Maximum experiments to run in parallel

        Returns:
            Dict mapping experiment name to result
        """
        configs = self.create_experiment_configs()

        if not configs:
            logger.error("No experiments configured. Check library paths.")
            return {}

        logger.info(f"Running {len(configs)} experiments with up to {max_parallel_experiments} in parallel")

        # Create output directories
        self.output_dir.mkdir(parents=True, exist_ok=True)
        charts_dir = self.output_dir / "charts"
        charts_dir.mkdir(exist_ok=True)

        # Start chart monitor for real-time updates
        experiment_names = [c.name for c in configs]
        chart_monitor = start_chart_monitor(
            results_dir=self.output_dir / "experiments",
            charts_dir=charts_dir,
            interval_seconds=self.snapshot_interval_seconds,
            experiment_names=experiment_names,
        )

        start_time = time.time()

        try:
            # Run experiments in parallel using ProcessPoolExecutor
            with concurrent.futures.ProcessPoolExecutor(max_workers=max_parallel_experiments) as executor:
                future_to_config = {
                    executor.submit(run_experiment, config): config
                    for config in configs
                }

                for future in concurrent.futures.as_completed(future_to_config):
                    config = future_to_config[future]
                    try:
                        name, result = future.result()
                        self.results[name] = result
                        logger.info(
                            f"Experiment {name} completed: "
                            f"{result.total_iterations} iterations, "
                            f"{result.total_crashes} crashes, "
                            f"{result.final_coverage} edges"
                        )
                    except Exception as e:
                        logger.error(f"Experiment {config.name} failed: {e}")

        finally:
            # Stop chart monitor
            chart_monitor.stop()
            chart_monitor.join(timeout=5.0)

        elapsed = time.time() - start_time
        logger.info(f"All experiments completed in {elapsed:.1f}s")

        # Generate final charts
        self._generate_final_charts()

        # Save summary
        self._save_summary(elapsed)

        return self.results

    def _generate_final_charts(self) -> None:
        """Generate final comparison charts."""
        charts_dir = self.output_dir / "charts"
        chart_generator = ChartGenerator()

        # Collect all timelines
        timelines = {}
        for name, result in self.results.items():
            if result.snapshots:
                timelines[name] = result.snapshots

        if timelines:
            chart_generator.generate_comparison_charts(timelines, charts_dir)

        # Bug comparison chart
        bug_counts = {name: result.total_crashes for name, result in self.results.items()}
        if any(count > 0 for count in bug_counts.values()):
            chart_generator.generate_bug_chart(
                bug_counts,
                "Bugs Found by Strategy",
                charts_dir / "bugs_comparison.png",
            )

    def _save_summary(self, elapsed_time: float) -> None:
        """Save experiment summary to JSON.

        Args:
            elapsed_time: Total elapsed time in seconds
        """
        summary = {
            "total_experiments": len(self.results),
            "elapsed_time_seconds": elapsed_time,
            "duration_per_experiment_seconds": self.duration_seconds,
            "workers_per_experiment": self.num_workers_per_experiment,
            "experiments": {},
        }

        for name, result in self.results.items():
            summary["experiments"][name] = {
                "strategy": result.config.strategy,
                "engine": result.config.engine,
                "total_iterations": result.total_iterations,
                "total_crashes": result.total_crashes,
                "final_coverage": result.final_coverage,
                "final_coverage_percent": result.final_coverage_percent,
                "duration_actual_seconds": result.duration_actual_seconds,
                "num_snapshots": len(result.snapshots),
            }

        summary_path = self.output_dir / "summary.json"
        with open(summary_path, "w") as f:
            json.dump(summary, f, indent=2)

        logger.info(f"Summary saved to {summary_path}")


def run_baseline_experiments(
    output_dir: Path,
    pcre_library_path: Optional[Path] = None,
    pcre2_library_path: Optional[Path] = None,
    duration_seconds: int = 10800,
    snapshot_interval_seconds: int = 600,
    num_workers: int = 4,
    seed_file: Optional[Path] = None,
    dictionary_path: Optional[Path] = None,
    max_parallel: int = 6,
) -> Dict[str, ExperimentResult]:
    """Convenience function to run all baseline experiments.

    Args:
        output_dir: Directory for outputs
        pcre_library_path: Path to instrumented PCRE library
        pcre2_library_path: Path to instrumented PCRE2 library
        duration_seconds: Duration per experiment
        snapshot_interval_seconds: Snapshot interval
        num_workers: Workers per experiment
        seed_file: Path to seed file
        dictionary_path: Path to dictionary file
        max_parallel: Maximum parallel experiments

    Returns:
        Dict mapping experiment name to result
    """
    # Set ASan options for reduced memory overhead
    os.environ.setdefault(
        "ASAN_OPTIONS",
        "quarantine_size_mb=64:malloc_context_size=5"
    )

    orchestrator = ExperimentOrchestrator(
        output_dir=output_dir,
        pcre_library_path=pcre_library_path,
        pcre2_library_path=pcre2_library_path,
        duration_seconds=duration_seconds,
        snapshot_interval_seconds=snapshot_interval_seconds,
        num_workers_per_experiment=num_workers,
        seed_file=seed_file,
        dictionary_path=dictionary_path,
    )

    return orchestrator.run_all(max_parallel_experiments=max_parallel)
