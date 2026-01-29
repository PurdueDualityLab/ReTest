"""Real-time chart monitoring during experiments.

This module provides a background thread that periodically updates
coverage comparison charts while experiments are running.
"""

import threading
import time
from pathlib import Path
from typing import Dict, List, Optional

from loguru import logger

from re_fuzzer.experiments.chart_generator import ChartGenerator
from re_fuzzer.experiments.coverage_collector import CoverageCollector
from re_fuzzer.experiments.experiment_config import CoverageSnapshot


class ChartMonitor(threading.Thread):
    """Background thread that updates charts periodically.

    This monitor reads coverage_timeline.csv files from each experiment
    directory and regenerates comparison charts at regular intervals.
    """

    def __init__(
        self,
        results_dir: Path,
        charts_dir: Optional[Path] = None,
        interval_seconds: int = 600,
        experiment_names: Optional[List[str]] = None,
    ):
        """Initialize the chart monitor.

        Args:
            results_dir: Directory containing experiment subdirectories
            charts_dir: Directory to save charts (defaults to results_dir/charts)
            interval_seconds: Seconds between chart updates
            experiment_names: List of experiment names to monitor (optional)
        """
        super().__init__(daemon=True)
        self.results_dir = Path(results_dir)
        self.charts_dir = Path(charts_dir) if charts_dir else self.results_dir / "charts"
        self.interval_seconds = interval_seconds
        self.experiment_names = experiment_names

        self._stop_event = threading.Event()
        self._chart_generator = ChartGenerator()

    def run(self) -> None:
        """Main monitoring loop."""
        logger.info(f"Chart monitor started (interval: {self.interval_seconds}s)")

        while not self._stop_event.is_set():
            try:
                self._update_charts()
            except Exception as e:
                logger.error(f"Chart update failed: {e}")

            # Wait for interval or stop signal
            self._stop_event.wait(timeout=self.interval_seconds)

        logger.info("Chart monitor stopped")

    def stop(self) -> None:
        """Signal the monitor to stop."""
        self._stop_event.set()

    def _update_charts(self) -> None:
        """Load timelines and regenerate charts."""
        timelines = self._load_all_timelines()

        if not timelines:
            logger.debug("No timeline data available yet")
            return

        # Generate comparison charts
        self.charts_dir.mkdir(parents=True, exist_ok=True)

        # Generate per-engine charts
        self._generate_pcre_chart(timelines)
        self._generate_pcre2_chart(timelines)
        self._generate_combined_chart(timelines)

        logger.info(f"Charts updated: {len(timelines)} experiments")

    def _load_all_timelines(self) -> Dict[str, List[CoverageSnapshot]]:
        """Load timelines from all experiment directories.

        Returns:
            Dict mapping experiment name to snapshot list
        """
        timelines = {}

        # Find experiment directories
        if self.experiment_names:
            exp_dirs = [self.results_dir / name for name in self.experiment_names]
        else:
            exp_dirs = [d for d in self.results_dir.iterdir() if d.is_dir() and d.name != "charts"]

        for exp_dir in exp_dirs:
            timeline_path = exp_dir / "coverage_timeline.csv"
            if timeline_path.exists():
                try:
                    snapshots = CoverageCollector.load_csv(timeline_path)
                    if snapshots:
                        timelines[exp_dir.name] = snapshots
                except Exception as e:
                    logger.debug(f"Failed to load {timeline_path}: {e}")

        return timelines

    def _generate_pcre_chart(self, timelines: Dict[str, List[CoverageSnapshot]]) -> None:
        """Generate PCRE comparison chart.

        Args:
            timelines: All experiment timelines
        """
        pcre_timelines = {k: v for k, v in timelines.items() if "pcre2" not in k.lower()}

        if pcre_timelines:
            output_path = self.charts_dir / "pcre_coverage.png"
            self._chart_generator.generate_coverage_chart(
                pcre_timelines,
                "PCRE 8.45 Coverage Comparison",
                output_path,
            )

    def _generate_pcre2_chart(self, timelines: Dict[str, List[CoverageSnapshot]]) -> None:
        """Generate PCRE2 comparison chart.

        Args:
            timelines: All experiment timelines
        """
        pcre2_timelines = {k: v for k, v in timelines.items() if "pcre2" in k.lower()}

        if pcre2_timelines:
            output_path = self.charts_dir / "pcre2_coverage.png"
            self._chart_generator.generate_coverage_chart(
                pcre2_timelines,
                "PCRE2 10.47 Coverage Comparison",
                output_path,
            )

    def _generate_combined_chart(self, timelines: Dict[str, List[CoverageSnapshot]]) -> None:
        """Generate combined comparison chart.

        Args:
            timelines: All experiment timelines
        """
        if timelines:
            output_path = self.charts_dir / "combined_coverage.png"
            self._chart_generator.generate_coverage_chart(
                timelines,
                "All Experiments Coverage Comparison",
                output_path,
            )


def start_chart_monitor(
    results_dir: Path,
    charts_dir: Optional[Path] = None,
    interval_seconds: int = 600,
    experiment_names: Optional[List[str]] = None,
) -> ChartMonitor:
    """Start a chart monitor in the background.

    Args:
        results_dir: Directory containing experiment results
        charts_dir: Directory to save charts (defaults to results_dir/charts)
        interval_seconds: Update interval in seconds
        experiment_names: List of experiment names to monitor

    Returns:
        Started ChartMonitor thread
    """
    monitor = ChartMonitor(
        results_dir=results_dir,
        charts_dir=charts_dir,
        interval_seconds=interval_seconds,
        experiment_names=experiment_names,
    )
    monitor.start()
    return monitor
