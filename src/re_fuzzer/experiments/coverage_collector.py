"""Coverage collection and snapshot management for experiments.

This module handles periodic collection of coverage snapshots during
fuzzing experiments and provides utilities for merging and analyzing
coverage data.
"""

import csv
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

import numpy as np
from loguru import logger

from re_fuzzer.experiments.experiment_config import CoverageSnapshot
from re_fuzzer.fuzzing.coverage_tracker import CoverageTracker


class CoverageCollector:
    """Collects periodic coverage snapshots during fuzzing experiments."""

    def __init__(
        self,
        tracker: CoverageTracker,
        interval_seconds: int = 600,
        output_dir: Optional[Path] = None,
    ):
        """Initialize the coverage collector.

        Args:
            tracker: CoverageTracker instance to collect from
            interval_seconds: Seconds between snapshots
            output_dir: Directory to save snapshots (optional)
        """
        self.tracker = tracker
        self.interval_seconds = interval_seconds
        self.output_dir = output_dir

        self.start_time = time.time()
        self.last_snapshot_time = self.start_time
        self.snapshots: List[CoverageSnapshot] = []

    def take_snapshot(
        self,
        iterations: int,
        crashes: int,
        force: bool = False,
    ) -> Optional[CoverageSnapshot]:
        """Take a coverage snapshot if interval has elapsed.

        Args:
            iterations: Current iteration count
            crashes: Current crash count
            force: Force snapshot regardless of interval

        Returns:
            CoverageSnapshot if taken, None otherwise
        """
        current_time = time.time()

        if not force and (current_time - self.last_snapshot_time) < self.interval_seconds:
            return None

        stats = self.tracker.get_statistics()

        snapshot = CoverageSnapshot(
            timestamp=current_time,
            elapsed_seconds=current_time - self.start_time,
            unique_edges=stats.get("unique_edges", 0),
            total_edges=stats.get("total_edges", 0),
            iterations=iterations,
            crashes=crashes,
        )

        self.snapshots.append(snapshot)
        self.last_snapshot_time = current_time

        logger.debug(
            f"Coverage snapshot: {snapshot.unique_edges}/{snapshot.total_edges} edges "
            f"({snapshot.coverage_percent:.2f}%) at {snapshot.elapsed_seconds:.0f}s"
        )

        # Auto-save if output directory is set
        if self.output_dir:
            self.save_csv(self.output_dir / "coverage_timeline.csv")

        return snapshot

    def save_csv(self, path: Path) -> None:
        """Save snapshots to CSV file.

        Args:
            path: Path to save CSV file
        """
        path.parent.mkdir(parents=True, exist_ok=True)

        with open(path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(
                [
                    "timestamp",
                    "elapsed_seconds",
                    "unique_edges",
                    "total_edges",
                    "iterations",
                    "crashes",
                    "coverage_percent",
                ]
            )
            for snapshot in self.snapshots:
                writer.writerow(
                    [
                        snapshot.timestamp,
                        snapshot.elapsed_seconds,
                        snapshot.unique_edges,
                        snapshot.total_edges,
                        snapshot.iterations,
                        snapshot.crashes,
                        snapshot.coverage_percent,
                    ]
                )

    @staticmethod
    def load_csv(path: Path) -> List[CoverageSnapshot]:
        """Load snapshots from CSV file.

        Args:
            path: Path to CSV file

        Returns:
            List of CoverageSnapshot objects
        """
        snapshots = []

        if not path.exists():
            return snapshots

        with open(path, newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                # Handle timestamp being optional (default to 0)
                timestamp = float(row.get("timestamp", 0))
                snapshot = CoverageSnapshot(
                    timestamp=timestamp,
                    elapsed_seconds=float(row["elapsed_seconds"]),
                    unique_edges=int(row["unique_edges"]),
                    total_edges=int(row["total_edges"]),
                    iterations=int(row["iterations"]),
                    crashes=int(row["crashes"]),
                    coverage_percent=float(row.get("coverage_percent", 0)),
                )
                snapshots.append(snapshot)

        return snapshots


@dataclass
class MergedCoverage:
    """Merged coverage data from multiple workers/experiments."""

    unique_edges: int
    total_edges: int
    coverage_percent: float
    bitmap: bytes


def merge_coverage_bitmaps(bitmaps: List[bytes]) -> Optional[MergedCoverage]:
    """Merge multiple coverage bitmaps using OR operation.

    Args:
        bitmaps: List of coverage bitmap bytes

    Returns:
        MergedCoverage object or None if no valid bitmaps
    """
    if not bitmaps:
        return None

    # Filter out empty bitmaps
    valid_bitmaps = [b for b in bitmaps if b]
    if not valid_bitmaps:
        return None

    # Find expected size (use most common size)
    sizes = [len(b) for b in valid_bitmaps]
    expected_size = max(set(sizes), key=sizes.count)

    # Merge bitmaps of matching size
    merged = None
    for bitmap in valid_bitmaps:
        if len(bitmap) != expected_size:
            continue

        arr = np.frombuffer(bitmap, dtype=np.bool_)
        if merged is None:
            merged = arr.copy()
        else:
            merged |= arr

    if merged is None:
        return None

    unique_edges = int(np.sum(merged))
    total_edges = len(merged)
    coverage_percent = (unique_edges / total_edges * 100) if total_edges > 0 else 0

    return MergedCoverage(
        unique_edges=unique_edges,
        total_edges=total_edges,
        coverage_percent=coverage_percent,
        bitmap=merged.tobytes(),
    )


def aggregate_timelines(
    timelines: Dict[str, List[CoverageSnapshot]],
    normalize_time: bool = True,
) -> Dict[str, List[CoverageSnapshot]]:
    """Aggregate multiple timelines for comparison.

    This function aligns snapshots by elapsed time for fair comparison.

    Args:
        timelines: Dict mapping experiment name to snapshot list
        normalize_time: Whether to align snapshots to common time points

    Returns:
        Dict of aligned timelines
    """
    if not normalize_time:
        return timelines

    # Find common time points (union of all elapsed times)
    all_times = set()
    for snapshots in timelines.values():
        for s in snapshots:
            # Round to nearest 10 seconds for alignment
            rounded = round(s.elapsed_seconds / 10) * 10
            all_times.add(rounded)

    time_points = sorted(all_times)

    # Interpolate each timeline to common time points
    result = {}
    for name, snapshots in timelines.items():
        if not snapshots:
            continue

        aligned = []
        for t in time_points:
            # Find nearest snapshot
            nearest = min(snapshots, key=lambda s: abs(s.elapsed_seconds - t))

            # Only include if within 30 seconds of target time
            if abs(nearest.elapsed_seconds - t) <= 30:
                aligned.append(
                    CoverageSnapshot(
                        timestamp=nearest.timestamp,
                        elapsed_seconds=t,  # Use normalized time
                        unique_edges=nearest.unique_edges,
                        total_edges=nearest.total_edges,
                        iterations=nearest.iterations,
                        crashes=nearest.crashes,
                        coverage_percent=nearest.coverage_percent,
                    )
                )

        result[name] = aligned

    return result
