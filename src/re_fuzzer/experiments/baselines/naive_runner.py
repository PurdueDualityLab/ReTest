"""Naive byte-level fuzzing baseline runner.

This implements a libFuzzer-style naive fuzzer that uses:
- Random byte mutations (bit flip, byte flip, insert, delete)
- Dictionary token injection
- No AST awareness or grammar knowledge
- Direct ctypes library invocation (no ReTest optimizations)
"""

import multiprocessing as mp
import os
import random
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from loguru import logger

from re_fuzzer.experiments.baselines.direct_pcre import create_direct_wrapper
from re_fuzzer.experiments.experiment_config import (
    BugInfo,
    CoverageSnapshot,
    ExperimentConfig,
    ExperimentResult,
)
from re_fuzzer.fuzzing.coverage_tracker import CoverageTracker


@dataclass
class MutationStats:
    """Statistics about mutations performed."""

    bit_flips: int = 0
    byte_flips: int = 0
    insertions: int = 0
    deletions: int = 0
    dictionary_inserts: int = 0
    crossovers: int = 0


class NaiveMutator:
    """Simple byte-level mutator similar to libFuzzer."""

    def __init__(self, dictionary_path: Optional[Path] = None, max_size: int = 4096):
        """Initialize mutator.

        Args:
            dictionary_path: Path to dictionary file with tokens
            max_size: Maximum pattern size in bytes
        """
        self.max_size = max_size
        self.dictionary: List[bytes] = []
        self.stats = MutationStats()

        if dictionary_path and dictionary_path.exists():
            self._load_dictionary(dictionary_path)

    def _load_dictionary(self, path: Path) -> None:
        """Load dictionary tokens from file."""
        try:
            with open(path, "r") as f:
                for line in f:
                    line = line.strip()
                    # Skip comments and empty lines
                    if not line or line.startswith("#"):
                        continue
                    # Remove quotes if present
                    if line.startswith('"') and line.endswith('"'):
                        line = line[1:-1]
                    # Handle escape sequences
                    try:
                        token = line.encode("utf-8").decode("unicode_escape").encode("utf-8")
                        self.dictionary.append(token)
                    except (UnicodeDecodeError, ValueError):
                        # Keep as-is if escape processing fails
                        self.dictionary.append(line.encode("utf-8"))

            logger.info(f"Loaded {len(self.dictionary)} dictionary tokens")
        except Exception as e:
            logger.warning(f"Failed to load dictionary: {e}")

    def generate_seed(self) -> bytes:
        """Generate a random seed pattern."""
        # Mix of random bytes and dictionary tokens
        if self.dictionary and random.random() < 0.5:
            # Start with a dictionary token
            pattern = random.choice(self.dictionary)
        else:
            # Random bytes
            length = random.randint(1, 50)
            pattern = bytes(random.randint(0, 255) for _ in range(length))

        return pattern

    def mutate(self, data: bytes) -> bytes:
        """Apply random mutations to the input.

        Args:
            data: Input bytes to mutate

        Returns:
            Mutated bytes
        """
        if not data:
            return self.generate_seed()

        # Choose mutation type
        mutation_type = random.choices(
            ["bit_flip", "byte_flip", "insert", "delete", "dictionary", "crossover"],
            weights=[0.2, 0.2, 0.2, 0.15, 0.2, 0.05],
            k=1,
        )[0]

        result = bytearray(data)

        if mutation_type == "bit_flip" and result:
            # Flip a random bit
            pos = random.randint(0, len(result) - 1)
            bit = random.randint(0, 7)
            result[pos] ^= 1 << bit
            self.stats.bit_flips += 1

        elif mutation_type == "byte_flip" and result:
            # Replace a random byte
            pos = random.randint(0, len(result) - 1)
            result[pos] = random.randint(0, 255)
            self.stats.byte_flips += 1

        elif mutation_type == "insert" and len(result) < self.max_size:
            # Insert random byte(s)
            pos = random.randint(0, len(result))
            count = random.randint(1, min(10, self.max_size - len(result)))
            insert_bytes = bytes(random.randint(0, 255) for _ in range(count))
            result = result[:pos] + insert_bytes + result[pos:]
            self.stats.insertions += 1

        elif mutation_type == "delete" and len(result) > 1:
            # Delete random byte(s)
            pos = random.randint(0, len(result) - 1)
            count = random.randint(1, min(5, len(result) - pos))
            result = result[:pos] + result[pos + count :]
            self.stats.deletions += 1

        elif mutation_type == "dictionary" and self.dictionary:
            # Insert dictionary token
            token = random.choice(self.dictionary)
            if len(result) + len(token) <= self.max_size:
                pos = random.randint(0, len(result))
                result = result[:pos] + token + result[pos:]
                self.stats.dictionary_inserts += 1

        elif mutation_type == "crossover":
            # No crossover for single input - generate new seed
            result = bytearray(self.generate_seed())
            self.stats.crossovers += 1

        return bytes(result[: self.max_size])


def _worker_process(
    worker_id: int,
    config: ExperimentConfig,
    result_queue: mp.Queue,
    stop_event: mp.Event,
    snapshot_interval: int,
) -> None:
    """Worker process for naive fuzzing.

    Args:
        worker_id: Unique worker identifier
        config: Experiment configuration
        result_queue: Queue for sending results back
        stop_event: Event to signal stop
        snapshot_interval: Seconds between snapshots
    """
    logger.info(f"Worker {worker_id} starting naive fuzzing")

    # Initialize components
    engine = create_direct_wrapper(config.engine, config.library_path)
    mutator = NaiveMutator(
        dictionary_path=config.dictionary_path,
        max_size=4096,
    )

    # Initialize coverage tracker
    coverage_tracker = CoverageTracker(str(config.library_path))

    # State
    start_time = time.time()
    last_snapshot_time = start_time
    iterations = 0
    crashes = 0
    bugs: List[BugInfo] = []

    # Record initial t=0 snapshot (before any fuzzing)
    # This captures the baseline coverage from library initialization
    initial_stats = coverage_tracker.get_statistics()
    initial_snapshot = CoverageSnapshot(
        timestamp=time.time(),
        elapsed_seconds=0.0,
        unique_edges=initial_stats.get("unique_edges", 0),
        total_edges=initial_stats.get("total_edges", 0),
        iterations=0,
        crashes=0,
    )
    result_queue.put(("snapshot", worker_id, initial_snapshot))

    # Corpus - small set of interesting inputs
    corpus: List[bytes] = [mutator.generate_seed() for _ in range(10)]

    # Also generate test strings
    test_strings = [
        b"",
        b"a",
        b"aaa",
        b"abc",
        b"abcdefghij",
        b"\x00\x01\x02",
        b"test string",
        b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ]

    try:
        while not stop_event.is_set():
            # Get input from corpus or generate new
            if corpus and random.random() < 0.8:
                base_pattern = random.choice(corpus)
            else:
                base_pattern = mutator.generate_seed()

            # Mutate
            pattern = mutator.mutate(base_pattern)

            # Test against subject strings
            test_string = random.choice(test_strings)

            try:
                coverage_tracker.reset()
                matched, error = engine.compile_and_match(pattern, test_string)

                # Check for new coverage
                if coverage_tracker.check_and_update_coverage():
                    # Add to corpus if new coverage
                    if len(corpus) < 1000:
                        corpus.append(pattern)
                    else:
                        # Replace random entry
                        corpus[random.randint(0, len(corpus) - 1)] = pattern

                if error and "crash" in error.lower():
                    crashes += 1
                    bug = BugInfo(
                        pattern=pattern.decode("utf-8", errors="replace"),
                        test_string=test_string.decode("utf-8", errors="replace"),
                        error_type="crash",
                        error_message=error,
                        timestamp=time.time(),
                    )
                    bugs.append(bug)

            except Exception as e:
                crashes += 1
                bug = BugInfo(
                    pattern=pattern.decode("utf-8", errors="replace"),
                    test_string=test_string.decode("utf-8", errors="replace"),
                    error_type="exception",
                    error_message=str(e),
                    timestamp=time.time(),
                )
                bugs.append(bug)

            iterations += 1

            # Periodic snapshot
            current_time = time.time()
            if current_time - last_snapshot_time >= snapshot_interval:
                stats = coverage_tracker.get_statistics()
                snapshot = CoverageSnapshot(
                    timestamp=current_time,
                    elapsed_seconds=current_time - start_time,
                    unique_edges=stats.get("unique_edges", 0),
                    total_edges=stats.get("total_edges", 0),
                    iterations=iterations,
                    crashes=crashes,
                )
                result_queue.put(("snapshot", worker_id, snapshot))
                last_snapshot_time = current_time

    except KeyboardInterrupt:
        pass

    # Final snapshot
    stats = coverage_tracker.get_statistics()
    final_snapshot = CoverageSnapshot(
        timestamp=time.time(),
        elapsed_seconds=time.time() - start_time,
        unique_edges=stats.get("unique_edges", 0),
        total_edges=stats.get("total_edges", 0),
        iterations=iterations,
        crashes=crashes,
    )
    result_queue.put(("final", worker_id, final_snapshot, bugs, coverage_tracker.export_bitmap()))
    logger.info(f"Worker {worker_id} finished: {iterations} iterations, {crashes} crashes")


class NaiveFuzzerRunner:
    """Runner for naive byte-level fuzzing baseline."""

    def __init__(self, config: ExperimentConfig):
        """Initialize runner with experiment configuration.

        Args:
            config: Experiment configuration
        """
        self.config = config

    def run(self) -> ExperimentResult:
        """Run the naive fuzzing experiment.

        Returns:
            ExperimentResult with coverage snapshots and bugs
        """
        logger.info(f"Starting naive fuzzing experiment: {self.config.name}")

        result = ExperimentResult(config=self.config)
        start_time = time.time()

        # Create output directories
        output_dir = self.config.output_dir / self.config.name
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "crashes").mkdir(exist_ok=True)

        # Multiprocessing setup
        ctx = mp.get_context("spawn")
        result_queue = ctx.Queue()
        stop_event = ctx.Event()

        # Start workers
        workers = []
        for i in range(self.config.num_workers):
            p = ctx.Process(
                target=_worker_process,
                args=(
                    i,
                    self.config,
                    result_queue,
                    stop_event,
                    self.config.snapshot_interval_seconds,
                ),
            )
            p.start()
            workers.append(p)

        # Collect results until duration expires
        merged_bitmap = None
        all_bugs: List[BugInfo] = []
        snapshots_by_time: dict[float, CoverageSnapshot] = {}
        timeline_path = output_dir / "coverage_timeline.csv"

        def write_timeline_csv():
            """Write current snapshots to CSV for real-time chart updates."""
            try:
                import csv
                sorted_snapshots = [s for _, s in sorted(snapshots_by_time.items())]
                with open(timeline_path, "w", newline="") as f:
                    writer = csv.writer(f)
                    writer.writerow(["elapsed_seconds", "unique_edges", "total_edges", "iterations", "crashes", "coverage_percent"])
                    for snap in sorted_snapshots:
                        writer.writerow([
                            snap.elapsed_seconds,
                            snap.unique_edges,
                            snap.total_edges,
                            snap.iterations,
                            snap.crashes,
                            snap.coverage_percent,
                        ])
            except Exception as e:
                logger.debug(f"Failed to write timeline CSV: {e}")

        try:
            while time.time() - start_time < self.config.duration_seconds:
                try:
                    msg = result_queue.get(timeout=1.0)
                    msg_type = msg[0]

                    if msg_type == "snapshot":
                        _, worker_id, snapshot = msg
                        # Aggregate snapshots by time bucket
                        time_bucket = int(snapshot.elapsed_seconds / self.config.snapshot_interval_seconds)
                        if time_bucket not in snapshots_by_time:
                            snapshots_by_time[time_bucket] = snapshot
                        else:
                            # Merge with existing
                            existing = snapshots_by_time[time_bucket]
                            existing.iterations += snapshot.iterations
                            existing.crashes += snapshot.crashes
                            existing.unique_edges = max(existing.unique_edges, snapshot.unique_edges)
                        # Write CSV for real-time chart updates
                        write_timeline_csv()

                    elif msg_type == "final":
                        _, worker_id, snapshot, bugs, bitmap = msg
                        all_bugs.extend(bugs)
                        # Also add the final snapshot to results
                        # Use a special time bucket to ensure it's included
                        time_bucket = int(snapshot.elapsed_seconds / self.config.snapshot_interval_seconds)
                        if time_bucket not in snapshots_by_time:
                            snapshots_by_time[time_bucket] = snapshot
                        else:
                            existing = snapshots_by_time[time_bucket]
                            existing.iterations += snapshot.iterations
                            existing.crashes += snapshot.crashes
                            existing.unique_edges = max(existing.unique_edges, snapshot.unique_edges)
                        # Merge coverage bitmap
                        if merged_bitmap is None and bitmap:
                            merged_bitmap = bytearray(bitmap)
                        elif bitmap and merged_bitmap:
                            import numpy as np
                            existing = np.frombuffer(bytes(merged_bitmap), dtype=np.bool_)
                            other = np.frombuffer(bitmap, dtype=np.bool_)
                            if len(existing) == len(other):
                                merged = existing | other
                                merged_bitmap = bytearray(merged.tobytes())

                except Exception:
                    pass

        except KeyboardInterrupt:
            logger.info("Experiment interrupted")

        finally:
            # Signal workers to stop
            stop_event.set()

            # Drain remaining messages - important for collecting final stats
            drain_timeout = time.time() + 5.0  # Max 5 seconds to drain
            while time.time() < drain_timeout:
                try:
                    msg = result_queue.get(timeout=0.5)
                    if msg[0] == "final":
                        _, worker_id, snapshot, bugs, bitmap = msg
                        all_bugs.extend(bugs)
                        # Add final snapshot to results
                        time_bucket = int(snapshot.elapsed_seconds / self.config.snapshot_interval_seconds)
                        if time_bucket not in snapshots_by_time:
                            snapshots_by_time[time_bucket] = snapshot
                        else:
                            existing = snapshots_by_time[time_bucket]
                            existing.iterations += snapshot.iterations
                            existing.crashes += snapshot.crashes
                            existing.unique_edges = max(existing.unique_edges, snapshot.unique_edges)
                except Exception:
                    break

            # Wait for workers
            for p in workers:
                p.join(timeout=5.0)
                if p.is_alive():
                    p.terminate()

        # Build final result
        for _, snapshot in sorted(snapshots_by_time.items()):
            result.add_snapshot(snapshot)

        for bug in all_bugs:
            result.add_bug(bug)

        result.duration_actual_seconds = time.time() - start_time

        if result.snapshots:
            result.final_coverage = result.snapshots[-1].unique_edges
            result.final_coverage_percent = result.snapshots[-1].coverage_percent
            result.total_iterations = result.snapshots[-1].iterations

        # Save results
        self._save_results(result, output_dir)

        logger.info(
            f"Naive fuzzing completed: {result.total_iterations} iterations, "
            f"{result.total_crashes} crashes, {result.final_coverage} edges"
        )

        return result

    def _save_results(self, result: ExperimentResult, output_dir: Path) -> None:
        """Save experiment results to files.

        Args:
            result: Experiment results
            output_dir: Directory to save to
        """
        import csv
        import json

        # Save coverage timeline
        timeline_path = output_dir / "coverage_timeline.csv"
        with open(timeline_path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(
                ["elapsed_seconds", "unique_edges", "total_edges", "iterations", "crashes", "coverage_percent"]
            )
            for snapshot in result.snapshots:
                writer.writerow(
                    [
                        snapshot.elapsed_seconds,
                        snapshot.unique_edges,
                        snapshot.total_edges,
                        snapshot.iterations,
                        snapshot.crashes,
                        snapshot.coverage_percent,
                    ]
                )

        # Save bugs
        for i, bug in enumerate(result.bugs):
            bug_dir = output_dir / "crashes" / f"bug_{i:04d}"
            bug_dir.mkdir(exist_ok=True)
            with open(bug_dir / "pattern.txt", "w") as f:
                f.write(bug.pattern)
            if bug.test_string:
                with open(bug_dir / "test_string.txt", "w") as f:
                    f.write(bug.test_string)
            with open(bug_dir / "info.json", "w") as f:
                json.dump(
                    {
                        "error_type": bug.error_type,
                        "error_message": bug.error_message,
                        "timestamp": bug.timestamp,
                    },
                    f,
                    indent=2,
                )

        # Save summary stats
        stats_path = output_dir / "stats.json"
        with open(stats_path, "w") as f:
            json.dump(
                {
                    "name": result.config.name,
                    "strategy": result.config.strategy,
                    "engine": result.config.engine,
                    "total_iterations": result.total_iterations,
                    "total_crashes": result.total_crashes,
                    "final_coverage": result.final_coverage,
                    "final_coverage_percent": result.final_coverage_percent,
                    "duration_seconds": result.duration_actual_seconds,
                    "num_snapshots": len(result.snapshots),
                },
                f,
                indent=2,
            )
