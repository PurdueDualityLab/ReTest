"""Parallel coordinator for multi-core fuzzing.

This module implements a coordinator that launches and manages multiple worker
processes for parallel fuzzing. It handles:
- Launching N worker processes (one per core)
- Periodic synchronization of coverage data
- Sharing interesting inputs via a common corpus directory
- Optional subtree pool merging

The architecture follows a coordinator-worker pattern where the coordinator
spawns worker processes and periodically merges their findings.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from loguru import logger


@dataclass
class WorkerConfig:
    """Configuration for a fuzzer worker process."""
    worker_id: int
    corpus_dir: Path
    stats_file: Path
    coverage_file: Path
    merged_coverage_file: Path
    pool_file: Path
    merged_pool_file: Path
    library_path: Optional[str]
    seed_file: Optional[str]
    max_seed_size: int = 10000
    max_subtree_bytes: int = 200
    max_pool_size: int = 100000
    mutation_probability: float = 0.8
    initial_pool_patterns: int = 5000
    passive_pool_update_chance: float = 0.05
    log_interval: int = 1000
    test_timeout: int = 2
    sut_type: str = "pcre2"


@dataclass
class CoordinatorConfig:
    """Configuration for the parallel coordinator."""
    num_workers: int = 4
    base_corpus_dir: str = "/tmp/re_fuzzer_parallel"
    library_path: Optional[str] = None
    seed_file: Optional[str] = None

    # Sync intervals (in seconds)
    coverage_sync_interval: int = 30
    corpus_sync_interval: int = 10
    pool_sync_interval: int = 300
    stats_report_interval: int = 60

    # Worker configuration
    max_seed_size: int = 10000
    max_subtree_bytes: int = 200
    max_pool_size: int = 100000
    mutation_probability: float = 0.8
    initial_pool_patterns: int = 5000
    passive_pool_update_chance: float = 0.05
    log_interval: int = 1000
    test_timeout: int = 2
    sut_type: str = "pcre2"

    # Atheris/libfuzzer options
    max_total_time: int = 0  # 0 = unlimited
    max_len: int = 1000


@dataclass
class WorkerStats:
    """Statistics for a single worker."""
    worker_id: int
    iterations: int = 0
    crashes: int = 0
    coverage_increases: int = 0
    pool_size: int = 0
    last_update: float = 0.0


class ParallelCoordinator:
    """Coordinator for parallel fuzzing across multiple cores.

    The coordinator manages multiple independent fuzzer processes, each running
    its own instance of AtherisHarness. It periodically:
    - Collects interesting inputs from workers
    - Distributes shared inputs across all workers
    - Aggregates statistics

    Workers communicate via the filesystem:
    - Each worker has its own corpus directory
    - Coordinator scans for new files and distributes them
    """

    def __init__(self, config: CoordinatorConfig):
        """Initialize the parallel coordinator.

        Args:
            config: Coordinator configuration
        """
        self.config = config
        self.workers: dict[int, subprocess.Popen] = {}
        self.worker_configs: dict[int, WorkerConfig] = {}
        self.worker_stats: dict[int, WorkerStats] = {}
        self.running = False

        # Create base directories
        self.base_dir = Path(config.base_corpus_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)

        # Shared corpus for interesting inputs
        self.shared_corpus_dir = self.base_dir / "shared_corpus"
        self.shared_corpus_dir.mkdir(exist_ok=True)

        # Stats directory
        self.stats_dir = self.base_dir / "stats"
        self.stats_dir.mkdir(exist_ok=True)

        # Track known files for sync
        self._known_corpus_files: set[str] = set()

        # Overall stats
        self.start_time = 0.0
        self.total_iterations = 0
        self.total_crashes = 0
        self.total_coverage_increases = 0

        # Historical stats from crashed/restarted workers (cumulative)
        self._historical_iterations = 0
        self._historical_crashes = 0
        self._historical_coverage_increases = 0
        self._historical_pool_size = 0

        logger.info(f"Parallel coordinator initialized with {config.num_workers} workers")

    def _create_worker_config(self, worker_id: int) -> WorkerConfig:
        """Create configuration for a worker process.

        Args:
            worker_id: Worker identifier (0 to num_workers-1)

        Returns:
            WorkerConfig for this worker
        """
        worker_dir = self.base_dir / f"worker_{worker_id}"
        corpus_dir = worker_dir / "corpus"
        corpus_dir.mkdir(parents=True, exist_ok=True)
        stats_file = worker_dir / "stats.json"
        coverage_file = worker_dir / "coverage.bin"
        merged_coverage_file = self.base_dir / "merged_coverage.bin"
        pool_file = worker_dir / "pool.jsonl"
        merged_pool_file = self.base_dir / "merged_pool.jsonl"

        return WorkerConfig(
            worker_id=worker_id,
            corpus_dir=corpus_dir,
            stats_file=stats_file,
            coverage_file=coverage_file,
            merged_coverage_file=merged_coverage_file,
            pool_file=pool_file,
            merged_pool_file=merged_pool_file,
            library_path=self.config.library_path,
            seed_file=self.config.seed_file,
            max_seed_size=self.config.max_seed_size,
            max_subtree_bytes=self.config.max_subtree_bytes,
            max_pool_size=self.config.max_pool_size,
            mutation_probability=self.config.mutation_probability,
            initial_pool_patterns=self.config.initial_pool_patterns,
            passive_pool_update_chance=self.config.passive_pool_update_chance,
            log_interval=self.config.log_interval,
            test_timeout=self.config.test_timeout,
            sut_type=self.config.sut_type,
        )

    def _build_worker_command(self, config: WorkerConfig) -> list[str]:
        """Build the command to launch a worker process.

        Args:
            config: Worker configuration

        Returns:
            Command as list of arguments
        """
        cmd = [
            sys.executable,
            "-m", "re_fuzzer.run_fuzzer",
            "--corpus-dir", str(config.corpus_dir),
            "--stats-file", str(config.stats_file),
            "--coverage-file", str(config.coverage_file),
            "--merged-coverage-file", str(config.merged_coverage_file),
            "--pool-file", str(config.pool_file),
            "--merged-pool-file", str(config.merged_pool_file),
            "--max-subtree-bytes", str(config.max_subtree_bytes),
            "--max-pool-size", str(config.max_pool_size),
            "--mutation-probability", str(config.mutation_probability),
            "--initial-pool-patterns", str(config.initial_pool_patterns),
            "--passive-pool-update-chance", str(config.passive_pool_update_chance),
            "--log-interval", str(config.log_interval),
            "--test-timeout", str(config.test_timeout),
            "--sut", config.sut_type,
            "--quiet",  # Reduce log noise in parallel mode
        ]

        if config.library_path:
            cmd.extend(["--library-path", config.library_path])

        if config.seed_file:
            cmd.extend(["--seed-file", config.seed_file])
        else:
            cmd.append("--no-seeds")

        # Add libfuzzer options after '--'
        cmd.append("--")

        if self.config.max_total_time > 0:
            cmd.append(f"-max_total_time={self.config.max_total_time}")

        cmd.append(f"-max_len={self.config.max_len}")
        cmd.append("-print_final_stats=0")  # We aggregate stats ourselves

        return cmd

    def _launch_worker(self, worker_id: int) -> subprocess.Popen:
        """Launch a single worker process.

        Args:
            worker_id: Worker identifier

        Returns:
            Popen object for the worker process
        """
        config = self._create_worker_config(worker_id)
        self.worker_configs[worker_id] = config

        cmd = self._build_worker_command(config)

        # Create log file for worker
        log_file = self.base_dir / f"worker_{worker_id}" / "worker.log"
        log_file.parent.mkdir(parents=True, exist_ok=True)

        logger.info(f"Launching worker {worker_id}: {' '.join(cmd[:5])}...")

        # Start process with output redirected to log file
        with open(log_file, "w") as f:
            process = subprocess.Popen(
                cmd,
                stdout=f,
                stderr=subprocess.STDOUT,
                cwd=Path.cwd(),
                env={**os.environ, "PYTHONUNBUFFERED": "1"},
            )

        self.worker_stats[worker_id] = WorkerStats(worker_id=worker_id)
        return process

    def _sync_corpus(self) -> int:
        """Synchronize corpus files across all workers.

        Scans each worker's corpus directory for new files and copies them
        to the shared corpus and other workers.

        Returns:
            Number of new files synchronized
        """
        new_files = 0

        # Collect new files from all workers
        all_new_files = []
        for worker_id, config in self.worker_configs.items():
            corpus_dir = config.corpus_dir
            if not corpus_dir.exists():
                continue

            for f in corpus_dir.iterdir():
                if f.is_file() and f.name not in self._known_corpus_files:
                    all_new_files.append((worker_id, f))
                    self._known_corpus_files.add(f.name)

        # Distribute new files to shared corpus and other workers
        for source_worker, source_file in all_new_files:
            # Copy to shared corpus
            shared_dest = self.shared_corpus_dir / source_file.name
            if not shared_dest.exists():
                try:
                    shared_dest.write_bytes(source_file.read_bytes())
                    new_files += 1
                except Exception as e:
                    logger.debug(f"Failed to copy {source_file} to shared: {e}")

            # Copy to other workers
            for worker_id, config in self.worker_configs.items():
                if worker_id == source_worker:
                    continue

                dest = config.corpus_dir / source_file.name
                if not dest.exists():
                    try:
                        dest.write_bytes(source_file.read_bytes())
                    except Exception as e:
                        logger.debug(f"Failed to copy to worker {worker_id}: {e}")

        if new_files > 0:
            logger.debug(f"Synchronized {new_files} new corpus files")

        return new_files

    def _sync_coverage(self) -> int:
        """Merge coverage bitmaps from all workers.

        Reads each worker's coverage file, OR-merges them together,
        and writes the merged result for workers to load.

        Returns:
            Number of new edges discovered in this sync
        """
        import numpy as np

        merged_file = self.base_dir / "merged_coverage.bin"
        merged_bitmap = None
        bitmap_size = 0

        # Read and merge all worker coverage files
        for worker_id, config in self.worker_configs.items():
            coverage_file = config.coverage_file
            if not coverage_file.exists():
                continue

            try:
                with open(coverage_file, "rb") as f:
                    data = f.read()
                if not data:
                    continue

                worker_bitmap = np.frombuffer(data, dtype=np.bool_).copy()

                if merged_bitmap is None:
                    merged_bitmap = worker_bitmap
                    bitmap_size = len(worker_bitmap)
                elif len(worker_bitmap) == bitmap_size:
                    # OR merge
                    merged_bitmap |= worker_bitmap
            except Exception as e:
                logger.debug(f"Failed to read coverage from worker {worker_id}: {e}")

        if merged_bitmap is None:
            return 0

        # Count total edges in merged bitmap
        total_edges = int(np.sum(merged_bitmap))

        # Write merged coverage for workers to load
        try:
            temp_file = merged_file.with_suffix(".tmp")
            with open(temp_file, "wb") as f:
                f.write(merged_bitmap.tobytes())
            temp_file.rename(merged_file)
            logger.debug(f"Merged coverage: {total_edges} total edges")
        except Exception as e:
            logger.debug(f"Failed to write merged coverage: {e}")

        return total_edges

    def _sync_pools(self) -> int:
        """Merge subtree pools from all workers.

        Reads each worker's pool file, merges them together,
        and writes the merged result for workers to load.

        Returns:
            Total number of entries in merged pool
        """
        import json

        merged_file = self.base_dir / "merged_pool.jsonl"
        seen_patterns: set[str] = set()
        merged_entries = []

        # Read and merge all worker pool files
        for worker_id, config in self.worker_configs.items():
            pool_file = config.pool_file
            if not pool_file.exists():
                continue

            try:
                with open(pool_file, "r") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            record = json.loads(line)
                            pattern = record.get("pattern", "")

                            # Deduplicate by pattern string
                            if pattern in seen_patterns:
                                continue
                            seen_patterns.add(pattern)
                            merged_entries.append(record)
                        except json.JSONDecodeError:
                            continue
            except Exception as e:
                logger.debug(f"Failed to read pool from worker {worker_id}: {e}")

        if not merged_entries:
            return 0

        # Write merged pool for workers to load
        try:
            temp_file = merged_file.with_suffix(".tmp")
            with open(temp_file, "w") as f:
                for record in merged_entries:
                    f.write(json.dumps(record) + "\n")
            temp_file.rename(merged_file)
            logger.debug(f"Merged pool: {len(merged_entries)} unique entries")
        except Exception as e:
            logger.debug(f"Failed to write merged pool: {e}")

        return len(merged_entries)

    def _collect_stats(self) -> None:
        """Collect statistics from worker stat files."""
        for worker_id in self.worker_configs:
            stat_file = self.base_dir / f"worker_{worker_id}" / "stats.json"
            if stat_file.exists():
                try:
                    with open(stat_file) as f:
                        data = json.load(f)

                    stats = self.worker_stats[worker_id]
                    stats.iterations = data.get("iterations", 0)
                    stats.crashes = data.get("crashes", 0)
                    stats.coverage_increases = data.get("coverage_increases", 0)
                    stats.pool_size = data.get("pool_size", 0)
                    stats.last_update = time.time()
                except Exception as e:
                    logger.debug(f"Failed to read stats for worker {worker_id}: {e}")

    def _report_stats(self) -> None:
        """Report aggregated statistics."""
        import numpy as np

        # Current stats from active workers + historical from crashed workers
        total_iterations = (
            sum(s.iterations for s in self.worker_stats.values())
            + self._historical_iterations
        )
        total_crashes = (
            sum(s.crashes for s in self.worker_stats.values())
            + self._historical_crashes
        )
        total_coverage = (
            sum(s.coverage_increases for s in self.worker_stats.values())
            + self._historical_coverage_increases
        )
        total_pool = sum(s.pool_size for s in self.worker_stats.values())

        elapsed = time.time() - self.start_time
        rate = total_iterations / elapsed if elapsed > 0 else 0

        # Count alive workers
        alive = sum(1 for p in self.workers.values() if p.poll() is None)

        # Calculate coverage percentage from merged bitmap
        coverage_pct = 0.0
        covered_edges = 0
        total_edges = 0
        merged_file = self.base_dir / "merged_coverage.bin"
        if merged_file.exists():
            try:
                with open(merged_file, "rb") as f:
                    data = f.read()
                if data:
                    bitmap = np.frombuffer(data, dtype=np.bool_)
                    total_edges = len(bitmap)
                    covered_edges = int(np.sum(bitmap))
                    coverage_pct = (covered_edges / total_edges * 100) if total_edges > 0 else 0.0
            except Exception:
                pass

        logger.info(
            f"[PARALLEL] Workers: {alive}/{self.config.num_workers} | "
            f"Iterations: {total_iterations:,} ({rate:.1f}/s) | "
            f"Coverage: {coverage_pct:.1f}% ({covered_edges:,}/{total_edges:,}) | "
            f"Coverage+: {total_coverage} | "
            f"Crashes: {total_crashes} | "
            f"Pool: {total_pool:,} | "
            f"Time: {elapsed:.0f}s"
        )

    def _check_workers(self) -> int:
        """Check worker health and restart dead workers.

        Returns:
            Number of workers restarted
        """
        restarted = 0
        for worker_id, process in list(self.workers.items()):
            if process.poll() is not None:
                # Worker died, check if we should restart
                exit_code = process.returncode
                if exit_code != 0:
                    logger.warning(f"Worker {worker_id} exited with code {exit_code}")

                # Preserve stats from the dead worker before restarting
                if worker_id in self.worker_stats:
                    old_stats = self.worker_stats[worker_id]
                    self._historical_iterations += old_stats.iterations
                    self._historical_crashes += old_stats.crashes
                    self._historical_coverage_increases += old_stats.coverage_increases
                    self._historical_pool_size = max(
                        self._historical_pool_size, old_stats.pool_size
                    )
                    logger.debug(
                        f"Preserved stats from worker {worker_id}: "
                        f"iterations={old_stats.iterations}, "
                        f"coverage+={old_stats.coverage_increases}"
                    )

                # Restart worker if we're still running
                if self.running:
                    logger.info(f"Restarting worker {worker_id}...")
                    self.workers[worker_id] = self._launch_worker(worker_id)
                    restarted += 1

        return restarted

    def start(self) -> None:
        """Start all worker processes."""
        self.running = True
        self.start_time = time.time()

        logger.info(f"Starting {self.config.num_workers} fuzzer workers...")

        for worker_id in range(self.config.num_workers):
            try:
                self.workers[worker_id] = self._launch_worker(worker_id)
                # Stagger worker starts slightly to reduce seed loading contention
                time.sleep(0.5)
            except Exception as e:
                logger.error(f"Failed to start worker {worker_id}: {e}")

        logger.info(f"All {len(self.workers)} workers started")

    def stop(self) -> None:
        """Stop all worker processes."""
        self.running = False

        logger.info("Stopping all workers...")

        for worker_id, process in self.workers.items():
            if process.poll() is None:
                # Send SIGTERM for graceful shutdown
                process.terminate()

        # Wait for graceful shutdown
        time.sleep(2)

        # Force kill any remaining
        for worker_id, process in self.workers.items():
            if process.poll() is None:
                logger.warning(f"Force killing worker {worker_id}")
                process.kill()

        self.workers.clear()
        logger.info("All workers stopped")

    def run(self, duration: int = 0) -> dict[str, Any]:
        """Run the parallel fuzzing campaign.

        Args:
            duration: How long to run in seconds (0 = until interrupted)

        Returns:
            Dictionary of aggregated statistics
        """
        # Set up signal handlers
        original_sigint = signal.signal(signal.SIGINT, lambda s, f: self._handle_interrupt())
        original_sigterm = signal.signal(signal.SIGTERM, lambda s, f: self._handle_interrupt())

        try:
            self.start()

            last_corpus_sync = time.time()
            last_coverage_sync = time.time()
            last_pool_sync = time.time()
            last_stats_report = time.time()
            last_worker_check = time.time()

            end_time = time.time() + duration if duration > 0 else float('inf')

            while self.running and time.time() < end_time:
                now = time.time()

                # Periodic corpus synchronization
                if now - last_corpus_sync >= self.config.corpus_sync_interval:
                    self._sync_corpus()
                    last_corpus_sync = now

                # Periodic coverage synchronization
                if now - last_coverage_sync >= self.config.coverage_sync_interval:
                    self._sync_coverage()
                    last_coverage_sync = now

                # Periodic pool synchronization (every 5 minutes)
                if now - last_pool_sync >= self.config.pool_sync_interval:
                    self._sync_pools()
                    last_pool_sync = now

                # Periodic stats collection and reporting
                if now - last_stats_report >= self.config.stats_report_interval:
                    self._collect_stats()
                    self._report_stats()
                    last_stats_report = now

                # Periodic worker health check
                if now - last_worker_check >= 10:  # Check every 10 seconds
                    self._check_workers()
                    last_worker_check = now

                # Sleep briefly to avoid busy waiting
                time.sleep(1)

        finally:
            # Restore signal handlers
            signal.signal(signal.SIGINT, original_sigint)
            signal.signal(signal.SIGTERM, original_sigterm)

            self.stop()

        # Collect final stats
        self._collect_stats()

        return {
            "total_iterations": (
                sum(s.iterations for s in self.worker_stats.values())
                + self._historical_iterations
            ),
            "total_crashes": (
                sum(s.crashes for s in self.worker_stats.values())
                + self._historical_crashes
            ),
            "total_coverage_increases": (
                sum(s.coverage_increases for s in self.worker_stats.values())
                + self._historical_coverage_increases
            ),
            "total_pool_size": sum(s.pool_size for s in self.worker_stats.values()),
            "elapsed_time": time.time() - self.start_time,
            "num_workers": self.config.num_workers,
            "corpus_files": len(self._known_corpus_files),
        }

    def _handle_interrupt(self) -> None:
        """Handle interrupt signal."""
        logger.info("Received interrupt signal, shutting down...")
        self.running = False


def run_parallel_fuzzer(
    num_workers: int = 4,
    library_path: Optional[str] = None,
    seed_file: Optional[str] = None,
    duration: int = 0,
    base_dir: str = "/tmp/re_fuzzer_parallel",
    sut_type: str = "pcre2",
    **kwargs,
) -> dict[str, Any]:
    """Convenience function to run parallel fuzzing.

    Args:
        num_workers: Number of parallel workers
        library_path: Path to instrumented library
        seed_file: Path to seed corpus
        duration: How long to run (0 = until interrupted)
        base_dir: Base directory for worker data
        sut_type: Type of SUT to use ("pcre", "pcre2")
        **kwargs: Additional configuration options

    Returns:
        Dictionary of aggregated statistics
    """
    config = CoordinatorConfig(
        num_workers=num_workers,
        library_path=library_path,
        seed_file=seed_file,
        base_corpus_dir=base_dir,
        sut_type=sut_type,
        max_total_time=duration,
        **{k: v for k, v in kwargs.items() if hasattr(CoordinatorConfig, k)},
    )

    coordinator = ParallelCoordinator(config)
    return coordinator.run(duration=duration)
