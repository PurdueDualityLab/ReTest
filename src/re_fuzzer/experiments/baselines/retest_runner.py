"""ReTest fuzzing runner - Pure Python implementation.

This implements ReTest-style fuzzing with:
- Grammar-aware AST mutation (Superion-style)
- Advanced pattern generation for PCRE features
- Coverage-guided subtree pool updates
- DirectPCRE wrapper for ASAN compatibility
- Pure Python fuzzing loop (no Atheris for ASAN compatibility)
"""

import json
import multiprocessing as mp
import random
import time
from pathlib import Path
from typing import List

from loguru import logger

from re_fuzzer.experiments.experiment_config import (
    BugInfo,
    CoverageSnapshot,
    ExperimentConfig,
    ExperimentResult,
)
from re_fuzzer.fuzzing.advanced_pattern_generator import AdvancedPatternGenerator, PCREFeature
from re_fuzzer.fuzzing.coverage_tracker import CoverageTracker
from re_fuzzer.fuzzing.grammar_aware_mutator import GrammarAwareMutator
from re_fuzzer.fuzzing.pool_updater import PoolUpdater
from re_fuzzer.fuzzing.seed_manager import SeedManager
from re_fuzzer.fuzzing.subtree_pool import SubtreePool


def _worker_process(
    worker_id: int,
    config: ExperimentConfig,
    result_queue: mp.Queue,
    stop_event: mp.Event,
    snapshot_interval: int,
    coordination_dir: Path,
) -> None:
    """Worker process for ReTest fuzzing.

    Uses pure Python fuzzing loop with grammar-aware mutation and CFFI wrapper.
    """
    logger.info(f"Worker {worker_id} starting ReTest fuzzing")

    # Initialize engine with DirectPCREReTest (ASAN-stable with coverage features)
    # Uses ctypes instead of CFFI but includes option rotation, DFA, partial matching, JIT
    from re_fuzzer.experiments.baselines.direct_pcre import create_retest_wrapper
    engine = create_retest_wrapper(
        config.engine,
        config.library_path,
        use_jit=True,
        use_dfa_percentage=0.2,  # 20% DFA matching
        rotate_options=True,  # Rotate compile/match options
        partial_match_percentage=0.1,  # 10% partial matching
    )

    # Initialize coverage tracker
    coverage_tracker = CoverageTracker(str(config.library_path))

    # Helper function to call engine with consistent interface
    def run_match(pattern_bytes: bytes, text_bytes: bytes):
        """Run match with DirectPCRE interface."""
        # DirectPCRE uses compile_and_match(pattern: bytes, subject: bytes)
        return engine.compile_and_match(pattern_bytes, text_bytes)

    # Initialize advanced pattern generator
    # Note: Advanced features are temporarily toned down to avoid ASAN crashes
    # while still getting coverage from basic grammar-aware mutation
    feature_weights = {
        PCREFeature.RECURSION: 0.5,  # Reduced - recursion can trigger bugs
        PCREFeature.CONDITIONAL: 1.0,
        PCREFeature.BACKTRACK_CONTROL: 0.2,  # Very low - these often crash
        PCREFeature.SUBROUTINE: 0.5,  # Reduced
        PCREFeature.ATOMIC_GROUP: 1.5,
        PCREFeature.UNICODE_PROPERTY: 0.5,  # Reduced - PCRE 8.45 has limited support
    }
    advanced_generator = AdvancedPatternGenerator(feature_weights=feature_weights)

    # Initialize subtree pool and mutator with advanced generator
    subtree_pool = SubtreePool(max_subtree_bytes=200, max_pool_size=config.max_pool_size)
    mutator = GrammarAwareMutator(
        subtree_pool,
        mutation_probability=config.mutation_probability,
        advanced_generator=advanced_generator,
        advanced_weight=config.advanced_generator_weight,
    )
    pool_updater = PoolUpdater(subtree_pool)

    # Load seed corpus - check for saved state first (for worker restart)
    seed_manager = SeedManager()
    corpus: List[bytes] = []

    # Shared corpus file for all workers (survives restarts)
    shared_corpus_file = coordination_dir / "shared_corpus.jsonl"

    def load_shared_corpus() -> List[bytes]:
        """Load corpus from shared file if it exists."""
        if shared_corpus_file.exists():
            try:
                patterns = []
                with open(shared_corpus_file, "r") as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            try:
                                data = json.loads(line)
                                patterns.append(data["pattern"].encode("utf-8"))
                            except Exception:
                                pass
                if patterns:
                    logger.info(f"Worker {worker_id}: Loaded {len(patterns)} patterns from shared corpus")
                    return patterns
            except Exception as e:
                logger.debug(f"Failed to load shared corpus: {e}")
        return []

    def save_to_shared_corpus(pattern: bytes):
        """Append a coverage-increasing pattern to shared corpus."""
        try:
            with open(shared_corpus_file, "a") as f:
                f.write(json.dumps({"pattern": pattern.decode("utf-8", errors="replace")}) + "\n")
        except Exception:
            pass

    # Try to load from shared corpus first (for restarts)
    corpus = load_shared_corpus()

    # If no shared corpus, load from seed file
    if not corpus and config.seed_file and config.seed_file.exists():
        patterns = seed_manager.load_from_jsonl(str(config.seed_file))
        logger.info(f"Worker {worker_id}: Loaded {len(patterns)} seed patterns")

        # Limit seed size
        if len(patterns) > config.max_seed_size:
            rng = random.Random(42 + worker_id)
            patterns = rng.sample(patterns, config.max_seed_size)

        # Filter valid patterns and build initial corpus
        for pattern in patterns:
            try:
                matched, error = run_match(pattern.encode("utf-8"), b"")
                if not error or "compil" not in error.lower():
                    corpus.append(pattern.encode("utf-8"))
            except Exception:
                pass

        logger.info(f"Worker {worker_id}: {len(corpus)} valid patterns in corpus")

    # Bootstrap subtree pool from corpus
    pool_patterns = corpus[:min(500, len(corpus))]
    for p in pool_patterns:
        try:
            pool_updater.update_from_input(p)
        except Exception:
            pass

    logger.info(f"Worker {worker_id}: Pool size = {subtree_pool.size()}")

    # If no seeds, start with simple patterns
    if not corpus:
        corpus = [b"a", b".*", b"[a-z]+", b"\\d+", b"(a|b)*"]

    # Test strings
    test_strings = [
        b"", b"a", b"aaa", b"abc", b"abcdefghij",
        b"hello world", b"test123", b"foo@bar.com",
        b"2024-01-15", b"192.168.1.1",
        b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        b"\x00\x01\x02\x03", b"the quick brown fox",
    ]

    # State
    start_time = time.time()
    last_snapshot_time = start_time
    iterations = 0
    crashes = 0
    coverage_increases = 0
    total_mutations = 0  # Total mutations attempted
    bugs: List[BugInfo] = []

    # Record initial t=0 snapshot
    initial_stats = coverage_tracker.get_statistics()
    initial_snapshot = CoverageSnapshot(
        timestamp=time.time(),
        elapsed_seconds=0.0,
        unique_edges=initial_stats.get("unique_edges", 0),
        total_edges=initial_stats.get("total_edges", 0),
        iterations=0,
        crashes=0,
        total_mutations=0,
        coverage_mutations=0,
    )
    result_queue.put(("snapshot", worker_id, initial_snapshot))

    # Worker-specific stats file and crash tracking
    worker_dir = coordination_dir / f"worker_{worker_id}"
    worker_dir.mkdir(parents=True, exist_ok=True)
    stats_file = worker_dir / "stats.json"
    pending_pattern_file = worker_dir / "pending_pattern.txt"
    heartbeat_file = worker_dir / "heartbeat"
    crashes_dir = config.output_dir / config.name / "crashes"
    crashes_dir.mkdir(parents=True, exist_ok=True)

    def write_heartbeat():
        """Write heartbeat timestamp - coordinator uses this to detect dead workers."""
        try:
            with open(heartbeat_file, "w") as f:
                f.write(str(time.time()))
        except Exception:
            pass

    def write_stats():
        try:
            stats = coverage_tracker.get_statistics()
            with open(stats_file, "w") as f:
                json.dump({
                    "iterations": iterations,
                    "crashes": crashes,
                    "coverage_increases": coverage_increases,
                    "total_mutations": total_mutations,
                    "unique_edges": stats.get("unique_edges", 0),
                    "total_edges": stats.get("total_edges", 0),
                    "pool_size": subtree_pool.size(),
                }, f)
        except Exception:
            pass

    def save_pending_pattern(pattern_bytes: bytes, test_bytes: bytes):
        """Save pattern before compile - if process crashes, this survives."""
        try:
            with open(pending_pattern_file, "wb") as f:
                f.write(b"PATTERN:\n")
                f.write(pattern_bytes)
                f.write(b"\nTEST:\n")
                f.write(test_bytes)
        except Exception:
            pass

    def clear_pending_pattern():
        """Clear pending pattern after successful compile."""
        try:
            if pending_pattern_file.exists():
                pending_pattern_file.unlink()
        except Exception:
            pass

    def save_crash(pattern_bytes: bytes, test_bytes: bytes, error_msg: str):
        """Save a crash to the crashes directory."""
        try:
            import hashlib
            pattern_hash = hashlib.sha1(pattern_bytes).hexdigest()[:12]
            crash_file = crashes_dir / f"crash_{pattern_hash}.txt"
            with open(crash_file, "w") as f:
                f.write(f"Pattern: {pattern_bytes.decode('utf-8', errors='replace')}\n")
                f.write(f"Test string: {test_bytes.decode('utf-8', errors='replace')}\n")
                f.write(f"Error: {error_msg}\n")
                f.write(f"Timestamp: {time.time()}\n")
        except Exception:
            pass

    # Write initial heartbeat
    write_heartbeat()
    logger.info(f"Worker {worker_id} entering main loop")

    try:
        while not stop_event.is_set() and (time.time() - start_time) < config.duration_seconds:
            # Pick a pattern from corpus and mutate it
            base_pattern = random.choice(corpus)

            try:
                # Grammar-aware mutation
                pattern = mutator.mutate(base_pattern, max_size=500, seed=random.randint(0, 2**31))
                total_mutations += 1  # Count successful mutations
            except Exception:
                pattern = base_pattern

            # Pick test string
            test_string = random.choice(test_strings)

            try:
                # Save pattern BEFORE compile - survives ASAN crashes
                save_pending_pattern(pattern, test_string)

                # Reset coverage for this iteration
                coverage_tracker.reset()

                # Compile and match
                matched, error = run_match(pattern, test_string)

                # Clear pending pattern after successful compile
                clear_pending_pattern()

                # Check for new coverage
                has_new_coverage = coverage_tracker.check_and_update_coverage()

                if has_new_coverage:
                    coverage_increases += 1
                    # Add to corpus if it found new coverage
                    if pattern not in corpus:
                        corpus.append(pattern)
                        # Save to shared corpus for restart persistence
                        save_to_shared_corpus(pattern)
                        if len(corpus) > 10000:
                            corpus = corpus[-5000:]  # Keep recent patterns
                    # Update pool with coverage-finding patterns
                    try:
                        pool_updater.update_from_input(pattern)
                    except Exception:
                        pass

                # Track crashes
                if error and ("crash" in error.lower() or "segfault" in error.lower()):
                    crashes += 1
                    save_crash(pattern, test_string, error)
                    bugs.append(BugInfo(
                        pattern=pattern.decode("utf-8", errors="replace"),
                        test_string=test_string.decode("utf-8", errors="replace"),
                        error_type="crash",
                        error_message=error,
                        timestamp=time.time(),
                    ))

            except Exception as e:
                crashes += 1
                save_crash(pattern, test_string, str(e))
                bugs.append(BugInfo(
                    pattern=pattern.decode("utf-8", errors="replace"),
                    test_string=test_string.decode("utf-8", errors="replace"),
                    error_type="exception",
                    error_message=str(e),
                    timestamp=time.time(),
                ))

            iterations += 1

            # Write stats and heartbeat periodically
            if iterations % 100 == 0:
                write_stats()
                write_heartbeat()

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
                    total_mutations=total_mutations,
                    coverage_mutations=coverage_increases,
                )
                result_queue.put(("snapshot", worker_id, snapshot))
                last_snapshot_time = current_time

                # Log progress
                logger.info(
                    f"Worker {worker_id}: {iterations} iter, "
                    f"{stats.get('unique_edges', 0)} edges, "
                    f"{coverage_increases} cov+, {total_mutations} mut, pool={subtree_pool.size()}"
                )

    except KeyboardInterrupt:
        logger.info(f"Worker {worker_id} interrupted by keyboard")
    except Exception as e:
        logger.error(f"Worker {worker_id} error in main loop: {e}")
        import traceback
        tb = traceback.format_exc()
        logger.error(tb)
        # Also save error to file for debugging
        try:
            error_file = worker_dir / "error.txt"
            with open(error_file, "w") as f:
                f.write(f"Exception: {e}\n\n{tb}")
        except Exception:
            pass

    # Final stats
    write_stats()
    stats = coverage_tracker.get_statistics()
    final_snapshot = CoverageSnapshot(
        timestamp=time.time(),
        elapsed_seconds=time.time() - start_time,
        unique_edges=stats.get("unique_edges", 0),
        total_edges=stats.get("total_edges", 0),
        iterations=iterations,
        crashes=crashes,
        total_mutations=total_mutations,
        coverage_mutations=coverage_increases,
    )
    result_queue.put(("final", worker_id, final_snapshot, bugs, b""))
    logger.info(f"Worker {worker_id} finished: {iterations} iter, {total_mutations} mut, {coverage_increases} cov+")


class ReTestFuzzerRunner:
    """Runner for ReTest fuzzing with grammar-aware mutation."""

    def __init__(self, config: ExperimentConfig):
        self.config = config

    def run(self) -> ExperimentResult:
        """Run the ReTest fuzzing experiment."""
        logger.info(f"Starting ReTest fuzzing experiment: {self.config.name}")

        result = ExperimentResult(config=self.config)
        start_time = time.time()

        # Create output directories
        output_dir = self.config.output_dir / self.config.name
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "crashes").mkdir(exist_ok=True)

        coordination_dir = output_dir / "coordination"
        coordination_dir.mkdir(exist_ok=True)

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
                    coordination_dir,
                ),
            )
            p.start()
            workers.append(p)

        # Collect results
        all_bugs: List[BugInfo] = []
        # Track per-worker stats (worker_id -> latest snapshot)
        worker_snapshots: dict[int, CoverageSnapshot] = {}
        timeline_path = output_dir / "coverage_timeline.csv"
        timeline_data: list[tuple[float, CoverageSnapshot]] = []  # (elapsed, aggregated snapshot)

        # Track cumulative stats that only ever increase (survives worker restarts)
        cumulative_iterations = 0
        cumulative_coverage_mutations = 0
        last_worker_iterations: dict[int, int] = {}  # worker_id -> last known iterations
        last_worker_coverage_mutations: dict[int, int] = {}

        def read_worker_stats_from_files() -> dict:
            """Read aggregated stats directly from worker stats files (more robust)."""
            total_iterations = 0
            total_crashes = 0
            max_edges = 0
            total_edges = 22017  # Default
            total_mutations = 0
            coverage_mutations = 0

            # Read from all worker directories
            for worker_dir in coordination_dir.glob("worker_*"):
                stats_file = worker_dir / "stats.json"
                if stats_file.exists():
                    try:
                        with open(stats_file, "r") as f:
                            stats = json.load(f)
                            total_iterations += stats.get("iterations", 0)
                            total_crashes += stats.get("crashes", 0)
                            max_edges = max(max_edges, stats.get("unique_edges", 0))
                            total_edges = stats.get("total_edges", total_edges)
                            total_mutations += stats.get("iterations", 0)  # Use iterations as proxy
                            coverage_mutations += stats.get("coverage_increases", 0)
                    except Exception:
                        pass

            return {
                "iterations": total_iterations,
                "crashes": total_crashes,
                "unique_edges": max_edges,
                "total_edges": total_edges,
                "total_mutations": total_mutations,
                "coverage_mutations": coverage_mutations,
            }

        def aggregate_and_write():
            """Aggregate worker stats and write to CSV."""
            nonlocal cumulative_iterations, cumulative_coverage_mutations
            nonlocal last_worker_iterations, last_worker_coverage_mutations

            # ALWAYS use coordinator's elapsed time (not worker-reported, which is wrong after restarts)
            elapsed_from_start = time.time() - start_time

            # Try queue-based snapshots first, fall back to file-based
            if worker_snapshots:
                # Update cumulative stats - only add the DELTA from each worker
                for worker_id, snapshot in worker_snapshots.items():
                    prev_iter = last_worker_iterations.get(worker_id, 0)
                    prev_cov = last_worker_coverage_mutations.get(worker_id, 0)

                    # If worker restarted, its iteration count might be lower than before
                    # In that case, add the new iterations (worker started fresh)
                    if snapshot.iterations < prev_iter:
                        # Worker restarted - add all its new iterations
                        cumulative_iterations += snapshot.iterations
                        cumulative_coverage_mutations += snapshot.coverage_mutations
                    else:
                        # Normal case - add the delta
                        cumulative_iterations += (snapshot.iterations - prev_iter)
                        cumulative_coverage_mutations += (snapshot.coverage_mutations - prev_cov)

                    last_worker_iterations[worker_id] = snapshot.iterations
                    last_worker_coverage_mutations[worker_id] = snapshot.coverage_mutations

                total_crashes = sum(s.crashes for s in worker_snapshots.values())
                max_edges = max(s.unique_edges for s in worker_snapshots.values())
                total_edges = next(iter(worker_snapshots.values())).total_edges
            else:
                # Fall back to reading from files
                file_stats = read_worker_stats_from_files()
                # For file-based, just use raw values (less accurate but better than nothing)
                cumulative_iterations = max(cumulative_iterations, file_stats["iterations"])
                cumulative_coverage_mutations = max(cumulative_coverage_mutations, file_stats["coverage_mutations"])
                total_crashes = file_stats["crashes"]
                max_edges = file_stats["unique_edges"]
                total_edges = file_stats["total_edges"]

            if max_edges == 0:
                return  # No data yet

            # Create aggregated snapshot using CUMULATIVE values (never decrease)
            agg_snapshot = CoverageSnapshot(
                timestamp=time.time(),
                elapsed_seconds=elapsed_from_start,
                unique_edges=max_edges,
                total_edges=total_edges,
                iterations=cumulative_iterations,
                crashes=total_crashes,
                total_mutations=cumulative_iterations,  # Use iterations as proxy
                coverage_mutations=cumulative_coverage_mutations,
            )

            # Add to timeline if this is a new time point (avoid duplicates)
            time_bucket = int(elapsed_from_start / self.config.snapshot_interval_seconds)
            if not timeline_data or int(timeline_data[-1][0] / self.config.snapshot_interval_seconds) < time_bucket:
                timeline_data.append((elapsed_from_start, agg_snapshot))
            else:
                # Update the last entry
                timeline_data[-1] = (elapsed_from_start, agg_snapshot)

            # Write CSV
            try:
                import csv
                with open(timeline_path, "w", newline="") as f:
                    writer = csv.writer(f)
                    writer.writerow(["elapsed_seconds", "unique_edges", "total_edges",
                                   "iterations", "crashes", "coverage_percent",
                                   "total_mutations", "coverage_mutations"])
                    for elapsed, snap in timeline_data:
                        writer.writerow([
                            snap.elapsed_seconds, snap.unique_edges, snap.total_edges,
                            snap.iterations, snap.crashes, snap.coverage_percent,
                            snap.total_mutations, snap.coverage_mutations,
                        ])
            except Exception as e:
                logger.debug(f"Failed to write timeline: {e}")

        # Track worker restart counts and worker_id -> slot mapping
        worker_restart_counts: dict[int, int] = {i: 0 for i in range(self.config.num_workers)}
        worker_id_to_slot: dict[int, int] = {i: i for i in range(self.config.num_workers)}
        next_worker_id = self.config.num_workers
        max_restarts_per_slot = 10  # Max restarts per worker slot

        def restart_worker(slot_idx: int, old_worker_id: int) -> mp.Process:
            """Restart a crashed worker in the given slot."""
            nonlocal next_worker_id
            new_worker_id = next_worker_id
            next_worker_id += 1
            worker_restart_counts[slot_idx] += 1

            # Remove stale snapshot from dead worker
            if old_worker_id in worker_snapshots:
                del worker_snapshots[old_worker_id]

            # Update mapping
            worker_id_to_slot[new_worker_id] = slot_idx

            logger.warning(
                f"Restarting worker in slot {slot_idx} (restart #{worker_restart_counts[slot_idx]}, "
                f"new worker_id={new_worker_id})"
            )

            p = ctx.Process(
                target=_worker_process,
                args=(
                    new_worker_id,
                    self.config,
                    result_queue,
                    stop_event,
                    self.config.snapshot_interval_seconds,
                    coordination_dir,
                ),
            )
            p.start()
            return p

        # Track which worker_id is in each slot
        slot_to_worker_id: dict[int, int] = {i: i for i in range(self.config.num_workers)}

        # Track when each slot was last started (for grace period)
        slot_start_times: dict[int, float] = {i: start_time for i in range(self.config.num_workers)}
        slot_last_restart_time: dict[int, float] = {i: 0.0 for i in range(self.config.num_workers)}

        last_file_update = time.time()
        file_update_interval = self.config.snapshot_interval_seconds
        heartbeat_timeout = 30.0  # Consider worker dead if no heartbeat for 30 seconds
        worker_grace_period = 60.0  # Give new workers 60 seconds before checking heartbeat
        min_restart_interval = 10.0  # Minimum 10 seconds between restarts for same slot

        def check_worker_heartbeat(worker_id: int) -> float:
            """Check worker heartbeat. Returns seconds since last heartbeat, or inf if missing."""
            heartbeat_file = coordination_dir / f"worker_{worker_id}" / "heartbeat"
            if heartbeat_file.exists():
                try:
                    with open(heartbeat_file, "r") as f:
                        last_heartbeat = float(f.read().strip())
                        return time.time() - last_heartbeat
                except Exception:
                    pass
            return float("inf")

        try:
            while time.time() - start_time < self.config.duration_seconds + 30:
                try:
                    msg = result_queue.get(timeout=1.0)
                    msg_type = msg[0]

                    if msg_type == "snapshot":
                        _, worker_id, snapshot = msg
                        # Update this worker's latest snapshot
                        worker_snapshots[worker_id] = snapshot
                        aggregate_and_write()

                    elif msg_type == "final":
                        _, worker_id, snapshot, bugs, _ = msg
                        all_bugs.extend(bugs)
                        # Update this worker's final snapshot
                        worker_snapshots[worker_id] = snapshot
                        aggregate_and_write()

                except Exception:
                    pass

                # Periodic file-based update (backup in case queue is failing)
                current_time = time.time()
                if current_time - last_file_update >= file_update_interval:
                    # Read stats directly from worker files and update CSV
                    file_stats = read_worker_stats_from_files()
                    if file_stats["unique_edges"] > 0:
                        elapsed = current_time - start_time
                        file_snapshot = CoverageSnapshot(
                            timestamp=current_time,
                            elapsed_seconds=elapsed,
                            unique_edges=file_stats["unique_edges"],
                            total_edges=file_stats["total_edges"],
                            iterations=file_stats["iterations"],
                            crashes=file_stats["crashes"],
                            total_mutations=file_stats["total_mutations"],
                            coverage_mutations=file_stats["coverage_mutations"],
                        )
                        # Check if this is newer than what we have
                        time_bucket = int(elapsed / self.config.snapshot_interval_seconds)
                        if not timeline_data or int(timeline_data[-1][0] / self.config.snapshot_interval_seconds) < time_bucket:
                            timeline_data.append((elapsed, file_snapshot))
                            # Write CSV
                            try:
                                import csv
                                with open(timeline_path, "w", newline="") as f:
                                    writer = csv.writer(f)
                                    writer.writerow(["elapsed_seconds", "unique_edges", "total_edges",
                                                   "iterations", "crashes", "coverage_percent",
                                                   "total_mutations", "coverage_mutations"])
                                    for _, snap in timeline_data:
                                        writer.writerow([
                                            snap.elapsed_seconds, snap.unique_edges, snap.total_edges,
                                            snap.iterations, snap.crashes, snap.coverage_percent,
                                            snap.total_mutations, snap.coverage_mutations,
                                        ])
                            except Exception:
                                pass
                    last_file_update = current_time

                # Check for crashed workers and restart them
                elapsed = time.time() - start_time
                if elapsed < self.config.duration_seconds:
                    for slot_idx, p in enumerate(workers):
                        if worker_restart_counts[slot_idx] >= max_restarts_per_slot:
                            continue  # Already maxed out restarts

                        old_worker_id = slot_to_worker_id[slot_idx]
                        should_restart = False
                        restart_reason = ""
                        current_time = time.time()

                        # Check minimum restart interval (prevent restart storm)
                        time_since_last_restart = current_time - slot_last_restart_time[slot_idx]
                        if time_since_last_restart < min_restart_interval:
                            continue  # Too soon to restart this slot

                        # Check worker age for grace period
                        worker_age = current_time - slot_start_times[slot_idx]

                        # Check 1: Process is dead
                        if not p.is_alive():
                            exit_code = p.exitcode
                            should_restart = True
                            if exit_code is None:
                                restart_reason = "process died without exit code (likely signal/ASAN)"
                            elif exit_code < 0:
                                restart_reason = f"killed by signal {-exit_code}"
                            elif exit_code != 0:
                                restart_reason = f"exit code {exit_code}"
                            else:
                                # Exit code 0 but experiment not done - unexpected termination
                                restart_reason = "unexpected clean exit"

                        # Check 2: Stale heartbeat (worker may be stuck/frozen)
                        # Only check after grace period
                        elif p.is_alive() and worker_age > worker_grace_period:
                            heartbeat_age = check_worker_heartbeat(old_worker_id)
                            if heartbeat_age > heartbeat_timeout:
                                logger.warning(
                                    f"Worker {old_worker_id} (slot {slot_idx}) has stale heartbeat "
                                    f"({heartbeat_age:.1f}s old), terminating and restarting..."
                                )
                                p.terminate()
                                p.join(timeout=5.0)
                                should_restart = True
                                restart_reason = f"stale heartbeat ({heartbeat_age:.1f}s)"

                        if should_restart:
                            logger.warning(
                                f"Worker {old_worker_id} (slot {slot_idx}) needs restart: {restart_reason}"
                            )
                            workers[slot_idx] = restart_worker(slot_idx, old_worker_id)
                            # Update slot mapping and timing
                            slot_to_worker_id[slot_idx] = next_worker_id - 1
                            slot_start_times[slot_idx] = current_time
                            slot_last_restart_time[slot_idx] = current_time

                # Check if all workers are done (and no more time left or max restarts reached)
                all_done = all(not p.is_alive() for p in workers)
                all_maxed_restarts = all(
                    worker_restart_counts[i] >= max_restarts_per_slot
                    for i in range(len(workers))
                )
                if all_done and (elapsed >= self.config.duration_seconds or all_maxed_restarts):
                    if all_maxed_restarts:
                        logger.warning("All workers hit max restart limit, ending experiment")
                    break

                # Periodic status log
                if int(elapsed) % 60 == 0 and int(elapsed) > 0:
                    file_stats = read_worker_stats_from_files()
                    alive_count = sum(1 for p in workers if p.is_alive())
                    total_restarts = sum(worker_restart_counts.values())
                    logger.info(
                        f"[{int(elapsed)}s] Workers alive: {alive_count}/{len(workers)}, "
                        f"restarts: {total_restarts}, edges: {file_stats['unique_edges']}, "
                        f"iter: {file_stats['iterations']}"
                    )

        except KeyboardInterrupt:
            logger.info("Experiment interrupted")

        finally:
            stop_event.set()
            for p in workers:
                p.join(timeout=5.0)
                if p.is_alive():
                    p.terminate()

        # Build final result from timeline data
        for _, snapshot in timeline_data:
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
            f"ReTest fuzzing completed: {result.total_iterations} iterations, "
            f"{result.total_crashes} crashes, {result.final_coverage} edges"
        )

        return result

    def _save_results(self, result: ExperimentResult, output_dir: Path) -> None:
        """Save experiment results to files."""
        import csv

        # Save coverage timeline
        timeline_path = output_dir / "coverage_timeline.csv"
        with open(timeline_path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(
                ["elapsed_seconds", "unique_edges", "total_edges", "iterations", "crashes",
                 "coverage_percent", "total_mutations", "coverage_mutations"]
            )
            for snapshot in result.snapshots:
                writer.writerow([
                    snapshot.elapsed_seconds,
                    snapshot.unique_edges,
                    snapshot.total_edges,
                    snapshot.iterations,
                    snapshot.crashes,
                    snapshot.coverage_percent,
                    snapshot.total_mutations,
                    snapshot.coverage_mutations,
                ])

        # Save bugs
        for i, bug in enumerate(result.bugs):
            bug_dir = output_dir / "crashes" / f"bug_{i:04d}"
            bug_dir.mkdir(exist_ok=True)
            with open(bug_dir / "pattern.txt", "w") as f:
                f.write(bug.pattern)
            if bug.test_string:
                with open(bug_dir / "test_string.txt", "w") as f:
                    f.write(bug.test_string)

        # Save summary stats
        stats_path = output_dir / "stats.json"
        with open(stats_path, "w") as f:
            json.dump({
                "name": result.config.name,
                "strategy": result.config.strategy,
                "engine": result.config.engine,
                "total_iterations": result.total_iterations,
                "total_crashes": result.total_crashes,
                "final_coverage": result.final_coverage,
                "final_coverage_percent": result.final_coverage_percent,
                "duration_seconds": result.duration_actual_seconds,
                "num_snapshots": len(result.snapshots),
            }, f, indent=2)
