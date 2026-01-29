"""Grammar-aware fuzzing baseline runner (FuzzTest simulation).

This implements a grammar-based fuzzer that uses:
- ANTLR4-style random walk pattern generation with EQUAL PROBABILITY transitions
- COVERAGE-GUIDED CORPUS LEARNING (FuzzTest style)
- Energy-based scheduling for corpus entries
- Grammar-aware mutation of high-coverage patterns
- Direct ctypes library invocation (no ReTest optimizations)
- V8-style test string generation (4 categories with equal probability)
- Systematic flag exploration via BitFlagCombinationOf
- Three-subject testing (fuzzed input, pattern itself, empty string)
- 1M backtrack limit to prevent DoS

This simulates Google FuzzTest's grammar-based approach with coverage guidance.
Reference: resources/baseline-v8-fuzzing/regexp-fuzzer.cc
"""

import multiprocessing as mp
import time
from pathlib import Path
from typing import List

from loguru import logger

from re_fuzzer.experiments.baselines.antlr4_generator import ANTLR4GrammarGenerator
from re_fuzzer.experiments.baselines.coverage_corpus import CoverageCorpus
from re_fuzzer.experiments.baselines.direct_pcre import create_direct_wrapper
from re_fuzzer.experiments.baselines.flags_domain import FlagsDomain
from re_fuzzer.experiments.baselines.grammar_mutator import GrammarMutator
from re_fuzzer.experiments.baselines.test_string_generator import V8TestStringGenerator
from re_fuzzer.experiments.experiment_config import (
    BugInfo,
    CoverageSnapshot,
    ExperimentConfig,
    ExperimentResult,
)
from re_fuzzer.fuzzing.coverage_tracker import CoverageTracker


def _worker_process(
    worker_id: int,
    config: ExperimentConfig,
    result_queue: mp.Queue,
    stop_event: mp.Event,
    snapshot_interval: int,
) -> None:
    """Worker process for grammar-aware fuzzing with COVERAGE GUIDANCE.

    This implements FuzzTest-style coverage-guided fuzzing:
    1. Generate patterns from grammar OR mutate corpus entries
    2. Execute and collect coverage
    3. Add patterns that discover new coverage to corpus
    4. Use energy-based scheduling to prioritize high-value patterns

    Args:
        worker_id: Unique worker identifier
        config: Experiment configuration
        result_queue: Queue for sending results back
        stop_event: Event to signal stop
        snapshot_interval: Seconds between snapshots
    """
    logger.info(f"Worker {worker_id} starting COVERAGE-GUIDED grammar fuzzing (FuzzTest style)")

    # Initialize components - use direct ctypes wrapper (NOT CFFI)
    engine = create_direct_wrapper(config.engine, config.library_path)

    # Initialize grammar generator with worker-specific seed
    generator = ANTLR4GrammarGenerator(
        max_depth=10,
        max_size=100,
        seed=int(time.time() * 1000) + worker_id,
    )

    # Initialize V8-style test string generator
    test_string_gen = V8TestStringGenerator(use_two_byte=False)

    # Initialize flags domain for systematic flag exploration
    flags_domain = FlagsDomain(config.engine)

    # Initialize coverage tracker
    coverage_tracker = CoverageTracker(str(config.library_path))

    # FUZZTEST-STYLE: Coverage-guided corpus
    corpus = CoverageCorpus(max_size=5000)

    # FUZZTEST-STYLE: Grammar-aware mutator for corpus entries
    mutator = GrammarMutator(mutation_rate=0.3)

    # State
    start_time = time.time()
    last_snapshot_time = start_time
    last_log_time = start_time
    iterations = 0
    crashes = 0
    bugs: List[BugInfo] = []
    corpus_hits = 0  # Track how often we use corpus

    try:
        while not stop_event.is_set():
            # FUZZTEST-STYLE: Decide between corpus mutation vs fresh generation
            if corpus.should_use_corpus():
                # Select high-energy pattern from corpus and mutate it
                entry = corpus.select_for_mutation()
                if entry:
                    pattern_str = mutator.mutate(entry.pattern, corpus.get_all_patterns())
                    corpus_hits += 1
                else:
                    pattern_str = generator.generate()
            else:
                # Fresh generation from grammar (exploration)
                try:
                    pattern_str = generator.generate()
                except Exception as e:
                    logger.debug(f"Generation error: {e}")
                    continue

            pattern = pattern_str.encode("utf-8")

            # Generate flags and test string
            flags = flags_domain.generate()
            fuzzed_subject = test_string_gen.generate()

            # Test against THREE subjects (V8 style)
            subjects_to_test = [fuzzed_subject, pattern, b""]

            # Track if this pattern discovered new coverage
            found_new_coverage = False
            pre_coverage = coverage_tracker.get_statistics().get("unique_edges", 0)

            for subject in subjects_to_test:
                try:
                    coverage_tracker.reset()
                    _, error = engine.compile_and_match(pattern, subject, flags)

                    # Check if new coverage was discovered
                    if coverage_tracker.check_and_update_coverage():
                        found_new_coverage = True

                    if error and ("crash" in error.lower() or "segfault" in error.lower()):
                        crashes += 1
                        bug = BugInfo(
                            pattern=pattern_str,
                            test_string=subject.decode("utf-8", errors="replace"),
                            error_type="crash",
                            error_message=error,
                            timestamp=time.time(),
                        )
                        bugs.append(bug)

                except Exception as e:
                    crashes += 1
                    bug = BugInfo(
                        pattern=pattern_str,
                        test_string=subject.decode("utf-8", errors="replace"),
                        error_type="exception",
                        error_message=str(e),
                        timestamp=time.time(),
                    )
                    bugs.append(bug)

            # FUZZTEST-STYLE: Add to corpus if new coverage discovered
            if found_new_coverage:
                post_coverage = coverage_tracker.get_statistics().get("unique_edges", 0)
                new_edges_count = max(1, post_coverage - pre_coverage)

                was_added, _ = corpus.add_if_new_coverage(pattern_str, new_edges_count)
                if was_added:
                    logger.debug(f"Corpus +1: ~{new_edges_count} new edges, pattern={pattern_str[:50]}...")

            iterations += 1

            # Periodic logging of corpus stats
            current_time = time.time()
            if current_time - last_log_time >= 30:  # Every 30 seconds
                corpus_stats = corpus.get_statistics()
                logger.info(
                    f"Worker {worker_id}: {iterations} iters, "
                    f"corpus={corpus_stats['corpus_size']}, "
                    f"coverage={corpus_stats['global_coverage']} edges, "
                    f"corpus_hits={corpus_hits}"
                )
                last_log_time = current_time

            # Periodic snapshot
            if current_time - last_snapshot_time >= snapshot_interval:
                stats = coverage_tracker.get_statistics()
                corpus_stats = corpus.get_statistics()
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
    corpus_stats = corpus.get_statistics()
    final_snapshot = CoverageSnapshot(
        timestamp=time.time(),
        elapsed_seconds=time.time() - start_time,
        unique_edges=stats.get("unique_edges", 0),
        total_edges=stats.get("total_edges", 0),
        iterations=iterations,
        crashes=crashes,
    )
    result_queue.put(("final", worker_id, final_snapshot, bugs, coverage_tracker.export_bitmap()))
    logger.info(
        f"Worker {worker_id} finished: {iterations} iterations, {crashes} crashes, "
        f"corpus={corpus_stats['corpus_size']}, coverage={corpus_stats['global_coverage']} edges"
    )


class GrammarAwareFuzzerRunner:
    """Runner for grammar-aware fuzzing baseline (FuzzTest simulation).

    This runner implements FuzzTest-style coverage-guided grammar fuzzing:

    - COVERAGE-GUIDED CORPUS: Maintains corpus of patterns that discovered new coverage
    - ENERGY-BASED SCHEDULING: Prioritizes high-value patterns for mutation
    - GRAMMAR-AWARE MUTATION: Mutates corpus entries while preserving syntax
    - BALANCED EXPLORATION: 80% corpus mutation, 20% fresh generation
    - Direct ctypes: Uses minimal library wrapper without optimizations

    V8 FuzzTest compatibility features (regexp-fuzzer.cc):
    - Equal probability transition selection (like VariantDomain/OneOf)
    - V8-style test string generation (4 categories with equal probability)
    - Systematic flag exploration via BitFlagCombinationOf
    - Three-subject testing (fuzzed input, pattern itself, empty string)
    - 1M backtrack limit to prevent DoS with pathological patterns
    """

    def __init__(self, config: ExperimentConfig):
        """Initialize runner with experiment configuration.

        Args:
            config: Experiment configuration
        """
        self.config = config

    def run(self) -> ExperimentResult:
        """Run the grammar-aware fuzzing experiment.

        Returns:
            ExperimentResult with coverage snapshots and bugs
        """
        logger.info(f"Starting grammar-aware fuzzing experiment: {self.config.name}")

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
            f"Grammar-aware fuzzing completed: {result.total_iterations} iterations, "
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
