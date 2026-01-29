"""Atheris harness for integrating grammar-aware fuzzing with libfuzzer.

This module provides the main fuzzing harness that integrates with Atheris
(Python bindings for libfuzzer). It sets up the test function, custom mutator,
coverage tracking, and pool updates.
"""

from __future__ import annotations

import json
import os
import random
import string
import sys
import time
from pathlib import Path
from typing import Optional, TYPE_CHECKING

import atheris
from loguru import logger

if TYPE_CHECKING:
    from .advanced_pattern_generator import AdvancedPatternGenerator

from re_fuzzer.sut.base_sut import BaseSUT

from ..input_generator.string_generator.xeger_string_generator import (
    XegerStringGenerator,
    XegerStringGeneratorConfig,
)
# Note: timeout handling is done by libFuzzer's -timeout flag with -ignore_timeouts=1
# We don't use Python-level signal timeouts as they interfere with libFuzzer's recovery
from .coverage_tracker import CoverageTracker
from .grammar_aware_mutator import GrammarAwareMutator
from .pool_updater import PoolUpdater
from .seed_manager import SeedManager
from .subtree_pool import SubtreePool


def _try_generate_regex_example(pattern: str) -> Optional[str]:
    """Try to generate a regex example string, with fallback if instrumentation unavailable."""
    try:
        from ..instrumentation.regex_hook import generate_regex_example
        return generate_regex_example(pattern)
    except ImportError:
        return None
    except Exception:
        return None


class AtherisHarness:
    """Main fuzzing harness integrating all components with Atheris/libfuzzer."""

    def __init__(
        self,
        sut: BaseSUT,
        library_path: Optional[str] = None,
        seed_corpus_path: Optional[str] = None,
        max_seed_size: int = 10000,
        corpus_dir: str = "/tmp/re_fuzzer_corpus",
        max_subtree_bytes: int = 200,
        max_pool_size: int = 100000,
        mutation_probability: float = 0.5,
        initial_pool_patterns: int = 5000,
        passive_pool_update_chance: float = 0.05,
        enable_regex_hook: bool = False,
        log_interval: int = 100,
        test_timeout: int = 0,
        stats_file: Optional[str] = None,
        coverage_file: Optional[str] = None,
        merged_coverage_file: Optional[str] = None,
        pool_file: Optional[str] = None,
        merged_pool_file: Optional[str] = None,
        advanced_generator: Optional["AdvancedPatternGenerator"] = None,
        advanced_weight: float = 0.0,
    ):
        """Initialize the fuzzing harness.

        Args:
            sut: System under test (must implement BaseSUT protocol)
            library_path: Path to the instrumented .so library for coverage tracking.
                         If None, coverage tracking will be disabled.
            seed_corpus_path: Path to JSONL file with seed patterns
            corpus_dir: Directory for Atheris corpus (defaults to temp dir)
            max_subtree_bytes: Maximum size for subtrees in pool
            max_pool_size: Maximum number of subtrees in pool
            mutation_probability: Probability of grammar-aware mutation vs fallback
            initial_pool_patterns: Number of seed patterns used for pool bootstrap
            passive_pool_update_chance: Probability of pool update without new coverage
            enable_regex_hook: Whether to enable Atheris' regex instrumentation hook
            log_interval: How often to log progress (every N iterations)
            test_timeout: Per-test-case timeout in seconds (0 disables, default: 0)
            stats_file: Path to write stats JSON file (for parallel mode)
            coverage_file: Path to export coverage bitmap (for parallel mode)
            merged_coverage_file: Path to load merged coverage from coordinator
            pool_file: Path to export subtree pool (for parallel mode)
            merged_pool_file: Path to load merged pool from coordinator
            advanced_generator: Optional advanced pattern generator (for ablation)
            advanced_weight: Weight for advanced generation (0 = disabled)
        """
        # Initialize SUT
        self.sut = sut
        self.stats_file = Path(stats_file) if stats_file else None
        self.coverage_file = Path(coverage_file) if coverage_file else None
        self.merged_coverage_file = Path(merged_coverage_file) if merged_coverage_file else None
        self.pool_file = Path(pool_file) if pool_file else None
        self.merged_pool_file = Path(merged_pool_file) if merged_pool_file else None
        self.log_interval = log_interval
        self.test_timeout = test_timeout
        logger.info(f"Using SUT: {self.sut.name}")

        self.max_seed_size = max_seed_size
        self.initial_pool_patterns = initial_pool_patterns
        self.passive_pool_update_chance = passive_pool_update_chance
        self.enable_regex_hook = enable_regex_hook

        # Initialize subtree pool
        self.subtree_pool = SubtreePool(
            max_subtree_bytes=max_subtree_bytes,
            max_pool_size=max_pool_size
        )

        # Initialize components
        self.mutator = GrammarAwareMutator(
            self.subtree_pool,
            mutation_probability=mutation_probability,
            advanced_generator=advanced_generator,
            advanced_weight=advanced_weight,
        )
        self.pool_updater = PoolUpdater(self.subtree_pool)

        # Initialize coverage tracker
        self.library_path = library_path
        if library_path:
            self.coverage_tracker = CoverageTracker(library_path)
            logger.info(f"Coverage tracking enabled for: {library_path}")
        else:
            self.coverage_tracker = None
            logger.warning("No library_path provided - coverage tracking disabled")

        self.seed_manager = SeedManager()

        # Initialize string generator for generating test inputs
        # TODO: make string generator configurable
        self.string_generator = XegerStringGenerator(
            XegerStringGeneratorConfig(
                seed=42,  # Use fixed seed for reproducibility
                star_plus_limit=50  # Limit repetitions to avoid very long strings
            )
        )

        # Setup corpus directory
        self.corpus_dir = Path(corpus_dir)
        self.corpus_dir.mkdir(parents=True, exist_ok=True)

        # Load initial seeds if provided
        self.seed_corpus_path = seed_corpus_path
        if seed_corpus_path:
            self._initialize_from_seeds()

        # Statistics
        # TODO: Define a proper statistics class
        self.stats = {
            "iterations": 0,
            "crashes": 0,
            "timeouts": 0,
            "coverage_increases": 0,
            "pool_updates": 0,
            "compile_errors": 0,
            "start_time": None,
        }

        # Note: Coverage tracking now uses check_and_update_coverage() which
        # maintains its own internal bitmap of seen edges

    def _initialize_from_seeds(self) -> None:
        """Initialize the corpus and pool from seed patterns."""
        logger.info(f"Loading seeds from {self.seed_corpus_path}")

        # Load patterns from JSONL
        patterns = self.seed_manager.load_from_jsonl(self.seed_corpus_path)
        logger.info(f"Loaded {len(patterns)} patterns")

        if len(patterns) > self.max_seed_size:
            rng = random.Random(42)
            original_len = len(patterns)
            patterns = rng.sample(patterns, self.max_seed_size)
            logger.info(f"Sampled {len(patterns)} patterns from {original_len}")

        # Filter patterns to only those that compile in the SUT
        valid_patterns = []
        invalid_count = 0

        logger.info("Filtering patterns for SUT compatibility...")
        for pattern in patterns:
            try:
                # Test if pattern compiles by trying a simple search
                result = self.sut.search(pattern, "")

                # Check if there was a compilation error
                if result.error and ("compil" in result.error.lower() or
                                    "invalid" in result.error.lower() or
                                    "syntax" in result.error.lower()):
                    invalid_count += 1
                    logger.debug(f"Skipping invalid pattern: {pattern[:50]}... - {result.error}")
                else:
                    valid_patterns.append(pattern)
            except Exception as e:
                invalid_count += 1
                logger.debug(f"Skipping pattern that caused exception: {pattern[:50]}... - {e}")

        if len(patterns) > 0:
            logger.info(
                f"Filtered patterns: {len(valid_patterns)} valid, {invalid_count} invalid "
                f"({100*len(valid_patterns)/len(patterns):.1f}% valid)"
            )
        else:
            logger.info("No seed patterns loaded - starting with empty corpus")

        # Initialize Atheris corpus files with valid patterns only
        corpus_files = self.seed_manager.write_corpus_files(
            valid_patterns,
            self.corpus_dir
        )
        logger.info(f"Wrote {len(corpus_files)} corpus files to {self.corpus_dir}")

        # Bootstrap subtree pool from a configurable subset of valid seeds
        pool_seed_count = min(len(valid_patterns), self.initial_pool_patterns)
        if pool_seed_count == len(valid_patterns):
            patterns_for_pool = valid_patterns
        else:
            rng = random.Random(1337)
            patterns_for_pool = rng.sample(valid_patterns, pool_seed_count)

        successful = self.pool_updater.bulk_update_from_patterns(patterns_for_pool)
        logger.info(
            f"Bootstrapped pool from {successful}/{len(patterns_for_pool)} seed patterns, "
            f"pool size: {self.subtree_pool.size()}"
        )

    def test_one_input(self, data: bytes) -> None:
        """Test function called by Atheris for each input.

        This is the main fuzzing target that executes the SUT with the input
        and tracks coverage for pool updates.

        Args:
            data: Input data (regex pattern as bytes)
        """
        self.stats["iterations"] += 1

        # Write stats frequently to ensure stats file exists even for short runs
        # This is important because libfuzzer may call C-level exit() at any time
        if self.stats["iterations"] % 10 == 0:
            self._write_stats()

        # Log progress periodically (includes coverage stats and pool sync)
        if self.stats["iterations"] % self.log_interval == 0:
            self._log_progress()

        # Convert input to string
        try:
            pattern = data.decode('utf-8')
        except UnicodeDecodeError:
            return

        compile_failed = False
        compile_error_recorded = False
        pattern_was_valid = False

        try:
            test_strings = self._generate_test_strings(pattern)
        except Exception as e:
            # String generation failed - use fallback strings
            logger.debug(f"String generation failed for pattern={pattern[:50]}: {e}")
            test_strings = ["", "test", "a"]

        for test_str in test_strings:
            if compile_failed:
                break

            try:
                # Execute regex match
                result = self.sut.search(pattern, test_str)

                # Check for crashes (error in result)
                if result.error:
                    if self._is_compile_error(result.error):
                        if not compile_error_recorded:
                            self.stats["compile_errors"] += 1
                            compile_error_recorded = True
                        compile_failed = True
                        logger.debug(
                            f"SUT compile error: {result.error} for pattern={pattern[:100]}"
                        )
                        break
                    else:
                        self.stats["crashes"] += 1
                        logger.warning(
                            f"SUT runtime error: {result.error} for pattern={pattern[:100]}, "
                            f"text={test_str}"
                        )
                    continue

            except Exception as e:
                # Catch any uncaught exceptions
                self.stats["crashes"] += 1
                logger.error(
                    f"Unexpected crash: {e} for pattern={pattern[:100]}, "
                    f"text={test_str}"
                )
                continue

            pattern_was_valid = True

        # Check for new coverage and update pool if needed
        if self.coverage_tracker:
            # Use libFuzzer-compatible coverage tracking that maintains
            # its own bitmap of seen edges
            has_new_coverage = self.coverage_tracker.check_and_update_coverage()

            if has_new_coverage:
                self.stats["coverage_increases"] += 1
                self._maybe_update_pool(data, reason="coverage")
            elif (
                pattern_was_valid
                and random.random() < self.passive_pool_update_chance
            ):
                self._maybe_update_pool(data, reason="passive")
        else:
            # No coverage tracker - use passive pool updates only
            if pattern_was_valid and random.random() < self.passive_pool_update_chance:
                self._maybe_update_pool(data, reason="passive")

    def custom_mutator(self, data: bytes, max_size: int, seed: int) -> bytes:
        """Custom mutator callback for Atheris.

        Args:
            data: Input to mutate
            max_size: Maximum size of mutated output
            seed: Random seed for mutation

        Returns:
            Mutated input
        """
        return self.mutator.mutate(data, max_size, seed)

    def run(
        self,
        argv: Optional[list[str]] = None,
        max_iterations: Optional[int] = None,
    ) -> dict:
        """Run the fuzzer.

        Args:
            argv: Command line arguments for Atheris
            max_iterations: Maximum iterations to run (if not in argv)

        Returns:
            Statistics dictionary
        """
        self.stats["start_time"] = time.time()

        # Prepare arguments
        if argv is None:
            argv = [sys.argv[0]]

        # Add corpus directory
        argv.append(str(self.corpus_dir))

        # Add max iterations if specified
        if max_iterations:
            argv.append(f"-max_total_time={max_iterations}")

        # Note: Per-test timeouts are handled at the Python level via test_timeout
        # parameter, not via libFuzzer's -timeout flag (which doesn't work well
        # with Python/CFFI and can crash the process).

        # Add other useful flags
        # Note: We avoid -fork mode as it doesn't work well with Python/Atheris
        # Instead we rely on -ignore_crashes and -ignore_timeouts to continue
        argv.extend([
            "-timeout=5",         # 5 second per-test timeout (prevents hangs)
            "-print_final_stats=1",
            "-use_value_profile=1",
            "-shrink=1",
            "-ignore_crashes=1",  # Continue fuzzing after crashes
            "-ignore_timeouts=1",  # Continue fuzzing after timeouts
        ])

        logger.info(f"Starting fuzzer with args: {argv}")

        # Write initial stats file so it exists even if fuzzer runs very few iterations
        self._write_stats()

        # Setup Atheris with our test function and custom mutator
        # Note on ASan options:
        # - With asan_with_fuzzer.so + patchelf workaround: use internal_libfuzzer=True
        # - With standalone libclang_rt.asan: use internal_libfuzzer=False (default)
        # See: https://github.com/google/atheris/issues/54
        atheris.Setup(
            argv,
            self.test_one_input,
            custom_mutator=self.custom_mutator,
            internal_libfuzzer=True,
        )

        # Note: We do NOT set our own SIGALRM handler here because:
        # 1. LibFuzzer's handler with -ignore_timeouts=1 can recover from timeouts
        # 2. Our handler would override libFuzzer's and break its recovery mechanism
        # 3. For pure Python hangs, we rely on libFuzzer's timeout as a fallback

        # Register atexit handler to write stats before exit
        # This is critical because libfuzzer calls exit() at C level when max_total_time expires,
        # bypassing Python's normal return flow
        import atexit
        def write_final_stats():
            logger.debug("atexit: Writing final stats before exit")
            self._write_stats()
            self._sync_coverage()
        atexit.register(write_final_stats)

        # Run the fuzzer
        try:
            atheris.Fuzz()
        except KeyboardInterrupt:
            logger.info("Fuzzing interrupted by user")
        except SystemExit:
            # libfuzzer may raise SystemExit when done
            pass
        except Exception as e:
            logger.error(f"Fuzzing failed with error: {e}")
            raise
        finally:
            # Clean up atexit handler if we return normally
            try:
                atexit.unregister(write_final_stats)
            except Exception:
                pass

        # Calculate final statistics
        elapsed_time = time.time() - self.stats["start_time"]
        self.stats["elapsed_time"] = elapsed_time
        self.stats["pool_size"] = self.subtree_pool.size()

        # Log final statistics
        self._log_final_statistics()

        return dict(self.stats)

    def _log_progress(self) -> None:
        """Log fuzzing progress periodically with real-time coverage stats."""
        elapsed = time.time() - self.stats["start_time"] if self.stats["start_time"] else 0
        pool_stats = self.subtree_pool.get_statistics()
        mutator_stats = self.mutator.get_statistics()

        # Calculate exec/s rate
        exec_per_sec = self.stats["iterations"] / elapsed if elapsed > 0 else 0

        # Build coverage string
        if self.coverage_tracker:
            coverage_stats = self.coverage_tracker.get_statistics()
            if "error" not in coverage_stats:
                cov_str = (
                    f"cov={coverage_stats.get('unique_edges', 0)}/"
                    f"{coverage_stats.get('total_edges', 0)} "
                    f"({coverage_stats.get('coverage_percent', 0):.2f}%)"
                )
            else:
                cov_str = f"cov=N/A ({coverage_stats.get('error', 'unknown error')})"
        else:
            cov_str = "cov=disabled"

        # Build mutation type breakdown string
        # Shows: G=grammar-aware, D=dictionary, I=inject, H=hybrid, F=fallback
        mut_breakdown = (
            f"G:{mutator_stats.get('grammar_aware_mutations', 0)}"
            f"/D:{mutator_stats.get('dictionary_mutations', 0)}"
            f"/I:{mutator_stats.get('dictionary_injections', 0)}"
            f"/H:{mutator_stats.get('hybrid_mutations', 0)}"
            f"/F:{mutator_stats.get('fallback_mutations', 0)}"
        )

        # [COV] tag ensures this shows up in quiet mode
        logger.info(
            f"[COV] [{elapsed:.1f}s] "
            f"exec={self.stats['iterations']} ({exec_per_sec:.0f}/s) | "
            f"{cov_str} | "
            f"new_cov={self.stats['coverage_increases']} | "
            f"crashes={self.stats['crashes']} | "
            f"pool={pool_stats['total_subtrees']} (hit={pool_stats['hit_rate']:.2%}) | "
            f"mut_ok={mutator_stats['success_rate']:.2%} ({mut_breakdown})"
        )

        # Write stats and sync coverage for parallel mode
        self._write_stats()
        self._sync_coverage()

        # Sync pool less frequently (every 50 log intervals = ~5000 iterations)
        if self.stats["iterations"] % (self.log_interval * 50) == 0:
            self._sync_pool()

    def _log_final_statistics(self) -> None:
        """Log final fuzzing statistics."""
        pool_stats = self.subtree_pool.get_statistics()
        mutator_stats = self.mutator.get_statistics()
        updater_stats = self.pool_updater.get_statistics()

        elapsed = self.stats.get('elapsed_time', 0)
        exec_per_sec = self.stats['iterations'] / elapsed if elapsed > 0 else 0

        # Use [COV] tag for important stats that should show in quiet mode
        logger.info("[COV] " + "=" * 66)
        logger.info("[COV] FUZZING CAMPAIGN COMPLETE")
        logger.info("[COV] " + "=" * 66)
        logger.info(f"[COV] Total iterations: {self.stats['iterations']:,}")
        logger.info(f"[COV] Execution rate: {exec_per_sec:.1f} exec/s")
        logger.info(f"[COV] Total crashes: {self.stats['crashes']}")
        logger.info(f"[COV] Compile errors: {self.stats['compile_errors']}")
        logger.info(f"[COV] Coverage increases: {self.stats['coverage_increases']}")
        logger.info(f"[COV] Pool updates: {self.stats['pool_updates']}")
        logger.info(f"[COV] Elapsed time: {elapsed:.1f}s")

        # Coverage statistics
        if self.coverage_tracker:
            coverage_stats = self.coverage_tracker.get_statistics()
            if "error" not in coverage_stats:
                logger.info("[COV] " + "-" * 66)
                logger.info("[COV] COVERAGE STATISTICS")
                logger.info(f"[COV] Unique edges hit: {coverage_stats.get('unique_edges', 0):,}")
                logger.info(f"[COV] Total edges: {coverage_stats.get('total_edges', 0):,}")
                logger.info(f"[COV] Coverage: {coverage_stats.get('coverage_percent', 0):.2f}%")

        # Detailed stats (not tagged - won't show in quiet mode)
        logger.info("-" * 70)
        logger.info("SUBTREE POOL STATISTICS")
        logger.info(f"Total subtrees: {pool_stats['total_subtrees']:,}")
        logger.info(f"Unique node types: {pool_stats['unique_types']}")
        logger.info(f"Pool hit rate: {pool_stats['hit_rate']:.2%}")
        logger.info(f"Type distribution: {pool_stats['type_distribution']}")
        logger.info("-" * 70)
        logger.info("MUTATION STATISTICS")
        logger.info(f"Total mutations: {mutator_stats['total_mutations']:,}")
        logger.info(f"Successful mutations: {mutator_stats['successful_mutations']:,}")
        logger.info(f"Parse failures: {mutator_stats['parse_failures']:,}")
        logger.info(f"Fallback mutations: {mutator_stats['fallback_mutations']:,}")
        logger.info(f"Success rate: {mutator_stats['success_rate']:.2%}")
        logger.info("-" * 70)
        logger.info("POOL UPDATE STATISTICS")
        logger.info(f"Inputs processed: {updater_stats['inputs_processed']:,}")
        logger.info(f"Subtrees extracted: {updater_stats['subtrees_extracted']:,}")
        logger.info(f"Subtrees rejected: {updater_stats['subtrees_rejected']:,}")
        logger.info("[COV] " + "=" * 66)

    def _write_stats(self) -> None:
        """Write current stats to JSON file for parallel mode coordination."""
        if not self.stats_file:
            return

        stats_data = {
            "iterations": self.stats["iterations"],
            "crashes": self.stats["crashes"],
            "timeouts": self.stats.get("timeouts", 0),
            "coverage_increases": self.stats["coverage_increases"],
            "pool_updates": self.stats.get("pool_updates", 0),
            "compile_errors": self.stats.get("compile_errors", 0),
            "pool_size": self.subtree_pool.size(),
            "timestamp": time.time(),
        }

        try:
            # Atomic write: write to temp file then rename
            temp_file = self.stats_file.with_suffix(".tmp")
            with open(temp_file, "w") as f:
                json.dump(stats_data, f)
            temp_file.rename(self.stats_file)
        except Exception as e:
            logger.debug(f"Failed to write stats file: {e}")

    def _sync_coverage(self) -> None:
        """Sync coverage bitmap for parallel mode coordination.

        1. Exports this worker's coverage to coverage_file
        2. Loads merged coverage from merged_coverage_file (if exists)
        """
        if not self.coverage_tracker:
            return

        # Export our coverage
        if self.coverage_file:
            self.coverage_tracker.save_bitmap(str(self.coverage_file))

        # Load merged coverage from coordinator
        if self.merged_coverage_file and self.merged_coverage_file.exists():
            new_edges = self.coverage_tracker.load_bitmap(str(self.merged_coverage_file))
            if new_edges > 0:
                logger.debug(f"Loaded {new_edges} new edges from merged coverage")

    def _sync_pool(self) -> None:
        """Sync subtree pool for parallel mode coordination.

        1. Exports this worker's pool to pool_file
        2. Loads merged pool from merged_pool_file (if exists)
        """
        # Export our pool
        if self.pool_file:
            self.subtree_pool.export_to_file(str(self.pool_file))

        # Load merged pool from coordinator
        if self.merged_pool_file and self.merged_pool_file.exists():
            imported = self.subtree_pool.import_from_file(str(self.merged_pool_file))
            if imported > 0:
                logger.debug(f"Imported {imported} subtrees from merged pool")

    def _generate_test_strings(self, pattern: str) -> list[str]:
        """Generate a diversified test string set for the provided pattern."""
        test_strings: list[str] = [""]

        example = _try_generate_regex_example(pattern)
        if example:
            example_str = example.decode("utf-8", errors="ignore") if isinstance(example, bytes) else example
            if example_str:
                test_strings.append(example_str)

        try:
            for generated in self.string_generator.generate(pattern, 5):
                test_strings.append(generated)
                if generated:
                    test_strings.append("x" + generated)
                    test_strings.append(generated + "y")
                    if len(generated) > 1:
                        test_strings.append(generated[1:])
        except Exception as exc:
            logger.debug(f"String generation failed for pattern {pattern[:50]}: {exc}")

        if len(test_strings) < 6:
            needed = 6 - len(test_strings)
            test_strings.extend(self._random_fallback_strings(needed))

        return list(dict.fromkeys(test_strings))[:10]

    def _random_fallback_strings(self, count: int) -> list[str]:
        """Create deterministic fallback probes when pattern generation fails."""
        alphabet = string.ascii_letters + string.digits
        strings: list[str] = []
        for _ in range(count):
            length = random.randint(1, 8)
            strings.append("".join(random.choice(alphabet) for _ in range(length)))
        # Mix in a few constant probes for consistency
        constants = ["a", "test", "123", "abc123"]
        strings.extend(constants)
        return strings[:count]

    @staticmethod
    def _is_compile_error(error_message: str) -> bool:
        """Best-effort detection of compilation-related errors."""
        lowered = error_message.lower()
        indicators = [
            "compil",
            "syntax",
            "unterminated",
            "invalid",
            "parse",
        ]
        return any(indicator in lowered for indicator in indicators)

    def _maybe_update_pool(self, data: bytes, reason: str) -> None:
        """Update the subtree pool if the input is worth learning from."""
        if self.subtree_pool.is_full():
            return
        if self.pool_updater.update_from_input(data):
            self.stats["pool_updates"] += 1
            logger.debug(
                f"Pool updated ({reason}): size={self.subtree_pool.size()}, "
                f"coverage_increases={self.stats['coverage_increases']}"
            )
