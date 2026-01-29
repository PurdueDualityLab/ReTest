#!/usr/bin/env python3
"""Main entry point for running the grammar-aware regex fuzzer.

This script sets up and runs the fuzzing campaign using Atheris/libfuzzer
with subtree-pool-based AST mutations for testing regex engines.

Usage:
    python -m re_fuzzer.run_fuzzer [options]

    or with Atheris options:

    python -m re_fuzzer.run_fuzzer -- -max_total_time=3600 -workers=4

Example:
    # Run with default settings
    python -m re_fuzzer.run_fuzzer

    # Run with custom seed file
    python -m re_fuzzer.run_fuzzer --seed-file data/oss_regexes.jsonl

    # Run for 1 hour with 4 workers
    python -m re_fuzzer.run_fuzzer -- -max_total_time=3600 -workers=4
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from loguru import logger

from re_fuzzer.fuzzing.atheris_harness import AtherisHarness
from re_fuzzer.sut.pcre2_cffi import PCRE2CFFI
from re_fuzzer.sut.pcre_cffi import PCRECFFI


def parse_arguments() -> tuple[argparse.Namespace, list[str]]:
    """Parse command line arguments.

    Returns:
        Tuple of (parsed_args, atheris_args)
    """
    parser = argparse.ArgumentParser(
        description="Grammar-aware regex fuzzer with subtree pool mutations",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Atheris/libfuzzer options can be passed after '--':
  -max_total_time=N    : Run for at most N seconds
  -max_len=N          : Maximum input length
  -workers=N          : Number of parallel workers
  -timeout=N          : Timeout for individual test runs
  -print_final_stats=1: Print statistics at the end

Example:
  python -m re_fuzzer.run_fuzzer --seed-file data/oss_regexes.jsonl -- -max_total_time=3600
        """
    )

    # Fuzzer configuration options
    parser.add_argument(
        "--seed-file",
        type=str,
        default="data/oss_regexes.jsonl",
        help="Path to JSONL file with seed regex patterns (default: data/oss_regexes.jsonl)"
    )
    parser.add_argument(
        "--max-seed-size",
        type=int,
        default=10000,
        help="Maximum number of seed patterns to use (default: 10000)"
    )
    parser.add_argument(
        "--corpus-dir",
        type=str,
        default="/tmp/re_fuzzer_corpus",
        help="Directory for fuzzer corpus (default: /tmp/re_fuzzer_corpus)"
    )
    parser.add_argument(
        "--max-subtree-bytes",
        type=int,
        default=200,
        help="Maximum size in bytes for subtrees in pool (default: 200)"
    )
    parser.add_argument(
        "--max-pool-size",
        type=int,
        default=100000,
        help="Maximum number of subtrees in pool (default: 100000)"
    )
    parser.add_argument(
        "--mutation-probability",
        type=float,
        default=0.8,
        help="Probability of grammar-aware mutation vs fallback (default: 0.8)"
    )
    parser.add_argument(
        "--initial-pool-patterns",
        type=int,
        default=5000,
        help="Number of valid seeds used to bootstrap the subtree pool (default: 5000)"
    )
    parser.add_argument(
        "--passive-pool-update-chance",
        type=float,
        default=0.05,
        help="Probability of learning from a valid input even without coverage gain (default: 0.05)"
    )
    parser.add_argument(
        "--no-seeds",
        action="store_true",
        help="Start with empty corpus (no seed loading)"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose debug logging"
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress all logs except coverage information"
    )
    parser.add_argument(
        "--enable-regex-hook",
        action="store_true",
        help="Enable Atheris regex instrumentation hook for the SUT"
    )
    parser.add_argument(
        "--library-path",
        type=str,
        default=None,
        help="Path to instrumented regex engine library (e.g., libpcre2-8.so). "
             "Can also be set via PCRE2_LIBRARY_PATH env var."
    )
    parser.add_argument(
        "--log-interval",
        type=int,
        default=100,
        help="How often to log progress (every N iterations, default: 100)"
    )
    parser.add_argument(
        "--test-timeout",
        type=int,
        default=2,
        help="Per-test-case timeout in seconds (default: 2)"
    )
    parser.add_argument(
        "--sut",
        type=str,
        default="pcre2",
        choices=["pcre", "pcre2"],
        help="SUT type to use (default: pcre2)"
    )
    parser.add_argument(
        "--parallel", "-p",
        type=int,
        default=0,
        metavar="N",
        help="Run N parallel workers (default: 0 for single-process mode)"
    )
    parser.add_argument(
        "--stats-file",
        type=str,
        default=None,
        help="Path to write stats JSON file (for parallel mode coordination)"
    )
    parser.add_argument(
        "--coverage-file",
        type=str,
        default=None,
        help="Path to export coverage bitmap (for parallel mode)"
    )
    parser.add_argument(
        "--merged-coverage-file",
        type=str,
        default=None,
        help="Path to load merged coverage from coordinator (for parallel mode)"
    )
    parser.add_argument(
        "--pool-file",
        type=str,
        default=None,
        help="Path to export subtree pool (for parallel mode)"
    )
    parser.add_argument(
        "--merged-pool-file",
        type=str,
        default=None,
        help="Path to load merged pool from coordinator (for parallel mode)"
    )
    parser.add_argument(
        "--generator-backend",
        type=str,
        default="superion",
        choices=["superion", "advanced", "hybrid"],
        help="Pattern generation backend: superion (default, mutation-based), "
             "advanced (template-based), or hybrid (both)"
    )

    # Parse arguments
    # Split args at '--' to separate our args from atheris args when provided.
    if "--" in sys.argv:
        split_index = sys.argv.index("--")
        our_args = sys.argv[1:split_index]
        atheris_args = sys.argv[split_index + 1:]
        args = parser.parse_args(our_args)
    else:
        args, atheris_args = parser.parse_known_args(sys.argv[1:])

    return args, atheris_args


def setup_logging(verbose: bool = False, quiet: bool = False) -> None:
    """Configure logging for the fuzzer.

    Args:
        verbose: Whether to enable verbose debug logging
        quiet: Whether to suppress all logs except coverage information
    """
    # Remove default logger
    logger.remove()

    if quiet:
        # In quiet mode, only show messages with [COV] tag
        def coverage_filter(record):
            return "[COV]" in record["message"]

        logger.add(
            sys.stderr,
            format="<green>{time:HH:mm:ss}</green> | <level>{message}</level>",
            level="INFO",
            filter=coverage_filter,
            colorize=True
        )
    else:
        # Add console logger with appropriate level
        level = "DEBUG" if verbose else "INFO"
        logger.add(
            sys.stderr,
            format="<green>{time:HH:mm:ss}</green> | <level>{level: <8}</level> | <level>{message}</level>",
            level=level,
            colorize=True
        )

    # Add file logger for detailed logs (always enabled)
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    logger.add(
        log_dir / "fuzzer_{time}.log",
        format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{line} | {message}",
        level="DEBUG",
        rotation="100 MB",
        retention="7 days"
    )


def main() -> int:
    """Main entry point for the fuzzer.

    Returns:
        Exit code (0 for success, non-zero for failure)
    """
    # Parse arguments
    args, atheris_args = parse_arguments()

    # Setup logging
    setup_logging(verbose=args.verbose, quiet=args.quiet)

    logger.info("=" * 60)
    logger.info("GRAMMAR-AWARE REGEX FUZZER")
    logger.info("=" * 60)

    # Verify seed file exists if not using --no-seeds
    seed_corpus_path = None
    if not args.no_seeds:
        seed_path = Path(args.seed_file)
        if not seed_path.exists():
            logger.error(f"Seed file not found: {args.seed_file}")
            return 1
        seed_corpus_path = str(seed_path.absolute())
        logger.info(f"Using seed file: {seed_corpus_path}")

    # Check for parallel mode
    if args.parallel > 0:
        logger.info(f"Running in parallel mode with {args.parallel} workers")
        from re_fuzzer.fuzzing.parallel_coordinator import run_parallel_fuzzer

        # Extract max_total_time from atheris args for coordinator duration
        duration = 0
        for arg in atheris_args:
            if arg.startswith("-max_total_time="):
                try:
                    duration = int(arg.split("=")[1])
                except ValueError:
                    pass
                break

        stats = run_parallel_fuzzer(
            num_workers=args.parallel,
            library_path=args.library_path,
            seed_file=seed_corpus_path,
            duration=duration,
            sut_type=args.sut,
            max_seed_size=args.max_seed_size,
            max_subtree_bytes=args.max_subtree_bytes,
            max_pool_size=args.max_pool_size,
            mutation_probability=args.mutation_probability,
            initial_pool_patterns=args.initial_pool_patterns,
            passive_pool_update_chance=args.passive_pool_update_chance,
            log_interval=args.log_interval,
            test_timeout=args.test_timeout,
        )

        logger.info("=" * 60)
        logger.info("PARALLEL FUZZING COMPLETE")
        logger.info(f"Total iterations: {stats.get('total_iterations', 0)}")
        logger.info(f"Total crashes: {stats.get('total_crashes', 0)}")
        logger.info(f"Coverage increases: {stats.get('total_coverage_increases', 0)}")
        logger.info(f"Corpus files: {stats.get('corpus_files', 0)}")
        logger.info(f"Elapsed time: {stats.get('elapsed_time', 0):.1f}s")
        logger.info("=" * 60)
        return 0

    # Initialize SUT based on --sut option
    try:
        if args.sut == "pcre":
            # Enable coverage-maximizing options:
            # - use_dfa_percentage=0.2: Use DFA engine for 20% of matches
            # - rotate_options=True: Rotate through compile/match options
            # - partial_match_percentage=0.1: Try partial matching for 10%
            sut = PCRECFFI(
                library_path=args.library_path,
                use_dfa_percentage=0.2,
                rotate_options=True,
                partial_match_percentage=0.1,
            )
        else:
            sut = PCRE2CFFI(library_path=args.library_path)
        logger.info(f"Initialized SUT: {sut.name}")
    except Exception as e:
        logger.error(f"Failed to initialize {args.sut.upper()} SUT: {e}")
        logger.error("Make sure the library is built and path is correct")
        logger.error("Set --library-path or appropriate env var")
        return 1

    # Configure advanced pattern generator based on --generator-backend
    advanced_generator = None
    advanced_weight = 0.0

    if args.generator_backend in ("advanced", "hybrid"):
        from re_fuzzer.fuzzing.advanced_pattern_generator import AdvancedPatternGenerator
        advanced_generator = AdvancedPatternGenerator()
        if args.generator_backend == "advanced":
            advanced_weight = 0.8  # Use advanced for 80% of generations
            logger.info("Generator backend: advanced (template-based, 80% weight)")
        else:  # hybrid
            advanced_weight = 0.3  # Use advanced for 30% of generations
            logger.info("Generator backend: hybrid (superion + advanced, 30% advanced)")
    else:
        logger.info("Generator backend: superion (mutation-based)")

    # Create harness
    logger.info("Initializing fuzzing harness...")
    try:
        harness = AtherisHarness(
            sut=sut,
            library_path=args.library_path,
            seed_corpus_path=seed_corpus_path,
            max_seed_size=args.max_seed_size,
            corpus_dir=args.corpus_dir,
            max_subtree_bytes=args.max_subtree_bytes,
            max_pool_size=args.max_pool_size,
            mutation_probability=args.mutation_probability,
            initial_pool_patterns=args.initial_pool_patterns,
            passive_pool_update_chance=args.passive_pool_update_chance,
            enable_regex_hook=args.enable_regex_hook,
            log_interval=args.log_interval,
            test_timeout=args.test_timeout,
            stats_file=args.stats_file,
            coverage_file=args.coverage_file,
            merged_coverage_file=args.merged_coverage_file,
            pool_file=args.pool_file,
            merged_pool_file=args.merged_pool_file,
            advanced_generator=advanced_generator,
            advanced_weight=advanced_weight,
        )
    except Exception as e:
        logger.error(f"Failed to initialize harness: {e}")
        return 1

    # Log configuration
    logger.info("-" * 60)
    logger.info("CONFIGURATION")
    logger.info(f"  Library path: {args.library_path or 'env:PCRE2_LIBRARY_PATH'}")
    logger.info(f"  Seed file: {seed_corpus_path or 'None (empty corpus)'}")
    logger.info(f"  Max seed size: {args.max_seed_size}")
    logger.info(f"  Corpus directory: {harness.corpus_dir}")
    logger.info(f"  Max subtree bytes: {args.max_subtree_bytes}")
    logger.info(f"  Max pool size: {args.max_pool_size}")
    logger.info(f"  Mutation probability: {args.mutation_probability:.2f}")
    logger.info(f"  Initial pool patterns: {args.initial_pool_patterns}")
    logger.info(f"  Passive pool update chance: {args.passive_pool_update_chance:.2f}")
    logger.info(f"  Log interval: {args.log_interval}")
    logger.info(f"  Test timeout: {args.test_timeout}s")
    logger.info(f"  Coverage tracking: {'enabled' if args.library_path else 'disabled'}")
    logger.info(f"  Generator backend: {args.generator_backend}")
    logger.info(f"  Atheris args: {atheris_args or 'Default'}")
    logger.info("-" * 60)

    # Run fuzzer
    logger.info("Starting fuzzing campaign...")
    try:
        # Prepare argv for atheris
        # Atheris expects argv[0] to be the program name
        atheris_argv = [sys.argv[0]] + atheris_args

        stats = harness.run(argv=atheris_argv)

        # Log summary
        logger.info("=" * 60)
        logger.info("FUZZING COMPLETE")
        logger.info(f"Total iterations: {stats.get('iterations', 0)}")
        logger.info(f"Crashes found: {stats.get('crashes', 0)}")
        logger.info(f"Coverage increases: {stats.get('coverage_increases', 0)}")
        logger.info(f"Final pool size: {stats.get('pool_size', 0)}")
        logger.info(f"Elapsed time: {stats.get('elapsed_time', 0):.1f}s")
        logger.info("=" * 60)

        return 0

    except KeyboardInterrupt:
        logger.info("\nFuzzing interrupted by user")
        return 130  # Standard exit code for SIGINT
    except Exception as e:
        logger.error(f"Fuzzing failed with error: {e}")
        logger.exception("Full traceback:")
        return 1


if __name__ == "__main__":
    sys.exit(main())
