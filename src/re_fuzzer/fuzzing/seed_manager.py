"""Seed manager for loading and managing the initial regex corpus.

This module handles loading regex patterns from JSONL files, filtering them
for compatibility, and creating the initial corpus for fuzzing.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from loguru import logger

# Try to import yapp for K-regex validation
try:
    from yapp.util import is_k_regex
    HAS_YAPP = True
except ImportError:
    HAS_YAPP = False
    logger.warning("yapp not available for K-regex validation")


class SeedManager:
    """Manages seed corpus for fuzzing initialization."""

    def __init__(self, validate_k_regex: bool = True):
        """Initialize the seed manager.

        Args:
            validate_k_regex: Whether to validate patterns are K-regex compatible
        """
        self.validate_k_regex = validate_k_regex and HAS_YAPP

        # Statistics
        self.stats = {
            "patterns_loaded": 0,
            "patterns_filtered": 0,
            "load_errors": 0,
            "parse_errors": 0,
        }

    def load_from_jsonl(self, file_path: str) -> list[str]:
        """Load regex patterns from a JSONL file.

        Expected format: {"pattern": "regex_pattern_here"}

        Args:
            file_path: Path to JSONL file

        Returns:
            List of regex pattern strings
        """
        patterns = []
        path = Path(file_path)

        if not path.exists():
            logger.error(f"Seed file not found: {file_path}")
            return patterns

        logger.info(f"Loading patterns from {file_path}")

        try:
            with open(path, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue

                    try:
                        data = json.loads(line)
                        if 'pattern' in data:
                            pattern = data['pattern']
                            patterns.append(pattern)
                            self.stats["patterns_loaded"] += 1
                        else:
                            logger.warning(
                                f"Line {line_num}: No 'pattern' field in JSON"
                            )
                            self.stats["load_errors"] += 1
                    except json.JSONDecodeError as e:
                        logger.warning(
                            f"Line {line_num}: Invalid JSON: {e}"
                        )
                        self.stats["parse_errors"] += 1
                    except Exception as e:
                        logger.warning(
                            f"Line {line_num}: Unexpected error: {e}"
                        )
                        self.stats["load_errors"] += 1

        except Exception as e:
            logger.error(f"Failed to read file {file_path}: {e}")
            return patterns

        logger.info(f"Loaded {len(patterns)} patterns from {file_path}")
        return patterns

    def filter_k_regexes(self, patterns: list[str]) -> list[str]:
        """Filter patterns to only include K-regex compatible ones.

        Args:
            patterns: List of regex patterns

        Returns:
            Filtered list of K-regex compatible patterns
        """
        if not self.validate_k_regex or not HAS_YAPP:
            logger.info("K-regex validation disabled or unavailable")
            return patterns

        logger.info(f"Filtering {len(patterns)} patterns for K-regex compatibility")
        k_regex_patterns = []

        for pattern in patterns:
            try:
                if is_k_regex(pattern):
                    k_regex_patterns.append(pattern)
                else:
                    self.stats["patterns_filtered"] += 1
            except Exception as e:
                logger.debug(f"Error checking K-regex for pattern: {e}")
                self.stats["patterns_filtered"] += 1

        logger.info(
            f"Filtered to {len(k_regex_patterns)} K-regex patterns "
            f"({self.stats['patterns_filtered']} filtered out)"
        )
        return k_regex_patterns

    def write_corpus_files(
        self,
        patterns: list[str],
        output_dir: Path,
        max_files: Optional[int] = None
    ) -> list[Path]:
        """Write patterns as individual corpus files for Atheris.

        Args:
            patterns: List of regex patterns
            output_dir: Directory to write corpus files
            max_files: Maximum number of files to write (None for all)

        Returns:
            List of paths to created corpus files
        """
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        corpus_files = []
        patterns_to_write = patterns[:max_files] if max_files else patterns

        logger.info(
            f"Writing {len(patterns_to_write)} corpus files to {output_dir}"
        )

        for i, pattern in enumerate(patterns_to_write):
            # Create a unique filename for each pattern
            file_name = f"seed_{i:05d}.txt"
            file_path = output_dir / file_name

            try:
                # Write pattern as bytes (Atheris expects bytes)
                with open(file_path, 'wb') as f:
                    f.write(pattern.encode('utf-8'))
                corpus_files.append(file_path)
            except Exception as e:
                logger.warning(f"Failed to write corpus file {file_path}: {e}")

        logger.info(f"Created {len(corpus_files)} corpus files")
        return corpus_files

    def load_multiple_jsonl_files(self, file_paths: list[str]) -> list[str]:
        """Load patterns from multiple JSONL files.

        Args:
            file_paths: List of paths to JSONL files

        Returns:
            Combined list of patterns from all files
        """
        all_patterns = []

        for file_path in file_paths:
            patterns = self.load_from_jsonl(file_path)
            all_patterns.extend(patterns)
            logger.info(
                f"Loaded {len(patterns)} patterns from {file_path}, "
                f"total: {len(all_patterns)}"
            )

        return all_patterns

    def deduplicate_patterns(self, patterns: list[str]) -> list[str]:
        """Remove duplicate patterns while preserving order.

        Args:
            patterns: List of patterns potentially with duplicates

        Returns:
            List of unique patterns in original order
        """
        seen = set()
        unique_patterns = []

        for pattern in patterns:
            if pattern not in seen:
                seen.add(pattern)
                unique_patterns.append(pattern)

        duplicates = len(patterns) - len(unique_patterns)
        if duplicates > 0:
            logger.info(f"Removed {duplicates} duplicate patterns")

        return unique_patterns

    def get_default_seed_files(self) -> list[str]:
        """Get list of default seed files in the data directory.

        Returns:
            List of paths to default seed files
        """
        data_dir = Path(__file__).parent.parent.parent.parent / "data"
        default_files = []

        # Look for common seed files
        seed_file_patterns = [
            "oss_regexes.jsonl",
            "internet_regexes.jsonl",
            "pcre_compat_regexes.jsonl",
        ]

        for pattern in seed_file_patterns:
            file_path = data_dir / pattern
            if file_path.exists():
                default_files.append(str(file_path))
                logger.debug(f"Found seed file: {file_path}")

        return default_files

    def get_statistics(self) -> dict:
        """Get seed manager statistics.

        Returns:
            Dictionary of statistics
        """
        return dict(self.stats)

    def reset_statistics(self) -> None:
        """Reset statistics counters."""
        self.stats = {
            "patterns_loaded": 0,
            "patterns_filtered": 0,
            "load_errors": 0,
            "parse_errors": 0,
        }