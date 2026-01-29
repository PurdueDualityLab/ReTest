"""Bug artifact collection and management for experiments.

This module handles collecting, deduplicating, and saving bug artifacts
discovered during fuzzing experiments.
"""

import hashlib
import json
from dataclasses import asdict
from pathlib import Path
from typing import Dict, List, Optional, Set

from loguru import logger

from re_fuzzer.experiments.experiment_config import BugInfo


class BugCollector:
    """Collects and manages bug artifacts from fuzzing experiments."""

    def __init__(
        self,
        output_dir: Path,
        deduplicate: bool = True,
    ):
        """Initialize the bug collector.

        Args:
            output_dir: Directory to save bug artifacts
            deduplicate: Whether to deduplicate bugs by pattern hash
        """
        self.output_dir = Path(output_dir)
        self.deduplicate = deduplicate

        self.bugs: List[BugInfo] = []
        self._seen_hashes: Set[str] = set()

        # Create output directory
        self.crashes_dir = self.output_dir / "crashes"
        self.crashes_dir.mkdir(parents=True, exist_ok=True)

    def record_bug(self, bug: BugInfo) -> bool:
        """Record and save a bug artifact.

        Args:
            bug: Bug information to record

        Returns:
            True if bug was recorded (not duplicate)
        """
        # Compute hash for deduplication
        bug_hash = self._compute_hash(bug)

        if self.deduplicate and bug_hash in self._seen_hashes:
            logger.debug(f"Duplicate bug skipped: {bug_hash[:8]}")
            return False

        self._seen_hashes.add(bug_hash)
        self.bugs.append(bug)

        # Save to disk
        self._save_bug(bug, bug_hash)

        logger.info(
            f"Bug recorded: {bug.error_type} - {bug.error_message[:50]}..."
            if len(bug.error_message) > 50
            else f"Bug recorded: {bug.error_type} - {bug.error_message}"
        )

        return True

    def _compute_hash(self, bug: BugInfo) -> str:
        """Compute unique hash for bug deduplication.

        Uses pattern and error type for deduplication.

        Args:
            bug: Bug to hash

        Returns:
            Hex hash string
        """
        content = f"{bug.pattern}|{bug.error_type}"
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    def _save_bug(self, bug: BugInfo, bug_hash: str) -> None:
        """Save bug artifact to disk.

        Args:
            bug: Bug information
            bug_hash: Unique hash for the bug
        """
        # Create bug directory
        bug_dir = self.crashes_dir / f"bug_{bug_hash[:16]}"
        bug_dir.mkdir(exist_ok=True)

        # Save pattern
        pattern_path = bug_dir / "pattern.txt"
        with open(pattern_path, "w", encoding="utf-8", errors="replace") as f:
            f.write(bug.pattern)

        # Save test string if present
        if bug.test_string:
            test_string_path = bug_dir / "test_string.txt"
            with open(test_string_path, "w", encoding="utf-8", errors="replace") as f:
                f.write(bug.test_string)

        # Save stack trace if present
        if bug.stack_trace:
            stack_path = bug_dir / "stack_trace.txt"
            with open(stack_path, "w", encoding="utf-8", errors="replace") as f:
                f.write(bug.stack_trace)

        # Save metadata
        info_path = bug_dir / "info.json"
        with open(info_path, "w") as f:
            json.dump(
                {
                    "error_type": bug.error_type,
                    "error_message": bug.error_message,
                    "timestamp": bug.timestamp,
                    "hash": bug_hash,
                },
                f,
                indent=2,
            )

    def get_summary(self) -> Dict:
        """Get summary statistics about collected bugs.

        Returns:
            Dict with bug statistics
        """
        by_type: Dict[str, int] = {}
        for bug in self.bugs:
            by_type[bug.error_type] = by_type.get(bug.error_type, 0) + 1

        return {
            "total_bugs": len(self.bugs),
            "unique_patterns": len(self._seen_hashes),
            "by_type": by_type,
        }

    def save_summary(self) -> None:
        """Save bug summary to disk."""
        summary = self.get_summary()
        summary_path = self.output_dir / "bug_summary.json"

        with open(summary_path, "w") as f:
            json.dump(summary, f, indent=2)

        # Also save list of all bugs
        bugs_path = self.output_dir / "all_bugs.json"
        with open(bugs_path, "w") as f:
            json.dump(
                [asdict(bug) for bug in self.bugs],
                f,
                indent=2,
                default=str,  # Handle non-serializable types
            )

    @staticmethod
    def load_bugs(bugs_dir: Path) -> List[BugInfo]:
        """Load bugs from a directory.

        Args:
            bugs_dir: Directory containing bug subdirectories

        Returns:
            List of BugInfo objects
        """
        bugs = []

        if not bugs_dir.exists():
            return bugs

        for bug_dir in bugs_dir.iterdir():
            if not bug_dir.is_dir():
                continue

            try:
                # Load info.json
                info_path = bug_dir / "info.json"
                if not info_path.exists():
                    continue

                with open(info_path) as f:
                    info = json.load(f)

                # Load pattern
                pattern_path = bug_dir / "pattern.txt"
                pattern = pattern_path.read_text() if pattern_path.exists() else ""

                # Load test string
                test_string_path = bug_dir / "test_string.txt"
                test_string = test_string_path.read_text() if test_string_path.exists() else None

                # Load stack trace
                stack_path = bug_dir / "stack_trace.txt"
                stack_trace = stack_path.read_text() if stack_path.exists() else None

                bug = BugInfo(
                    pattern=pattern,
                    test_string=test_string,
                    error_type=info.get("error_type", "unknown"),
                    error_message=info.get("error_message", ""),
                    stack_trace=stack_trace,
                    timestamp=info.get("timestamp", 0.0),
                )
                bugs.append(bug)

            except Exception as e:
                logger.debug(f"Failed to load bug from {bug_dir}: {e}")

        return bugs


def merge_bug_collectors(
    collectors: List[BugCollector],
    output_dir: Path,
) -> BugCollector:
    """Merge multiple bug collectors into one.

    Args:
        collectors: List of bug collectors to merge
        output_dir: Output directory for merged collector

    Returns:
        New BugCollector with merged bugs
    """
    merged = BugCollector(output_dir=output_dir, deduplicate=True)

    for collector in collectors:
        for bug in collector.bugs:
            merged.record_bug(bug)

    return merged
