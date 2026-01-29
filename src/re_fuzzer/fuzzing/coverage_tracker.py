"""Coverage tracking for determining when inputs trigger new code paths.

This module implements coverage tracking using LLVM sanitizer coverage by
directly reading the __sancov_cntrs ELF section.

Supports both standalone ASan and atheris's asan_with_fuzzer.so.
"""

from __future__ import annotations

import ctypes
import os
import subprocess

import numpy as np
from loguru import logger


class CoverageTracker:
    """Tracks code coverage using LLVM inline-8bit-counters instrumentation."""

    def __init__(self, object_path: str):
        """Initialize the coverage tracker."""
        self.object_path = object_path
        self.counters = None
        self._np_view = None  # Numpy view for fast operations
        self.size = 0
        self._seen_bitmap = None  # Boolean numpy array for O(1) edge tracking

        # Try to load the coverage counters from the extension module
        try:
            # Resolve to absolute path for consistent matching
            abs_object_path = os.path.abspath(object_path)

            # First, ensure the library is loaded
            try:
                ctypes.CDLL(abs_object_path)
            except OSError:
                pass  # Library might already be loaded

            # Use nm (without -D) to find local symbols for coverage counters
            # The sancov symbols are local data symbols, not dynamic
            result = subprocess.run(
                ['nm', abs_object_path],
                capture_output=True,
                text=True,
                check=True
            )

            start_offset = None
            stop_offset = None

            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 3:
                    if parts[2] == '__start___sancov_cntrs':
                        start_offset = int(parts[0], 16)
                    elif parts[2] == '__stop___sancov_cntrs':
                        stop_offset = int(parts[0], 16)

            if start_offset is None or stop_offset is None:
                raise RuntimeError(
                    f"Coverage counter symbols not found in library. "
                    f"Make sure {abs_object_path} was built with -fsanitize-coverage=inline-8bit-counters"
                )

            self.size = stop_offset - start_offset
            logger.debug(f"Found sancov counters: offset=0x{start_offset:x}, size={self.size}")

            # Find the correct memory mapping for the data segment (rw-p)
            # The counters are in the read-write data segment, not the executable segment
            with open('/proc/self/maps', 'r') as f:
                all_lines = f.readlines()

            # Get basename for flexible matching (library might be loaded via different path)
            lib_basename = os.path.basename(abs_object_path)

            mappings = []
            for line in all_lines:
                # Match by full path OR basename
                if abs_object_path in line or lib_basename in line:
                    mappings.append(line.strip())

            if not mappings:
                # Debug: show what libraries ARE mapped
                logger.debug(f"Looking for library: {abs_object_path} (basename: {lib_basename})")
                logger.debug("Available mappings containing 'pcre2' or 'libpcre':")
                for line in all_lines:
                    if 'pcre' in line.lower():
                        logger.debug(f"  {line.strip()}")
                raise RuntimeError(f"Library {abs_object_path} not found in memory maps")

            logger.debug(f"Found {len(mappings)} memory mappings for {lib_basename}")

            # Find the rw-p (read-write) mapping which contains the data segment
            # This is where the sancov counters live
            for mapping in mappings:
                parts = mapping.split()
                addr_range = parts[0]
                perms = parts[1]
                offset = int(parts[2], 16)

                base_addr = int(addr_range.split('-')[0], 16)
                end_addr = int(addr_range.split('-')[1], 16)

                # Check if this mapping contains our counter offset
                # The counter offset is relative to the start of the file
                if 'rw' in perms:
                    # For rw mappings, calculate if the counter falls within
                    file_offset_in_mapping = start_offset - offset
                    if 0 <= file_offset_in_mapping < (end_addr - base_addr):
                        actual_start = base_addr + file_offset_in_mapping

                        # Verify we can access the memory
                        ArrayType = ctypes.c_uint8 * self.size
                        try:
                            self.counters = ArrayType.from_address(actual_start)
                            self._np_view = np.ctypeslib.as_array(self.counters)

                            # Verify access by reading
                            _ = self._np_view[0]

                            # Initialize bitmap for tracking seen edges
                            self._seen_bitmap = np.zeros(self.size, dtype=np.bool_)

                            logger.info(f"Coverage tracking: {self.size} edges at 0x{actual_start:x}")
                            return
                        except (ValueError, OSError) as e:
                            logger.debug(f"Failed to access memory at 0x{actual_start:x}: {e}")
                            continue

            # Fallback: try all mappings
            for mapping in mappings:
                parts = mapping.split()
                addr_range = parts[0]
                base_addr = int(addr_range.split('-')[0], 16)

                actual_start = base_addr + start_offset
                ArrayType = ctypes.c_uint8 * self.size

                try:
                    self.counters = ArrayType.from_address(actual_start)
                    self._np_view = np.ctypeslib.as_array(self.counters)
                    _ = self._np_view[0]  # Test access
                    self._seen_bitmap = np.zeros(self.size, dtype=np.bool_)
                    logger.info(f"Coverage tracking (fallback): {self.size} edges at 0x{actual_start:x}")
                    return
                except (ValueError, OSError):
                    continue

            raise RuntimeError("Could not find accessible coverage counters in memory")

        except Exception as exc:
            logger.warning(
                f"Failed to initialize LLVM coverage tracking: {exc}. "
                "Coverage-guided pool updates will be disabled."
            )
            self.counters = None
            self._np_view = None

    def get_current_coverage(self) -> int:
        """Get the current coverage counter.

        Returns:
            Total unique coverage edges hit (non-zero counters)
        """
        if self._np_view is None:
            return 0

        try:
            # Use numpy for fast counting (100x faster than Python loop)
            return int(np.count_nonzero(self._np_view))
        except Exception as exc:
            logger.error(f"Failed to read coverage counters: {exc}")
            return 0

    def check_and_update_coverage(self) -> bool:
        """Check if this test execution discovered new edges.

        This method is designed for use with libFuzzer, which resets counters
        before each test. It maintains an internal bitmap of all edges ever
        seen and returns True if any new edges were discovered.

        Returns:
            True if new edges were discovered in this execution
        """
        if self._np_view is None or self._seen_bitmap is None:
            return False

        try:
            # Create boolean mask of edges hit this run (non-zero counters)
            hit_mask = self._np_view > 0

            # Find new edges: hit this run AND not seen before
            new_mask = hit_mask & ~self._seen_bitmap

            # Check if any new edges
            if np.any(new_mask):
                # Update seen bitmap with OR operation
                self._seen_bitmap |= hit_mask
                return True

            return False

        except Exception as exc:
            logger.error(f"Failed to check coverage: {exc}")
            return False

    def has_new_coverage(self, previous: int, current: int) -> bool:
        """Check if current coverage has increased.

        Note: This method uses simple counting which doesn't work well with
        libFuzzer (which resets counters). Use check_and_update_coverage()
        for libFuzzer-based fuzzing.

        Args:
            previous: Previous coverage counter
            current: Current coverage counter

        Returns:
            True if new coverage was discovered
        """
        return current > previous

    def reset(self) -> None:
        """Reset coverage tracking by zeroing all counters."""
        if self._np_view is None:
            return

        try:
            # Use numpy for fast reset
            self._np_view.fill(0)
        except Exception as exc:
            logger.warning(f"Failed to reset coverage counters: {exc}")

    def get_statistics(self) -> dict:
        """Get coverage statistics.

        Returns:
            Dictionary of coverage statistics
        """
        if self.counters is None or self._seen_bitmap is None:
            return {"error": "Coverage tracking not available"}

        try:
            # Report cumulative edges seen (not just current run)
            unique = int(np.sum(self._seen_bitmap))
            return {
                "unique_edges": unique,
                "total_edges": self.size,
                "coverage_percent": (unique / self.size * 100) if self.size > 0 else 0
            }
        except Exception as exc:
            return {"error": str(exc)}

    def get_initial_state(self) -> int:
        """Return an initial coverage snapshot.

        Returns:
            Current coverage counter value
        """
        return self.get_current_coverage()

    # -------------------------------------------------------------------------
    # Methods for parallel coverage synchronization
    # -------------------------------------------------------------------------

    def export_bitmap(self) -> bytes:
        """Export the seen bitmap as bytes for sharing with other workers.

        Returns:
            Bitmap as bytes (empty if tracking unavailable)
        """
        if self._seen_bitmap is None:
            return b""
        return self._seen_bitmap.tobytes()

    def merge_bitmap(self, other_bitmap: bytes) -> int:
        """Merge another worker's bitmap into this one.

        Args:
            other_bitmap: Bitmap bytes from another worker

        Returns:
            Number of new edges discovered from the merge
        """
        if self._seen_bitmap is None or not other_bitmap:
            return 0

        try:
            other = np.frombuffer(other_bitmap, dtype=np.bool_)
            if len(other) != len(self._seen_bitmap):
                logger.warning(
                    f"Bitmap size mismatch: {len(other)} vs {len(self._seen_bitmap)}"
                )
                return 0

            # Count new edges before merge
            new_edges = int(np.sum(other & ~self._seen_bitmap))

            # Merge with OR operation
            self._seen_bitmap |= other
            return new_edges

        except Exception as e:
            logger.debug(f"Failed to merge bitmap: {e}")
            return 0

    def save_bitmap(self, path: str) -> bool:
        """Save the seen bitmap to a file.

        Args:
            path: File path to save bitmap

        Returns:
            True if saved successfully
        """
        if self._seen_bitmap is None:
            return False

        try:
            with open(path, "wb") as f:
                f.write(self._seen_bitmap.tobytes())
            return True
        except Exception as e:
            logger.debug(f"Failed to save bitmap: {e}")
            return False

    def load_bitmap(self, path: str) -> int:
        """Load and merge a bitmap from a file.

        Args:
            path: File path to load bitmap from

        Returns:
            Number of new edges discovered from the load
        """
        try:
            with open(path, "rb") as f:
                data = f.read()
            return self.merge_bitmap(data)
        except FileNotFoundError:
            return 0
        except Exception as e:
            logger.debug(f"Failed to load bitmap: {e}")
            return 0

    def get_bitmap_size(self) -> int:
        """Get the size of the coverage bitmap in bytes.

        Returns:
            Size in bytes, or 0 if unavailable
        """
        if self._seen_bitmap is None:
            return 0
        return len(self._seen_bitmap)
