"""Systematic regex flag combination generator (V8 FuzzTest style).

Implements ArbitraryFlags() from regexp-fuzzer.cc using BitFlagCombinationOf
with filtering for incompatible flag combinations.

Reference: resources/baseline-v8-fuzzing/regexp-fuzzer.cc lines 40-59
"""

import random
from enum import IntFlag
from typing import List


class PCREFlags(IntFlag):
    """PCRE (libpcre) compile-time flags.

    These correspond to the flags defined in pcre.h.
    """

    NONE = 0
    CASELESS = 0x00000001  # i - case insensitive
    MULTILINE = 0x00000002  # m - ^ and $ match newlines
    DOTALL = 0x00000004  # s - . matches newlines
    EXTENDED = 0x00000008  # x - ignore whitespace/comments
    ANCHORED = 0x00000010  # pattern anchored at start
    UNGREEDY = 0x00000200  # invert greedy quantifiers
    UTF8 = 0x00000800  # UTF-8 mode
    UCP = 0x20000000  # Unicode character properties


class PCRE2Flags(IntFlag):
    """PCRE2 (libpcre2) compile-time flags.

    These correspond to the flags defined in pcre2.h.
    Note: PCRE2 uses different flag values than PCRE.
    """

    NONE = 0
    CASELESS = 0x00000008  # i
    DOTALL = 0x00000020  # s
    EXTENDED = 0x00000080  # x
    MULTILINE = 0x00000400  # m
    UCP = 0x00020000  # Unicode character properties
    UTF = 0x00080000  # UTF-8 mode


class FlagsDomain:
    """Generates flag combinations systematically like V8's ArbitraryFlags().

    V8's ArbitraryFlags() uses BitFlagCombinationOf to generate all valid
    combinations of regex flags, then filters out incompatible combinations.

    For PCRE/PCRE2, we generate combinations of the common flags that affect
    regex behavior, similar to V8's approach with:
    - HasIndices, Global, IgnoreCase, Multiline, Sticky, Unicode/UnicodeSets, DotAll
    """

    def __init__(self, engine: str = "pcre"):
        """Initialize the flags domain.

        Args:
            engine: Either "pcre" or "pcre2"
        """
        self.engine = engine

        if engine == "pcre":
            self.flags_class = PCREFlags
            # Base flags always applied (UTF-8 and Unicode properties)
            self.base_flags = PCREFlags.UTF8 | PCREFlags.UCP
            # Flags to combine (like V8's BitFlagCombinationOf)
            self.compatible_flags = [
                PCREFlags.CASELESS,
                PCREFlags.MULTILINE,
                PCREFlags.DOTALL,
                PCREFlags.EXTENDED,
                PCREFlags.UNGREEDY,
            ]
        else:  # pcre2
            self.flags_class = PCRE2Flags
            self.base_flags = PCRE2Flags.UTF | PCRE2Flags.UCP
            self.compatible_flags = [
                PCRE2Flags.CASELESS,
                PCRE2Flags.MULTILINE,
                PCRE2Flags.DOTALL,
                PCRE2Flags.EXTENDED,
            ]

        # Pre-compute all valid combinations (like BitFlagCombinationOf)
        self._all_combinations = self._generate_all_combinations()

    def _generate_all_combinations(self) -> List[int]:
        """Generate all valid flag combinations.

        Similar to fuzztest::BitFlagCombinationOf, this generates all 2^n
        combinations of the compatible flags, then filters out any invalid ones.

        Returns:
            List of valid flag combination integers
        """
        combinations = []
        n = len(self.compatible_flags)

        # Generate all 2^n combinations
        for i in range(1 << n):
            combo = int(self.base_flags)
            for j, flag in enumerate(self.compatible_flags):
                if i & (1 << j):
                    combo |= int(flag)
            if self._is_valid_combination(combo):
                combinations.append(combo)

        return combinations

    def _is_valid_combination(self, flags: int) -> bool:
        """Filter out incompatible flag combinations.

        V8's ArbitraryFlags() uses fuzztest::Filter with RegExp::VerifyFlags
        to remove invalid combinations. For PCRE/PCRE2, most flag combinations
        are valid, but we can add checks here if needed.

        Args:
            flags: The flag combination to validate

        Returns:
            True if the combination is valid
        """
        # Currently all PCRE/PCRE2 flag combinations are valid
        # Add specific incompatibility checks here if needed
        return True

    def generate(self) -> int:
        """Generate a random valid flag combination.

        Uses equal probability selection (like fuzztest::OneOf) across all
        pre-computed valid combinations.

        Returns:
            A valid flag combination as an integer
        """
        return random.choice(self._all_combinations)

    def generate_all(self) -> List[int]:
        """Return all valid flag combinations for systematic testing.

        Returns:
            List of all valid flag combinations
        """
        return self._all_combinations.copy()

    def get_flag_count(self) -> int:
        """Get the total number of valid flag combinations.

        Returns:
            Number of valid flag combinations
        """
        return len(self._all_combinations)


def generate_flags(engine: str = "pcre") -> int:
    """Convenience function to generate a random flag combination.

    Args:
        engine: Either "pcre" or "pcre2"

    Returns:
        A valid flag combination as an integer
    """
    return FlagsDomain(engine).generate()
