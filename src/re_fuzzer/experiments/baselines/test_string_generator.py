"""V8/FuzzTest-style test string generator.

Implements the ArbitraryBytes strategy from V8's regexp-fuzzer.cc:
- 25% fixed example ("foobar")
- 25% simple chars ('a', 'b', ' ') max 10 chars
- 25% printable ASCII max 10 chars
- 25% arbitrary bytes (0-255) max 10 chars

Reference: resources/baseline-v8-fuzzing/regexp-fuzzer.cc lines 61-99
"""

import random
import string
from typing import List


# V8 uses WithMaxSize(10) for all test string categories
MAX_TEST_STRING_LENGTH = 10


class V8TestStringGenerator:
    """Generates test strings following V8 FuzzTest's ArbitraryBytes strategy.

    This matches the behavior of ArbitraryOneBytes() and ArbitraryTwoBytes()
    from V8's regexp-fuzzer.cc, which uses fuzztest::OneOf to select equally
    between four categories of test strings.
    """

    # Fixed example from ArbitraryOneBytes (line 93 of regexp-fuzzer.cc)
    FIXED_EXAMPLE_ONE_BYTE = b"foobar"

    # Fixed example for two-byte (line 98: {'f', 0xD83D, 0xDCA9, 'b', 'a', 0x2603})
    # This is "f" + poop emoji + "ba" + snowman
    FIXED_EXAMPLE_TWO_BYTE = "f\U0001F4A9ba\u2603".encode("utf-8")

    # Simple chars: 'a', 'b', ' ' (line 72-74 of regexp-fuzzer.cc)
    SIMPLE_CHARS = [ord("a"), ord("b"), ord(" ")]

    def __init__(self, use_two_byte: bool = False):
        """Initialize the generator.

        Args:
            use_two_byte: If True, use two-byte (UTF-16) style examples.
                          If False, use one-byte ASCII style examples.
        """
        self.use_two_byte = use_two_byte
        self.fixed_example = (
            self.FIXED_EXAMPLE_TWO_BYTE if use_two_byte else self.FIXED_EXAMPLE_ONE_BYTE
        )

    def generate(self) -> bytes:
        """Generate a test string using V8's hybrid distribution.

        Uses fuzztest::OneOf semantics: equal probability (25% each) for:
        - Fixed example ("foobar")
        - Simple chars ('a', 'b', ' ')
        - Printable ASCII
        - Arbitrary bytes (0-255)

        Returns:
            Generated test string as bytes
        """
        category = random.randint(0, 3)  # 4 categories, equal probability

        if category == 0:
            # Fixed example (25%)
            return self.fixed_example
        elif category == 1:
            # Simple chars: 'a', 'b', ' ' (25%)
            return self._generate_simple()
        elif category == 2:
            # Printable ASCII (25%)
            return self._generate_printable()
        else:
            # Arbitrary bytes 0-255 (25%)
            return self._generate_arbitrary()

    def _generate_simple(self) -> bytes:
        """Generate string with only 'a', 'b', and space.

        Matches fuzztest::OneOf(fuzztest::InRange('a', 'b'), fuzztest::Just(' '))
        from regexp-fuzzer.cc line 72-74.
        """
        length = random.randint(0, MAX_TEST_STRING_LENGTH)
        return bytes(random.choice(self.SIMPLE_CHARS) for _ in range(length))

    def _generate_printable(self) -> bytes:
        """Generate printable ASCII string.

        Matches fuzztest::PrintableAsciiChar() from regexp-fuzzer.cc line 78-79.
        """
        length = random.randint(0, MAX_TEST_STRING_LENGTH)
        # string.printable includes digits, letters, punctuation, whitespace
        # Take first 95 chars (0x20-0x7E) to match PrintableAsciiChar
        printable_chars = string.printable[:95]
        return "".join(random.choice(printable_chars) for _ in range(length)).encode(
            "utf-8"
        )

    def _generate_arbitrary(self) -> bytes:
        """Generate arbitrary bytes (0-255).

        Matches fuzztest::Arbitrary<T>() from regexp-fuzzer.cc line 83-85.
        """
        length = random.randint(0, MAX_TEST_STRING_LENGTH)
        return bytes(random.randint(0, 255) for _ in range(length))

    def generate_batch(self, count: int) -> List[bytes]:
        """Generate multiple test strings.

        Args:
            count: Number of test strings to generate

        Returns:
            List of generated test strings
        """
        return [self.generate() for _ in range(count)]


def generate_test_string(use_two_byte: bool = False) -> bytes:
    """Convenience function to generate a single test string.

    Args:
        use_two_byte: Whether to use two-byte style examples

    Returns:
        Generated test string
    """
    return V8TestStringGenerator(use_two_byte).generate()
