from dataclasses import dataclass
from re_fuzzer.metamorphic_testing.test_case import TestCase


@dataclass(frozen=True)
class RunContext:
    """What was tested (before/after transforms)."""
    original: TestCase
    transformed: TestCase
