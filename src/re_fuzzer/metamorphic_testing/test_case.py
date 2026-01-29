from dataclasses import dataclass
from re_fuzzer.metamorphic_testing.regex_match_kind import RegexMatchKind
from typing import Optional

@dataclass
class TestCase:
    pattern: str
    input: str
    flags: Optional[list[str]] = None
    match_kind: Optional[RegexMatchKind] = None
