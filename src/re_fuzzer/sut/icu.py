from __future__ import annotations

import re
from typing import Optional, List, Tuple

from icu import RegexPattern, RegexMatcher, URegexpFlag  # type: ignore[attr-defined]

from re_fuzzer.sut.base_sut import BaseSUT
from re_fuzzer.sut.engine_match import EngineMatch


def _icu_flags(py_flags: int) -> int:
    """
    Map Python's re flags to ICU's flags.
    Unsupported flags (ASCII, LOCALE, DEBUG, TEMPLATE) are ignored.
    """
    flags = 0
    if py_flags & re.IGNORECASE:
        flags |= URegexpFlag.CASE_INSENSITIVE
    if py_flags & re.DOTALL:
        flags |= URegexpFlag.DOTALL
    if py_flags & re.MULTILINE:
        flags |= URegexpFlag.MULTILINE
    if py_flags & re.VERBOSE:
        flags |= URegexpFlag.COMMENTS
    return flags


class ICURegex(BaseSUT):
    name = "icu_regex"

    def search(self, pattern: str, text: str, flags: int = 0) -> EngineMatch:
        try:
            pat = RegexPattern.compile(pattern, _icu_flags(flags))
            m = pat.matcher(text)

            # First match (like re.search)
            found = m.find()
            first_span: Optional[Tuple[int, int]] = None
            captures: Optional[List[Optional[str]]] = None
            if found:
                first_span = (m.start(), m.end())
                # Groups 1..groupCount (ICU returns UnicodeString; cast to str)
                n = m.groupCount()
                captures = [str(m.group(i)) if m.group(i) is not None else None
                            for i in range(1, n + 1)]

            # All spans (like list(rx.finditer))
            spans: List[Tuple[int, int]] = []
            m.reset(text)
            while m.find():
                s, e = m.start(), m.end()
                if (s, e) != (0, 0):          # mirror your zero-span filter
                    spans.append((s, e))

            longest_span = max(spans, key=lambda x: x[1] - x[0]) if spans else None

            return EngineMatch(
                matched=found,
                span=first_span,
                longest_span=longest_span,
                spans=spans,
                captures=captures,
                error=None,
            )

        except Exception as exc:
            return EngineMatch(
                matched=False,
                span=None,
                longest_span=None,
                spans=[],
                captures=None,
                error=f"{type(exc).__name__}: {exc}",
            )
