from __future__ import annotations

import stdrx

from re_fuzzer.sut.base_sut import BaseSUT
from re_fuzzer.sut.engine_match import EngineMatch


class StdRegex(BaseSUT):
    name = "std_regex"

    def search(self, pattern: str, text: str, flags: int = 0) -> EngineMatch:
        try:
            rx = stdrx.compile(pattern, flags)
            m = rx.search(text)
            spans = [mm.span() for mm in rx.finditer(text) if mm.span() != (0, 0)]
            captures = list(m.groups()) if m else None
            longest_span = max(spans, key=lambda x: x[1] - x[0]) if spans else None
            return EngineMatch(
                matched=m is not None,
                span=m.span() if m else None,
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
