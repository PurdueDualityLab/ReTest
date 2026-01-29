import pcre

from re_fuzzer.sut.base_sut import BaseSUT
from re_fuzzer.sut.engine_match import EngineMatch

class PCRE(BaseSUT):
    name = "pcre"

    def search(self, pattern: str, text: str, flags: int = 0) -> EngineMatch:
        try:
            rx = pcre.compile(pattern, flags)
            m = rx.search(text) # type: ignore[attr-defined]
            spans = [mm.span() for mm in rx.finditer(text) if mm.span() != (0, 0)] # type: ignore[attr-defined]
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
