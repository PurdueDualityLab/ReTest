# ruby_re.py
from __future__ import annotations
from typing import List, Optional, Tuple
import re

import onigurumacffi
from re_fuzzer.sut.base_sut import BaseSUT
from re_fuzzer.sut.engine_match import EngineMatch

class RubyRE(BaseSUT):
    name = "ruby_re_onig"

    def _inject_inline_flags(self, pattern: str, flags: int) -> str:
        """Translate Python flags to Ruby/Onig inline options."""
        opts = []
        if flags & re.IGNORECASE: opts.append("i")
        if flags & re.MULTILINE:  opts.append("m")  # Ruby: ^/$ are line-based; 'm' makes . match \n
        if flags & re.DOTALL:     opts.append("s")  # singleline (dotall)
        if flags & re.VERBOSE:    opts.append("x")  # ignore whitespace/comments
        if not opts:
            return pattern
        return f"(?{''.join(opts)})" + pattern

    def search(self, pattern: str, text: str, flags: int = 0) -> EngineMatch:
        try:
            pat = onigurumacffi.compile(self._inject_inline_flags(pattern, flags))

            # 1) first match (Ruby's Regexp#match equivalent)
            m = pat.search(text)
            span: Optional[Tuple[int, int]] = m.span() if m else None
            captures: Optional[List[Optional[str]]] = None
            if m:
                # positional groups like Python's .groups()
                n = pat.number_of_captures()
                captures = [m.group(i) if m.group(i) is not None else None
                            for i in range(1, n + 1)]

            # 2) spans for ALL matches (like Python finditer)
            spans: List[Tuple[int, int]] = []
            pos = 0
            while True:
                mm = pat.search(text, start=pos)
                if not mm:
                    break
                s, e = mm.span()
                if (s, e) != (0, 0):
                    spans.append((s, e))
                # prevent infinite loop on zero-width matches
                pos = e if e > pos else pos + 1
                if pos > len(text):
                    break

            longest_span = max(spans, key=lambda x: x[1] - x[0]) if spans else None
            return EngineMatch(
                matched=m is not None,
                span=span,
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
