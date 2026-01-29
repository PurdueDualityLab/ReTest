from __future__ import annotations

import re
import hyperscan

from re_fuzzer.sut.base_sut import BaseSUT
from re_fuzzer.sut.engine_match import EngineMatch


def _map_re_flags_to_hyperscan(flags: int) -> int:
    """Translate a subset of Python `re` flags to Hyperscan flags."""
    hs_flags = hyperscan.HS_FLAG_SOM_LEFTMOST  # to get accurate start offsets
    if flags & re.IGNORECASE:
        hs_flags |= hyperscan.HS_FLAG_CASELESS
    if flags & re.DOTALL:
        hs_flags |= hyperscan.HS_FLAG_DOTALL
    if flags & re.MULTILINE:
        hs_flags |= hyperscan.HS_FLAG_MULTILINE
    # add more...
    return hs_flags


class Hyperscan(BaseSUT):
    name = "hyperscan"

    def search(self, pattern: str, text: str, flags: int = 0) -> EngineMatch:
        try:
            # Hyperscan requires bytes patterns and bytes input
            expr = pattern.encode("utf-8", errors="surrogatepass")
            data = text.encode("utf-8", errors="surrogatepass")

            db = hyperscan.Database()
            hs_flags = _map_re_flags_to_hyperscan(flags)

            # Compile a single expression with id=0
            db.compile(
                expressions=[expr],
                flags=[hs_flags],
                ids=[0],
            )

            scratch = hyperscan.Scratch(db)

            spans: list[tuple[int, int]] = []

            def on_match(_id: int, start: int, end: int, _flags: int, _ctx):
                # start/end are byte offsets; they align with Python slice indices
                if (start, end) != (0, 0):
                    spans.append((start, end))
                # Return None to continue scanning (collect all matches)
                return None

            db.scan(
                data,
                match_event_handler=on_match,
                scratch=scratch,
            )

            # Derive results similar to `re`
            if spans:
                # First match: leftmost (then earliest end)
                first_span = min(spans, key=lambda s: (s[0], s[1]))
                longest_span = max(spans, key=lambda s: (s[1] - s[0]))
                matched = True
            else:
                first_span = None
                longest_span = None
                matched = False

            # Hyperscan doesn't provide capture groups
            captures = None

            return EngineMatch(
                matched=matched,
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
