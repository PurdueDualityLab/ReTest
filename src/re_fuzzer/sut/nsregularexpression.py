from __future__ import annotations

from Foundation import (
    NSRegularExpression, # type: ignore[attr-defined]
    NSRegularExpressionCaseInsensitive, # type: ignore[attr-defined]
    NSRegularExpressionDotMatchesLineSeparators, # type: ignore[attr-defined]
    NSRegularExpressionAnchorsMatchLines, # type: ignore[attr-defined]
    NSRegularExpressionAllowCommentsAndWhitespace, # type: ignore[attr-defined]
    NSRegularExpressionUseUnicodeWordBoundaries, # type: ignore[attr-defined]
    NSMakeRange, # type: ignore[attr-defined]
    NSNotFound, # type: ignore[attr-defined]
)
import re  # only to read Python's flag bits; not used for matching

from re_fuzzer.sut.base_sut import BaseSUT
from re_fuzzer.sut.engine_match import EngineMatch


def _ns_options_from_re_flags(flags: int) -> int:
    """
    Map a subset of Python's re flags to NSRegularExpression options.

    Python -> NSRegularExpression:
      - re.IGNORECASE           -> NSRegularExpressionCaseInsensitive
      - re.DOTALL               -> NSRegularExpressionDotMatchesLineSeparators
      - re.MULTILINE            -> NSRegularExpressionAnchorsMatchLines
      - re.VERBOSE              -> NSRegularExpressionAllowCommentsAndWhitespace
    Extras:
      - NSRegularExpressionUseUnicodeWordBoundaries to get better \\b in Unicode contexts.
    """
    opts = 0
    if flags & re.IGNORECASE:
        opts |= NSRegularExpressionCaseInsensitive
    if flags & re.DOTALL:
        opts |= NSRegularExpressionDotMatchesLineSeparators
    if flags & re.MULTILINE:
        opts |= NSRegularExpressionAnchorsMatchLines
    if flags & re.VERBOSE:
        opts |= NSRegularExpressionAllowCommentsAndWhitespace

    # Python's re is Unicode-aware by default; this helps \b behave more like Python's.
    # opts |= NSRegularExpressionUseUnicodeWordBoundaries

    return opts


def _nsrange_to_slice_tuple(nsrange):
    """Convert an NSRange to a Python (start, end) tuple."""
    if nsrange.location == NSNotFound or nsrange.length == NSNotFound:
        return None
    start = int(nsrange.location)
    end = start + int(nsrange.length)
    return (start, end)


def _capture_list(text: str, match_obj, rx) -> list[str | None]:
    """
    Build a Python-style captures list from the first match:
    groups 1..N, with None for unmatched optional groups.
    """
    n_groups = int(rx.numberOfCaptureGroups())
    caps: list[str | None] = []
    for i in range(1, n_groups + 1):
        r = match_obj.rangeAtIndex_(i)
        tpl = _nsrange_to_slice_tuple(r)
        if tpl is None:
            caps.append(None)
        else:
            s, e = tpl
            caps.append(text[s:e])
    return caps


class NSRegularExpression(BaseSUT):
    name = "nsregular_expression"

    def search(self, pattern: str, text: str, flags: int = 0) -> EngineMatch:
        try:
            opts = _ns_options_from_re_flags(flags)

            # Compile
            # Using the designated initializer: regularExpressionWithPattern:options:error:
            rx = NSRegularExpression.regularExpressionWithPattern_options_error_( # type: ignore
                pattern, opts, None
            )

            full_range = NSMakeRange(0, len(text))

            # First match (≈ re.search)
            first = rx.firstMatchInString_options_range_(text, 0, full_range)

            # All matches (≈ re.finditer)
            all_matches = rx.matchesInString_options_range_(text, 0, full_range)

            # Spans list like [(start, end), ...] excluding (0, 0)
            spans = []
            for m in all_matches:
                r = _nsrange_to_slice_tuple(m.range())
                if r and r != (0, 0):
                    spans.append(r)

            # Captures from the first match (Python-style: list or None)
            captures = _capture_list(text, first, rx) if first is not None else None

            # Longest span by width
            longest_span = max(spans, key=lambda x: x[1] - x[0]) if spans else None

            return EngineMatch(
                matched=first is not None,
                span=_nsrange_to_slice_tuple(first.range()) if first is not None else None,
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
