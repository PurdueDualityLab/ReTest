# spidermonkey_re.py
from __future__ import annotations

import re
from typing import Optional, List, Tuple

import pythonmonkey as pm
from re_fuzzer.sut.base_sut import BaseSUT
from re_fuzzer.sut.engine_match import EngineMatch


class SpiderMonkeyRE(BaseSUT):
    """
    JS/SpiderMonkey-backed equivalent of PythonRE.search(), via PythonMonkey.
    - Supports flags: IGNORECASE -> 'i', MULTILINE -> 'm', DOTALL -> 's'
    - Always adds 'd' to enable match indices for spans (JS RegExp Match Indices)
    - Collects spans for all matches (like Python's finditer)
    Notes:
      * Python's re.VERBOSE / re.ASCII semantics don't have a 1:1 mapping in JS.
      * If your pattern uses features JS doesn't support, the JS engine will raise;
        that error text is returned in EngineMatch.error.
    """

    name = "spidermonkey"

    def __init__(self) -> None:
        # One JS function handles compile + search + enumerate spans.
        # We use /gd so we can harvest spans via m.indices for every match.
        self._runner = pm.eval(r"""
        (pattern, text, flags) => {
          // Normalize flags: ensure 'g' and 'd' present for enumeration/indices
          const need = (s, ch) => s.includes(ch) ? s : (s + ch);
          let allFlags = flags || "";
          allFlags = need(allFlags, "g");
          allFlags = need(allFlags, "d"); // match indices

          const reAll = new RegExp(pattern, allFlags);

          // Collect all matches (with indices)
          const matches = Array.from(text.matchAll(reAll));

          const result = {
            matched: matches.length > 0,
            span: null,
            spans: [],
            captures: null,
            error: null
          };

          if (matches.length > 0) {
            const first = matches[0];
            // span for the whole first match
            if (first.indices && first.indices[0]) {
              result.span = [first.indices[0][0], first.indices[0][1]];
            }
            // captures from the first match (positional, like Python)
            const capCount = Math.max(0, first.length - 1);
            result.captures = [];
            for (let i = 1; i <= capCount; i++) {
              // undefined becomes null when crossing to Python (nice parity with Python's None)
              result.captures.push(first[i] === undefined ? null : first[i]);
            }
          }

          // spans for *all* matches
          for (const m of matches) {
            if (m.indices && m.indices[0]) {
              result.spans.push([m.indices[0][0], m.indices[0][1]]);
            }
          }

          return result;
        }
        """)

    @staticmethod
    def _py_flags_to_js(flags: int) -> str:
        """
        Map Python's re flags to JS RegExp flags.
        Only those with reasonably equivalent JS semantics are mapped.
        """
        js = []
        if flags & re.IGNORECASE:
            js.append("i")
        if flags & re.MULTILINE:
            js.append("m")
        if flags & re.DOTALL:
            js.append("s")

        # Python's VERBOSE and ASCII (and others) have no direct JS flag.
        # If you *must* emulate VERBOSE, pre-strip whitespace/comments before calling search().
        # If you *must* emulate ASCII classes, consider adjusting your pattern (e.g., avoid \w).
        return "".join(js)

    def search(self, pattern: str, text: str, flags: int = 0) -> EngineMatch:
        try:
            js_flags = self._py_flags_to_js(flags)
            out = self._runner(pattern, text, js_flags)

            # out is a plain dict (auto-converted from JS object)
            matched = bool(out.get("matched"))

            span: Optional[Tuple[int, int]] = None
            span_raw = out.get("span")
            if isinstance(span_raw, (list, tuple)) and len(span_raw) == 2:
                span = (int(span_raw[0]), int(span_raw[1]))

            spans: List[Tuple[int, int]] = []
            spans_raw = out.get("spans")
            if isinstance(spans_raw, (list, tuple)):
                for entry in spans_raw:
                    if isinstance(entry, (list, tuple)) and len(entry) == 2:
                        a, b = int(entry[0]), int(entry[1])
                        if (a, b) != (0, 0):
                            spans.append((a, b))

            captures: Optional[List[Optional[str]]] = None
            captures_raw = out.get("captures")
            if isinstance(captures_raw, (list, tuple)):
                captures = [None if value is None else str(value) for value in captures_raw]

            longest_span = max(spans, key=lambda x: x[1] - x[0]) if spans else None

            return EngineMatch(
                matched=matched,
                span=span,
                longest_span=longest_span,
                spans=spans,
                captures=captures,
                error=None,
            )
        except Exception as exc:
            # Surface JS syntax/runtime errors, or any bridge issues
            return EngineMatch(
                matched=False,
                span=None,
                longest_span=None,
                spans=[],
                captures=None,
                error=f"{type(exc).__name__}: {exc}",
            )
