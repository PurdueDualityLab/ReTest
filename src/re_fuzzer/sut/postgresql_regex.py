from __future__ import annotations

from collections import OrderedDict
from typing import Any, Tuple

import postgresql_regex

from re_fuzzer.sut.base_sut import BaseSUT
from re_fuzzer.sut.engine_match import EngineMatch
from re_fuzzer.instrumentation.regex_hook import hook_postgresql_regex


class PostgreSQLRegex(BaseSUT):
    name = "postgresql_regex"

    def __init__(self, cache_capacity: int = 1024, enable_regex_hook: bool = False) -> None:
        self._cache_capacity = cache_capacity
        self._compile_cache: OrderedDict[Tuple[str, int], Any] = OrderedDict()
        if enable_regex_hook:
            hook_postgresql_regex(postgresql_regex)

    def _get_compiled(self, pattern: str, flags: int):
        """Return a cached compiled regex, compiling with simple LRU eviction."""
        key = (pattern, flags)
        cached = self._compile_cache.get(key)
        if cached is not None:
            self._compile_cache.move_to_end(key)
            return cached

        compiled = postgresql_regex.compile(pattern, flags)
        self._compile_cache[key] = compiled
        if len(self._compile_cache) > self._cache_capacity:
            self._compile_cache.popitem(last=False)
        return compiled

    def search(self, pattern: str, text: str, flags: int = 0) -> EngineMatch:
        try:
            rx = self._get_compiled(pattern, flags)
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
