from __future__ import annotations

from typing import Protocol

from re_fuzzer.sut.engine_match import EngineMatch


class BaseSUT(Protocol):
    name: str

    def search(self, pattern: str, text: str, flags: int = 0) -> EngineMatch:
        ...


