from dataclasses import dataclass
from typing import List, Optional, Tuple

@dataclass(slots=True)
class EngineMatch:
    matched: bool
    span: Optional[Tuple[int, int]]
    longest_span: Optional[Tuple[int, int]]
    spans: List[Tuple[int, int]]
    captures: Optional[List[Optional[str]]]
    error: Optional[str]
