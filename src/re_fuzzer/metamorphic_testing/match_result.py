from dataclasses import asdict, dataclass
from typing import Optional, Tuple, List, Dict, Any

@dataclass
class MatchResult:
    matched: Optional[bool]
    span: Optional[Tuple[int, int]]               # first/primary match span
    longest_span: Optional[Tuple[int, int]]        # longest overall span among matches
    spans: List[Tuple[int, int]]                  # all non-overlapping matches
    captures: Optional[Dict[str, Any]]            # capture groups by name or index
    error: Optional[str]
    time_ms: Optional[float]                      # time taken to match in milliseconds

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["span"] = list(d["span"]) if d["span"] is not None else None
        d["longest_span"] = list(d["longest_span"]) if d["longest_span"] is not None else None
        d["spans"] = [list(t) for t in d["spans"]]
        return d
