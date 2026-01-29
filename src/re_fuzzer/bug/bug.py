from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
from enum import Enum
import hashlib
from typing import Any, Dict, Mapping, Optional

from re_fuzzer.oracle.base_oracle import Finding
from re_fuzzer.sut.engine_match import EngineMatch

class BugKind(str, Enum):
    METAMORPHIC = "METAMORPHIC"
    CRASH = "CRASH"
    DIFF = "DIFF"
    PERF = "PERF"


def _serialize_engine_match(m: EngineMatch) -> Dict[str, Any]:
    span = list(m.span) if m.span is not None else None
    longest_span = list(m.longest_span) if m.longest_span is not None else None
    spans = [list(s) for s in m.spans]

    captures: Optional[list[Optional[str]]] = None
    if m.captures is not None:
        captures = []
        for value in m.captures:
            if value is None:
                captures.append(None)
            else:
                captures.append(str(value))

    error = None if m.error is None else str(m.error)

    return {
        "matched": bool(m.matched),
        "span": span,
        "longest_span": longest_span,
        "spans": spans,
        "captures": captures,
        "error": error,
    }


def _stable_bug_id(
    *, sut: str, kind: BugKind, relation_id: str, pattern_after: str, text: str, message: str
) -> str:
    # Stable id across runs for the same underlying issue
    h = hashlib.sha1()
    payload = "\u241f".join([sut, kind.value, relation_id, pattern_after, text, message])
    h.update(payload.encode("utf-8", errors="replace"))
    return h.hexdigest()


@dataclass(slots=True)
class Bug:
    id: str
    sut: str
    kind: BugKind
    relation_id: str
    title: str
    message: str
    pattern_before: str
    pattern_after: str
    text: str
    flags: int
    base: Mapping[str, Any]
    variant: Mapping[str, Any]
    timestamp: str

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        # Ensure enum is serialized as string
        d["kind"] = self.kind.value
        return d


def bug_from_finding(*, sut_name: str, finding: Finding, flags: int, kind: BugKind = BugKind.METAMORPHIC) -> Bug:
    bug_id = _stable_bug_id(
        sut=sut_name,
        kind=kind,
        relation_id=finding.relation_id,
        pattern_after=finding.pattern_after,
        text=finding.text,
        message=finding.message,
    )
    return Bug(
        id=bug_id,
        sut=sut_name,
        kind=kind,
        relation_id=finding.relation_id,
        title=finding.title,
        message=finding.message,
        pattern_before=finding.pattern_before,
        pattern_after=finding.pattern_after,
        text=finding.text,
        flags=flags,
        base=_serialize_engine_match(finding.base),
        variant=_serialize_engine_match(finding.variant),
        timestamp=datetime.now().isoformat(timespec="seconds"),
    )
