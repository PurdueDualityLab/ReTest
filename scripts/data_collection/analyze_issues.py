#!/usr/bin/env python3
"""
Classify GitHub issues via the OpenAI Batch API using an external system prompt (.md).

Input:
  - issues.ndjson  (one JSON per line; produced by your GitHub fetcher)

Outputs:
  - issues_batch.jsonl          (requests file uploaded to Batch API)
  - issues_batch_output.jsonl   (raw Batch API responses)
  - issues_classified.ndjson    (joined: issue_number + parsed classification JSON)

Usage:
  export OPENAI_API_KEY=sk-...
  python analyze_issues.py \
      --in issues.ndjson \
      --system-prompt-path system_prompt.md \
      --engine-name "PCRE2" \
      --engine-developer "PCRE2Project" \
      --model gpt-4.1-mini
"""

import argparse, json, os, sys, time
from pathlib import Path
from typing import Any, Dict, List, Optional
from openai import OpenAI

# -------- Structured Outputs JSON Schema (matches the spec you provided) --------
SCHEMA = {
    "type": "object",
    "properties": {
        "number": {"type": "string"},
        "is_real_bug": {"type": "boolean"},
        "is_fixed": {"type": "boolean"},
        "found_pointer": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "type": {"type": ["string", "null"], "enum": ["Version", "Commit Hash", "Pull Request Number", "Other", None]},
                    "value": {"type": ["string", "null"]}
                },
                "required": ["type", "value"],
                "additionalProperties": False
            }
        },
        "fixed_pointer": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "type": {"type": ["string", "null"], "enum": ["Version", "Commit Hash", "Pull Request Number", "Other", None]},
                    "value": {"type": ["string", "null"]}
                },
                "required": ["type", "value"],
                "additionalProperties": False
            }
        },
        "bug_kind": {
            "type": ["string", "null"],
            "enum": ["SEMANTIC", "CRASH", "DIFF", "PERF", "MEMORY", "DOC", "OTHER", None]
        },
        "how_found": {
            "type": ["string", "null"],
            "enum": ["FUZZING", "STATIC_ANALYSIS", "MANUAL_REVIEW", "DIFFERENTIAL_TESTING", "OTHER", None]
        },
        "reproduction_pattern_and_input": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "pattern": {"type": ["string", "null"]},
                    "input": {"type": ["string", "null"]}
                },
                "required": ["pattern", "input"],
                "additionalProperties": False
            }
        },
        "log": {"type": ["string", "null"]},
        "summary": {"type": "string"}
    },
    "required": [
        "number",
        "is_real_bug",
        "is_fixed",
        "found_pointer",
        "fixed_pointer",
        "bug_kind",
        "how_found",
        "reproduction_pattern_and_input",
        "log",
        "summary"
    ],
    "additionalProperties": False
}

def load_system_prompt(path: Path, engine_name: str, engine_developer: str) -> str:
    text = path.read_text(encoding="utf-8")
    text = text.replace("{{ENGINE_NAME}}", engine_name)
    text = text.replace("{{ENGINE_DEVELOPER}}", engine_developer)
    return text

def to_research_issue(obj: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convert harvested GitHub issue line into the exact JSON structure
    the system prompt expects:
      {
        "number": "...", "title": "...", "author": "...",
        "state": "...", "labels": ["..."], "description": "...",
        "comments": [{"author":"...","body":"..."}]
      }
    Handles both the enriched format from our earlier fetcher (obj["issue"], obj["comments"])
    and a already-normalized shape.
    """
    if "issue" in obj:
        i = obj["issue"] or {}
        number = i.get("number")
        title = i.get("title")
        author = (i.get("user") or {}).get("login") or i.get("author")
        state = i.get("state")
        labels = []
        raw_labels = i.get("labels") or []
        for L in raw_labels:
            if isinstance(L, dict) and "name" in L:
                labels.append(L["name"])
            elif isinstance(L, str):
                labels.append(L)
        description = i.get("body")
        comments_src = obj.get("comments") or []
        comments = []
        for c in comments_src:
            comments.append({
                "author": ((c.get("user") or {}).get("login")) or c.get("author"),
                "body": c.get("body")
            })
    else:
        number = obj.get("number")
        title = obj.get("title")
        author = obj.get("author")
        state = obj.get("state")
        labels = obj.get("labels") or []
        description = obj.get("description") or obj.get("body")
        comments = []
        for c in obj.get("comments", []):
            comments.append({"author": c.get("author"), "body": c.get("body")})

    # Coerce to strings where needed
    number = "" if number is None else str(number)
    title = "" if title is None else str(title)
    author = "" if author is None else str(author)
    description = "" if description is None else str(description)
    labels = [str(x) for x in labels]

    return {
        "number": number,
        "title": title,
        "author": author,
        "state": state,
        "labels": labels,
        "description": description,
        "comments": [{"author": str(c.get("author") or ""), "body": c.get("body") or ""} for c in comments]
    }

def to_batch_line(custom_id: str, model: str, system_prompt: str, issue_payload: Dict[str, Any]) -> Dict[str, Any]:
    if "gpt-5" in model:
        temperature = 1
    else:
        temperature = 0
    """
    Build one JSONL request line for the Batch API targeting /v1/chat/completions
    with Structured Outputs (strict JSON Schema).
    """
    return {
        "custom_id": custom_id,
        "method": "POST",
        "url": "/v1/chat/completions",
        "body": {
            "model": model,
            "temperature": temperature,
            "response_format": {
                "type": "json_schema",
                "json_schema": {"name": "RegexIssueClassification", "schema": SCHEMA, "strict": True}
            },
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": json.dumps(issue_payload, ensure_ascii=False)}
            ]
        }
    }

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="in_path", default="issues.ndjson")
    ap.add_argument("--system-prompt-path", required=True, help="Path to the Markdown file containing the system prompt")
    ap.add_argument("--engine-name", required=True)
    ap.add_argument("--engine-developer", required=True)
    ap.add_argument("--model", default="gpt-4.1-mini")
    ap.add_argument("--max", type=int, default=0, help="Limit number of requests for a dry run (0 = all)")
    args = ap.parse_args()

    in_path = Path(args.in_path)
    if not in_path.exists():
        print(f"Input not found: {in_path}", file=sys.stderr)
        sys.exit(2)

    system_prompt = load_system_prompt(Path(args.system_prompt_path), args.engine_name, args.engine_developer)

    # 1) Build the batch JSONL file
    batch_lines: List[Dict[str, Any]] = []
    count = 0
    with in_path.open() as fp:
        for line in fp:
            src = json.loads(line)
            issue_payload = to_research_issue(src)
            cid = f"{args.engine_developer}_{args.engine_name}_issue_{issue_payload['number']}"
            batch_lines.append(to_batch_line(cid, args.model, system_prompt, issue_payload))
            count += 1
            if args.max and count >= args.max:
                break

    batch_jsonl = Path(f"{args.engine_developer}_{args.engine_name}_batch.jsonl")
    with batch_jsonl.open("w", encoding="utf-8") as f:
        for item in batch_lines:
            f.write(json.dumps(item, ensure_ascii=False) + "\n")
    print(f"Wrote batch input: {batch_jsonl.resolve()} ({len(batch_lines)} requests)")

    # 2) Upload the batch file & 3) Create the batch job
    client = OpenAI()  # reads OPENAI_API_KEY
    uploaded = client.files.create(file=open(batch_jsonl, "rb"), purpose="batch")
    job = client.batches.create(
        input_file_id=uploaded.id,
        endpoint="/v1/chat/completions",
        completion_window="24h",
    )
    print(f"Batch created: {job.id}")

    # 4) Poll until done
    while True:
        job = client.batches.retrieve(job.id)
        if job.status in ("completed", "failed", "cancelled", "expired"):
            print(f"Final status: {job.status}")
            break
        print(f"Batch status: {job.status}")
        time.sleep(10)

    if job.status != "completed":
        sys.exit(1)

    # 5) Download results
    out_file_id = job.output_file_id
    raw = client.files.content(out_file_id).content
    batch_out = Path(f"{args.engine_developer}_{args.engine_name}_batch_output.jsonl")
    with batch_out.open("wb") as f:
        f.write(raw)
    print(f"Wrote raw results: {batch_out.resolve()}")

if __name__ == "__main__":
    main()
