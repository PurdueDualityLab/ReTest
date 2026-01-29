#!/usr/bin/env python3
"""
Archive issues and comments from a GitHub repository into NDJSON.

For each issue:
- issue JSON
- issue reactions
- issue comments (+ reactions on each comment)
- issue events
- issue timeline items

Usage:
  python issues_archive.py --owner OWNER --repo REPO --token $GITHUB_TOKEN --out issues.ndjson
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone
from typing import Dict, Iterable, List, Optional, Tuple
import requests

API = "https://api.github.com"
API_VERSION = "2022-11-28"

def make_session(token: str) -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": API_VERSION,
        "User-Agent": "issues-archiver/1.0"
    })
    return s

def parse_link_header(link_header: Optional[str]) -> Dict[str, str]:
    """Parse GitHub-style Link header into a dict of rel -> url."""
    if not link_header:
        return {}
    parts = link_header.split(",")
    out = {}
    for p in parts:
        segs = p.strip().split(";")
        if len(segs) < 2:
            continue
        url = segs[0].strip()[1:-1]  # <url>
        rel = None
        for s in segs[1:]:
            s = s.strip()
            if s.startswith('rel='):
                rel = s.split("=")[1].strip('"\'')
        if rel:
            out[rel] = url
    return out

def gh_request(session: requests.Session, method: str, url: str, **kwargs) -> requests.Response:
    """Single request with basic rate-limit/backoff handling."""
    while True:
        resp = session.request(method, url, timeout=60, **kwargs)
        # Handle rate limit (403 with remaining == 0)
        remaining = resp.headers.get("X-RateLimit-Remaining")
        reset = resp.headers.get("X-RateLimit-Reset")
        if resp.status_code == 403 and remaining == "0" and reset:
            sleep_for = max(0, int(reset) - int(time.time())) + 2
            time.sleep(sleep_for)
            continue
        # Handle abuse/secondary limit (usually 429 or 403 w/o remaining change)
        if resp.status_code in (429,) or (resp.status_code == 403 and "secondary" in resp.text.lower()):
            time.sleep(5)
            continue
        if resp.ok:
            return resp
        # Surface other errors
        try:
            err = resp.json()
        except Exception:
            err = resp.text
        raise RuntimeError(f"GitHub API error {resp.status_code} on {url}: {err}")

def gh_paginate(session: requests.Session, url: str, params: Optional[Dict] = None) -> Iterable[Dict]:
    """Yield JSON items across all pages for a list endpoint."""
    params = dict(params or {})
    params.setdefault("per_page", 100)
    while url:
        resp = gh_request(session, "GET", url, params=params)
        data = resp.json()
        if isinstance(data, list):
            for item in data:
                yield item
        else:
            # Some endpoints return dict with 'items' key, but not used here.
            for item in data.get("items", []):
                yield item
        link = parse_link_header(resp.headers.get("Link"))
        url = link.get("next")
        params = None  # params already encoded in 'next' URL

def list_all_issues(session: requests.Session, owner: str, repo: str) -> Iterable[Dict]:
    """List all issues (state=all), excluding PRs."""
    url = f"{API}/repos/{owner}/{repo}/issues"
    params = {"state": "all", "per_page": 100, "sort": "created", "direction": "asc"}
    for issue in gh_paginate(session, url, params):
        # Skip pull requests; issues list returns both.
        if "pull_request" in issue:
            continue
        yield issue

def list_issue_comments(session: requests.Session, owner: str, repo: str, number: int) -> List[Dict]:
    url = f"{API}/repos/{owner}/{repo}/issues/{number}/comments"
    return list(gh_paginate(session, url))

def list_issue_reactions(session: requests.Session, owner: str, repo: str, number: int) -> List[Dict]:
    url = f"{API}/repos/{owner}/{repo}/issues/{number}/reactions"
    return list(gh_paginate(session, url))

def list_comment_reactions(session: requests.Session, owner: str, repo: str, comment_id: int) -> List[Dict]:
    url = f"{API}/repos/{owner}/{repo}/issues/comments/{comment_id}/reactions"
    return list(gh_paginate(session, url))

def list_issue_events(session: requests.Session, owner: str, repo: str, number: int) -> List[Dict]:
    url = f"{API}/repos/{owner}/{repo}/issues/{number}/events"
    return list(gh_paginate(session, url))

def list_issue_timeline(session: requests.Session, owner: str, repo: str, number: int) -> List[Dict]:
    url = f"{API}/repos/{owner}/{repo}/issues/{number}/timeline"
    return list(gh_paginate(session, url))

def enrich_issue(session: requests.Session, owner: str, repo: str, issue: Dict) -> Dict:
    number = issue["number"]

    # Comments (with reactions)
    comments = list_issue_comments(session, owner, repo, number)
    for c in comments:
        try:
            c["reactions_full"] = list_comment_reactions(session, owner, repo, c["id"])
        except Exception as e:
            c["reactions_full_error"] = str(e)

    # Issue-level reactions, events, timeline
    try:
        reactions = list_issue_reactions(session, owner, repo, number)
    except Exception as e:
        reactions = []
        reactions_error = str(e)
    else:
        reactions_error = None

    try:
        events = list_issue_events(session, owner, repo, number)
    except Exception as e:
        events = []
        events_error = str(e)
    else:
        events_error = None

    try:
        timeline = list_issue_timeline(session, owner, repo, number)
    except Exception as e:
        timeline = []
        timeline_error = str(e)
    else:
        timeline_error = None

    archived = {
        "issue": issue,
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "comments": comments,
        "reactions": reactions,
        "events": events,
        "timeline": timeline,
        "errors": {
            "reactions": reactions_error,
            "events": events_error,
            "timeline": timeline_error
        }
    }
    return archived

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--owner", required=True)
    ap.add_argument("--repo", required=True)
    ap.add_argument("--token", default=os.getenv("GITHUB_TOKEN"), help="GitHub token (env:GITHUB_TOKEN)")
    ap.add_argument("--out", default="issues.ndjson")
    ap.add_argument("--max", type=int, default=0, help="Stop after N issues (for testing). 0 = no limit")
    args = ap.parse_args()

    if not args.token:
        print("Error: provide a token via --token or GITHUB_TOKEN env.", file=sys.stderr)
        sys.exit(2)

    session = make_session(args.token)
    count = 0
    with open(args.out, "w", encoding="utf-8") as fp:
        for issue in list_all_issues(session, args.owner, args.repo):
            archived = enrich_issue(session, args.owner, args.repo, issue)
            fp.write(json.dumps(archived, ensure_ascii=False) + "\n")
            count += 1
            if args.max and count >= args.max:
                break
            if count % 25 == 0:
                print(f"Archived {count} issues...", file=sys.stderr)

    print(f"Done. Wrote {count} issues to {args.out}")

if __name__ == "__main__":
    main()
