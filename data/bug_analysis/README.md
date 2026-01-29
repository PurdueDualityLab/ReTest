# Bug Analysis Data

This directory contains data from our analysis of regex engine bugs (RQ2, Section 5.1 of the paper).

## Overview

We conducted a systematic review of issues from 11 third-party regex engine implementations, analyzing 2,342 issue reports and classifying 1,007 as confirmed bugs.

## Files

| File | Description | Size |
|------|-------------|------|
| `regex_bug_db.xlsx` | Database of 1,007 classified bugs | ~674 KB |
| `bug_analysis_summary.csv` | Summary statistics by engine | ~1.4 KB |
| `issues/raw/` | Raw GitHub issues in NDJSON format | ~145 MB |
| `issues/analyzed/` | LLM-classified bug reports (JSONL) | ~52 MB |

## Schema

### regex_bug_db.xlsx

| Column | Description | Type |
|--------|-------------|------|
| `number` | GitHub issue number | Integer |
| `engine` | Engine identifier (e.g., `google_re2`, `PCRE2Project_PCRE2`) | String |
| `is_real_bug` | Whether the issue is a confirmed defect | Boolean |
| `bug_kind` | Bug type classification | Enum (see below) |
| `how_found` | Discovery method | Enum (see below) |
| `is_fixed` | Whether the bug has been resolved | Boolean |
| `found_pointer` | Version/commit where bug was found | String |
| `fixed_pointer` | Version/commit where bug was fixed | String |
| `reproduction_pattern` | Regex pattern to reproduce the bug | String |
| `reproduction_input` | Input string to reproduce the bug | String |
| `summary` | Brief description of the bug | String |

### Bug Kinds

| Value | Description |
|-------|-------------|
| `SEMANTIC` | Incorrect match results |
| `CRASH` | Abnormal termination (panics, segfaults) |
| `MEMORY` | Memory leaks, buffer errors |
| `PERF` | Catastrophic backtracking, timeouts |
| `DOC` | Documentation errors |
| `OTHER` | Confirmed bugs not fitting other categories |

### Discovery Methods

| Value | Description |
|-------|-------------|
| `MANUAL_REVIEW` | User-reported (82% of bugs) |
| `FUZZING` | Discovered via fuzzing (6%) |
| `DIFFERENTIAL_TESTING` | Cross-engine comparison (5%) |
| `STATIC_ANALYSIS` | Code analysis tools |
| `OTHER` | Other methods |

## Target Engines

| Engine Key | Display Name | Issues | Bugs | Bug Rate |
|------------|--------------|--------|------|----------|
| `google_re2` | RE2 | 539 | 199 | 36.9% |
| `intel_hyperscan` | Hyperscan | 358 | 157 | 43.9% |
| `PCRE2Project_PCRE2` | PCRE2 | 340 | 147 | 43.2% |
| `kkos_oniguruma` | Oniguruma | 388 | 230 | 59.3% |
| `kokke_tiny-regex-c` | tiny-regex-c | 126 | 59 | 46.8% |
| `dlclark_regexp2` | regexp2 | 139 | 62 | 44.6% |
| `laurikari_tre` | TRE | 77 | 23 | 29.9% |
| `k-takata_Onigmo` | Onigmo | 110 | 37 | 33.6% |
| `openresty_sregex` | sregex | 23 | 2 | 8.7% |
| `mrabarnett_mrab-regex` | mrab-regex | 569 | 302 | 53.1% |
| `fancy-regex_fancy-regex` | fancy-regex | 121 | 52 | 43.0% |

## Key Statistics (Paper Section 5.1)

- **Total issues analyzed**: 2,342
- **Confirmed bugs**: 1,007 (43.0%)
- **Bug types**:
  - Semantic: 35.3% (355 bugs)
  - Crash: 14.3% (144 bugs)
  - Memory: 11.4% (115 bugs)
  - Other: 26.8%
  - Performance: 6.5%
  - Documentation: 5.8%
- **Discovery methods**:
  - Manual review (user-reported): 82.1%
  - Fuzzing: 6.3%
  - Differential testing: 5.4%
- **Fix rate**: 55.5% of bugs subsequently fixed

## Data Collection Methodology

1. **Issue Collection**: Used GitHub API to fetch all issues from target repositories
2. **Classification**: Used OpenAI's `gpt-5.1-mini` model with a structured prompt (see `../llm_prompt/`)
3. **Validation**: Manual verification of classification schema conformance

## Reproduction

To regenerate figures from this data:

```bash
python scripts/analysis/regexbugbench_analysis.py
```

This generates:
- `figures/bug_types_by_engine.pdf` - Bug type distribution (Figure 1)
- `figures/discovery_methods.pdf` - Discovery method distribution
- `tables/bug_summary.tex` - LaTeX table
