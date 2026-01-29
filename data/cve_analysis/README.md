# CVE Analysis Data

This directory contains data from our analysis of regex engine CVEs (RQ2, Section 5.2 of the paper).

## Overview

We collected and analyzed 156 CVEs (Common Vulnerabilities and Exposures) associated with regex engines from the NIST National Vulnerability Database (NVD), spanning the period 2005-2025.

## Files

| File | Description | Size |
|------|-------------|------|
| `regex_cve_report.xlsx` | Database of 156 CVEs | ~67 KB |

## Schema

### regex_cve_report.xlsx

| Column | Description | Type |
|--------|-------------|------|
| `CVE ID` | CVE identifier (e.g., CVE-2015-2325) | String |
| `Engine` | Affected regex engine | String |
| `CWE` | Common Weakness Enumeration | String |
| `Severity` | CVSS severity rating | Enum |
| `CVSS Score` | Numeric severity score | Float |
| `Year` | Year disclosed | Integer |
| `Description` | Brief vulnerability description | String |

### Severity Levels

| Value | Count | Percentage |
|-------|-------|------------|
| CRITICAL | 32 | 21% |
| HIGH | 45 | 29% |
| MEDIUM | 30 | 19% |
| LOW/NONE | 49 | 31% |

### CWE Categories

| Category | CWEs | Count | Percentage |
|----------|------|-------|------------|
| Memory Safety | CWE-119, 125, 787, 416, 190, 476, 122, 121, 120, 189, 415, 674 | 81 | 52% |
| ReDoS | CWE-1333, 400 | 27 | 17% |
| Code Injection | CWE-94 | 15 | 10% |
| Other | Various | 33 | 21% |

## CVE Distribution by Engine

| Engine | CVE Count | Notable |
|--------|-----------|---------|
| PCRE | 50 | 32% of all CVEs (11 critical) |
| PHP PCRE | 27 | PCRE bindings in PHP |
| Oniguruma | 18 | |
| PCRE2 | 12 | |
| Python re | 8 | |
| Hyperscan | 7 | |
| JavaScript | 6 | V8, SpiderMonkey |
| Ruby | 5 | |
| Java | 4 | |
| Other | 19 | |

*Note: 7 of 22 surveyed engines have zero reported CVEs.*

## Key Statistics (Paper Section 5.2)

- **Total CVEs**: 156 across 15 engines (2005-2025)
- **Critical/High severity**: 50% (77 CVEs)
- **Memory safety vulnerabilities**: 52% of all CVEs
- **ReDoS vulnerabilities**: 17% of all CVEs
- **PCRE alone**: 50 CVEs (32% of total)

## Memory Safety CWEs

The following CWEs are classified as memory safety vulnerabilities:

| CWE | Name | Count |
|-----|------|-------|
| CWE-119 | Buffer Errors | 15 |
| CWE-125 | Out-of-bounds Read | 12 |
| CWE-787 | Out-of-bounds Write | 11 |
| CWE-416 | Use After Free | 8 |
| CWE-190 | Integer Overflow | 7 |
| CWE-476 | NULL Pointer Dereference | 6 |
| CWE-122 | Heap Buffer Overflow | 5 |
| Other | Various memory issues | 17 |

## Data Collection Methodology

1. **Query NVD**: Used NIST NVD API to search for CVEs mentioning each of the 22 surveyed regex engines
2. **Manual Filtering**: Removed false positives (e.g., unrelated software with same name)
3. **Classification**: Categorized by CWE, severity, and engine

## Reproduction

To regenerate figures from this data:

```bash
python scripts/analysis/cve_analysis.py
```

This generates:
- `figures/cve_types_by_engine.pdf` - CVE types by engine (Figure 2)
- `figures/cves_by_engine.pdf` - CVE counts per engine
- `figures/cwe_categories.pdf` - CWE category breakdown
- `tables/cve_summary.tex` - LaTeX table

## Key Finding

The abundance of CVEs in PCRE and PCRE2 engines suggests that systematic testing of these and other widely-deployed libraries could yield significant security benefits. Memory safety is the dominant vulnerability class and should be a primary target of any testing approach.
