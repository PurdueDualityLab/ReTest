# ReTest: Systematic Testing of Regular Expression Engines

This repository contains the artifact for the paper **Towards the Systematic Testing of Regular Expression Engines** by Berk Çakar, Dongyoon Lee, and James C. Davis:
## Abstract

ReTest is a work-in-progress systematic testing framework for regex engines that combines grammar-aware fuzzing with metamorphic testing. Current testing practices for regex engines are largely ad hoc: 82% of bugs are user-reported, and existing approaches lack a dialect-independent semantic oracle. ReTest addresses these gaps by:

1. **Grammar-aware fuzzing** that generates syntactically valid regex patterns via AST-based subtree mutations
2. **Metamorphic testing** using algebraic relations from Kleene algebra as dialect-independent oracles

**Key Results:**
- Survey of testing practices across 22 regex engines
- Analysis of 1,007 bugs and 156 CVEs in regex engines
- 16 metamorphic relations for dialect-independent semantic oracles
- 3× higher coverage than existing fuzzing approaches on PCRE
- 3 new memory safety bugs discovered in PCRE 8.45

## Repository Structure

```
ReTest-artifact-jaws/
├── README.md                   # This file
├── pyproject.toml              # Python dependencies
│
├── src/re_fuzzer/              # Core framework source code
│   ├── fuzzing/                # Grammar-aware fuzzing engine
│   ├── metamorphic_testing/    # 16 Kleene algebra metamorphic relations
│   ├── transformations/        # MR pattern transformers
│   ├── sut/                    # 12+ regex engine adapters (PCRE, RE2, etc.)
│   ├── input_generator/        # Pattern and string generators
│   ├── analysis/               # Analysis scripts
│   ├── experiments/            # Experiment framework
│   ├── bug/                    # Bug classification
│   └── run_fuzzer.py           # Main entry point
│
├── scripts/                    # Utility scripts
│   ├── data_collection/        # GitHub issues & CVE collection
│   └── analysis/               # Figure and table generation
│
├── data/                       # Datasets
│   ├── bug_analysis/           # 1,007 bugs across 11 engines
│   ├── cve_analysis/           # 156 CVEs across 15 engines
│   └── llm_prompt/             # LLM classification prompt
│
├── bugs_found/                 # Bugs found in PCRE 8.45
├── figures/                    # Paper figures (PDF + PNG)
├── tables/                     # Paper tables (LaTeX)
```

## Requirements

- **Python**: 3.11 or higher (< 3.13.1)
- **Dependencies**: Listed in `pyproject.toml`

### Installation

```bash
# Using Poetry (recommended)
poetry install

# Or using pip
pip install -e .
```

**Note**: Some regex engine bindings (PCRE, Hyperscan, Oniguruma) require native libraries to be installed. See the individual engine documentation in `src/re_fuzzer/sut/` for details.

## Quick Start

### Running the Fuzzer

```bash
# View available options
python -m re_fuzzer.run_fuzzer --help

# Run fuzzing with default settings
python -m re_fuzzer.run_fuzzer --seed-file seeds.txt -- -max_total_time=3600
```

## Data Documentation

| Directory | Description | README |
|-----------|-------------|--------|
| `data/bug_analysis/` | 1,007 bugs across 11 third-party regex engines | [README](data/bug_analysis/README.md) |
| `data/cve_analysis/` | 156 CVEs across 15 regex engines (2005-2025) | [README](data/cve_analysis/README.md) |
| `figures/` | All paper figures | [README](figures/README.md) |
| `tables/` | LaTeX tables | [README](tables/README.md) |

## Paper-to-Artifact Cross-Reference

The following table maps claims in the paper that reference this artifact to their locations:

| Paper Reference | Artifact Location |
|-----------------|-------------------|
| "The system prompt we used for classifying regex engine issue reports is available in our artifact" (Section 5.1) | [`data/llm_prompt/issues_bug_search_prompt.md`](data/llm_prompt/issues_bug_search_prompt.md) |
| "Detailed per-engine statistics are available in our artifact" (Section 5.1) | [`data/bug_analysis/regex_bug_db.xlsx`](data/bug_analysis/regex_bug_db.xlsx) and [`data/bug_analysis/bug_analysis_summary.csv`](data/bug_analysis/bug_analysis_summary.csv) |
| "Detailed analysis is available in our artifact" (Section 7, RQ3c) | [`bugs_found/pcre_bug_reports.md`](bugs_found/pcre_bug_reports.md) |
