#!/usr/bin/env python3
"""
Analysis script for regex engine bug review - ICSE paper.

Analyzes GitHub issues from 11 third-party regex engines and generates:
- Publication-quality figures (PDF)
- LaTeX tables
- Summary statistics for paper prose

Usage:
    python src/re_fuzzer/analysis/regexbugbench_analysis.py
"""

import json
import os
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

# Configure matplotlib for publication quality
plt.rcParams.update({
    'font.family': 'serif',
    'font.size': 9,
    'axes.labelsize': 9,
    'axes.titlesize': 10,
    'xtick.labelsize': 8,
    'ytick.labelsize': 8,
    'legend.fontsize': 8,
    'figure.dpi': 300,
    'savefig.dpi': 300,
    'savefig.bbox': 'tight',
    'savefig.pad_inches': 0.05,
})

# Target engines (11 third-party GitHub engines)
TARGET_ENGINES = {
    'google_re2': 'RE2',
    'intel_hyperscan': 'Hyperscan',
    'PCRE2Project_PCRE2': 'PCRE2',
    'kkos_oniguruma': 'Oniguruma',
    'kokke_tiny-regex-c': 'tiny-regex-c',
    'dlclark_regexp2': 'regexp2',
    'laurikari_tre': 'TRE',
    'k-takata_Onigmo': 'Onigmo',
    'openresty_sregex': 'sregex',
    'mrabarnett_mrab-regex': 'mrab-regex',
    'fancy-regex_fancy-regex': 'fancy-regex',
}

# Bug kind display order and colors (colorblind-friendly palette)
# Note: DIFF bugs are merged into SEMANTIC for analysis
BUG_KINDS = ['SEMANTIC', 'CRASH', 'MEMORY', 'PERF', 'DOC', 'OTHER']
BUG_KIND_COLORS = {
    'SEMANTIC': '#0077BB',   # Blue
    'CRASH': '#CC3311',      # Red
    'MEMORY': '#EE7733',     # Orange
    'PERF': '#009988',       # Teal
    'DOC': '#BBBBBB',        # Gray
    'OTHER': '#33BBEE',      # Cyan
}

# Discovery methods
DISCOVERY_METHODS = ['MANUAL_REVIEW', 'FUZZING', 'DIFFERENTIAL_TESTING', 'STATIC_ANALYSIS', 'OTHER']
DISCOVERY_COLORS = {
    'MANUAL_REVIEW': '#4477AA',
    'FUZZING': '#EE6677',
    'DIFFERENTIAL_TESTING': '#228833',
    'STATIC_ANALYSIS': '#CCBB44',
    'OTHER': '#AA3377',
}


def get_project_root() -> Path:
    """Get the project root directory."""
    return Path(__file__).parent.parent.parent.parent


def load_analyzed_issues(data_dir: Path) -> dict[str, list[dict[str, Any]]]:
    """Load analyzed issues from NDJSON files for target engines."""
    analyzed_dir = data_dir / 'issues' / 'analyzed'
    engine_bugs = {}

    for file_path in analyzed_dir.glob('*_batch_output.jsonl'):
        # Extract engine key from filename (e.g., "google_re2_batch_output.jsonl")
        engine_key = file_path.stem.replace('_batch_output', '')

        if engine_key not in TARGET_ENGINES:
            continue

        bugs = []
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                try:
                    obj = json.loads(line)
                    content_str = obj['response']['body']['choices'][0]['message']['content']
                    parsed = json.loads(content_str)
                    bugs.append(parsed)
                except (KeyError, IndexError, json.JSONDecodeError):
                    continue

        engine_bugs[engine_key] = bugs

    return engine_bugs


def load_raw_issue_counts(data_dir: Path) -> dict[str, int]:
    """Count raw issues per engine from NDJSON files."""
    raw_dir = data_dir / 'issues' / 'raw'
    counts = {}

    # Build case-insensitive lookup for TARGET_ENGINES
    target_lower = {k.lower(): k for k in TARGET_ENGINES}

    for file_path in raw_dir.glob('*_issues.ndjson'):
        engine_key = file_path.stem.replace('_issues', '')

        # Try exact match first, then case-insensitive
        if engine_key in TARGET_ENGINES:
            canonical_key = engine_key
        elif engine_key.lower() in target_lower:
            canonical_key = target_lower[engine_key.lower()]
        else:
            continue

        count = sum(1 for _ in open(file_path, 'r', encoding='utf-8'))
        counts[canonical_key] = count

    return counts


def compute_statistics(engine_bugs: dict[str, list], raw_counts: dict[str, int]) -> pd.DataFrame:
    """Compute per-engine statistics."""
    rows = []

    for engine_key, display_name in TARGET_ENGINES.items():
        bugs = engine_bugs.get(engine_key, [])
        raw_count = raw_counts.get(engine_key, 0)

        real_bugs = [b for b in bugs if b.get('is_real_bug', False)]
        fixed_bugs = [b for b in real_bugs if b.get('is_fixed', False)]

        # Count bug kinds (merge DIFF into SEMANTIC)
        bug_kinds = Counter()
        for b in real_bugs:
            kind = b.get('bug_kind')
            if kind == 'DIFF':
                kind = 'SEMANTIC'  # Merge DIFF into SEMANTIC
            bug_kinds[kind] += 1
        discovery_methods = Counter(b.get('how_found') for b in real_bugs)

        # Find top bug kind
        top_kind = bug_kinds.most_common(1)[0][0] if bug_kinds else 'N/A'

        rows.append({
            'engine_key': engine_key,
            'engine': display_name,
            'total_issues': raw_count,
            'real_bugs': len(real_bugs),
            'bug_rate': len(real_bugs) / raw_count * 100 if raw_count > 0 else 0,
            'fixed': len(fixed_bugs),
            'fix_rate': len(fixed_bugs) / len(real_bugs) * 100 if real_bugs else 0,
            'top_bug_kind': top_kind,
            **{f'kind_{k}': bug_kinds.get(k, 0) for k in BUG_KINDS},
            **{f'method_{m}': discovery_methods.get(m, 0) for m in DISCOVERY_METHODS},
        })

    df = pd.DataFrame(rows)
    df = df.sort_values('real_bugs', ascending=False)
    return df


def plot_bug_types_by_engine(df: pd.DataFrame, output_path: Path):
    """Create stacked horizontal bar chart of bug types by engine."""
    fig, ax = plt.subplots(figsize=(3.5, 3.0))  # Single column width

    # Sort by total bugs for better visualization
    df_sorted = df.sort_values('real_bugs', ascending=True)

    engines = df_sorted['engine'].tolist()
    y_pos = np.arange(len(engines))

    # Build stacked bars
    left = np.zeros(len(engines))
    for kind in BUG_KINDS:
        values = df_sorted[f'kind_{kind}'].values
        bars = ax.barh(y_pos, values, left=left, label=kind,
                       color=BUG_KIND_COLORS[kind], height=0.7)
        left += values

    ax.set_yticks(y_pos)
    ax.set_yticklabels(engines)
    ax.set_xlabel('Number of Bugs')
    ax.set_xlim(0, df_sorted['real_bugs'].max() * 1.1)

    plt.tight_layout()

    # Legend outside plot (2 rows, 3 per row) - placed after tight_layout
    ax.legend(loc='upper center', bbox_to_anchor=(0.35, -0.15),
              ncol=3, frameon=False, columnspacing=0.8)
    plt.savefig(output_path, format='pdf', bbox_inches='tight')
    plt.savefig(output_path.with_suffix('.png'), format='png', bbox_inches='tight')
    plt.close()
    print(f"Saved: {output_path}")


def plot_discovery_methods(df: pd.DataFrame, output_path: Path):
    """Create bar chart of discovery methods (aggregated across all engines)."""
    # Aggregate discovery methods
    method_totals = {m: df[f'method_{m}'].sum() for m in DISCOVERY_METHODS}
    total_bugs = sum(method_totals.values())

    # Filter out zero counts and sort
    method_totals = {k: v for k, v in method_totals.items() if v > 0}
    methods = sorted(method_totals.keys(), key=lambda x: method_totals[x], reverse=True)
    values = [method_totals[m] for m in methods]
    percentages = [v / total_bugs * 100 for v in values]

    # Display names
    display_names = {
        'MANUAL_REVIEW': 'Manual',
        'FUZZING': 'Fuzzing',
        'DIFFERENTIAL_TESTING': 'Differential',
        'STATIC_ANALYSIS': 'Static Analysis',
        'OTHER': 'Other',
    }
    labels = [display_names.get(m, m) for m in methods]
    colors = [DISCOVERY_COLORS[m] for m in methods]

    fig, ax = plt.subplots(figsize=(3.5, 2.0))
    bars = ax.bar(labels, values, color=colors)

    # Add percentage labels on bars
    for bar, pct in zip(bars, percentages):
        height = bar.get_height()
        ax.annotate(f'{pct:.1f}%',
                    xy=(bar.get_x() + bar.get_width() / 2, height),
                    xytext=(0, 3), textcoords="offset points",
                    ha='center', va='bottom', fontsize=7)

    ax.set_ylabel('Number of Bugs')
    ax.set_xlabel('Discovery Method')

    plt.tight_layout()
    plt.savefig(output_path, format='pdf', bbox_inches='tight')
    plt.savefig(output_path.with_suffix('.png'), format='png', bbox_inches='tight')
    plt.close()
    print(f"Saved: {output_path}")


def generate_latex_table(df: pd.DataFrame, output_path: Path):
    """Generate LaTeX table for paper."""
    # Select and rename columns
    table_df = df[['engine', 'total_issues', 'real_bugs', 'bug_rate', 'fix_rate', 'top_bug_kind']].copy()
    table_df.columns = ['Engine', 'Issues', 'Bugs', 'Bug Rate (\\%)', 'Fixed (\\%)', 'Top Type']

    # Format percentages
    table_df['Bug Rate (\\%)'] = table_df['Bug Rate (\\%)'].apply(lambda x: f'{x:.1f}')
    table_df['Fixed (\\%)'] = table_df['Fixed (\\%)'].apply(lambda x: f'{x:.1f}')

    # Generate LaTeX
    latex = table_df.to_latex(index=False, escape=False, column_format='lrrrrr')

    # Wrap in table environment
    full_latex = f"""\\begin{{table}}[t]
\\centering
\\caption{{Summary of bugs identified in third-party regex engines.}}
\\label{{tab:bug-summary}}
\\small
{latex}\\end{{table}}
"""

    output_path.write_text(full_latex)
    print(f"Saved: {output_path}")


def print_summary_statistics(df: pd.DataFrame, engine_bugs: dict):
    """Print summary statistics for use in paper prose."""
    total_issues = df['total_issues'].sum()
    total_bugs = df['real_bugs'].sum()
    total_fixed = df['fixed'].sum()

    # Aggregate bug kinds
    kind_totals = {k: df[f'kind_{k}'].sum() for k in BUG_KINDS}
    method_totals = {m: df[f'method_{m}'].sum() for m in DISCOVERY_METHODS}

    print("\n" + "=" * 60)
    print("SUMMARY STATISTICS FOR PAPER")
    print("=" * 60)

    print(f"\n[SCALE]")
    print(f"  Total engines analyzed: {len(df)}")
    print(f"  Total issues collected: {total_issues:,}")
    print(f"  Real bugs identified: {total_bugs:,}")
    print(f"  Overall bug rate: {total_bugs / total_issues * 100:.1f}%")
    print(f"  Bugs fixed: {total_fixed:,} ({total_fixed / total_bugs * 100:.1f}%)")

    print(f"\n[BUG TYPES]")
    for kind in sorted(kind_totals.keys(), key=lambda x: kind_totals[x], reverse=True):
        count = kind_totals[kind]
        pct = count / total_bugs * 100
        print(f"  {kind}: {count} ({pct:.1f}%)")

    print(f"\n[DISCOVERY METHODS]")
    for method in sorted(method_totals.keys(), key=lambda x: method_totals[x], reverse=True):
        count = method_totals[method]
        pct = count / total_bugs * 100 if total_bugs > 0 else 0
        print(f"  {method}: {count} ({pct:.1f}%)")

    print(f"\n[PER-ENGINE STATISTICS]")
    for _, row in df.iterrows():
        print(f"  {row['engine']}: {row['real_bugs']} bugs from {row['total_issues']} issues "
              f"({row['bug_rate']:.1f}% bug rate, {row['fix_rate']:.1f}% fixed)")

    # Count bugs with reproduction info
    repro_count = 0
    for bugs in engine_bugs.values():
        for bug in bugs:
            if bug.get('is_real_bug') and bug.get('reproduction_pattern_and_input'):
                repro_info = bug['reproduction_pattern_and_input']
                if repro_info and any(r.get('pattern') or r.get('input') for r in repro_info):
                    repro_count += 1

    print(f"\n[REPRODUCTION INFO]")
    print(f"  Bugs with pattern/input: {repro_count} ({repro_count / total_bugs * 100:.1f}%)")

    print("\n" + "=" * 60)


def load_raw_issues_with_dates(data_dir: Path) -> dict[str, dict[str, str]]:
    """Load raw issues to get creation dates. Returns {engine_key: {issue_number: created_at}}."""
    raw_dir = data_dir / 'issues' / 'raw'
    issue_dates = {}

    target_lower = {k.lower(): k for k in TARGET_ENGINES}

    for file_path in raw_dir.glob('*_issues.ndjson'):
        engine_key = file_path.stem.replace('_issues', '')

        if engine_key in TARGET_ENGINES:
            canonical_key = engine_key
        elif engine_key.lower() in target_lower:
            canonical_key = target_lower[engine_key.lower()]
        else:
            continue

        dates = {}
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                obj = json.loads(line)
                issue = obj.get('issue', obj)
                number = str(issue.get('number', ''))
                created_at = issue.get('created_at', '')
                if number and created_at:
                    dates[number] = created_at
        issue_dates[canonical_key] = dates

    return issue_dates


def compute_temporal_statistics(engine_bugs: dict[str, list], issue_dates: dict[str, dict]) -> tuple[dict, dict]:
    """Compute bugs and all issues by year statistics."""
    bugs_by_year = Counter()
    issues_by_year = Counter()

    for engine_key, bugs in engine_bugs.items():
        dates = issue_dates.get(engine_key, {})
        for bug in bugs:
            issue_num = str(bug.get('number', ''))
            created_at = dates.get(issue_num, '')
            if created_at and len(created_at) >= 4:
                year = created_at[:4]
                issues_by_year[year] += 1
                if bug.get('is_real_bug'):
                    bugs_by_year[year] += 1

    return dict(sorted(bugs_by_year.items())), dict(sorted(issues_by_year.items()))


def print_temporal_statistics(bugs_by_year: dict, issues_by_year: dict):
    """Print temporal statistics for paper."""
    print(f"\n[TEMPORAL DISTRIBUTION - BUGS]")
    total_bugs = sum(bugs_by_year.values())

    # Group into ranges for summary
    early = sum(v for k, v in bugs_by_year.items() if k < '2015')
    mid = sum(v for k, v in bugs_by_year.items() if '2015' <= k < '2020')
    recent = sum(v for k, v in bugs_by_year.items() if '2020' <= k < '2025')
    latest = sum(v for k, v in bugs_by_year.items() if k >= '2025')

    print(f"  Before 2015: {early} ({early/total_bugs*100:.1f}%)")
    print(f"  2015-2019: {mid} ({mid/total_bugs*100:.1f}%)")
    print(f"  2020-2024: {recent} ({recent/total_bugs*100:.1f}%)")
    print(f"  2025+: {latest} ({latest/total_bugs*100:.1f}%)")

    print(f"\n  Year-by-year breakdown (bugs):")
    for year, count in bugs_by_year.items():
        print(f"    {year}: {count}")

    print(f"\n[TEMPORAL DISTRIBUTION - ALL ISSUES]")
    total_issues = sum(issues_by_year.values())

    early_i = sum(v for k, v in issues_by_year.items() if k < '2015')
    mid_i = sum(v for k, v in issues_by_year.items() if '2015' <= k < '2020')
    recent_i = sum(v for k, v in issues_by_year.items() if '2020' <= k < '2025')
    latest_i = sum(v for k, v in issues_by_year.items() if k >= '2025')

    print(f"  Before 2015: {early_i} ({early_i/total_issues*100:.1f}%)")
    print(f"  2015-2019: {mid_i} ({mid_i/total_issues*100:.1f}%)")
    print(f"  2020-2024: {recent_i} ({recent_i/total_issues*100:.1f}%)")
    print(f"  2025+: {latest_i} ({latest_i/total_issues*100:.1f}%)")

    print(f"\n  Year-by-year breakdown (all issues):")
    for year, count in issues_by_year.items():
        print(f"    {year}: {count}")


def main():
    project_root = get_project_root()
    data_dir = project_root / 'src' / 're_fuzzer' / 'data'

    # Create output directories
    figures_dir = data_dir / 'figures'
    tables_dir = data_dir / 'tables'
    figures_dir.mkdir(exist_ok=True)
    tables_dir.mkdir(exist_ok=True)

    print("Loading data...")
    engine_bugs = load_analyzed_issues(data_dir)
    raw_counts = load_raw_issue_counts(data_dir)
    issue_dates = load_raw_issues_with_dates(data_dir)

    print(f"Loaded bugs from {len(engine_bugs)} engines")

    print("\nComputing statistics...")
    df = compute_statistics(engine_bugs, raw_counts)
    bugs_by_year, issues_by_year = compute_temporal_statistics(engine_bugs, issue_dates)

    print("\nGenerating figures...")
    plot_bug_types_by_engine(df, figures_dir / 'bug_types_by_engine.pdf')
    plot_discovery_methods(df, figures_dir / 'discovery_methods.pdf')

    print("\nGenerating LaTeX table...")
    generate_latex_table(df, tables_dir / 'bug_summary.tex')

    print_summary_statistics(df, engine_bugs)
    print_temporal_statistics(bugs_by_year, issues_by_year)

    # Save raw data as CSV for reference
    df.to_csv(data_dir / 'bug_analysis_summary.csv', index=False)
    print(f"\nSaved raw data: {data_dir / 'bug_analysis_summary.csv'}")


if __name__ == '__main__':
    main()
