#!/usr/bin/env python3
"""
Self-contained driver script to measure LLVM source-based coverage of a regex
C library (exposed as a Python module) over a JSONL dataset of regex patterns.

High-level idea
---------------
* Build your regex C library with clang's source-based coverage:
    -fprofile-instr-generate -fcoverage-mapping

* Install the resulting wheel so that importing your module loads the
  coverage-instrumented shared library.

* Run this script to:
  - execute each regex in its own Python process with LLVM_PROFILE_FILE set,
  - collect .profraw files,
  - post-process them with llvm-profdata / llvm-cov, and
  - generate plots of coverage.

This script assumes your Python module exposes a ``compile(pattern)`` function,
similar to ``re.compile``. You can tweak ``_run_pattern_in_module`` below if
your API is different.
"""

import argparse
import json
import multiprocessing
import os
import random
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Dict, Optional, Sequence, Tuple

import matplotlib

try:
    from tqdm import tqdm
except ImportError:  # pragma: no cover - optional dependency at runtime
    tqdm = None

from re_fuzzer.input_generator.string_generator.xeger_string_generator import XegerStringGenerator, XegerStringGeneratorConfig
STRING_GENERATOR = XegerStringGenerator(XegerStringGeneratorConfig(seed=42, star_plus_limit=10))
matplotlib.use("Agg")
import matplotlib.pyplot as plt

METRICS = ("lines", "functions", "branches")


def _parse_driver_args(argv: Sequence[str]):
    parser = argparse.ArgumentParser(
        description="Measure LLVM source-based coverage for a regex engine "
                    "over a JSONL regex dataset."
    )
    parser.add_argument(
        "--mode",
        required=True,
        choices=["individual", "cumulative"],
        help=(
            "Coverage aggregation mode:\n"
            "  individual: measure coverage for each regex separately and\n"
            "              plot a box plot of per-regex coverage.\n"
            "  cumulative: as you add regexes in order, measure coverage of "
            "the union\n"
            "              and plot a line chart of cumulative coverage."
        ),
    )
    parser.add_argument(
        "--work-dir",
        required=True,
        help="Directory to store profile data and plots.",
    )
    parser.add_argument(
        "--jsonl",
        required=True,
        help="Path to JSONL file with regex patterns in the 'pattern' key.",
    )
    parser.add_argument(
        "--module-name",
        required=True,
        help="Name of the Python module that wraps your regex engine "
             "(e.g. 'myregexlib').",
    )
    parser.add_argument(
        "--object-path",
        default=None,
        help=(
            "Optional explicit path to the coverage-instrumented shared "
            "library (.so/.dylib/.dll). If omitted, the script will use "
            "module.__file__ from --module-name."
        ),
    )
    parser.add_argument(
        "--llvm-profdata",
        default="llvm-profdata",
        help="Path to llvm-profdata executable (default: llvm-profdata).",
    )
    parser.add_argument(
        "--llvm-cov",
        default="llvm-cov",
        help="Path to llvm-cov executable (default: llvm-cov).",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Optional maximum number of regexes to process.",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=None,
        help=(
            "Number of parallel workers to spawn for running patterns. "
            "Defaults to the number of CPU cores."
        ),
    )
    parser.add_argument(
        "--ignore-filename-regex",
        default=None,
        help="Regex to pass to llvm-cov -ignore-filename-regex to skip external files "
            "(e.g. '.*/python3\\.11/.*').",
    )
    return parser.parse_args(argv)


def _parse_child_args(argv: Sequence[str]):
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--_run-one", action="store_true", required=True)
    parser.add_argument("--module-name", required=True)
    parser.add_argument("--pattern", required=True)
    return parser.parse_args(argv)


def _ensure_tool_exists(cli_flag_name: str, exe: str):
    if shutil.which(exe) is None:
        raise SystemExit(
            "Required tool '{exe}' not found on PATH. Install LLVM tools and "
            "or pass a custom path with --{flag}."
            .format(exe=exe, flag=cli_flag_name)
        )


def _read_patterns(jsonl_path: Path, limit: Optional[int]):
    patterns = []
    with jsonl_path.open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as e:
                print(
                    "[warn] Skipping line {ln}: invalid JSON: {err}".format(
                        ln=line_no, err=e
                    ),
                    file=sys.stderr,
                )
                continue
            if "pattern" not in obj:
                print(
                    "[warn] Skipping line {ln}: no 'pattern' key".format(
                        ln=line_no
                    ),
                    file=sys.stderr,
                )
                continue
            patterns.append(str(obj["pattern"]))
            if limit is not None and len(patterns) >= limit:
                break
    return patterns


def _run_profdata_merge(
    llvm_profdata: str, inputs, output: Path, num_threads: Optional[int] = None
):
    cmd = [llvm_profdata, "merge", "-sparse"]
    if num_threads and num_threads > 0:
        cmd.append(f"-num-threads={num_threads}")
    cmd.extend(str(p) for p in inputs)
    cmd.extend(["-o", str(output)])
    # Let this raise on failure; better to surface issues early.
    subprocess.run(cmd, check=True)


def _get_coverage_percentages(
    llvm_cov: str,
    profdata_path: Path,
    object_path: Path,
    ignore_filename_regex: Optional[str] = None,
) -> Dict[str, float]:
    cmd = [
        llvm_cov,
        "export",
        sys.executable,
        "-instr-profile={}".format(profdata_path),
        "-object={}".format(object_path),
        "-summary-only",
    ]
    if ignore_filename_regex:
        cmd.append(f"-ignore-filename-regex={ignore_filename_regex}")

    result = subprocess.run(
        cmd, check=True, capture_output=True, text=True
    )
    data = json.loads(result.stdout)
    try:
        totals = data["data"][0]["totals"]
    except (KeyError, IndexError) as e:
        raise RuntimeError(
            "Unexpected JSON from llvm-cov export for {p}: {err}".format(
                p=profdata_path, err=e
            )
        )

    coverage = {}
    for metric in METRICS:
        try:
            coverage[metric] = float(totals[metric]["percent"])
        except (KeyError, TypeError, ValueError) as e:
            raise RuntimeError(
                "Coverage metric '{metric}' missing from llvm-cov export for {p}: {err}".format(
                    metric=metric, p=profdata_path, err=e
                )
            )
    return coverage


def _determine_object_path(module_name: str, explicit: Optional[str]) -> Path:
    if explicit is not None:
        return Path(explicit).resolve()
    try:
        mod = __import__(module_name)
    except ImportError as e:
        raise SystemExit(
            "Failed to import module '{mod}'. Is your wheel installed in this "
            "environment?\nOriginal error: {err}".format(mod=module_name, err=e)
        )
    if not hasattr(mod, "__file__") or mod.__file__ is None:
        raise SystemExit(
            "Module '{mod}' has no __file__ attribute; cannot determine shared "
            "library path. Please pass --object-path."
            .format(mod=module_name)
        )
    return Path(mod.__file__).resolve()


def _run_pattern_child(
    script_path: Path,
    module_name: str,
    pattern: str,
    profraw_path: Path,
    pattern_index: Optional[int] = None,
) -> bool:
    """Spawn a child process to run a single pattern, return True on success.

    The child process will import the module and call compile(pattern).
    LLVM_PROFILE_FILE is pointed at profraw_path so the coverage runtime
    writes that file when the process exits.
    """
    if "\x00" in pattern:
        prefix = "[warn] "
        if pattern_index is not None:
            prefix += "Pattern #{idx}: ".format(idx=pattern_index)
        print(
            "{prefix}Skipping pattern containing embedded NUL byte (no coverage collected).".format(
                prefix=prefix
            ),
            file=sys.stderr,
        )
        return False

    env = os.environ.copy()
    env["LLVM_PROFILE_FILE"] = str(profraw_path)

    env["DYLD_INSERT_LIBRARIES"] = (
        "/Users/friberk/.miniconda3/envs/re-fuzzer/lib/clang/19/lib/darwin/"
        "libclang_rt.asan_osx_dynamic.dylib"
    )

    # Source

    cmd = [
        sys.executable,
        str(script_path),
        "--_run-one",
        "--module-name",
        module_name,
        "--pattern",
        pattern,
    ]
    proc = subprocess.run(cmd, env=env)
    if proc.returncode != 0:
        print(
            "[warn] Child process for pattern exited with code {code}".format(
                code=proc.returncode
            ),
            file=sys.stderr,
        )
        return False
    if not profraw_path.exists():
        print(
            "[warn] Expected profile '{p}' was not created."
            .format(p=profraw_path),
            file=sys.stderr,
        )
        return False
    return True


def _pattern_worker(task_args: Tuple[int, str, str, str, str]) -> Tuple[int, bool]:
    idx, pattern, script_path_str, module_name, profraw_path_str = task_args
    script_path = Path(script_path_str)
    profraw_path = Path(profraw_path_str)
    ok = _run_pattern_child(script_path, module_name, pattern, profraw_path, idx)
    return idx, ok


def _plot_individual_boxplot(metric: str, values, out_path: Path):
    if not values:
        print(
            "[warn] No coverage values to plot for metric '{metric}' (individual mode).".format(
                metric=metric
            )
        )
        return
    metric_label = metric.capitalize()
    fig, ax = plt.subplots(figsize=(6, 4))
    ax.boxplot(values, vert=True)
    ax.set_ylabel("{metric} coverage (%)".format(metric=metric_label))
    ax.set_xticklabels(["All regexes"])
    ax.set_title("Per-regex {metric} coverage".format(metric=metric_label))
    fig.tight_layout()
    fig.savefig(out_path, dpi=150)
    plt.close(fig)


def _plot_cumulative_line(metric: str, values, out_path: Path):
    if not values:
        print(
            "[warn] No coverage values to plot for metric '{metric}' (cumulative mode).".format(
                metric=metric
            )
        )
        return
    metric_label = metric.capitalize()
    xs = list(range(1, len(values) + 1))
    fig, ax = plt.subplots(figsize=(8, 4))
    ax.plot(xs, values)
    ax.set_xlabel("Regex index")
    ax.set_ylabel(
        "Cumulative {metric} coverage (%)".format(metric=metric_label)
    )
    ax.set_title(
        "Cumulative {metric} coverage vs. regex index".format(metric=metric_label)
    )
    fig.tight_layout()
    fig.savefig(out_path, dpi=150)
    plt.close(fig)


def _driver_main(argv: Sequence[str]):
    args = _parse_driver_args(argv)

    _ensure_tool_exists("llvm-profdata", args.llvm_profdata)
    _ensure_tool_exists("llvm-cov", args.llvm_cov)

    work_dir = Path(args.work_dir).resolve()
    # if work_dir exists, delete it
    if work_dir.exists():
        shutil.rmtree(work_dir)
    work_dir.mkdir(parents=True, exist_ok=True)
    profiles_raw_dir = work_dir / "profiles_raw"
    profiles_raw_dir.mkdir(exist_ok=True)
    profdata_dir = work_dir / "profdata"
    profdata_dir.mkdir(exist_ok=True)
    plots_dir = work_dir / "plots"
    plots_dir.mkdir(exist_ok=True)

    jsonl_path = Path(args.jsonl).resolve()
    if not jsonl_path.is_file():
        raise SystemExit("JSONL file '{p}' does not exist."
                         .format(p=jsonl_path))

    patterns = _read_patterns(jsonl_path, args.limit)
    if not patterns:
        raise SystemExit("No patterns loaded from JSONL file.")

    # Randomly sample 100 patterns
    random.seed(42)
    sample_size = min(10000, len(patterns))
    patterns = random.sample(patterns, sample_size)

    object_path = _determine_object_path(args.module_name, args.object_path)
    print("[info] Using object for coverage: {p}".format(p=object_path))

    script_path = Path(__file__).resolve()

    per_regex_coverage = {metric: [] for metric in METRICS}
    cumulative_coverage = {metric: [] for metric in METRICS}

    cumulative_profdata = work_dir / "cumulative.profdata"
    if args.mode == "cumulative" and cumulative_profdata.exists():
        cumulative_profdata.unlink()

    num_workers = args.workers if args.workers and args.workers > 0 else (os.cpu_count() or 1)
    num_workers = max(1, num_workers)
    num_workers = min(num_workers, len(patterns))

    print(
        "[info] Processing {n} patterns with {w} worker(s)...".format(
            n=len(patterns), w=num_workers
        )
    )

    script_path_str = str(script_path)
    tasks = []
    profraw_paths = {}
    for idx, pattern in enumerate(patterns):
        profraw_path = profiles_raw_dir / "input-{i:05d}.profraw".format(i=idx)
        profraw_paths[idx] = profraw_path
        tasks.append((idx, pattern, script_path_str, args.module_name, str(profraw_path)))

    success_flags = [False] * len(patterns)

    if num_workers == 1:
        task_iter = tasks
        if tqdm is not None:
            task_iter = tqdm(
                tasks,
                desc="Processing patterns",
                unit="pattern",
            )
        for task in task_iter:
            idx, ok = _pattern_worker(task)
            success_flags[idx] = ok
    else:
        with multiprocessing.Pool(processes=num_workers) as pool:
            result_iter = pool.imap_unordered(_pattern_worker, tasks)
            if tqdm is not None:
                result_iter = tqdm(
                    result_iter,
                    total=len(tasks),
                    desc="Processing patterns",
                    unit="pattern",
                )
            for idx, ok in result_iter:
                success_flags[idx] = ok

    successful_indices = [idx for idx, ok in enumerate(success_flags) if ok]
    successful_count = len(successful_indices)
    failed_count = len(patterns) - successful_count

    print(
        "[info] Successfully executed {s} / {n} patterns.".format(
            s=successful_count, n=len(patterns)
        )
    )
    if failed_count:
        print(
            "[warn] {f} pattern(s) failed during execution and will be skipped.".format(
                f=failed_count
            )
        )

    if not successful_indices:
        print("[warn] No successful pattern executions; aborting coverage analysis.")
        return

    if args.mode == "individual":
        for idx in successful_indices:
            profraw_path = profraw_paths[idx]
            profdata_path = profdata_dir / "input-{i:05d}.profdata".format(
                i=idx
            )
            _run_profdata_merge(
                args.llvm_profdata, [profraw_path], profdata_path, num_workers
            )
            coverage = _get_coverage_percentages(
                args.llvm_cov,
                profdata_path,
                object_path,
                args.ignore_filename_regex,
            )
            for metric, pct in coverage.items():
                per_regex_coverage[metric].append(pct)

    elif args.mode == "cumulative":
        # Incremental merge per successful regex to capture the coverage curve
        iter_indices = successful_indices
        if tqdm is not None:
            iter_indices = tqdm(
                successful_indices,
                desc="Merging cumulative coverage",
                unit="pattern",
            )
        for idx in iter_indices:
            profraw_path = profraw_paths[idx]
            if not cumulative_profdata.exists():
                _run_profdata_merge(
                    args.llvm_profdata, [profraw_path], cumulative_profdata, num_workers
                )
            else:
                tmp = work_dir / "cumulative.tmp.profdata"
                _run_profdata_merge(
                    args.llvm_profdata, [cumulative_profdata, profraw_path], tmp, num_workers
                )
                os.replace(tmp, cumulative_profdata)
            coverage = _get_coverage_percentages(
                args.llvm_cov,
                cumulative_profdata,
                object_path,
                args.ignore_filename_regex,
            )
            for metric, pct in coverage.items():
                cumulative_coverage[metric].append(pct)

    if args.mode == "individual":
        processed_count = len(per_regex_coverage[METRICS[0]])
        if processed_count:
            print(
                "[info] Processed {n} patterns in individual mode.".format(
                    n=processed_count
                )
            )
            for metric in METRICS:
                values = per_regex_coverage[metric]
                if not values:
                    continue
                metric_label = metric.capitalize()
                boxplot_path = plots_dir / "individual_{metric}_coverage_boxplot.png".format(
                    metric=metric
                )
                _plot_individual_boxplot(metric, values, boxplot_path)
                print(
                    "[info] {metric} box plot written to: {path}".format(
                        metric=metric_label, path=boxplot_path
                    )
                )
        else:
            print("[warn] No coverage data collected in individual mode.")

    elif args.mode == "cumulative":
        processed_count = len(cumulative_coverage[METRICS[0]])
        if processed_count:
            print(
                "[info] Processed {n} patterns in cumulative mode.".format(
                    n=processed_count
                )
            )
            for metric in METRICS:
                values = cumulative_coverage[metric]
                if not values:
                    continue
                metric_label = metric.capitalize()
                lineplot_path = plots_dir / "cumulative_{metric}_coverage_line.png".format(
                    metric=metric
                )
                _plot_cumulative_line(metric, values, lineplot_path)
                print(
                    "[info] {metric} line chart written to: {path}".format(
                        metric=metric_label, path=lineplot_path
                    )
                )
                print(
                    "[info] Final cumulative {metric} coverage: {pct:.2f}%".format(
                        metric=metric_label, pct=values[-1]
                    )
                )
        else:
            print("[warn] No coverage data collected in cumulative mode.")


def _run_pattern_in_module(module_name: str, pattern: str):
    """Child-process helper: import module and compile the pattern.

    This function is intentionally small and easy to edit if your Python
    bindings expose a different API than `compile(pattern)`.
    """
    try:
        mod = __import__(module_name)
    except ImportError as e:
        print(
            "[child] Failed to import module {mod!r}: {err}"
            .format(mod=module_name, err=e),
            file=sys.stderr,
        )
        sys.exit(1)

    compile_fn = getattr(mod, "compile", None)
    if compile_fn is None:
        print(
            "[child] Module {mod!r} has no 'compile' attribute; "
            "edit _run_pattern_in_module() to match your API."
            .format(mod=module_name),
            file=sys.stderr,
        )
        sys.exit(1)

    try:
        regex_obj = compile_fn(pattern)
    except Exception as e:
        # It's still interesting coverage if compilation fails.
        print(
            "[child] compile({pat!r}) raised {typ}: {err}"
            .format(pat=pattern, typ=type(e).__name__, err=e),
            file=sys.stderr,
        )
        return

    # Best-effort: try a few simple matches if methods exist, but don't
    # assume any particular API beyond compile().
    # for candidate in ("match", "search", "fullmatch"):
    for candidate in ["search"]:
        meth = getattr(regex_obj, candidate, None)
        if callable(meth):
            test_strings = []
            pos_test_strings = STRING_GENERATOR.generate(pattern, 3)
            # Append negative test strings
            for pos_test_string in pos_test_strings:
                test_strings.append(pos_test_string)
                if random.random() < 0.5:
                    test_strings.append("p" + pos_test_string)
                else:
                    test_strings.append(pos_test_string + "p")

            for test_s in test_strings:
                try:
                    _ = meth(test_s)
                except Exception:
                    # Ignore runtime errors; we only care about coverage.
                    pass


def _child_main(argv: Sequence[str]):
    args = _parse_child_args(argv)
    _run_pattern_in_module(args.module_name, args.pattern)


def main():
    if "--_run-one" in sys.argv:
        # Child mode: run exactly one pattern under coverage.
        _child_main(sys.argv[1:])
    else:
        _driver_main(sys.argv[1:])


if __name__ == "__main__":
    main()
