"""Baseline fuzzing runners for comparison experiments."""

from re_fuzzer.experiments.baselines.direct_pcre import (
    DirectPCRE,
    DirectPCRE2,
    DirectPCREReTest,
    create_direct_wrapper,
    create_retest_wrapper,
)
from re_fuzzer.experiments.baselines.naive_runner import NaiveFuzzerRunner, NaiveMutator
from re_fuzzer.experiments.baselines.grammar_runner import GrammarAwareFuzzerRunner
from re_fuzzer.experiments.baselines.antlr4_generator import ANTLR4GrammarGenerator
from re_fuzzer.experiments.baselines.retest_runner import ReTestFuzzerRunner

__all__ = [
    # Direct wrappers
    "DirectPCRE",
    "DirectPCRE2",
    "DirectPCREReTest",
    "create_direct_wrapper",
    "create_retest_wrapper",
    # Runners
    "NaiveFuzzerRunner",
    "NaiveMutator",
    "GrammarAwareFuzzerRunner",
    "ANTLR4GrammarGenerator",
    "ReTestFuzzerRunner",
]
