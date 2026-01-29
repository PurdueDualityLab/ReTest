from __future__ import annotations

"""
In-process wrapper around Grammarinator's "generate" CLI.

This module mirrors the semantics of Grammarinator's upstream CLI while
exposing a Python-friendly API:

- Uses GeneratorTool with RuleSize-based limits (depth/tokens).
- Allows setting model, listeners, transformers, serializer, and weights.
- Supports populations with configurable tree codec/extension.
- Applies per-index seeding: random_seed + i (matching upstream).
- Captures stdout when out_format is an empty string; otherwise reads back
  the generated file, or returns the serialized text directly when a
  serializer is configured.
"""

import contextlib
import io
import json
import random
from collections.abc import Generator, Sequence
from pathlib import Path

from grammarinator.tool.generator import (  # mypy: disable-error-code="unused-ignore"  # type: ignore  # noqa: PGH003
    DefaultGeneratorFactory,
    GeneratorTool,
)
from grammarinator.tool.default_population import DefaultPopulation
from grammarinator.runtime import RuleSize  # mypy: disable-error-code="unused-ignore"  # type: ignore  # noqa: PGH003
from inators.imp import import_object  # mypy: disable-error-code="unused-ignore"  # type: ignore  # noqa: PGH003
from loguru import logger  # mypy: disable-error-code="unused-ignore"  # type: ignore  # noqa: PGH003

from re_fuzzer.input_generator.regex_generator.base_regex_generator import (
    BaseRegexGenerator,
    BaseRegexGeneratorConfig,
)
from re_fuzzer.util.import_object import load_class_with_getattr

class GrammarinatorGenerator(BaseRegexGenerator):
    """Produce regex strings via Grammarinator inside the same Python process.

    Internally, this class builds a DefaultGeneratorFactory and a GeneratorTool
    to generate test cases. Generation closely follows the upstream CLI logic
    (RuleSize-based limits, per-index seeding, optional population support).
    """

    def __init__(self, config: GrammarinatorGeneratorConfig) -> None:
        super().__init__(config)
        self._config = config

    def generate(self, count: int) -> Generator[str, None, None]:
        """Generate ``count`` regex strings according to the configuration.

        - If ``out_format == ''``, the produced text is captured from stdout.
        - If a serializer is configured, the returned value is the serialized
          string produced by the serializer.
        - Otherwise, the tool returns a file path; its content is read and
          yielded as text.

        The random number generator is seeded with ``random_seed + i`` for each
        generated item ``i`` if ``random_seed`` is provided, matching upstream.
        """
        cfg = self._config

        class_name = cfg.generator_path.stem  # convention: <file>.py defines <file>
        generator_cls = load_class_with_getattr(str(cfg.generator_path), class_name)
        model_cls = import_object(cfg.model)
        listeners = [import_object(listener) for listener in cfg.listener]
        transformers = [import_object(transformer) for transformer in cfg.transformer]
        serializer_fn = import_object(cfg.serializer) if cfg.serializer else None

        factory = DefaultGeneratorFactory(
            generator_cls,
            model_class=model_cls,
            weights=cfg.materialised_weights,
            listener_classes=listeners,
        )

        population_obj = DefaultPopulation(cfg.population, cfg.tree_extension, cfg.tree_codec) if cfg.population else None

        with GeneratorTool(
            generator_factory=factory,
            rule=cfg.rule,
            out_format=cfg.out_format,
            limit=RuleSize(depth=cfg.max_depth, tokens=(cfg.max_tokens if cfg.max_tokens is not None else RuleSize.max.tokens)),
            population=population_obj,
            generate=cfg.generate,
            mutate=cfg.mutate,
            recombine=cfg.recombine,
            unrestricted=cfg.unrestricted,
            keep_trees=cfg.keep_trees,
            transformers=transformers,
            serializer=serializer_fn,
            memo_size=cfg.memo_size,
            unique_attempts=cfg.unique_attempts,
            cleanup=False,
            encoding=cfg.encoding,
            errors=cfg.encoding_errors,
            dry_run=cfg.dry_run,
        ) as tool:
            buf = io.StringIO()
            for i in range(count):
                # Per-index seeding for reproducibility matching the CLI.
                if cfg.random_seed is not None:
                    random.seed(cfg.random_seed + i)

                # capture stdout in case the user chose out_format==""
                with contextlib.redirect_stdout(buf):
                    result = tool.create_test(i)

                captured = buf.getvalue()
                buf.truncate(0)
                buf.seek(0)

                if cfg.dry_run:
                    continue  # skip yielding in dry-run mode

                text: str | None = None
                # If printing to stdout, prefer captured output.
                if cfg.out_format == "":
                    text = captured.strip()

                # If we still don't have text, try to use the result first as a path, then as plain text.
                if text is None and isinstance(result, str):
                    path = Path(result)
                    if path.exists():
                        with path.open("r", encoding=cfg.encoding, errors=cfg.encoding_errors) as fp:
                            text = fp.read()
                    else:
                        # Some versions return the serialized string directly when a serializer is set.
                        text = result

                # Fall back to whatever was captured on stdout.
                if text is None:
                    text = captured.strip()

                # Yield even empty strings to mirror upstream behavior and
                # guarantee exactly `count` items are produced.
                yield text


class GrammarinatorGeneratorConfig(BaseRegexGeneratorConfig):
    """
    Grammarinator's "generate" CLI options.

    Only ``generator_path`` is mandatory. All other fields align with upstream
    defaults and behavior.
    """

    def __init__(
        self,
        *,
        # Essentials ---------------------------------------------------------
        generator_path: str,  # path to *_Generator.py
        rule: str | None = None,
        model: str = "grammarinator.runtime.DefaultModel",
        listener: Sequence[str] | None = None,
        transformer: Sequence[str] | None = None,
        serializer: str | None = None,
        # Size limit ---------------------------------------------------------
        max_depth: int = RuleSize.max.depth,
        max_tokens: int | None = RuleSize.max.tokens,
        # Weights ------------------------------------------------------------
        weights: str | dict[tuple[str, int, int], float] | None = None,
        # Evolutionary --------------------------------------------------------
        population: str | None = None,
        generate: bool = True,
        mutate: bool = True,
        recombine: bool = True,
        unrestricted: bool = True,
        keep_trees: bool = False,
        tree_extension: str | None = None,
        tree_codec: str | None = None,
        # Output --------------------------------------------------------------
        out_format: str = "",  # empty → stdout (captured)
        encoding: str = "utf-8",
        encoding_errors: str = "strict",
        dry_run: bool = False,
        # Uniqueness/memoization ---------------------------------------------
        memo_size: int = 0,
        unique_attempts: int = 2,
        # Misc ----------------------------------------------------------------
        random_seed: int | None = None,
        jobs: int = 1,
    ) -> None:
        """Create a configuration equivalent to the upstream "generate" CLI.

        Parameters
        ----------
        generator_path
            Path to the generator created by grammarinator-process (path to
            ``*_Generator.py``). Convention: ``<file>.py`` defines class
            ``<file>``.
        rule
            Name of the rule to start generation from (default: the parser rule
            set by grammarinator-process).
        model
            Reference to the decision model (``package.module.class`` format)
            (default: ``grammarinator.runtime.DefaultModel``).
        listener
            Reference(s) to listeners (``package.module.class`` format).
        transformer
            Reference(s) to transformers (``package.module.function`` format)
            to postprocess the generated tree. The results of these
            transformers will be saved into the serialized tree (e.g., variable
            matching).
        serializer
            Reference to a serializer (``package.module.function`` format) that
            takes a tree and produces a string from it.
        max_depth
            Maximum recursion depth during generation (default:
            ``RuleSize.max.depth``).
        max_tokens
            Maximum token number during generation (default:
            ``RuleSize.max.tokens``).
        weights
            JSON file path defining custom weights for alternatives, or a
            pre-materialized mapping of
            ``{(rule, alternation_idx, alternative_idx): weight}``.
        population
            Directory of Grammarinator tree pool.
        generate
            Enable test generation from grammar (default: ``True``).
        mutate
            Enable test generation by mutation (disabled by default if no
            population is given).
        recombine
            Enable test generation by recombination (disabled by default if no
            population is given).
        unrestricted
            Enable applying grammar-violating mutators (enabled by default).
        keep_trees
            Keep generated tests to participate in further mutations or
            recombinations (only if population is given).
        tree_extension
            Tree file extension corresponding to ``--tree-format`` (e.g.,
            ``"grtp"``, ``"grtj"``, ``"grtf"``).
        tree_codec
            Tree codec instance corresponding to ``--tree-format``.
        out_format
            Output file name pattern (default: a path pattern). Empty string
            prints test cases to stdout (alias of CLI ``--stdout``).
        encoding
            Output file encoding (default: ``utf-8``).
        encoding_errors
            Encoding error handling scheme (default: ``strict``).
        dry_run
            Generate tests without writing them to file or printing to stdout
            (do not keep generated tests in population either).
        memo_size
            Memoize the last ``NUM`` unique tests; if a memoized test case is
            generated again, it is discarded and generation of a unique test
            case is retried.
        unique_attempts
            Limit on how many times to try to generate a unique (i.e.,
            non-memoized) test case; no effect if ``memo_size == 0``.
        random_seed
            Initialize random number generator with fixed seed. Per upstream,
            seeding is performed as ``seed + i`` for each generated item.
        jobs
            Parallelization level (present for CLI parity; this wrapper does
            not spawn worker processes).
        """
        # fmt: on
        # Public attributes ---------------------------------------------------
        self.generator_path: Path = Path(generator_path)
        self.rule: str | None = rule
        self.model: str = model
        self.listener: list[str] = list(listener) if listener else []
        self.transformer: list[str] = list(transformer) if transformer else []
        self.serializer: str | None = serializer
        self.max_depth: int = max_depth
        self.max_tokens: int | None = max_tokens
        self.weights: str | dict[tuple[str, int, int], float] | None = weights
        self.materialised_weights: dict[tuple[str, int, int], float] | None = self._materialise_weights()
        self.population: str | None = population
        self.generate: bool = generate
        self.mutate: bool = bool(mutate and population)
        self.recombine: bool = bool(recombine and population)
        self.unrestricted: bool = unrestricted
        self.keep_trees: bool = keep_trees
        self.tree_extension: str | None = tree_extension
        self.tree_codec: str | None = tree_codec
        self.out_format: str = out_format
        self.encoding: str = encoding
        self.encoding_errors: str = encoding_errors
        self.dry_run: bool = dry_run
        self.memo_size: int = memo_size
        self.unique_attempts: int = unique_attempts
        self.random_seed: int | None = random_seed
        self.jobs: int = max(1, jobs)

        # Sanity checks ------------------------------------------------------
        if not self.generator_path.exists():
            logger.error("Grammarinator generator file not found: {}", self.generator_path.resolve())
            raise FileNotFoundError(self.generator_path)

    # ---------------------------------------------------------------------
    # Helpers
    # ---------------------------------------------------------------------

    def _materialise_weights(self) -> dict[tuple[str, int, int], float] | None:
        """Materialize weights from a JSON file path to the required mapping.

        The expected JSON structure matches upstream (rule → alternation →
        alternative → weight). Returns ``None`` if no weights are configured.
        """
        if self.weights is None or isinstance(self.weights, dict):
            return self.weights

        weight_path = Path(self.weights)
        if not weight_path.exists():
            raise FileNotFoundError(weight_path)

        with weight_path.open("r", encoding="utf-8") as f:
            raw = json.load(f)

        weights: dict[tuple[str, int, int], float] = {}
        for rule, alts in raw.items():
            for alternation_idx, alternatives in alts.items():
                for alternative_idx, w in alternatives.items():
                    weights[(rule, int(alternation_idx), int(alternative_idx))] = w
        return weights
