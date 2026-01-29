from __future__ import annotations

import warnings
from collections.abc import Generator
from pathlib import Path

from hypothesis.core import seed as hypothesis_seed
from hypothesis.errors import NonInteractiveExampleWarning
from hypothesis.extra.lark import from_lark
from lark import Lark
from loguru import logger

from re_fuzzer.input_generator.regex_generator.base_regex_generator import BaseRegexGenerator, BaseRegexGeneratorConfig

warnings.filterwarnings("ignore", category=NonInteractiveExampleWarning)


class HypothesisGenerator(BaseRegexGenerator):
    """Generates regex patterns using hypothesis."""

    def __init__(self, config: HypothesisGeneratorConfig) -> None:
        """
        Initialize the hypothesis generator with a configuration.

        :param config: An instance of HypothesisGeneratorConfig.
        """
        super().__init__(config)
        self._config: HypothesisGeneratorConfig = config
        try:
            self._grammar: Lark = Lark(Path(config.lark_grammar_path).read_text(), start=config.lark_start_symbol)
        except Exception as e:
            logger.error("Failed to initialize Lark grammar from path {0}: {1}", config.lark_grammar_path, e)
            raise
        self._hypothesis_strategy = from_lark(self._grammar)

    # (FIXME): Seed does not work with hypothesis example() method
    def generate(self, count: int) -> Generator[str, None, None]:
        """
        Generate a list of regex patterns.

        :param count: The number of regex patterns to generate.
        :return: A generator yielding generated regex patterns.
        """
        logger.info("Generating {} regex patterns", count)
        for i in range(count):
            if self._config.seed is not None:
                # Set the hypothesis seed before generating the example
                hypothesis_seed(self._config.seed + i)
                yield self._hypothesis_strategy.example()
            else:
                yield self._hypothesis_strategy.example()


class HypothesisGeneratorConfig(BaseRegexGeneratorConfig):
    """Configuration for the HypothesisGenerator."""

    def __init__(
        self,
        *,
        seed: int | None = None,
        lark_start_symbol: str = "pcre",
        lark_grammar_path: str = "resources/grammars/pcre_parser.lark",
    ) -> None:
        """
        Initialize the configuration with given parameters for the Hypothesis-library-based regex generator.

        :param seed: Optional seed for Hypothesis example() method to ensure reproducibility.
        :param lark_start_symbol: The start symbol for the Lark grammar.
        :param lark_grammar_path: Path to the Lark grammar file.
        """
        self.seed = seed
        self.lark_start_symbol = lark_start_symbol
        self.lark_grammar_path = lark_grammar_path
