from __future__ import annotations

from collections.abc import Generator
from random import Random

from loguru import logger
from rstr.xeger import Xeger

from re_fuzzer.input_generator.string_generator.base_string_generator import (
    BaseStringGenerator,
    BaseStringGeneratorConfig,
)


class XegerStringGenerator(BaseStringGenerator):
    """Generates strings matching a regex pattern using rstr's Xeger."""

    def __init__(self, config: XegerStringGeneratorConfig) -> None:
        """
        Initialize the Xeger string generator with a configuration.

        :param config: An instance of XegerStringGeneratorConfig.
        """
        super().__init__(config)
        self._config: XegerStringGeneratorConfig = config

        # Initialize Xeger with a seeded Random instance if seed is provided
        if self._config.seed is not None:
            random_instance = Random(self._config.seed)
            self._xeger = Xeger(random=random_instance, star_plus_limit=self._config.star_plus_limit)
        else:
            self._xeger = Xeger(star_plus_limit=self._config.star_plus_limit)

    def generate(self, regex_pattern: str, count: int) -> Generator[str, None, None]:
        """
        Generate strings matching the given regex pattern.

        :param regex_pattern: The regex pattern to generate strings from.
        :param count: The number of strings to generate.
        :yield: Generated strings matching the regex pattern.
        """
        # logger.info("Generating {} strings for regex pattern: {}", count, regex_pattern)
        for _ in range(count):
            try:
                yield self._xeger.xeger(regex_pattern)
            except Exception as e:
                logger.error(f"Failed to generate string for regex {regex_pattern}: {e}")
                pass


class XegerStringGeneratorConfig(BaseStringGeneratorConfig):
    """Configuration for the XegerStringGenerator."""

    def __init__(
        self,
        *,
        seed: int | None = None,
        star_plus_limit: int = 100,
    ) -> None:
        """
        Initialize the configuration with given parameters for the Xeger-based string generator.

        :param seed: Optional seed for reproducibility via random.Random(seed).
        :param star_plus_limit: Controls repetition bounds in xeger (default: 100).
        """
        self.seed = seed
        self.star_plus_limit = star_plus_limit

