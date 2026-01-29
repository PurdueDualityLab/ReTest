from abc import abstractmethod
from collections.abc import Generator

from re_fuzzer.input_generator.base_input_generator import BaseInputGenerator, BaseInputGeneratorConfig


class BaseRegexGenerator(BaseInputGenerator):
    """Abstract base class for regex generators."""

    @abstractmethod
    def __init__(self, config: "BaseRegexGeneratorConfig") -> None:
        """
        Initialize the regex generator with a configuration.

        :param config: An instance of BaseRegexGeneratorConfig.
        """
        self.config = config

    @abstractmethod
    def generate(self, count: int) -> Generator[str, None, None]:
        """
        Generate a list of regex patterns.

        :param count: The number of regex patterns to generate.
        :return: A list of generated regex patterns.
        """


class BaseRegexGeneratorConfig(BaseInputGeneratorConfig):
    """Abstract base class for regex generator configurations."""

    @abstractmethod
    def __init__(self, *args: object, **kwargs: object) -> None:
        """
        Initialize the configuration with given arguments.

        :param args: Positional arguments.
        :param kwargs: Keyword arguments.
        """
