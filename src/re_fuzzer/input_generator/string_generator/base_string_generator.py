from abc import abstractmethod
from collections.abc import Generator

from re_fuzzer.input_generator.base_input_generator import BaseInputGenerator, BaseInputGeneratorConfig


class BaseStringGenerator(BaseInputGenerator):
    """Abstract base class for string generators."""

    @abstractmethod
    def __init__(self, config: "BaseStringGeneratorConfig") -> None:
        """
        Initialize the string generator with a configuration.

        :param config: An instance of BaseStringGeneratorConfig.
        """
        self.config = config

    @abstractmethod
    def generate(self, regex_pattern: str, count: int) -> Generator[str, None, None]:
        """
        Generate a list of strings for a given regex.

        :param regex_pattern: The regex pattern to generate strings from.
        :param count: The number of strings to generate.
        :return: A generator yielding generated strings.
        """


class BaseStringGeneratorConfig(BaseInputGeneratorConfig):
    """Abstract base class for string generator configurations."""

    @abstractmethod
    def __init__(self, *args: object, **kwargs: object) -> None:
        """
        Initialize the configuration with given arguments.

        :param args: Positional arguments.
        :param kwargs: Keyword arguments.
        """
