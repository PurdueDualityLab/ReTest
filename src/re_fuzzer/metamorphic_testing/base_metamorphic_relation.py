from typing import Callable, Optional
from abc import ABC, abstractmethod
from re_fuzzer.metamorphic_testing.match_result import MatchResult
from re_fuzzer.metamorphic_testing.test_case import TestCase
from re_fuzzer.transformations.base_transformer import BaseTransformer

class BaseMetamorphicRelation(ABC):
    def __init__(self, name: str, pattern_transformer: BaseTransformer, input_transformer: Optional[BaseTransformer] = None):
        self.name = name
        self.pattern_transformer = pattern_transformer
        self.input_transformer = input_transformer

    @abstractmethod
    def apply_transformations(self, original: TestCase) -> TestCase:
        raise NotImplementedError

    @abstractmethod
    def precondition(self, original: TestCase) -> bool:
        raise NotImplementedError

    @abstractmethod
    def assert_relation(self, original: MatchResult, transformed: MatchResult) -> bool:
        """
        Return True iff the MR holds. Use the engine to evaluate behavior
        on ctx.original and ctx.transformed.
        """
        raise NotImplementedError
