from __future__ import annotations

from typing import Optional

from re_fuzzer.metamorphic_testing.base_metamorphic_relation import BaseMetamorphicRelation
from re_fuzzer.metamorphic_testing.match_result import MatchResult
from re_fuzzer.metamorphic_testing.test_case import TestCase
from re_fuzzer.transformations.base_transformer import BaseTransformer
from re_fuzzer.transformations.mr_transformations import (
    AlternationAssociativityTransformer,
    AlternationCommutativityTransformer,
    AlternationIdempotenceTransformer,
    AlternationZeroIdentityTransformer,
    ConcatenationAssociativityTransformer,
    ConcatenationOneIdentityTransformer,
    ConcatenationZeroIdentityTransformer,
    KleeneStarCollapsingIdempotenceTransformer,
    KleeneStarUnrollingIdempotenceTransformer,
    LeftDistributivityTransformer,
    LeftKleeneStarUnrollingTransformer,
    ProductStarTransformer,
    RightDistributivityTransformer,
    RightKleeneStarUnrollingTransformer,
    SumStarLeftTransformer,
    SumStarRightTransformer,
)
from yapp.util import is_k_regex


def _results_equivalent(original: MatchResult, transformed: MatchResult) -> bool:
    return (
        original.matched == transformed.matched
        # and original.span == transformed.span
        # and original.longest_span == transformed.longest_span
        # and original.spans == transformed.spans
        # and original.captures == transformed.captures
        # and original.error == transformed.error
    )


class AlternationAssociativityMetamorphicRelation(BaseMetamorphicRelation):
    def __init__(
        self,
        pattern_transformer: AlternationAssociativityTransformer,
        input_transformer: Optional[BaseTransformer] = None,
    ):
        super().__init__("alternation_associativity", pattern_transformer, input_transformer)

    def apply_transformations(self, original: TestCase) -> TestCase:
        if not self.precondition(original):
            return original

        transformed_pattern = self.pattern_transformer.transform(regex1=original.pattern)
        return TestCase(
            pattern=transformed_pattern,
            input=original.input,
            flags=original.flags,
            match_kind=original.match_kind,
        )

    def precondition(self, original: TestCase) -> bool:
        return is_k_regex(original.pattern)

    def assert_relation(self, original: MatchResult, transformed: MatchResult) -> bool:
        return _results_equivalent(original, transformed)


class ConcatenationAssociativityMetamorphicRelation(BaseMetamorphicRelation):
    def __init__(
        self,
        pattern_transformer: ConcatenationAssociativityTransformer,
        input_transformer: Optional[BaseTransformer] = None,
    ):
        super().__init__("concatenation_associativity", pattern_transformer, input_transformer)

    def apply_transformations(self, original: TestCase) -> TestCase:
        if not self.precondition(original):
            return original

        transformed_pattern = self.pattern_transformer.transform(regex1=original.pattern)
        return TestCase(
            pattern=transformed_pattern,
            input=original.input,
            flags=original.flags,
            match_kind=original.match_kind,
        )

    def precondition(self, original: TestCase) -> bool:
        return is_k_regex(original.pattern)

    def assert_relation(self, original: MatchResult, transformed: MatchResult) -> bool:
        return _results_equivalent(original, transformed)


class AlternationCommutativityMetamorphicRelation(BaseMetamorphicRelation):
    def __init__(
        self,
        pattern_transformer: AlternationCommutativityTransformer,
        input_transformer: Optional[BaseTransformer] = None,
    ):
        super().__init__("alternation_commutativity", pattern_transformer, input_transformer)

    def apply_transformations(self, original: TestCase) -> TestCase:
        if not self.precondition(original):
            return original

        transformed_pattern = self.pattern_transformer.transform(regex1=original.pattern)
        return TestCase(
            pattern=transformed_pattern,
            input=original.input,
            flags=original.flags,
            match_kind=original.match_kind,
        )

    def precondition(self, original: TestCase) -> bool:
        return is_k_regex(original.pattern)

    def assert_relation(self, original: MatchResult, transformed: MatchResult) -> bool:
        return _results_equivalent(original, transformed)


class AlternationZeroIdentityMetamorphicRelation(BaseMetamorphicRelation):
    def __init__(
        self,
        pattern_transformer: AlternationZeroIdentityTransformer,
        input_transformer: Optional[BaseTransformer] = None,
    ):
        super().__init__("alternation_zero_identity", pattern_transformer, input_transformer)

    def apply_transformations(self, original: TestCase) -> TestCase:
        if not self.precondition(original):
            return original

        transformed_pattern = self.pattern_transformer.transform(regex1=original.pattern)
        return TestCase(
            pattern=transformed_pattern,
            input=original.input,
            flags=original.flags,
            match_kind=original.match_kind,
        )

    def precondition(self, original: TestCase) -> bool:
        return is_k_regex(original.pattern)

    def assert_relation(self, original: MatchResult, transformed: MatchResult) -> bool:
        return _results_equivalent(original, transformed)


class ConcatenationZeroIdentityMetamorphicRelation(BaseMetamorphicRelation):
    def __init__(
        self,
        pattern_transformer: ConcatenationZeroIdentityTransformer,
        input_transformer: Optional[BaseTransformer] = None,
    ):
        super().__init__("concatenation_zero_identity", pattern_transformer, input_transformer)

    def apply_transformations(self, original: TestCase) -> TestCase:
        if not self.precondition(original):
            return original

        transformed_pattern = self.pattern_transformer.transform(regex1=original.pattern)
        return TestCase(
            pattern=transformed_pattern,
            input=original.input,
            flags=original.flags,
            match_kind=original.match_kind,
        )

    def precondition(self, original: TestCase) -> bool:
        return is_k_regex(original.pattern)

    def assert_relation(self, original: MatchResult, transformed: MatchResult) -> bool:
        if original.error is not None:
            return transformed.error is not None
        return (
            transformed.error is None
            and not transformed.matched
            and transformed.span is None
            and transformed.longest_span is None
            and not transformed.spans
        )


class ConcatenationOneIdentityMetamorphicRelation(BaseMetamorphicRelation):
    def __init__(
        self,
        pattern_transformer: ConcatenationOneIdentityTransformer,
        input_transformer: Optional[BaseTransformer] = None,
    ):
        super().__init__("concatenation_one_identity", pattern_transformer, input_transformer)

    def apply_transformations(self, original: TestCase) -> TestCase:
        if not self.precondition(original):
            return original

        transformed_pattern = self.pattern_transformer.transform(regex1=original.pattern)
        return TestCase(
            pattern=transformed_pattern,
            input=original.input,
            flags=original.flags,
            match_kind=original.match_kind,
        )

    def precondition(self, original: TestCase) -> bool:
        return is_k_regex(original.pattern)

    def assert_relation(self, original: MatchResult, transformed: MatchResult) -> bool:
        return _results_equivalent(original, transformed)


class LeftDistributivityMetamorphicRelation(BaseMetamorphicRelation):
    def __init__(
        self,
        pattern_transformer: LeftDistributivityTransformer,
        input_transformer: Optional[BaseTransformer] = None,
    ):
        super().__init__("left_distributivity", pattern_transformer, input_transformer)

    def apply_transformations(self, original: TestCase) -> TestCase:
        if not self.precondition(original):
            return original

        transformed_pattern = self.pattern_transformer.transform(regex1=original.pattern)
        return TestCase(
            pattern=transformed_pattern,
            input=original.input,
            flags=original.flags,
            match_kind=original.match_kind,
        )

    def precondition(self, original: TestCase) -> bool:
        return is_k_regex(original.pattern)

    def assert_relation(self, original: MatchResult, transformed: MatchResult) -> bool:
        return _results_equivalent(original, transformed)


class RightDistributivityMetamorphicRelation(BaseMetamorphicRelation):
    def __init__(
        self,
        pattern_transformer: RightDistributivityTransformer,
        input_transformer: Optional[BaseTransformer] = None,
    ):
        super().__init__("right_distributivity", pattern_transformer, input_transformer)

    def apply_transformations(self, original: TestCase) -> TestCase:
        if not self.precondition(original):
            return original

        transformed_pattern = self.pattern_transformer.transform(regex1=original.pattern)
        return TestCase(
            pattern=transformed_pattern,
            input=original.input,
            flags=original.flags,
            match_kind=original.match_kind,
        )

    def precondition(self, original: TestCase) -> bool:
        return is_k_regex(original.pattern)

    def assert_relation(self, original: MatchResult, transformed: MatchResult) -> bool:
        return _results_equivalent(original, transformed)


class AlternationIdempotenceMetamorphicRelation(BaseMetamorphicRelation):
    def __init__(
        self,
        pattern_transformer: AlternationIdempotenceTransformer,
        input_transformer: Optional[BaseTransformer] = None,
    ):
        super().__init__("alternation_idempotence", pattern_transformer, input_transformer)

    def apply_transformations(self, original: TestCase) -> TestCase:
        if not self.precondition(original):
            return original

        transformed_pattern = self.pattern_transformer.transform(regex1=original.pattern)
        return TestCase(
            pattern=transformed_pattern,
            input=original.input,
            flags=original.flags,
            match_kind=original.match_kind,
        )

    def precondition(self, original: TestCase) -> bool:
        return is_k_regex(original.pattern)

    def assert_relation(self, original: MatchResult, transformed: MatchResult) -> bool:
        return _results_equivalent(original, transformed)


class LeftKleeneStarUnrollingMetamorphicRelation(BaseMetamorphicRelation):
    def __init__(
        self,
        pattern_transformer: LeftKleeneStarUnrollingTransformer,
        input_transformer: Optional[BaseTransformer] = None,
    ):
        super().__init__("left_kleene_star_unrolling", pattern_transformer, input_transformer)

    def apply_transformations(self, original: TestCase) -> TestCase:
        if not self.precondition(original):
            return original

        transformed_pattern = self.pattern_transformer.transform(regex1=original.pattern)
        return TestCase(
            pattern=transformed_pattern,
            input=original.input,
            flags=original.flags,
            match_kind=original.match_kind,
        )

    def precondition(self, original: TestCase) -> bool:
        return is_k_regex(original.pattern)

    def assert_relation(self, original: MatchResult, transformed: MatchResult) -> bool:
        return _results_equivalent(original, transformed)


class RightKleeneStarUnrollingMetamorphicRelation(BaseMetamorphicRelation):
    def __init__(
        self,
        pattern_transformer: RightKleeneStarUnrollingTransformer,
        input_transformer: Optional[BaseTransformer] = None,
    ):
        super().__init__("right_kleene_star_unrolling", pattern_transformer, input_transformer)

    def apply_transformations(self, original: TestCase) -> TestCase:
        if not self.precondition(original):
            return original

        transformed_pattern = self.pattern_transformer.transform(regex1=original.pattern)
        return TestCase(
            pattern=transformed_pattern,
            input=original.input,
            flags=original.flags,
            match_kind=original.match_kind,
        )

    def precondition(self, original: TestCase) -> bool:
        return is_k_regex(original.pattern)

    def assert_relation(self, original: MatchResult, transformed: MatchResult) -> bool:
        return _results_equivalent(original, transformed)


class KleeneStarCollapsingIdempotenceMetamorphicRelation(BaseMetamorphicRelation):
    def __init__(
        self,
        pattern_transformer: KleeneStarCollapsingIdempotenceTransformer,
        input_transformer: Optional[BaseTransformer] = None,
    ):
        super().__init__("kleene_star_collapsing_idempotence", pattern_transformer, input_transformer)

    def apply_transformations(self, original: TestCase) -> TestCase:
        if not self.precondition(original):
            return original

        transformed_pattern = self.pattern_transformer.transform(regex1=original.pattern)
        return TestCase(
            pattern=transformed_pattern,
            input=original.input,
            flags=original.flags,
            match_kind=original.match_kind,
        )

    def precondition(self, original: TestCase) -> bool:
        return is_k_regex(original.pattern)

    def assert_relation(self, original: MatchResult, transformed: MatchResult) -> bool:
        return original.matched == transformed.matched \
          and original.span == transformed.span \
          and original.spans == transformed.spans \
          and original.error == transformed.error


class KleeneStarUnrollingIdempotenceMetamorphicRelation(BaseMetamorphicRelation):
    def __init__(
        self,
        pattern_transformer: KleeneStarUnrollingIdempotenceTransformer,
        input_transformer: Optional[BaseTransformer] = None,
    ):
        super().__init__("kleene_star_unrolling_idempotence", pattern_transformer, input_transformer)

    def apply_transformations(self, original: TestCase) -> TestCase:
        if not self.precondition(original):
            return original

        transformed_pattern = self.pattern_transformer.transform(regex1=original.pattern)
        return TestCase(
            pattern=transformed_pattern,
            input=original.input,
            flags=original.flags,
            match_kind=original.match_kind,
        )

    def precondition(self, original: TestCase) -> bool:
        return is_k_regex(original.pattern)

    def assert_relation(self, original: MatchResult, transformed: MatchResult) -> bool:
        return original.matched == transformed.matched \
          and original.span == transformed.span \
          and original.spans == transformed.spans \
          and original.error == transformed.error


class SumStarLeftMetamorphicRelation(BaseMetamorphicRelation):
    def __init__(
        self,
        pattern_transformer: SumStarLeftTransformer,
        input_transformer: Optional[BaseTransformer] = None,
    ):
        super().__init__("sum_star_left", pattern_transformer, input_transformer)

    def apply_transformations(self, original: TestCase) -> TestCase:
        if not self.precondition(original):
            return original

        transformed_pattern = self.pattern_transformer.transform(regex1=original.pattern)
        return TestCase(
            pattern=transformed_pattern,
            input=original.input,
            flags=original.flags,
            match_kind=original.match_kind,
        )

    def precondition(self, original: TestCase) -> bool:
        return is_k_regex(original.pattern)

    def assert_relation(self, original: MatchResult, transformed: MatchResult) -> bool:
        return _results_equivalent(original, transformed)


class SumStarRightMetamorphicRelation(BaseMetamorphicRelation):
    def __init__(
        self,
        pattern_transformer: SumStarRightTransformer,
        input_transformer: Optional[BaseTransformer] = None,
    ):
        super().__init__("sum_star_right", pattern_transformer, input_transformer)

    def apply_transformations(self, original: TestCase) -> TestCase:
        if not self.precondition(original):
            return original

        transformed_pattern = self.pattern_transformer.transform(regex1=original.pattern)
        return TestCase(
            pattern=transformed_pattern,
            input=original.input,
            flags=original.flags,
            match_kind=original.match_kind,
        )

    def precondition(self, original: TestCase) -> bool:
        return is_k_regex(original.pattern)

    def assert_relation(self, original: MatchResult, transformed: MatchResult) -> bool:
        return _results_equivalent(original, transformed)


class ProductStarMetamorphicRelation(BaseMetamorphicRelation):
    def __init__(
        self,
        pattern_transformer: ProductStarTransformer,
        input_transformer: Optional[BaseTransformer] = None,
    ):
        super().__init__("product_star", pattern_transformer, input_transformer)

    def apply_transformations(self, original: TestCase) -> TestCase:
        if not self.precondition(original):
            return original

        transformed_pattern = self.pattern_transformer.transform(regex1=original.pattern)
        return TestCase(
            pattern=transformed_pattern,
            input=original.input,
            flags=original.flags,
            match_kind=original.match_kind,
        )

    def precondition(self, original: TestCase) -> bool:
        return is_k_regex(original.pattern)

    def assert_relation(self, original: MatchResult, transformed: MatchResult) -> bool:
        return _results_equivalent(original, transformed)
