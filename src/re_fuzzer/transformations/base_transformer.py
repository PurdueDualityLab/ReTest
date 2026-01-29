from abc import ABC, abstractmethod
import random
from typing import Callable, List

from re_fuzzer.transformations.transformers_policy import TransformerPolicy
from yapp.ast.traverse import NodeVisitor


class BaseTransformer(ABC, NodeVisitor):
    def __init__(self, policy: TransformerPolicy = TransformerPolicy.TRANSFORM_FIRST):
        super().__init__()
        self.policy = policy
        self._pending_transformations: List[Callable[[], None]] = []
        self._stop_traversal = False

    def reset_transformer_state(self):
        self._pending_transformations.clear()
        self._stop_traversal = False

    def record_transformation(self, transformation: Callable[[], None]) -> bool:
        """
        Register a transformation callback and execute it immediately depending on policy.

        Returns True if the transformation was executed right away, False otherwise.
        """

        if self.policy == TransformerPolicy.TRANSFORM_ALL:
            transformation()
            return True

        if self.policy == TransformerPolicy.TRANSFORM_FIRST:
            transformation()
            self._stop_traversal = True
            return True

        # TRANSFORM_LAST or TRANSFORM_RANDOM store transformations for later execution
        self._pending_transformations.append(transformation)
        return False

    def apply_pending_transformations(self):
        if not self._pending_transformations:
            return

        if self.policy == TransformerPolicy.TRANSFORM_LAST:
            self._pending_transformations[-1]()
        elif self.policy == TransformerPolicy.TRANSFORM_RANDOM:
            random.choice(self._pending_transformations)()

        self._pending_transformations.clear()

    @property
    def should_stop(self) -> bool:
        return self._stop_traversal

    def generic_visit(self, node):  # type: ignore[override]
        if self._stop_traversal:
            return node
        return super().generic_visit(node)

    @abstractmethod
    def precondition(self, **regexes: str) -> bool:
        pass

    @abstractmethod
    def transform(self, **regexes: str) -> str:
        pass
