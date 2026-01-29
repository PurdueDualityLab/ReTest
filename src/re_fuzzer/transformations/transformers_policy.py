from enum import Enum, auto


class TransformerPolicy(Enum):
    TRANSFORM_FIRST = auto()
    TRANSFORM_LAST = auto()
    TRANSFORM_ALL = auto()
    TRANSFORM_RANDOM = auto()
