import random
from typing import Generator, Optional, Sequence

from atheris import FuzzedDataProvider  # type: ignore

from re_fuzzer.input_generator.regex_generator.base_regex_generator import BaseRegexGenerator, BaseRegexGeneratorConfig


class AtherisRegexGeneratorConfig(BaseRegexGeneratorConfig):
    def __init__(self,
        alphabet: Sequence[str] = tuple(
            [chr(i) for i in range(32, 127)]  # printable ASCII
        ),
        min_len: int = 0,
        max_len: int = 128,
        repeat_bias: bool = True,
        fallback_seed: Optional[int] = None,
    ) -> None:
        self.alphabet = alphabet
        self.min_len = min_len
        self.max_len = max_len
        self.repeat_bias = repeat_bias
        self.fallback_seed = fallback_seed

    def __post_init__(self):
        if self.min_len < 0:
            raise ValueError("min_len must be >= 0")
        if self.max_len < self.min_len:
            raise ValueError("max_len must be >= min_len")
        if not self.alphabet:
            raise ValueError("alphabet cannot be empty")
        # Dedup alphabet, preserve order
        seen, dedup = set(), []
        for ch in self.alphabet:
            if ch not in seen:
                dedup.append(ch); seen.add(ch)
        self.alphabet = tuple(dedup)

class AtherisRegexGenerator(BaseRegexGenerator):
    """
    Pure string generator: picks characters from a given alphabet for a length in [min_len, max_len].
    All decisions come from FuzzedDataProvider when provided (for coverage guidance & determinism).
    """

    def __init__(self, config: AtherisRegexGeneratorConfig) -> None:
        self.config = config
        self._alphabet = self.config.alphabet
        self._alen = len(self._alphabet)

    def _choose_len(self, fdp: Optional[FuzzedDataProvider], rng: Optional[random.Random]) -> int:
        c = self.config
        if c.min_len == c.max_len:
            return c.min_len
        if fdp is not None:
            return fdp.ConsumeIntInRange(c.min_len, c.max_len)
        assert rng is not None
        return rng.randint(c.min_len, c.max_len)

    def _pick_index(self, fdp: Optional[FuzzedDataProvider], rng: Optional[random.Random]) -> int:
        if fdp is not None:
            return fdp.ConsumeIntInRange(0, self._alen - 1)
        assert rng is not None
        return rng.randrange(self._alen)

    def _emit_string(self, fdp: Optional[FuzzedDataProvider], rng: Optional[random.Random], n: int) -> str:
        # Optional simple repeat bias: occasionally repeat the last chosen char
        if not self.config.repeat_bias or n <= 1 or fdp is None:
            return "".join(self._alphabet[self._pick_index(fdp, rng)] for _ in range(n))

        out = []
        i = 0
        while i < n:
            idx = self._pick_index(fdp, rng)
            ch = self._alphabet[idx]
            out.append(ch); i += 1
            # ~1/4 chance to repeat current char for a small run (length derived from fdp)
            if fdp.ConsumeIntInRange(0, 3) == 0 and i < n:
                run = min(n - i, fdp.ConsumeIntInRange(1, 8))
                out.extend(ch for _ in range(run))
                i += run
        return "".join(out)

    def generate(self, count: int, fdp: Optional[FuzzedDataProvider] = None) -> Generator[str, None, None]:
        rng = None if fdp is not None else random.Random(self.config.fallback_seed)
        for _ in range(count):
            n = self._choose_len(fdp, rng)
            yield self._emit_string(fdp, rng, n)
