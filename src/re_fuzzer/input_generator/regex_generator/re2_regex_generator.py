from __future__ import annotations

import random
from collections.abc import Generator

from loguru import logger

from re_fuzzer.input_generator.regex_generator.base_regex_generator import BaseRegexGenerator, BaseRegexGeneratorConfig
from re_fuzzer.util.string_utils import count_args


class RE2RegexGenerator(BaseRegexGenerator):
    """RE2 regex generator that uses the RE2 library for generating regex patterns."""

    # override
    def __init__(self, config: RE2RegexGeneratorConfig) -> None:
        """
        Initialize the RE2 regex generator with a configuration.

        :param config: An instance of RE2RegexGeneratorConfig containing parameters for the generator.
        """
        super().__init__(config)
        self.config: RE2RegexGeneratorConfig = config

    @staticmethod
    def egrep_ops() -> list[str]:
        """Returns a list of the egrep regexp operators."""
        return [
            "%s%s",  # concatenation
            "%s|%s",  # alternation
            "%s*",  # zero or more
            "%s+",  # one or more
            "%s?",  # zero or one
            "%s\\C*",  # followed by any chars
        ]

    # override
    def generate(self, count: int) -> Generator[str, None, None]:
        """
        Generate regex patterns using RE2, yielding them one by one.

        The generation mode depends on the config.use_random setting:
        - Exhaustive mode (use_random=False): Systematically explores all possible
          regex combinations within the constraints, yielding patterns in a
          deterministic order. Guarantees finding all unique patterns.
        - Random mode (use_random=True): Uses probabilistic choices to generate
          patterns randomly. Faster but may produce duplicates and won't
          guarantee finding all possible patterns.

        :param count: The maximum number of regex patterns to generate.
        :yield: Generated regex patterns one by one.
        """
        if count <= 0:
            return

        # For exhaustive generation, generate all patterns
        if self.config.use_random:
            yield from self._generate_random_patterns(count)
        else:
            yield from self._generate_exhaustive_patterns(count)

    def _generate_exhaustive_patterns(self, max_count: int) -> Generator[str, None, None]:
        """
        EXHAUSTIVE GENERATION: Systematically explores all possible regex combinations.

        This method performs a depth-first traversal of the entire search space,
        generating patterns in a deterministic, reproducible order. It explores
        every valid combination of atoms and operators within the constraints.

        Characteristics:
        - Deterministic: Same input always produces same output in same order
        - Complete: Will eventually find all unique patterns (given enough count)
        - Slower: Must explore the full search tree systematically
        - No duplicates: Each unique pattern appears exactly once
        - Memory efficient: Uses recursion, no pattern storage

        Use when:
        - You need all possible patterns within constraints
        - You want deterministic, reproducible results
        - You're doing comprehensive testing or analysis
        - Pattern uniqueness is important

        :param max_count: Maximum number of patterns to generate before stopping
        :yield: Regex patterns in deterministic order
        """
        logger.info("Generating {} regex patterns", max_count)
        postfix: list[str] = []
        for count, pattern in enumerate(self._generate_postfix_exhaustive(postfix, 0, 0, 0)):
            yield pattern
            if count + 1 >= max_count:
                break

    def _generate_random_patterns(self, count: int) -> Generator[str, None, None]:
        """
        RANDOM GENERATION: Uses probabilistic choices to generate diverse patterns quickly.

        This method makes random decisions at each step (add atom vs operator,
        which atom/operator to choose, when to stop), using backtracking to
        ensure valid patterns are produced.

        Characteristics:
        - Fast: Makes random choices instead of systematic exploration
        - Non-deterministic: Different runs produce different results (unless seeded)
        - May produce duplicates: Same pattern can be generated multiple times
        - Incomplete: May never find some rare/complex patterns
        - Good diversity: Tends to generate varied patterns quickly
        - Controllable: Use config.rng.seed() for reproducible randomness

        Use when:
        - You need diverse patterns quickly for testing
        - You don't need exhaustive coverage
        - You want to stress-test with varied inputs
        - Generation speed is more important than completeness

        :param count: Exact number of patterns to attempt generating
        :yield: Randomly generated regex patterns
        """
        logger.info("Generating {} regex patterns", count)
        for _ in range(count):
            postfix: list[str] = []
            pattern = self._generate_random_postfix(postfix, 0, 0, 0)
            if pattern:
                yield pattern

    def _generate_postfix_exhaustive(
        self, post: list[str], nstk: int, ops: int, atoms: int
    ) -> Generator[str, None, None]:
        """
        Generates all possible postfix command sequences exhaustively.
        Each complete sequence is handed off to _run_postfix to generate regex variants.

        Args:
            post: Current postfix sequence
            nstk: Number of elements that would be on stack after executing sequence
            ops: Number of operators used in the sequence
            atoms: Number of atoms used in the sequence

        """
        if nstk == 1:
            yield from self._run_postfix_exhaustive(post)

        # Early out: if used too many operators or can't
        # get back down to a single expression on the stack
        # using binary operators, give up.
        if ops + nstk - 1 > self.config.maxops:
            return

        # Add atoms if there is room
        if atoms < self.config.maxatoms:
            for atom in self.config.atoms:
                post.append(atom)
                yield from self._generate_postfix_exhaustive(post, nstk + 1, ops, atoms + 1)
                post.pop()

        # Add operators if there are enough arguments
        if ops < self.config.maxops:
            for fmt in self.config.ops:
                nargs = count_args(fmt)
                if nargs <= nstk:
                    post.append(fmt)
                    yield from self._generate_postfix_exhaustive(post, nstk - nargs + 1, ops + 1, atoms)
                    post.pop()

    def _generate_random_postfix(self, post: list[str], nstk: int, ops: int, atoms: int) -> str | None:
        """
        Generates a random postfix command sequence.
        Returns True once a single sequence has been generated.

        Args:
            post: Current postfix sequence
            nstk: Number of elements on stack
            ops: Number of operators used
            atoms: Number of atoms used

        Returns:
            Regex pattern if a complete sequence was generated, None otherwise.

        """
        while True:
            # Stop if we get to a single element, but only sometimes
            if nstk == 1 and self.config.rng.randint(0, max(0, self.config.maxatoms - atoms)) == 0:
                return self._run_postfix_single(post)

            # Early out: if used too many operators or can't
            # get back down to a single expression on the stack
            # using binary operators, give up.
            if ops + nstk - 1 > self.config.maxops:
                return None

            # Add operators if there are enough arguments
            if ops < self.config.maxops and self.config.rng.randint(0, 1) == 0:
                fmt = self.config.rng.choice(self.config.ops)
                nargs = count_args(fmt)
                if nargs <= nstk:
                    post.append(fmt)
                    ret = self._generate_random_postfix(post, nstk - nargs + 1, ops + 1, atoms)
                    post.pop()
                    if ret:
                        return ret

            # Add atoms if there is room
            if atoms < self.config.maxatoms and self.config.rng.randint(0, 1) == 0:
                atom = self.config.rng.choice(self.config.atoms)
                post.append(atom)
                ret = self._generate_random_postfix(post, nstk + 1, ops, atoms + 1)
                post.pop()
                if ret:
                    return ret

    def _run_postfix_exhaustive(self, post: list[str]) -> Generator[str, None, None]:
        """Generate all 4 regex variants from postfix and yield them."""
        base_pattern = self._run_postfix_single(post)
        if base_pattern:
            # Generate all 4 variants like the original C++ code
            yield base_pattern
            yield f"^(?:{base_pattern})$"
            yield f"^(?:{base_pattern})"
            yield f"(?:{base_pattern})$"

    def _run_postfix_single(self, post: list[str]) -> str:
        """
        Interprets the postfix command sequence to create a single regular expression.
        The results of operators like %s|%s are wrapped in (?:) to avoid needing
        to maintain a precedence table.

        Args:
            post: The postfix command sequence

        Returns:
            The generated regex pattern

        """
        regexps: list[str] = []

        for cmd in post:
            nargs = count_args(cmd)

            if nargs == 0:
                # Atom
                regexps.append(cmd)
            elif nargs == 1:
                # Unary operator
                if len(regexps) < 1:
                    logger.error(f"Not enough arguments for operator: {cmd}")
                    raise ValueError(f"Not enough arguments for operator: {cmd}")
                a = regexps.pop()
                result = f"(?:{cmd % a})"
                regexps.append(result)
            elif nargs == 2:
                # Binary operator
                if len(regexps) < 2:
                    logger.error(f"Not enough arguments for operator: {cmd}")
                    raise ValueError(f"Not enough arguments for operator: {cmd}")
                b = regexps.pop()
                a = regexps.pop()
                result = f"(?:{cmd % (a, b)})"
                regexps.append(result)
            else:
                raise ValueError(f"Bad operator: {cmd}")

        if len(regexps) != 1:
            # Internal error - should never happen
            logger.error("Bad regexp program:")
            for cmd in post:
                logger.error(f"  {cmd!r}")
            logger.error("Stack after running program:")
            for regexp in regexps:
                logger.error(f"  {regexp!r}")
            logger.error("Bad regexp program")
            raise ValueError("Bad regexp program")

        return regexps[0]


class RE2RegexGeneratorConfig(BaseRegexGeneratorConfig):
    """Configuration class for RE2 regex generator."""

    def __init__(
        self,
        maxatoms: int,
        maxops: int,
        atoms: list[str],
        ops: list[str],
        *,
        use_random: bool = False,
        seed: int | None = None,
    ) -> None:
        """
        Initialize the configuration with given parameters for the RE2 regex generator.

        :param maxatoms: Maximum number of atoms allowed in expression.
        :param maxops: Maximum number of operators allowed in expression.
        :param atoms: List of possible atom strings.
        :param ops: List of possible operator format strings (with %s placeholders).
        :param use_random: Whether to use random generation instead of exhaustive.
        :param seed: Random seed for reproducible generation.
        """
        self.maxatoms = maxatoms
        self.maxops = maxops
        self.atoms = atoms
        self.ops = ops
        self.use_random = use_random
        self.seed = seed
        self.rng = random.Random()

        if seed is not None:
            self.rng.seed(seed)

        # Degenerate cases
        if not self.atoms:
            self.maxatoms = 0
        if not self.ops:
            self.maxops = 0
