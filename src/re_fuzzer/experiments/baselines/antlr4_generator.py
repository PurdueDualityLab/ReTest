"""ANTLR4-based random walk regex pattern generator.

This module uses the actual ANTLR4 ATN (Augmented Transition Network) from
the V8 fuzzer_regexp_grammar.g4 to generate syntactically valid regex patterns.
This provides an authentic simulation of grammar-based fuzzing like FuzzTest.

The generator walks the ATN randomly, following transitions and emitting
characters when terminal states are reached.
"""

import random
import string
from typing import List, Optional, Set

from antlr4.atn.ATN import ATN
from antlr4.atn.ATNState import (
    ATNState,
    RuleStartState,
    RuleStopState,
    BasicState,
    BasicBlockStartState,
    BlockEndState,
    PlusBlockStartState,
    PlusLoopbackState,
    StarLoopEntryState,
    StarLoopbackState,
    LoopEndState,
)
from antlr4.atn.Transition import (
    Transition,
    AtomTransition,
    RuleTransition,
    EpsilonTransition,
    SetTransition,
    NotSetTransition,
    RangeTransition,
    WildcardTransition,
)
from antlr4.IntervalSet import IntervalSet
from loguru import logger

from re_fuzzer.experiments.baselines.grammar_parser import fuzzer_regexp_grammarLexer


class ANTLR4GrammarGenerator:
    """Random walk regex generator using ANTLR4's ATN.

    This generator walks the ATN (Augmented Transition Network) from the
    ANTLR4-generated lexer, randomly choosing transitions at each state
    to produce syntactically valid regex patterns.
    """

    def __init__(
        self,
        max_depth: int = 20,
        max_size: int = 200,
        seed: Optional[int] = None,
    ):
        """Initialize the generator.

        Args:
            max_depth: Maximum recursion depth for rule references
            max_size: Maximum output size in characters
            seed: Random seed for reproducibility
        """
        self.max_depth = max_depth
        self.max_size = max_size

        if seed is not None:
            random.seed(seed)

        # Get the ATN from the lexer
        self._atn: ATN = fuzzer_regexp_grammarLexer.atn
        self._rule_names = fuzzer_regexp_grammarLexer.ruleNames
        self._symbolic_names = fuzzer_regexp_grammarLexer.symbolicNames

        # Build rule name to index mapping
        self._rule_to_index = {name: i for i, name in enumerate(self._rule_names)}

        # Find key starting rules
        self._pattern_rule = self._rule_to_index.get("Disjunction", 0)

    def generate(self, start_rule: str = "Disjunction") -> str:
        """Generate a pattern by randomly walking the ATN.

        Args:
            start_rule: The rule to start generation from

        Returns:
            Generated regex pattern string
        """
        rule_index = self._rule_to_index.get(start_rule, self._pattern_rule)

        try:
            result = self._generate_from_rule(rule_index, depth=0, visited=set())
            # Truncate to max size
            return result[:self.max_size]
        except RecursionError:
            logger.debug("Recursion limit hit, returning fallback")
            return self._generate_fallback()
        except Exception as e:
            logger.debug(f"Generation error: {e}, returning fallback")
            return self._generate_fallback()

    def _generate_from_rule(
        self,
        rule_index: int,
        depth: int,
        visited: Set[int],
    ) -> str:
        """Generate output starting from a specific rule.

        Args:
            rule_index: Index of the rule to start from
            depth: Current recursion depth
            visited: Set of rule indices visited in current path

        Returns:
            Generated string
        """
        if depth > self.max_depth:
            return self._generate_minimal_for_rule(rule_index)

        # Get the start state for this rule
        start_state = self._atn.ruleToStartState[rule_index]
        if start_state is None:
            return ""

        # Walk the ATN from this state
        return self._walk_atn(start_state, depth, visited)

    def _walk_atn(
        self,
        state: ATNState,
        depth: int,
        visited: Set[int],
    ) -> str:
        """Walk the ATN from a given state, generating output.

        Args:
            state: Current ATN state
            depth: Current recursion depth
            visited: Set of visited rule indices

        Returns:
            Generated string
        """
        result = []
        current_state = state
        loop_count = 0
        max_loops = 100  # Prevent infinite loops

        while current_state is not None and loop_count < max_loops:
            loop_count += 1

            # Check for stop state
            if isinstance(current_state, RuleStopState):
                break

            # Get available transitions
            transitions = current_state.transitions
            if not transitions:
                break

            # Filter and weight transitions
            valid_transitions = self._filter_transitions(transitions, depth)
            if not valid_transitions:
                break

            # Randomly choose a transition
            transition = self._choose_transition(valid_transitions, depth)

            # Process the transition
            output, next_state = self._process_transition(transition, depth, visited)
            if output:
                result.append(output)

            current_state = next_state

        return "".join(result)

    def _filter_transitions(
        self,
        transitions: List[Transition],
        depth: int,
    ) -> List[Transition]:
        """Filter transitions to valid options.

        V8 FuzzTest style: No depth-based filtering. The grammar structure
        itself determines what transitions are valid. Removing bias allows
        generation of more complex nested patterns.

        Args:
            transitions: List of transitions from current state
            depth: Current depth (unused - kept for API compatibility)

        Returns:
            List of valid transitions (unfiltered)
        """
        # V8 FuzzTest doesn't filter based on depth - grammar structure handles this
        return list(transitions)

    def _choose_transition(
        self,
        transitions: List[Transition],
        depth: int,
    ) -> Transition:
        """Choose a transition with EQUAL probability (V8 FuzzTest style).

        V8's fuzztest uses VariantDomain/OneOf() which selects alternatives
        with equal probability. This avoids biasing pattern structure.

        Args:
            transitions: Available transitions
            depth: Current depth (unused - kept for API compatibility)

        Returns:
            Randomly chosen transition with equal probability
        """
        if len(transitions) == 1:
            return transitions[0]

        # V8 FuzzTest uses equal probability selection via OneOf()
        return random.choice(transitions)

    def _process_transition(
        self,
        transition: Transition,
        depth: int,
        visited: Set[int],
    ) -> tuple[str, Optional[ATNState]]:
        """Process a transition, generating output if applicable.

        Args:
            transition: The transition to process
            depth: Current depth
            visited: Set of visited rules

        Returns:
            Tuple of (output_string, next_state)
        """
        if isinstance(transition, EpsilonTransition):
            return "", transition.target

        elif isinstance(transition, AtomTransition):
            # Single character - label can be int or IntervalSet
            label = transition.label
            if isinstance(label, int):
                char = self._code_point_to_char(label)
            elif isinstance(label, IntervalSet):
                char = self._random_from_interval_set(label)
            else:
                char = "a"
            return char, transition.target

        elif isinstance(transition, RangeTransition):
            # Character range [a-b]
            char = self._random_from_range(transition.start, transition.stop)
            return char, transition.target

        elif isinstance(transition, SetTransition):
            # Character set
            char = self._random_from_interval_set(transition.label)
            return char, transition.target

        elif isinstance(transition, NotSetTransition):
            # Negated set - pick something NOT in the set
            char = self._random_not_in_set(transition.label)
            return char, transition.target

        elif isinstance(transition, WildcardTransition):
            # Any character
            char = random.choice(string.printable[:94])  # Printable ASCII
            return char, transition.target

        elif isinstance(transition, RuleTransition):
            # Recurse into another rule
            rule_index = transition.ruleIndex
            if rule_index in visited:
                # Avoid infinite recursion
                return self._generate_minimal_for_rule(rule_index), transition.followState
            new_visited = visited | {rule_index}
            output = self._generate_from_rule(rule_index, depth + 1, new_visited)
            return output, transition.followState

        else:
            # Unknown transition type - follow it without output
            return "", transition.target

    def _code_point_to_char(self, code_point: int) -> str:
        """Convert a code point to a character.

        Args:
            code_point: Unicode code point

        Returns:
            Character string
        """
        try:
            if 0 <= code_point <= 0x10FFFF:
                return chr(code_point)
        except (ValueError, OverflowError):
            pass
        return "?"

    def _random_from_range(self, start, stop) -> str:
        """Generate a random character from a range.

        Args:
            start: Start of range (inclusive) - may be int or IntervalSet
            stop: End of range (inclusive) - may be int or IntervalSet

        Returns:
            Random character from range
        """
        try:
            # Handle case where start/stop might be IntervalSets
            if isinstance(start, IntervalSet):
                return self._random_from_interval_set(start)
            if isinstance(stop, IntervalSet):
                return self._random_from_interval_set(stop)

            # Normal int case
            if isinstance(start, int) and isinstance(stop, int):
                code_point = random.randint(start, stop)
                return chr(code_point)

            return "a"
        except (ValueError, OverflowError, TypeError):
            return "a"

    def _random_from_interval_set(self, interval_set: IntervalSet) -> str:
        """Generate a random character from an IntervalSet.

        Args:
            interval_set: ANTLR4 IntervalSet

        Returns:
            Random character from the set
        """
        try:
            # Get all intervals
            intervals = list(interval_set.intervals)
            if not intervals:
                return "a"

            # Pick a random interval
            interval = random.choice(intervals)

            # Pick a random code point from the interval
            # interval is (start, stop) where both are inclusive
            if hasattr(interval, 'start') and hasattr(interval, 'stop'):
                start, stop = interval.start, interval.stop
            elif isinstance(interval, tuple) and len(interval) == 2:
                start, stop = interval
            else:
                return "a"

            code_point = random.randint(start, stop)
            return chr(code_point)
        except Exception:
            return "a"

    def _random_not_in_set(self, interval_set: IntervalSet) -> str:
        """Generate a character NOT in the interval set.

        Args:
            interval_set: Set of characters to avoid

        Returns:
            Character not in the set
        """
        # Try random printable characters
        for _ in range(100):
            char = random.choice(string.printable[:94])
            code_point = ord(char)
            # Use IntervalSet's contains method instead of 'in' operator
            try:
                if not interval_set.contains(code_point):
                    return char
            except Exception:
                # Fallback: check manually against intervals
                in_set = False
                if interval_set.intervals:
                    for interval in interval_set.intervals:
                        if hasattr(interval, 'start') and hasattr(interval, 'stop'):
                            if interval.start <= code_point <= interval.stop:
                                in_set = True
                                break
                        elif isinstance(interval, tuple) and len(interval) == 2:
                            if interval[0] <= code_point <= interval[1]:
                                in_set = True
                                break
                if not in_set:
                    return char
        return "x"  # Fallback

    def _generate_minimal_for_rule(self, rule_index: int) -> str:
        """Generate minimal output for a rule (used at max depth).

        Args:
            rule_index: Rule index

        Returns:
            Minimal valid string for the rule
        """
        if rule_index < len(self._rule_names):
            rule_name = self._rule_names[rule_index]
            # Map common rules to minimal outputs
            minimal_map = {
                "SourceCharacter": "a",
                "PatternCharacter": "a",
                "Disjunction": "a",
                "Alternative": "a",
                "Term": "a",
                "Atom": "a",
                "Assertion": "^",
                "Quantifier": "*",
                "QuantifierPrefix": "*",
                "CharacterClass": "[a]",
                "CharacterClassEscape": "d",
                "CharacterEscape": "n",
                "ControlEscape": "n",
                "DecimalDigit": "0",
                "DecimalDigits": "0",
                "HexDigit": "0",
                "Hex4Digits": "0000",
                "AsciiLetter": "a",
                "IdentifierStartChar": "a",
                "IdentifierPartChar": "a",
            }
            return minimal_map.get(rule_name, "a")
        return "a"

    def _generate_fallback(self) -> str:
        """Generate a simple fallback pattern.

        Returns:
            Simple valid regex pattern
        """
        patterns = [
            "a+",
            "[a-z]+",
            "\\d+",
            "^foo$",
            ".*",
            "\\w+",
            "(a|b)+",
            "[0-9]{1,3}",
            "(?:abc)+",
            "\\s*\\w+\\s*",
        ]
        return random.choice(patterns)

    def generate_batch(self, count: int) -> List[str]:
        """Generate multiple patterns.

        Args:
            count: Number of patterns to generate

        Returns:
            List of generated patterns
        """
        return [self.generate() for _ in range(count)]


def generate_pattern(
    max_depth: int = 20,
    max_size: int = 200,
    seed: Optional[int] = None,
) -> str:
    """Generate a single regex pattern.

    Args:
        max_depth: Maximum recursion depth
        max_size: Maximum output size
        seed: Random seed for reproducibility

    Returns:
        Generated regex pattern
    """
    gen = ANTLR4GrammarGenerator(max_depth=max_depth, max_size=max_size, seed=seed)
    return gen.generate()
