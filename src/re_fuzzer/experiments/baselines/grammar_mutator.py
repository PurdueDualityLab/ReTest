"""Grammar-aware pattern mutator for FuzzTest-style corpus mutation.

FuzzTest mutates corpus entries while maintaining structural validity.
This mutator applies regex-aware mutations that preserve syntax.

Mutation strategies:
1. Quantifier mutation: *, +, ?, {n,m} variations
2. Character class mutation: add/remove chars, negate
3. Group mutation: capturing <-> non-capturing, add lookahead/behind
4. Alternation mutation: add/remove/swap alternatives
5. Anchor mutation: add/remove ^, $, \b
6. Escape mutation: \d <-> \w <-> \s variations
7. Splice mutation: combine parts of two corpus patterns
"""

import random
import re
from typing import List, Optional, Tuple


class GrammarMutator:
    """Grammar-aware mutator for regex patterns.

    Applies mutations that maintain regex syntax validity while
    exploring the grammar space around high-coverage patterns.
    """

    # Quantifier variations
    QUANTIFIERS = ["*", "+", "?", "*?", "+?", "??", "{1}", "{1,}", "{1,3}", "{0,1}"]

    # Character class escapes
    CHAR_ESCAPES = [r"\d", r"\D", r"\w", r"\W", r"\s", r"\S", r"\b", r"\B"]

    # Anchors
    ANCHORS = ["^", "$", r"\A", r"\z", r"\Z"]

    # Group prefixes
    GROUP_PREFIXES = [
        "(",       # Capturing
        "(?:",     # Non-capturing
        "(?=",     # Positive lookahead
        "(?!",     # Negative lookahead
        "(?<=",    # Positive lookbehind
        "(?<!",    # Negative lookbehind
        "(?>",     # Atomic group
    ]

    def __init__(self, mutation_rate: float = 0.3):
        """Initialize the mutator.

        Args:
            mutation_rate: Probability of applying each mutation type
        """
        self.mutation_rate = mutation_rate

        # Mutation strategies with weights (higher = more likely)
        self.strategies = [
            (self._mutate_quantifier, 3.0),
            (self._mutate_char_class, 2.0),
            (self._mutate_escape, 2.0),
            (self._mutate_group, 1.5),
            (self._mutate_anchor, 1.0),
            (self._mutate_alternation, 1.5),
            (self._insert_random_element, 1.0),
            (self._delete_random_element, 0.5),
            (self._duplicate_element, 1.0),
        ]

    def mutate(self, pattern: str, corpus_patterns: Optional[List[str]] = None) -> str:
        """Apply grammar-aware mutation to a pattern.

        Args:
            pattern: The pattern to mutate
            corpus_patterns: Optional list of corpus patterns for splicing

        Returns:
            Mutated pattern
        """
        if not pattern:
            return pattern

        # Select mutation strategy based on weights
        strategies, weights = zip(*self.strategies)
        total_weight = sum(weights)
        normalized_weights = [w / total_weight for w in weights]

        # Apply 1-3 mutations
        num_mutations = random.randint(1, 3)
        result = pattern

        for _ in range(num_mutations):
            strategy = random.choices(strategies, weights=normalized_weights, k=1)[0]
            try:
                mutated = strategy(result)
                if mutated and mutated != result:
                    result = mutated
            except Exception:
                # If mutation fails, continue with original
                pass

        # Occasionally splice with corpus pattern
        if corpus_patterns and random.random() < 0.1:
            try:
                result = self._splice_patterns(result, random.choice(corpus_patterns))
            except Exception:
                pass

        return result

    def _mutate_quantifier(self, pattern: str) -> str:
        """Mutate quantifiers in the pattern."""
        # Find quantifiers: *, +, ?, {n}, {n,}, {n,m}
        quantifier_regex = r"[*+?]|\{[0-9]+(?:,[0-9]*)?\}"
        matches = list(re.finditer(quantifier_regex, pattern))

        if not matches:
            # Add a quantifier after a random position
            if len(pattern) > 1:
                pos = random.randint(1, len(pattern) - 1)
                # Don't add after special chars
                if pattern[pos - 1] not in "^$|()[]{}\\":
                    return pattern[:pos] + random.choice(self.QUANTIFIERS) + pattern[pos:]
            return pattern

        # Replace a random quantifier
        match = random.choice(matches)
        new_quantifier = random.choice(self.QUANTIFIERS)
        return pattern[:match.start()] + new_quantifier + pattern[match.end():]

    def _mutate_char_class(self, pattern: str) -> str:
        """Mutate character classes [...]."""
        # Find character classes
        class_regex = r"\[[^\]]*\]"
        matches = list(re.finditer(class_regex, pattern))

        if not matches:
            # Insert a character class
            if len(pattern) > 0:
                pos = random.randint(0, len(pattern))
                new_class = random.choice(["[a-z]", "[0-9]", "[A-Z]", "[a-zA-Z0-9]", "[^\\s]", "."])
                return pattern[:pos] + new_class + pattern[pos:]
            return pattern

        match = random.choice(matches)
        char_class = match.group()

        # Mutation options
        mutations = [
            # Negate/un-negate
            lambda c: "[^" + c[1:] if not c.startswith("[^") else "[" + c[2:],
            # Add a character
            lambda c: c[:-1] + random.choice("aeiou0-9_") + "]",
            # Replace with escape
            lambda c: random.choice(self.CHAR_ESCAPES),
            # Replace with dot
            lambda c: ".",
        ]

        mutated_class = random.choice(mutations)(char_class)
        return pattern[:match.start()] + mutated_class + pattern[match.end():]

    def _mutate_escape(self, pattern: str) -> str:
        """Mutate escape sequences."""
        # Find escape sequences
        escape_regex = r"\\[dDwWsSbBAzZ]"
        matches = list(re.finditer(escape_regex, pattern))

        if not matches:
            # Insert an escape
            if len(pattern) > 0:
                pos = random.randint(0, len(pattern))
                return pattern[:pos] + random.choice(self.CHAR_ESCAPES) + pattern[pos:]
            return pattern

        match = random.choice(matches)
        new_escape = random.choice(self.CHAR_ESCAPES)
        return pattern[:match.start()] + new_escape + pattern[match.end():]

    def _mutate_group(self, pattern: str) -> str:
        """Mutate groups (...)."""
        # Find groups - simple matching for opening
        group_starts = []
        i = 0
        while i < len(pattern):
            if pattern[i] == "(" and (i == 0 or pattern[i-1] != "\\"):
                # Find the group prefix end
                prefix_end = i + 1
                if i + 1 < len(pattern) and pattern[i + 1] == "?":
                    # Extended group syntax
                    j = i + 2
                    while j < len(pattern) and pattern[j] in ":<>=!":
                        j += 1
                    prefix_end = j
                group_starts.append((i, prefix_end))
            i += 1

        if not group_starts:
            # Wrap something in a group
            if len(pattern) > 2:
                start = random.randint(0, len(pattern) - 2)
                end = random.randint(start + 1, min(start + 10, len(pattern)))
                prefix = random.choice(self.GROUP_PREFIXES)
                return pattern[:start] + prefix + pattern[start:end] + ")" + pattern[end:]
            return pattern

        # Modify a group's prefix
        start, prefix_end = random.choice(group_starts)
        new_prefix = random.choice(self.GROUP_PREFIXES)
        return pattern[:start] + new_prefix + pattern[prefix_end:]

    def _mutate_anchor(self, pattern: str) -> str:
        """Add, remove, or change anchors."""
        # Find anchors
        anchor_regex = r"\^|\$|\\[AbBzZ]"
        matches = list(re.finditer(anchor_regex, pattern))

        if not matches or random.random() < 0.5:
            # Add an anchor
            if random.random() < 0.5:
                # Add at start
                return random.choice(["^", r"\A"]) + pattern
            else:
                # Add at end
                return pattern + random.choice(["$", r"\z", r"\Z"])

        # Remove or replace an anchor
        match = random.choice(matches)
        if random.random() < 0.3:
            # Remove
            return pattern[:match.start()] + pattern[match.end():]
        else:
            # Replace
            new_anchor = random.choice(self.ANCHORS)
            return pattern[:match.start()] + new_anchor + pattern[match.end():]

    def _mutate_alternation(self, pattern: str) -> str:
        """Mutate alternation |."""
        # Find | not in character class
        pipe_positions = []
        in_class = False
        for i, c in enumerate(pattern):
            if c == "[" and (i == 0 or pattern[i-1] != "\\"):
                in_class = True
            elif c == "]" and in_class:
                in_class = False
            elif c == "|" and not in_class:
                pipe_positions.append(i)

        if not pipe_positions:
            # Add alternation
            if len(pattern) > 2:
                pos = random.randint(1, len(pattern) - 1)
                alternatives = ["a", "[0-9]", r"\w+", ".", "x*"]
                return pattern[:pos] + "|" + random.choice(alternatives) + pattern[pos:]
            return pattern

        # Modify around a pipe
        pos = random.choice(pipe_positions)
        if random.random() < 0.3:
            # Remove the pipe and one side
            return pattern[:pos] + pattern[pos+1:]
        else:
            # Swap sides or add alternative
            return pattern[:pos+1] + random.choice(["", "x", r"\d"]) + pattern[pos+1:]

    def _insert_random_element(self, pattern: str) -> str:
        """Insert a random regex element."""
        elements = [
            ".", "a", "[a-z]", r"\d", r"\w", r"\s",
            "(x)", "(?:y)", "z+", "w*", "[0-9]",
        ]
        pos = random.randint(0, len(pattern))
        return pattern[:pos] + random.choice(elements) + pattern[pos:]

    def _delete_random_element(self, pattern: str) -> str:
        """Delete a random part of the pattern."""
        if len(pattern) <= 2:
            return pattern

        start = random.randint(0, len(pattern) - 2)
        length = random.randint(1, min(3, len(pattern) - start))
        return pattern[:start] + pattern[start + length:]

    def _duplicate_element(self, pattern: str) -> str:
        """Duplicate a part of the pattern."""
        if len(pattern) <= 1:
            return pattern + pattern

        start = random.randint(0, len(pattern) - 1)
        length = random.randint(1, min(5, len(pattern) - start))
        element = pattern[start:start + length]
        insert_pos = random.randint(0, len(pattern))
        return pattern[:insert_pos] + element + pattern[insert_pos:]

    def _splice_patterns(self, pattern1: str, pattern2: str) -> str:
        """Combine parts of two patterns (crossover)."""
        if not pattern1 or not pattern2:
            return pattern1 or pattern2

        # Take prefix from pattern1, suffix from pattern2
        split1 = random.randint(0, len(pattern1))
        split2 = random.randint(0, len(pattern2))

        return pattern1[:split1] + pattern2[split2:]


def mutate_pattern(pattern: str, corpus: Optional[List[str]] = None) -> str:
    """Convenience function to mutate a pattern.

    Args:
        pattern: Pattern to mutate
        corpus: Optional corpus patterns for splicing

    Returns:
        Mutated pattern
    """
    return GrammarMutator().mutate(pattern, corpus)
