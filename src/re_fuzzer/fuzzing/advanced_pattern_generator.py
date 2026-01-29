"""Advanced pattern generator for targeted PCRE feature testing.

Alternative backend to Superion-style mutation for ablation comparison.
Generates patterns by combining feature templates rather than mutating existing patterns.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional


class PCREFeature(Enum):
    """PCRE features to target for coverage."""
    RECURSION = auto()           # (?R), (?1), (?&name)
    CONDITIONAL = auto()         # (?(1)yes|no), (?(R)yes)
    BACKTRACK_CONTROL = auto()   # (*ACCEPT), (*FAIL), (*COMMIT)
    CALLOUT = auto()             # (?C), (?C1)
    ATOMIC_GROUP = auto()        # (?>...)
    LOOKAHEAD = auto()           # (?=...), (?!...)
    LOOKBEHIND = auto()          # (?<=...), (?<!...)
    NAMED_GROUP = auto()         # (?<name>...), (?P<name>...)
    SUBROUTINE = auto()          # (?&name), (?P>name)
    UNICODE_PROPERTY = auto()    # \p{...}, \P{...}
    SCRIPT_RUN = auto()          # (*sr:...), (*asr:...)
    POSSESSIVE = auto()          # *+, ++, ?+
    RESET_MATCH = auto()         # \K
    # PCRE 8.45-specific features for better coverage
    BRANCH_RESET = auto()        # (?|...) - branch reset groups
    GRAPHEME_CLUSTER = auto()    # \X - extended grapheme cluster
    DEEP_RECURSION = auto()      # Patterns targeting recursion depth
    DFA_FRIENDLY = auto()        # Patterns optimized for DFA engine


@dataclass
class FeatureTemplate:
    """Template for generating a specific PCRE feature."""
    feature: PCREFeature
    patterns: list[str]          # Template strings with {0}, {1} placeholders
    requires: list[PCREFeature] = field(default_factory=list)
    weight: float = 1.0          # Selection weight


class AdvancedPatternGenerator:
    """Generate patterns targeting specific PCRE features.

    This generator creates regex patterns by combining feature-specific templates.
    Unlike the Superion-style mutation approach which modifies existing patterns,
    this generator builds patterns from scratch using templates designed to exercise
    specific PCRE features.

    Usage:
        generator = AdvancedPatternGenerator()
        pattern = generator.generate()  # Get a random pattern
        pattern = generator.generate_single_feature()  # Get pattern for one feature
    """

    def __init__(self, feature_weights: Optional[dict[PCREFeature, float]] = None):
        """Initialize the generator.

        Args:
            feature_weights: Optional weights for feature selection.
                            Higher weights mean the feature is more likely to be selected.
        """
        self.templates = self._build_templates()
        self.feature_weights = feature_weights or {}
        self.stats: dict[str, int | dict[PCREFeature, int]] = {
            "generated": 0,
            "by_feature": {f: 0 for f in PCREFeature}
        }

    def _build_templates(self) -> dict[PCREFeature, FeatureTemplate]:
        """Build feature templates."""
        return {
            PCREFeature.RECURSION: FeatureTemplate(
                feature=PCREFeature.RECURSION,
                patterns=[
                    "({0}(?R)?)",           # Simple recursion
                    "({0}(?1))*",           # Numbered subroutine
                    "(?<r>{0}(?&r)?)",      # Named recursion
                    "((?R)|{0})",           # Alternation with recursion
                    "(?:({0})(?1)?)+",      # Nested numbered calls
                    "({0}(?R){1})",         # Recursion with suffix
                    "(a(?:b(?R)?c)?d)",     # Palindrome-like
                ],
                weight=1.5
            ),
            PCREFeature.CONDITIONAL: FeatureTemplate(
                feature=PCREFeature.CONDITIONAL,
                patterns=[
                    "({0})(?(1){1}|{2})",           # Group reference conditional
                    "(?(R){0}|{1})",                # Recursion conditional
                    "(?(<name>){0}|{1})",           # Named reference conditional
                    "(?(DEFINE)(?<x>{0}))(?&x)",   # DEFINE block
                    "({0})(?(1){1})(?(1){2})",     # Multiple conditionals
                    "(?(R1){0}|{1})",               # Specific recursion conditional
                    "({0})?{1}(?(1){2})",          # Optional capture conditional
                ],
                weight=1.5
            ),
            PCREFeature.BACKTRACK_CONTROL: FeatureTemplate(
                feature=PCREFeature.BACKTRACK_CONTROL,
                patterns=[
                    "{0}(*ACCEPT)",
                    "{0}|(*FAIL)",
                    "{0}(*COMMIT){1}",
                    "{0}(*PRUNE){1}",
                    "{0}(*SKIP){1}",
                    "{0}(*MARK:A)(*SKIP:A){1}",
                    "(*:name){0}(*SKIP:name)",
                    "{0}(*THEN){1}|{2}",
                    "{0}(*F)|{1}",
                ],
                weight=1.2
            ),
            PCREFeature.CALLOUT: FeatureTemplate(
                feature=PCREFeature.CALLOUT,
                patterns=[
                    "{0}(?C){1}",
                    "{0}(?C0){1}",
                    "{0}(?C255){1}",
                    "(?C'tag'){0}",
                    "{0}(?C1)(?C2){1}",
                    "(?C{name}){0}",
                ],
                weight=0.8
            ),
            PCREFeature.ATOMIC_GROUP: FeatureTemplate(
                feature=PCREFeature.ATOMIC_GROUP,
                patterns=[
                    "(?>{0}+)",
                    "(?>{0}|{1})",
                    "(?>(?>){0})",        # Nested atomic
                    "(?>{0})*{1}",
                    "(?>{0}*){1}",
                    "(?>{0})+?{1}",       # Atomic with lazy outer
                ],
                weight=1.0
            ),
            PCREFeature.LOOKAHEAD: FeatureTemplate(
                feature=PCREFeature.LOOKAHEAD,
                patterns=[
                    "(?={0}){1}",          # Positive lookahead
                    "(?!{0}){1}",          # Negative lookahead
                    "(?=(?={0}){1}){2}",   # Nested lookahead
                    "{0}(?={1})(?={2})",   # Multiple lookaheads
                    "(?={0}){0}",          # Lookahead matching same
                    "(?!(?!{0})){1}",      # Double negative
                ],
                weight=1.0
            ),
            PCREFeature.LOOKBEHIND: FeatureTemplate(
                feature=PCREFeature.LOOKBEHIND,
                patterns=[
                    "(?<={0}){1}",         # Positive lookbehind
                    "(?<!{0}){1}",         # Negative lookbehind
                    "(?<={0})(?<={1}){2}", # Multiple lookbehinds
                    "(?<=a|b){0}",         # Alternation in lookbehind
                    "(?<!(?<!{0})){1}",    # Double negative lookbehind
                ],
                weight=1.0
            ),
            PCREFeature.NAMED_GROUP: FeatureTemplate(
                feature=PCREFeature.NAMED_GROUP,
                patterns=[
                    "(?<name>{0})\\k<name>",      # Named with backref
                    "(?P<name>{0})(?P=name)",     # Python-style named
                    "(?'name'{0})\\k'name'",      # Perl-style named
                    "(?<a>{0})(?<b>{1})\\k<a>\\k<b>",  # Multiple named
                ],
                weight=1.0
            ),
            PCREFeature.SUBROUTINE: FeatureTemplate(
                feature=PCREFeature.SUBROUTINE,
                patterns=[
                    "(?<sub>{0})(?&sub)",         # Named subroutine
                    "({0})(?1)",                  # Numbered subroutine
                    "(?P<sub>{0})(?P>sub)",       # Python-style subroutine
                    "({0})({1})(?1)(?2)",         # Multiple subroutines
                    "(?<a>(?<b>{0})(?&b))(?&a)",  # Nested subroutines
                ],
                weight=1.2
            ),
            PCREFeature.UNICODE_PROPERTY: FeatureTemplate(
                feature=PCREFeature.UNICODE_PROPERTY,
                patterns=[
                    "\\p{L}+{0}",
                    "\\P{N}*{0}",
                    "[\\p{L}\\p{N}]+{0}",
                    "\\p{Script=Latin}+{0}",
                    "\\p{gc=L}{0}\\P{gc=N}",
                    "\\C+{0}",                     # Single byte (PCRE specific)
                    "\\p{}{0}",                   # Empty property (edge case)
                    "\\P{}{0}",                   # Empty negated property
                    "\\p{Han}*{0}",
                    "\\p{Block=Basic_Latin}{0}",
                ],
                weight=1.2
            ),
            PCREFeature.SCRIPT_RUN: FeatureTemplate(
                feature=PCREFeature.SCRIPT_RUN,
                patterns=[
                    "(*sr:{0}+)",
                    "(*atomic_script_run:{0}+)",
                    "(*asr:{0}+)",
                    "(*sr:{0}|{1})",
                ],
                weight=0.8
            ),
            PCREFeature.POSSESSIVE: FeatureTemplate(
                feature=PCREFeature.POSSESSIVE,
                patterns=[
                    "{0}++",
                    "{0}*+",
                    "{0}?+",
                    "{0}{1,}+",
                    "({0}++)*+",           # Nested possessive
                    "{0}++{1}++",          # Multiple possessive
                    "(?:{0}++)+",          # Possessive in group
                ],
                weight=1.0
            ),
            PCREFeature.RESET_MATCH: FeatureTemplate(
                feature=PCREFeature.RESET_MATCH,
                patterns=[
                    "{0}\\K{1}",
                    "(?:{0}\\K)+{1}",
                    "{0}\\K{1}\\K{2}",     # Multiple resets
                    "({0})\\K({1})",       # Reset between captures
                ],
                weight=0.8
            ),
            # PCRE 8.45-specific features
            PCREFeature.BRANCH_RESET: FeatureTemplate(
                feature=PCREFeature.BRANCH_RESET,
                patterns=[
                    "(?|({0})|({1}))",           # Branch reset - both branches get group 1
                    "(?|({0})({1})|({2}))",      # Multiple groups in branch reset
                    "(?|(?:({0})|({1})))",       # Nested with non-capturing
                    "(?|({0})|({1}))\\1",        # Branch reset with backref
                    "(?|(?<n>{0})|(?<n>{1}))\\k<n>",  # Named branch reset
                ],
                weight=1.5
            ),
            PCREFeature.GRAPHEME_CLUSTER: FeatureTemplate(
                feature=PCREFeature.GRAPHEME_CLUSTER,
                patterns=[
                    "\\X+{0}",                    # Extended grapheme cluster
                    "\\X*{0}\\X",                # Multiple grapheme matches
                    "(?:{0}\\X)+",               # Grapheme in repetition
                    "\\X{1,5}{0}",               # Bounded grapheme quantifier
                    "(?=\\X){0}",                # Grapheme in lookahead
                ],
                weight=1.0
            ),
            PCREFeature.DEEP_RECURSION: FeatureTemplate(
                feature=PCREFeature.DEEP_RECURSION,
                patterns=[
                    "((?R)?{0})",                     # Simple deep recursion
                    "((a(?R)?b))",                    # Palindrome recursion
                    "(({0}(?1)?)+)",                 # Numbered recursion with quantifier
                    "(?<n>(?&n)?{0})",               # Named deep recursion
                    "((?R)|(?R)|{0})",               # Multiple recursion branches
                    "({0}(?1){0}(?1)?)",             # Multiple self-references
                    "((?:(?R)|{0})+)",               # Recursion in alternation
                ],
                weight=2.0  # High weight to stress recursion limit code
            ),
            PCREFeature.DFA_FRIENDLY: FeatureTemplate(
                feature=PCREFeature.DFA_FRIENDLY,
                patterns=[
                    # DFA can find multiple matches - alternation with overlapping
                    "({0}|{0}{1})",
                    # DFA handles long matches differently
                    "{0}+{1}*{0}",
                    # DFA with fixed-length branches
                    "({0}{0}|{1}{1})",
                    # No backreferences (DFA limitation) - pure automata
                    "(?:{0})+(?:{1})*",
                    # Character class heavy (DFA strength)
                    "[{0}]+[{1}]*",
                    # Alternation chains
                    "({0}|{1}|{2})+",
                ],
                weight=1.0
            ),
        }

    def _get_atom(self) -> str:
        """Get a random atomic pattern."""
        atoms = [
            "a", "b", "x", "y",           # Simple literals
            "\\d", "\\w", "\\s",          # Character classes
            "\\D", "\\W", "\\S",          # Negated classes
            ".", "[a-z]", "[0-9]",        # Dot and ranges
            "\\p{L}", "\\p{N}",           # Unicode properties
            "\\C",                         # Single byte (PCRE)
            "[[:alpha:]]",                 # POSIX class
        ]
        return random.choice(atoms)

    def _get_quantified_atom(self) -> str:
        """Get an atom with optional quantifier."""
        atom = self._get_atom()
        quantifiers = ["", "", "", "+", "*", "?", "{1,3}", "++", "*+"]
        quant = random.choice(quantifiers)
        return atom + quant

    def _fill_template(self, template: str, depth: int = 0) -> str:
        """Fill template placeholders with atoms or sub-patterns.

        Args:
            template: Template string with {0}, {1}, etc. placeholders
            depth: Current recursion depth (to prevent infinite nesting)

        Returns:
            Filled template string
        """
        result = template
        placeholder_count = template.count("{")

        for i in range(placeholder_count):
            placeholder = "{" + str(i) + "}"
            if placeholder in result:
                if depth < 2 and random.random() < 0.3:
                    # Recursively generate a sub-pattern
                    sub = self.generate_single_feature(depth + 1)
                    result = result.replace(placeholder, f"({sub})", 1)
                else:
                    result = result.replace(placeholder, self._get_quantified_atom(), 1)

        return result

    def generate_single_feature(self, depth: int = 0) -> str:
        """Generate a pattern for a single random feature.

        Args:
            depth: Current recursion depth

        Returns:
            Generated pattern string
        """
        # Weight selection
        weights = []
        features = list(self.templates.keys())
        for f in features:
            w = self.templates[f].weight
            w *= self.feature_weights.get(f, 1.0)
            weights.append(w)

        total = sum(weights)
        r = random.random() * total
        cumulative = 0.0
        selected = features[0]
        for i, f in enumerate(features):
            cumulative += weights[i]
            if r <= cumulative:
                selected = f
                break

        template = self.templates[selected]
        pattern_template = random.choice(template.patterns)
        result = self._fill_template(pattern_template, depth)

        # Track statistics
        by_feature = self.stats["by_feature"]
        if isinstance(by_feature, dict):
            by_feature[selected] = by_feature.get(selected, 0) + 1

        return result

    def generate_combined(self, num_features: int = 3) -> str:
        """Generate a pattern combining multiple features.

        Args:
            num_features: Number of features to combine

        Returns:
            Combined pattern string
        """
        parts = []
        for _ in range(num_features):
            parts.append(self.generate_single_feature())

        # Combine with alternation or concatenation
        if random.random() < 0.3:
            result = "|".join(parts)
        else:
            result = "".join(f"({p})" for p in parts)

        if isinstance(self.stats["generated"], int):
            self.stats["generated"] += 1

        return result

    def generate(self, max_size: int = 500) -> str:
        """Generate a random pattern.

        This is the main entry point for pattern generation.

        Args:
            max_size: Maximum pattern length

        Returns:
            Generated pattern string
        """
        num_features = random.randint(1, 4)
        pattern = self.generate_combined(num_features)

        if len(pattern) > max_size:
            pattern = pattern[:max_size]

        return pattern

    def get_statistics(self) -> dict:
        """Get generation statistics.

        Returns:
            Dictionary with generation statistics
        """
        return dict(self.stats)

    def reset_statistics(self) -> None:
        """Reset generation statistics."""
        self.stats = {
            "generated": 0,
            "by_feature": {f: 0 for f in PCREFeature}
        }
