"""PCRE2 fuzz dictionary for enhanced mutation strategies.

This module provides a categorized dictionary of PCRE2 tokens that can be
used alongside grammar-aware mutation to improve fuzzing effectiveness.

Uses yapp's grammar-aware insert function for semantically correct insertions.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Literal, Optional

from loguru import logger

# Import yapp's grammar-aware insert function
try:
    from yapp.util import insert as yapp_insert
    from yapp.util import InsertError, InvalidConstructError, NoValidPositionError
    YAPP_INSERT_AVAILABLE = True
except ImportError:
    YAPP_INSERT_AVAILABLE = False
    logger.warning("yapp.util.insert not available, falling back to string-level injection")


class TokenCategory(Enum):
    """Categories of regex tokens for smart mutation."""
    ANCHOR = auto()           # ^, $, \b, etc.
    CHAR_CLASS = auto()       # \d, \w, \s, etc.
    POSIX_CLASS = auto()      # [:alnum:], [:alpha:], etc.
    UNICODE_PROP = auto()     # \p{L}, \P{N}, etc.
    QUANTIFIER = auto()       # *, +, ?, {n,m}, etc.
    GROUP_OPEN = auto()       # (, (?:, (?>, etc.
    GROUP_CLOSE = auto()      # )
    BACKREFERENCE = auto()    # \1, \g{1}, etc.
    CONDITIONAL = auto()      # (?(1), (?(R), etc.
    FLAG = auto()             # (?i), (?m), etc.
    BACKTRACK_VERB = auto()   # (*ACCEPT), (*FAIL), etc.
    SUBROUTINE = auto()       # (?R), (?1), etc.
    CHAR_ESCAPE = auto()      # \x00, \n, \t, etc.
    CHAR_CLASS_OP = auto()    # [^, [a-z], etc.
    ASSERTION = auto()        # (?=, (?!, (?<=, (?<!
    SCRIPT_RUN = auto()       # (*sr:, (*asr:, etc.
    OPTION = auto()           # (*UTF), (*UCP), (*CR), etc.
    CALLOUT = auto()          # (?C), (?C0), etc.
    SPECIAL = auto()          # \K, ., etc.
    ATOM = auto()             # Standalone matchable tokens


@dataclass
class DictionaryEntry:
    """A single dictionary entry with metadata."""
    token: str
    category: TokenCategory
    weight: float = 1.0  # Higher weight = more likely to be selected
    is_atom: bool = False  # Can stand alone as a complete pattern element


@dataclass
class FuzzDictionary:
    """PCRE2 fuzz dictionary with categorized tokens."""

    entries: list[DictionaryEntry] = field(default_factory=list)
    by_category: dict[TokenCategory, list[DictionaryEntry]] = field(default_factory=dict)
    atoms: list[DictionaryEntry] = field(default_factory=list)

    def __post_init__(self):
        """Initialize category index."""
        for cat in TokenCategory:
            self.by_category[cat] = []

    def add(self, token: str, category: TokenCategory,
            weight: float = 1.0, is_atom: bool = False) -> None:
        """Add a token to the dictionary."""
        entry = DictionaryEntry(token, category, weight, is_atom)
        self.entries.append(entry)
        self.by_category[category].append(entry)
        if is_atom:
            self.atoms.append(entry)

    def get_random(self, category: Optional[TokenCategory] = None) -> str:
        """Get a random token, optionally from a specific category."""
        if category and self.by_category[category]:
            entries = self.by_category[category]
        else:
            entries = self.entries

        if not entries:
            return ""

        # Weighted random selection
        weights = [e.weight for e in entries]
        total = sum(weights)
        r = random.random() * total
        cumulative = 0
        for entry in entries:
            cumulative += entry.weight
            if r <= cumulative:
                return entry.token
        return entries[-1].token

    def get_random_atom(self) -> str:
        """Get a random atom (standalone matchable token)."""
        if not self.atoms:
            return "."
        return random.choice(self.atoms).token

    def get_random_quantifier(self) -> str:
        """Get a random quantifier."""
        return self.get_random(TokenCategory.QUANTIFIER)

    def get_random_group_open(self) -> str:
        """Get a random group opener."""
        return self.get_random(TokenCategory.GROUP_OPEN)

    def get_random_assertion(self) -> str:
        """Get a random assertion."""
        return self.get_random(TokenCategory.ASSERTION)

    def generate_random_pattern(self, max_tokens: int = 10) -> str:
        """Generate a random pattern using dictionary tokens."""
        tokens = []
        num_tokens = random.randint(1, max_tokens)

        for _ in range(num_tokens):
            # Weighted selection of what to add
            r = random.random()
            if r < 0.4:
                # Add an atom
                tokens.append(self.get_random_atom())
            elif r < 0.6:
                # Add quantifier to last token if exists
                if tokens:
                    tokens.append(self.get_random_quantifier())
            elif r < 0.7:
                # Add a group
                tokens.append(self.get_random_group_open())
                tokens.append(self.get_random_atom())
                tokens.append(")")
            elif r < 0.8:
                # Add an assertion
                tokens.append(self.get_random_assertion())
            elif r < 0.9:
                # Add a flag
                tokens.append(self.get_random(TokenCategory.FLAG))
            else:
                # Add any random token
                tokens.append(self.get_random())

        return "".join(tokens)

    def inject_into_pattern(
        self,
        pattern: str,
        num_injections: int = 1,
        strategy: Literal["first", "last", "all", "random"] = "random"
    ) -> str:
        """Inject dictionary tokens into a pattern using grammar-aware insertion.

        Uses yapp's insert function for semantically correct insertions that
        maintain regex validity.

        Args:
            pattern: The regex pattern to modify
            num_injections: Number of tokens to inject
            strategy: Insertion strategy - "first", "last", "all", or "random"

        Returns:
            Modified pattern with injected tokens
        """
        if not pattern:
            return self.get_random_atom()

        result = pattern

        for _ in range(num_injections):
            token = self.get_random()

            if YAPP_INSERT_AVAILABLE:
                try:
                    result = yapp_insert(result, token, insert_strategy=strategy)
                except (InsertError, InvalidConstructError, NoValidPositionError, ValueError):
                    # If grammar-aware insert fails, try a different token
                    for _ in range(3):  # Try up to 3 different tokens
                        token = self.get_random()
                        try:
                            result = yapp_insert(result, token, insert_strategy=strategy)
                            break
                        except (InsertError, InvalidConstructError, NoValidPositionError, ValueError):
                            continue
                    else:
                        # All attempts failed, skip this injection
                        logger.debug(f"Could not insert any token into pattern: {pattern[:50]}")
                except Exception as e:
                    logger.debug(f"Unexpected error in yapp_insert: {e}")
            else:
                # Fallback to naive string insertion
                pos = random.randint(0, len(result))
                result = result[:pos] + token + result[pos:]

        return result

    def smart_insert(
        self,
        pattern: str,
        construct: str,
        strategy: Literal["first", "last", "all", "random"] = "random"
    ) -> Optional[str]:
        """Insert a specific construct into a pattern using grammar-aware insertion.

        Args:
            pattern: The regex pattern to modify
            construct: The PCRE construct to insert (e.g., "*", "(?:", "\\d")
            strategy: Insertion strategy

        Returns:
            Modified pattern or None if insertion failed
        """
        if not YAPP_INSERT_AVAILABLE:
            # Fallback: just append the construct
            return pattern + construct if pattern else construct

        try:
            return yapp_insert(pattern, construct, insert_strategy=strategy)
        except (InsertError, InvalidConstructError, NoValidPositionError, ValueError) as e:
            logger.debug(f"smart_insert failed for '{construct}': {e}")
            return None
        except Exception as e:
            logger.debug(f"Unexpected error in smart_insert: {e}")
            return None

    @classmethod
    def load_pcre2_dictionary(cls) -> "FuzzDictionary":
        """Load the default PCRE2 fuzz dictionary."""
        d = cls()

        # Anchors and boundaries
        for token in ["^", "$", "\\A", "\\Z", "\\z", "\\b", "\\B"]:
            d.add(token, TokenCategory.ANCHOR)

        # Character classes (atoms)
        for token in ["\\d", "\\D", "\\w", "\\W", "\\s", "\\S",
                      "\\h", "\\H", "\\v", "\\V", "\\R", "\\N"]:
            d.add(token, TokenCategory.CHAR_CLASS, is_atom=True)

        # POSIX classes
        for token in ["[:alnum:]", "[:alpha:]", "[:ascii:]", "[:blank:]",
                      "[:cntrl:]", "[:digit:]", "[:graph:]", "[:lower:]",
                      "[:print:]", "[:punct:]", "[:space:]", "[:upper:]",
                      "[:word:]", "[:xdigit:]"]:
            d.add(token, TokenCategory.POSIX_CLASS)

        # Unicode properties (atoms) - COMPREHENSIVE for coverage
        # General categories (top-level)
        for token in ["\\p{L}", "\\p{Lu}", "\\p{Ll}", "\\p{Lt}", "\\p{Lm}", "\\p{Lo}",
                      "\\p{M}", "\\p{Mn}", "\\p{Mc}", "\\p{Me}",
                      "\\p{N}", "\\p{Nd}", "\\p{Nl}", "\\p{No}",
                      "\\p{P}", "\\p{Pc}", "\\p{Pd}", "\\p{Ps}", "\\p{Pe}", "\\p{Pi}", "\\p{Pf}", "\\p{Po}",
                      "\\p{S}", "\\p{Sm}", "\\p{Sc}", "\\p{Sk}", "\\p{So}",
                      "\\p{Z}", "\\p{Zs}", "\\p{Zl}", "\\p{Zp}",
                      "\\p{C}", "\\p{Cc}", "\\p{Cf}", "\\p{Cs}", "\\p{Co}", "\\p{Cn}"]:
            d.add(token, TokenCategory.UNICODE_PROP, is_atom=True, weight=0.5)

        # Negated categories
        for token in ["\\P{L}", "\\P{N}", "\\P{S}", "\\P{P}", "\\P{Z}", "\\P{C}", "\\P{M}"]:
            d.add(token, TokenCategory.UNICODE_PROP, is_atom=True, weight=0.3)

        # Script names
        for token in ["\\p{Arabic}", "\\p{Armenian}", "\\p{Bengali}", "\\p{Cyrillic}",
                      "\\p{Greek}", "\\p{Han}", "\\p{Hangul}", "\\p{Hebrew}",
                      "\\p{Hiragana}", "\\p{Katakana}", "\\p{Latin}", "\\p{Thai}",
                      "\\p{Common}", "\\p{Inherited}"]:
            d.add(token, TokenCategory.UNICODE_PROP, is_atom=True, weight=0.3)

        # Binary properties
        for token in ["\\p{Alphabetic}", "\\p{Any}", "\\p{ASCII}",
                      "\\p{Lowercase}", "\\p{Uppercase}", "\\p{White_Space}",
                      "\\p{Hex_Digit}", "\\p{Emoji}"]:
            d.add(token, TokenCategory.UNICODE_PROP, is_atom=True, weight=0.3)

        # \X for extended grapheme cluster
        d.add("\\X", TokenCategory.UNICODE_PROP, is_atom=True)

        # Single byte match (PCRE specific - caused bugs!)
        d.add("\\C", TokenCategory.CHAR_CLASS, is_atom=True, weight=1.5)

        # Empty/malformed property braces (edge cases)
        d.add("\\p{}", TokenCategory.UNICODE_PROP, is_atom=True, weight=0.5)
        d.add("\\P{}", TokenCategory.UNICODE_PROP, is_atom=True, weight=0.5)

        # Property value syntax
        for token in ["\\p{gc=L}", "\\p{gc=N}", "\\p{gc=P}", "\\p{gc=S}",
                      "\\p{Script=Latin}", "\\p{Script=Greek}", "\\p{Script=Han}",
                      "\\p{sc=Latn}", "\\p{sc=Grek}", "\\p{sc=Hani}",
                      "\\p{General_Category=Letter}", "\\p{Block=Basic_Latin}"]:
            d.add(token, TokenCategory.UNICODE_PROP, is_atom=True, weight=0.3)

        # Quantifiers
        for token in ["*", "+", "?", "*?", "+?", "??", "*+", "++", "?+",
                      "{1}", "{1,}", "{1,2}", "{1,2}?", "{1,2}+"]:
            d.add(token, TokenCategory.QUANTIFIER)

        # Group openers
        for token in ["(", "(?:", "(?>", "(?|", "(?=", "(?!",
                      "(?<=", "(?<!", "(?<name>", "(?'name'", "(?P<name>"]:
            d.add(token, TokenCategory.GROUP_OPEN)

        # Group close
        d.add(")", TokenCategory.GROUP_CLOSE)

        # Backreferences
        for token in ["\\1", "\\g{1}", "\\g{-1}", "\\g{name}",
                      "\\k<name>", "\\k'name'", "(?P=name)"]:
            d.add(token, TokenCategory.BACKREFERENCE)

        # Relative backreferences (PCRE specific)
        for token in ["\\g{+1}", "\\g{+2}", "\\g{-1}", "\\g{-2}"]:
            d.add(token, TokenCategory.BACKREFERENCE, weight=0.5)

        # Conditionals - COMPREHENSIVE for coverage
        # Numbered conditionals
        for token in ["(?(1)", "(?(2)", "(?(3)"]:
            d.add(token, TokenCategory.CONDITIONAL, weight=0.7)

        # Recursion conditionals
        for token in ["(?(R)", "(?(R1)", "(?(R2)"]:
            d.add(token, TokenCategory.CONDITIONAL, weight=0.5)

        # Named conditionals
        for token in ["(?(<name>)", "(?(name)", "(?('name')"]:
            d.add(token, TokenCategory.CONDITIONAL, weight=0.5)

        # Assertion conditionals
        for token in ["(?(assert)", "(?(?=)", "(?(?!)", "(?(?<=)", "(?(?<!)"]:
            d.add(token, TokenCategory.CONDITIONAL, weight=0.3)

        # DEFINE block (special case)
        d.add("(?(DEFINE)", TokenCategory.CONDITIONAL, weight=0.5)

        # Flags
        for token in ["(?i)", "(?m)", "(?s)", "(?x)", "(?-i)", "(?i:)"]:
            d.add(token, TokenCategory.FLAG)

        # Backtrack control verbs - COMPREHENSIVE for coverage
        # Basic verbs
        for token in ["(*ACCEPT)", "(*FAIL)", "(*F)"]:
            d.add(token, TokenCategory.BACKTRACK_VERB, weight=0.7)

        # Named marks
        for token in ["(*MARK:name)", "(*:name)", "(*MARK:A)", "(*:X)"]:
            d.add(token, TokenCategory.BACKTRACK_VERB, weight=0.5)

        # Backtracking control
        for token in ["(*COMMIT)", "(*COMMIT:name)"]:
            d.add(token, TokenCategory.BACKTRACK_VERB, weight=0.5)

        for token in ["(*PRUNE)", "(*PRUNE:name)"]:
            d.add(token, TokenCategory.BACKTRACK_VERB, weight=0.5)

        for token in ["(*SKIP)", "(*SKIP:name)"]:
            d.add(token, TokenCategory.BACKTRACK_VERB, weight=0.5)

        for token in ["(*THEN)", "(*THEN:name)"]:
            d.add(token, TokenCategory.BACKTRACK_VERB, weight=0.5)

        # Atomic/possessive groups
        for token in ["(?>", "(?>.*)"]:
            d.add(token, TokenCategory.GROUP_OPEN)

        # Subroutine calls and recursion - COMPREHENSIVE for coverage
        # Full recursion
        for token in ["(?R)", "(?0)"]:
            d.add(token, TokenCategory.SUBROUTINE, weight=0.7)

        # Numbered recursion/subroutine calls
        for token in ["(?1)", "(?2)", "(?3)", "(?+1)", "(?+2)", "(?-1)", "(?-2)"]:
            d.add(token, TokenCategory.SUBROUTINE, weight=0.5)

        # Named recursion
        for token in ["(?&name)", "(?P>name)", "\\g<name>", "\\g<1>", "\\g<-1>"]:
            d.add(token, TokenCategory.SUBROUTINE, weight=0.5)

        # Character escapes (atoms)
        for token in ["\\x00", "\\x7f", "\\xff", "\\x{100}", "\\x{10FFFF}",
                      "\\o{177}", "\\c@", "\\cA", "\\e", "\\f",
                      "\\n", "\\r", "\\t", "\\0"]:
            d.add(token, TokenCategory.CHAR_ESCAPE, is_atom=True)

        # Character class operations
        for token in ["[^", "[a-z]", "[\\d]", "[[:alpha:]]", "[^[:space:]]"]:
            d.add(token, TokenCategory.CHAR_CLASS_OP)

        # Literal quoting blocks
        for token in ["\\Q\\E", "\\Qtext\\E", "\\Q[test]\\E", "\\Q.*\\E"]:
            d.add(token, TokenCategory.CHAR_ESCAPE, is_atom=True, weight=0.5)

        # Negated POSIX classes
        for token in ["[[:^alnum:]]", "[[:^alpha:]]", "[[:^digit:]]",
                      "[[:^space:]]", "[[:^word:]]"]:
            d.add(token, TokenCategory.POSIX_CLASS, is_atom=True, weight=0.3)

        # Assertions (lookahead/lookbehind)
        for token in ["(?=.*)", "(?!.*)", "(?<=.)", "(?<!.)"]:
            d.add(token, TokenCategory.ASSERTION)

        # Script runs (PCRE2)
        for token in ["(*sr:", "(*atomic_script_run:", "(*asr:"]:
            d.add(token, TokenCategory.SCRIPT_RUN, weight=0.3)

        # Newline options
        for token in ["(*CR)", "(*LF)", "(*CRLF)", "(*ANYCRLF)",
                      "(*ANY)", "(*NUL)"]:
            d.add(token, TokenCategory.OPTION, weight=0.3)

        # UTF and UCP options
        for token in ["(*UTF)", "(*UCP)", "(*NO_START_OPT)",
                      "(*NO_AUTO_POSSESS)", "(*LIMIT_HEAP=",
                      "(*LIMIT_MATCH=", "(*LIMIT_DEPTH="]:
            d.add(token, TokenCategory.OPTION, weight=0.3)

        # Callouts - COMPREHENSIVE for coverage
        # Numbered callouts
        for token in ["(?C)", "(?C0)", "(?C1)", "(?C127)", "(?C255)"]:
            d.add(token, TokenCategory.CALLOUT, weight=0.3)

        # Named callouts (PCRE2 style)
        for token in ["(?C'name')", "(?C{name})"]:
            d.add(token, TokenCategory.CALLOUT, weight=0.2)

        # Special tokens
        d.add("\\K", TokenCategory.SPECIAL)
        d.add(".", TokenCategory.SPECIAL, is_atom=True, weight=2.0)

        # Add common literal atoms with higher weight
        for char in "abcdefghijklmnopqrstuvwxyz0123456789":
            d.add(char, TokenCategory.ATOM, is_atom=True, weight=0.5)

        return d


# Global dictionary instance
_PCRE2_DICTIONARY: Optional[FuzzDictionary] = None


def get_pcre2_dictionary() -> FuzzDictionary:
    """Get the global PCRE2 dictionary instance."""
    global _PCRE2_DICTIONARY
    if _PCRE2_DICTIONARY is None:
        _PCRE2_DICTIONARY = FuzzDictionary.load_pcre2_dictionary()
    return _PCRE2_DICTIONARY
