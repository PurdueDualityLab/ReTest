"""PCFG-based regex generator: simple, grammar-faithful derivation."""
from __future__ import annotations

from dataclasses import dataclass
import json
import random
from pathlib import Path
from typing import Any, Optional, Union, Iterable

from loguru import logger

from re_fuzzer.input_generator.regex_generator.base_regex_generator import (
    BaseRegexGenerator,
    BaseRegexGeneratorConfig,
)


class PCFGModel:
    """Load and index a PCFG for efficient sampling."""

    def __init__(self, model_data: dict[str, Any]):
        self.pcfg: dict[str, dict[str, Any]] = model_data.get("pcfg", {})

        # Build rule -> [(rhs_tokens, prob)] index
        self._pcfg_index: dict[str, list[tuple[list[str], float]]] = {}
        for lhs, data in self.pcfg.items():
            rules = data.get("rules", {})
            if not rules:
                continue
            items = [(rhs.split(), float(prob)) for rhs, prob in rules.items()]
            # Normalize just in case
            s = sum(p for _, p in items) or 1.0
            items = [(rhs, p / s) for rhs, p in items]
            self._pcfg_index[lhs] = items

    @classmethod
    def load(cls, path: str | Path) -> PCFGModel:
        with open(path, "r") as f:
            data = json.load(f)
        return cls(data)

    def sample_production(self, lhs: str, rng: random.Random) -> Optional[list[str]]:
        if lhs not in self._pcfg_index:
            # try base with ROOT annotation
            if '^' in lhs:
                base = lhs.split('^')[0]
                fallback = f"{base}^ROOT"
                if fallback in self._pcfg_index:
                    lhs = fallback
                else:
                    return None
            else:
                return None
        prods = self._pcfg_index[lhs]
        if not prods:
            return None
        r = rng.random()
        cum = 0.0
        for rhs, p in prods:
            cum += p
            if r <= cum:
                return rhs
        return prods[-1][0]

    def get_minimal_production(self, lhs: str) -> Optional[list[str]]:
        if lhs not in self._pcfg_index:
            if '^' in lhs:
                base = lhs.split('^')[0]
                fallback = f"{base}^ROOT"
                if fallback in self._pcfg_index:
                    lhs = fallback
                else:
                    return None
            else:
                return None
        # Minimal by fewest nonterminals (lowercase names)
        def nonterm_count(rhs: list[str]) -> int:
            return sum(1 for s in rhs if any(c.islower() for c in s.split('^')[0]))
        prods = self._pcfg_index[lhs]
        return min(prods, key=lambda it: nonterm_count(it[0]))[0]


class SimpleTerminalExpander:
    """Mapping from terminal buckets to concrete text with minimal class-range semantics."""

    TERMINAL_MAP = {
        'LPAREN': '(', 'RPAREN': ')', 'LBRACK': '[', 'RBRACK': ']', 'LBRACE': '{', 'RBRACE': '}',
        'STAR': '*', 'PLUS': '+', 'QMARK': '?', 'DOT': '.', 'BSLASH': '\\', 'CARET': '^', 'DOLLAR': '$',
        'ALT': '|', 'COMMA': ',', 'DASH': '-', 'COLON': ':', 'LT': '<', 'GT': '>', 'EQ': '=', 'BANG': '!',
        'HASH': '#', 'AMP': '&', 'APOSTROPHE': "'", 'UNDERSCORE': '_',
        'RANGE_DASH': '-', 'CLASS_NEGATE_SYM': '^', 'CLASS_END': ']', 'CLASS_ESCAPE': '\\',
    }

    def __init__(self, rng: random.Random):
        self.rng = rng
        # Character class state
        self.in_class: int = 0
        self.class_item_count_stack: list[int] = []
        self.prev_class_char: Optional[str] = None
        self.pending_range_start_char: Optional[str] = None
        # Quantifier state
        self.quant_state: Optional[dict[str, Any]] = None
        # Previous token/escape tracking for quantifier gating
        self.prev_terminal: Optional[str] = None
        self.prev_escape: Optional[str] = None
        self.prev_was_escape_atom: bool = False
        self.prev_is_atom: bool = False

    def expand(self, terminal: str) -> str:
        # Character class entry
        if terminal == 'LBRACK':
            self.in_class += 1
            self.class_item_count_stack.append(0)
            self.prev_class_char = None
            self.pending_range_start_char = None
            return self._emit('[', terminal)

        # Character class close (either token form)
        if terminal in {'RBRACK', 'CLASS_END'}:
            out = ''
            if self.class_item_count_stack:
                if self.class_item_count_stack[-1] == 0:
                    # ensure class is non-empty
                    ch = self._sample_class_char('abcdefghijklmnopqrstuvwxyz')
                    out += self._emit(ch, 'CLASS_LETTER')
                self.class_item_count_stack.pop()
            if self.in_class > 0:
                self.in_class -= 1
            self.prev_class_char = None
            self.pending_range_start_char = None
            out += self._emit(']', terminal)
            # A character class is an atom
            self.prev_is_atom = True
            return out

        # Range dash inside class
        if terminal == 'RANGE_DASH' and self.in_class:
            # start a range only if we have a previous literal
            if self.prev_class_char is not None:
                self.pending_range_start_char = self.prev_class_char
            else:
                self.pending_range_start_char = None
            self.prev_class_char = None
            return self._emit('-', terminal)

        # Class-specific literal categories
        if terminal in {'CLASS_LETTER', 'CLASS_DIGIT', 'CLASS_WHITESPACE', 'CLASS_LITERAL', 'CLASS_PUNCTUATION', 'CLASS_OTHER'}:
            if terminal == 'CLASS_LETTER':
                ch = self._sample_class_char('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ')
            elif terminal == 'CLASS_DIGIT':
                ch = self._sample_class_char('0123456789')
            elif terminal == 'CLASS_WHITESPACE':
                ch = self._sample_class_char(' \t')
            else:
                pool = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-'
                ch = self._sample_class_char(pool)
            self._mark_class_item(ch)
            return self._emit(ch, terminal)

        # Quantifier handling
        if terminal == 'LBRACE':
            if self.in_class:
                return self._emit('{', terminal)
            # begin quantifier accumulation
            if not self._quantifier_allowed():
                return self._emit('\\{', terminal)
            self.quant_state = {'lower': '', 'upper': '', 'has_comma': False, 'phase': 'lower'}
            return self._emit('{', terminal)
        if terminal == 'COMMA' and self.quant_state is not None:
            self.quant_state['has_comma'] = True
            self.quant_state['phase'] = 'upper'
            return ''
        if terminal == 'RBRACE':
            if self.quant_state is None:
                return self._emit('}', terminal)
            lower = self.quant_state['lower'] or '0'
            upper = self.quant_state['upper']
            has_comma = self.quant_state['has_comma']
            self.quant_state = None
            if not has_comma:
                out = self._emit(f"{lower}}}", 'RBRACE')
                self.prev_is_atom = False
                return out
            if upper:
                try:
                    li = int(lower)
                    ui = int(upper)
                    if ui < li:
                        li, ui = ui, li
                    out = self._emit(f"{li},{ui}}}", 'RBRACE')
                    self.prev_is_atom = False
                    return out
                except Exception:
                    out = self._emit(f"{lower},{upper}}}", 'RBRACE')
                    self.prev_is_atom = False
                    return out
            else:
                out = self._emit(f"{lower},}}", 'RBRACE')
                self.prev_is_atom = False
                return out

        # Direct mapping for generic tokens
        if terminal in self.TERMINAL_MAP:
            # Group constructs right after LPAREN
            if terminal == 'QMARK' and self.prev_terminal == 'LPAREN':
                self.prev_is_atom = False
                return self._emit('?', terminal)
            if terminal == 'STAR' and self.prev_terminal == 'LPAREN':
                # Support (*...) constructs
                self.prev_is_atom = False
                return self._emit('*', terminal)
            # Handle simple quantifiers with gating
            if terminal in {'STAR', 'PLUS', 'QMARK'} and not self.in_class:
                if not self._quantifier_allowed():
                    # escape to literal
                    escaped = {'STAR': '\\*', 'PLUS': '\\+', 'QMARK': '\\?'}[terminal]
                    # escaped literal char is an atom
                    self.prev_is_atom = True
                    return self._emit(escaped, terminal)
            text = self.TERMINAL_MAP[terminal]
            # If we are emitting a real quantifier, the next token is not an atom
            if terminal in {'STAR', 'PLUS', 'QMARK'} and not self.in_class:
                self.prev_is_atom = False
            # Update atom status for some tokens
            if terminal in {'DOT', 'RPAREN'}:
                self.prev_is_atom = True
            if terminal in {'LPAREN'}:
                self.prev_is_atom = False
            if terminal in {'ALT', 'CARET', 'DOLLAR'}:
                self.prev_is_atom = False
            return self._emit(text, terminal)

        # Escaped literal from bucketing: ESC_XX -> \<char>
        if terminal.startswith('ESC_'):
            hex_part = terminal[4:]
            try:
                if hex_part:
                    ch = chr(int(hex_part, 16))
                    # If inside a class and a range is pending, enforce ordering
                    if self.in_class and self.pending_range_start_char is not None:
                        start_ord = ord(self.pending_range_start_char)
                        if ord(ch) < start_ord:
                            ch = chr(start_ord)
                        self.pending_range_start_char = None
                        self.prev_class_char = ch
                        self._inc_class_items(1)
                        # class items contribute to atom, but overall class handles it
                        return self._emit('\\' + ch, terminal)
                    if self.in_class:
                        # treat as literal inside class
                        self.prev_class_char = ch
                        self._inc_class_items(1)
                    return self._emit('\\' + ch, terminal)
            except ValueError:
                return ''

        # Generic literal classes
        if terminal == 'LETTER':
            self.prev_is_atom = True
            return self._emit(self.rng.choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'), terminal)
        if terminal == 'DIGIT':
            if self.quant_state is not None:
                if self.quant_state['phase'] == 'lower':
                    self.quant_state['lower'] += self.rng.choice('0123456789')
                else:
                    self.quant_state['upper'] += self.rng.choice('0123456789')
                return ''
            self.prev_is_atom = True
            return self._emit(self.rng.choice('0123456789'), terminal)
        if terminal == 'WHITESPACE':
            self.prev_is_atom = True
            return self._emit(self.rng.choice(' \t'), terminal)
        if terminal == 'PUNCTUATION':
            self.prev_is_atom = True
            return self._emit(self.rng.choice("!@#$%^&*_=,.;:"), terminal)
        if terminal == 'LITERAL':
            # fallback to alnum
            self.prev_is_atom = True
            return self._emit(self.rng.choice('abcdefghijklmnopqrstuvwxyz0123456789'), terminal)
        if terminal == 'TOK_OTHER':
            self.prev_is_atom = True
            return self._emit('x', terminal)

        # Unknown token -> empty
        return ''

    _NON_QUANTIFIABLE_ESCAPES = {'\\A', '\\Z', '\\z', '\\G', '\\b', '\\B', '\\K'}

    def _quantifier_allowed(self) -> bool:
        if self.in_class:
            return False
        if self.prev_escape is not None:
            # forbid quantifying certain zero-width escapes
            return self.prev_escape not in self._NON_QUANTIFIABLE_ESCAPES
        # Otherwise rely on prev_is_atom computed during emission
        return self.prev_is_atom

    def _emit(self, text: str, terminal: str) -> str:
        # update previous terminal and escape state
        prev_terminal_before = self.prev_terminal
        self.prev_terminal = terminal
        self.prev_escape = None
        self.prev_was_escape_atom = False
        if text.startswith('\\'):
            # record the escaped form for gating
            if terminal.startswith('ESC_') and len(text) >= 2:
                self.prev_escape = text[:2]
                self.prev_was_escape_atom = True
                self.prev_is_atom = True
            # escaped literal quantifier (e.g., \*, \+, \?) is an atom
            if text in {'\\*', '\\+', '\\?'}:
                self.prev_is_atom = True
        # If previous token was a backslash token and now a LETTER was emitted, combine to detect escapes like \A
        if prev_terminal_before == 'BSLASH' and terminal in {'LETTER', 'DIGIT'} and len(text) == 1:
            # Set a two-char escape for gating
            self.prev_escape = '\\' + text
            # Some escapes are zero-width and non-quantifiable
            if self.prev_escape in self._NON_QUANTIFIABLE_ESCAPES:
                self.prev_is_atom = False
            else:
                self.prev_is_atom = True
        # track class item counts for non-bracket text inside classes
        if self.in_class and terminal not in {'LBRACK', 'RBRACK', 'CLASS_END', 'RANGE_DASH'}:
            # approximate literal count by removing backslashes
            lit = len(text.replace('\\', ''))
            self._inc_class_items(max(1, lit))
        # update prev_class_char if a single literal char was emitted in class
        if self.in_class and len(text.replace('\\', '')) == 1:
            self.prev_class_char = text.replace('\\', '')[-1]
        return text

    def _inc_class_items(self, k: int) -> None:
        if self.class_item_count_stack:
            self.class_item_count_stack[-1] += k

    def _mark_class_item(self, ch: str) -> None:
        self.prev_class_char = ch
        self._inc_class_items(1)
        # close any pending range
        self.pending_range_start_char = None

    def _sample_class_char(self, alphabet: str) -> str:
        if self.pending_range_start_char is None:
            return self.rng.choice(alphabet)
        start_ord = ord(self.pending_range_start_char)
        candidates = [c for c in alphabet if ord(c) >= start_ord]
        if not candidates:
            ch = self.pending_range_start_char
        else:
            ch = self.rng.choice(candidates)
        self.pending_range_start_char = None
        return ch


class PCFGDerivationEngine:
    """Derive a regex from the PCFG by recursive expansion."""

    def __init__(self, model: PCFGModel, rng: random.Random):
        self.model = model
        self.rng = rng
        self.expander = SimpleTerminalExpander(rng)

    def generate(self, max_depth: int = 30) -> str:
        # Fresh expander per generation to avoid state carryover
        self.expander = SimpleTerminalExpander(self.rng)
        tree = self._derive('pcre^ROOT', depth=0, max_depth=max_depth, parent='ROOT')
        regex = self._expand(tree)
        # Neutralize escape sequences that can change bracket semantics before balancing
        regex = self._filter_unsupported_escapes(regex)
        regex = self._balance_character_classes(regex)
        regex = self._sanitize_group_prefixes(regex)
        regex = self._sanitize_class_ranges(regex)
        regex = self._escape_orphan_quantifiers(regex)
        # regex = self._balance_parentheses(regex)
        return regex

    def _derive(self, symbol: str, depth: int, max_depth: int, parent: str) -> Union[str, list]:
        # terminals are uppercase buckets or ESC_* tokens
        if self._is_terminal(symbol):
            return symbol

        annotated = symbol if '^' in symbol else f"{symbol}^{parent}"

        if depth >= max_depth:
            prod = self.model.get_minimal_production(annotated)
            if prod is None:
                return []
            # Shallow expand at depth limit: only keep terminals
            QUANT_TOKENS = {'STAR', 'PLUS', 'QMARK', 'LBRACE', 'COMMA', 'RBRACE'}
            return [s for s in prod if self._is_terminal(s) and s not in QUANT_TOKENS]

        prod = self.model.sample_production(annotated, self.rng)
        if prod is None:
            prod = self.model.get_minimal_production(annotated)
            if prod is None:
                return []

        res = []
        base_symbol = symbol.split('^')[0] if '^' in symbol else symbol
        for rhs in prod:
            res.append(self._derive(rhs, depth + 1, max_depth, base_symbol))
        return res

    def _is_terminal(self, symbol: str) -> bool:
        base = symbol.split('^')[0] if '^' in symbol else symbol
        if base.startswith('ESC_'):
            return True
        # Uppercase bucket tokens and class tokens
        if any(c.islower() for c in base):
            return False
        return True

    def _expand(self, node: Union[str, list]) -> str:
        if isinstance(node, str):
            return self.expander.expand(node)
        if isinstance(node, list):
            parts: list[str] = []
            for ch in node:
                parts.append(self._expand(ch))
            return ''.join(parts)
        return ''

    def _filter_unsupported_escapes(self, regex: str) -> str:
        """Remove or replace escape sequences not supported by PCRE.

        Unsupported in PCRE:
        - \\L, \\l (lowercase)
        - \\U, \\u (uppercase) - except \\uHHHH unicode
        - \\N{name} (named unicode)

        Args:
            regex: Generated regex string

        Returns:
            Regex with unsupported escapes removed
        """
        import re as re_module

        # Convert \uXXXX or \uXXXXXXXX to \x{...}
        def _unicode_repl(match: re_module.Match[str]) -> str:
            hi = match.group(1)
            lo = match.group(2) or ''
            return f"\\x{{{hi}{lo}}}"

        text = re_module.sub(r'\\u([0-9a-fA-F]{4})([0-9a-fA-F]{4})?', _unicode_repl, regex)

        unsupported = {'L': 'L', 'l': 'l', 'U': 'U', 'u': 'u', 'Q': 'Q', 'E': 'E', 'o': 'o'}

        out: list[str] = []
        i = 0
        n = len(text)
        while i < n:
            ch = text[i]
            if ch != '\\':
                out.append(ch)
                i += 1
                continue

            # Count run of backslashes
            j = i
            while j < n and text[j] == '\\':
                j += 1
            slash_count = j - i
            next_char = text[j] if j < n else ''

            # If odd run, last backslash is active; sanitize unsupported sequences
            if slash_count % 2 == 1 and next_char in unsupported:
                out.append('\\' * (slash_count // 2))
                out.append(unsupported[next_char])
                i = j + 1
                continue

            if slash_count % 2 == 1 and next_char == 'N':
                out.append('\\' * (slash_count // 2))
                # Skip optional {...}
                k = j + 1
                if k < n and text[k] == '{':
                    k += 1
                    while k < n and text[k] != '}':
                        k += 1
                    if k < n:
                        k += 1
                out.append('N')
                i = k
                continue

            # Otherwise, keep the backslashes as-is
            out.append('\\' * slash_count)
            i = j

        return ''.join(out)

    def _balance_character_classes(self, regex: str) -> str:
        """Ensure that every unescaped '[' that starts a class has a matching ']'.

        Correctly handles runs of backslashes: only an odd-length run escapes the next char.
        """
        out: list[str] = []
        in_class = 0
        pos_in_class = 0
        after_caret = False
        i = 0
        n = len(regex)
        while i < n:
            ch = regex[i]
            if ch == '\\':
                # count run
                j = i
                while j < n and regex[j] == '\\':
                    j += 1
                run = j - i
                out.append('\\' * run)
                if j < n:
                    nxt = regex[j]
                    if run % 2 == 1:
                        # escaped next char: treat literally, no class state change
                        out.append(nxt)
                        if in_class:
                            pos_in_class += 1
                    else:
                        # not escaped: apply class state rules
                        if nxt == '[' and in_class == 0:
                            in_class = 1
                            pos_in_class = 0
                            after_caret = False
                        elif nxt == ']' and in_class == 1:
                            # ']' is literal if it is the first item (or immediately after leading '^')
                            if pos_in_class == 0 or (pos_in_class == 0 and after_caret):
                                pos_in_class += 1
                            else:
                                in_class = 0
                                pos_in_class = 0
                                after_caret = False
                        out.append(nxt)
                    i = j + 1
                else:
                    i = j
                continue

            # regular (non-backslash) char
            if ch == '[' and in_class == 0:
                in_class = 1
                pos_in_class = 0
                after_caret = False
            elif ch == ']' and in_class == 1:
                if pos_in_class == 0 or (pos_in_class == 0 and after_caret):
                    pos_in_class += 1
                else:
                    in_class = 0
                    pos_in_class = 0
                    after_caret = False
            out.append(ch)
            if in_class:
                if pos_in_class == 0 and ch == '^':
                    after_caret = True
                else:
                    pos_in_class += 1
            i += 1

        if in_class > 0:
            # add a simple filler to avoid empty class edge case
            out.append('a]')
        return ''.join(out)

    def _escape_orphan_quantifiers(self, regex: str) -> str:
        """Escape quantifiers that have no valid preceding atom.

        - Outside character classes only.
        - Recognizes backslash-run parity so escaped quantifier remains literal.
        - Treats group introducers '(?' and '(*' specially (kept as-is).
        - Treats zero-width escapes (\A, \Z, \z, \G, \b, \B, \K) as non-quantifiable atoms.
        """
        zero_width = {'A', 'Z', 'z', 'G', 'b', 'B', 'K'}
        out: list[str] = []
        in_class = 0
        prev_is_atom = False
        i = 0
        n = len(regex)

        def is_group_prefix(prev_char: str, ch: str) -> bool:
            return prev_char == '(' and ch in {'?', '*'}

        while i < n:
            ch = regex[i]

            if ch == '\\':
                # handle run of backslashes
                j = i
                while j < n and regex[j] == '\\':
                    j += 1
                run = j - i
                out.append('\\' * run)
                if j < n:
                    nxt = regex[j]
                    if run % 2 == 1:
                        # escaped next char -> literal or escape sequence
                        out.append(nxt)
                        # Determine atom status for escapes
                        if nxt in zero_width:
                            prev_is_atom = False
                        else:
                            prev_is_atom = True
                        i = j + 1
                        continue
                    else:
                        # not escaped; treat nxt as active below in next loop iteration
                        ch = nxt
                        i = j
                        # fall through into non-backslash handling with current ch
                else:
                    i = j
                    continue

            if ch == '[' and not in_class:
                in_class = 1
                prev_is_atom = False
                out.append(ch)
                i += 1
                continue
            if ch == ']' and in_class:
                in_class = 0
                prev_is_atom = True
                out.append(ch)
                i += 1
                continue

            if in_class:
                out.append(ch)
                # inside class, characters contribute to class, do not affect prev_is_atom here
                i += 1
                continue

            # Outside class
            if ch in {'*', '+', '?'}:
                prev_char = out[-1] if out else ''
                if is_group_prefix(prev_char, ch):
                    # (? or (* prefixes
                    out.append(ch)
                    prev_is_atom = False
                else:
                    if prev_is_atom:
                        out.append(ch)
                        prev_is_atom = False
                    else:
                        out.append('\\' + ch)
                        prev_is_atom = True
                i += 1
                continue

            if ch == '{':
                if prev_is_atom:
                    out.append(ch)
                    prev_is_atom = False
                else:
                    out.append('\\{')
                    prev_is_atom = True
                i += 1
                continue

            if ch in {'^', '$', '|', '('}:
                out.append(ch)
                # LPAREN might start a group; not an atom yet
                prev_is_atom = False
                i += 1
                continue

            if ch in {')', '.'}:
                out.append(ch)
                prev_is_atom = True
                i += 1
                continue

            # default literal outside class
            out.append(ch)
            prev_is_atom = True
            i += 1

        return ''.join(out)

    def _sanitize_class_ranges(self, regex: str) -> str:
        """Within each [...] class, escape '-' when it cannot form a valid range.

        Rules:
        - Only consider '-' as a range operator when both neighbors are single literal characters.
        - If neighbors are not single literals, or ordering would be invalid (end < start), emit '\-'.
        - Recognize odd/even backslash runs; '\-' is a literal and should not be treated as a range operator.
        - '^' directly after '[' (or '[^') is not considered a neighbor for ranges.
        """
        out: list[str] = []
        i = 0
        n = len(regex)

        def process_class(content: str) -> str:
            # Tokenize class content into items:
            # ('char', c) for single literal characters
            # ('esc_char', c) for escapes representing a single char (\[, \], \\ , \-)
            # ('esc_other', seq) for other escapes (\d, \w, \p, etc.) which are not single chars
            tokens: list[tuple[str, str]] = []
            j = 0
            m = len(content)
            while j < m:
                ch = content[j]
                if ch == '\\':
                    k = j
                    while k < m and content[k] == '\\':
                        k += 1
                    run = k - j
                    if k < m:
                        nxt = content[k]
                        if run % 2 == 1:
                            # escaped next char
                            if nxt in {'[', ']', '-', '^', '\\'}:
                                tokens.append(('esc_char', nxt))
                            else:
                                # treat other escapes as non-single
                                tokens.append(('esc_other', '\\' + nxt))
                            j = k + 1
                            continue
                        else:
                            # even run, escapes cancel; record the slashes then continue with nxt
                            tokens.extend([('char', '\\')] * run)
                            j = k
                            continue
                    else:
                        tokens.extend([('char', '\\')] * run)
                        j = k
                        continue
                else:
                    tokens.append(('char', ch))
                    j += 1

            # Now rebuild with '-' sanitized
            res: list[str] = []
            prev_single: Optional[str] = None
            k = 0
            # Skip leading '^' for prev_single consideration
            if tokens and tokens[0] == ('char', '^'):
                res.append('^')
                k = 1
                prev_single = None
            while k < len(tokens):
                typ, val = tokens[k]
                if typ == 'char' and val == '-':
                    # lookahead for next token
                    nxt_typ, nxt_val = tokens[k + 1] if (k + 1) < len(tokens) else (None, '')
                    left = prev_single
                    right_single = nxt_val if nxt_typ in {'char', 'esc_char'} and len(nxt_val) == 1 else None
                    if left is not None and right_single is not None and ord(right_single) >= ord(left):
                        # keep as range
                        res.append('-')
                        # do not update prev_single yet; it stays as left until we consume right
                    else:
                        # escape dash
                        res.append('\\-')
                        # a literal contributes as single
                        prev_single = '-'
                    k += 1
                    continue

                # normal emission
                if typ in {'char', 'esc_char'} and len(val) == 1:
                    res.append(val)
                    prev_single = val
                else:
                    # other escapes break range context
                    res.append(val)
                    prev_single = None
                k += 1

            return ''.join(res)

        while i < n:
            ch = regex[i]
            if ch != '[':
                out.append(ch)
                i += 1
                continue
            # Potential class start; confirm not escaped by odd backslash run
            # Check backslashes immediately before i
            b = i - 1
            slash_run = 0
            while b >= 0 and regex[b] == '\\':
                slash_run += 1
                b -= 1
            if slash_run % 2 == 1:
                out.append('[')
                i += 1
                continue

            # Find matching ']' respecting escapes and leading ']' as literal
            start = i + 1
            j = start
            # optional leading '^'
            if j < n and regex[j] == '^':
                j += 1
            # optional leading ']' literal
            if j < n and regex[j] == ']':
                j += 1
            # now scan for closing bracket
            while j < n:
                if regex[j] == '\\':
                    j += 2
                    continue
                if regex[j] == ']':
                    break
                j += 1

            if j >= n:
                # no closing ']' found, bail out
                out.append(regex[i:])
                break

            # sanitize content inside [ ... ]
            inner = regex[i + 1:j]
            sanitized = process_class(inner)
            out.append('[')
            out.append(sanitized)
            out.append(']')
            i = j + 1

        return ''.join(out)

    def _sanitize_group_prefixes(self, regex: str) -> str:
        """Ensure constructs starting with '(?' or '(*' have allowed next chars.

        If an unknown letter appears after '(?', convert '(?X' to '(?:X' by inserting ':'.
        Allowed starters after '(?': ':', '=', '!', '<', 'P', "'", '|', '*', '#', digits, '-', and option flags i,J,m,s,U,x,R,C.
        """
        # PCRE option flags allowed after '(?' when used as flags
        # Conservative set of inline option letters supported by PCRE (not PCRE2-specific):
        # i, m, s, x (lowercase); U, J, X, A, D (uppercase). Do not accept lowercase 'j'.
        allowed_flag_letters = set('imsxUJXAD')
        out: list[str] = []
        i = 0
        n = len(regex)
        while i < n:
            ch = regex[i]
            if ch != '(':
                out.append(ch)
                i += 1
                continue
            # Check if '(' is escaped
            b = i - 1
            slash_run = 0
            while b >= 0 and regex[b] == '\\':
                slash_run += 1
                b -= 1
            if slash_run % 2 == 1:
                out.append('(')
                i += 1
                continue

            # Look for '(?'
            if i + 1 < n and regex[i + 1] == '?':
                out.append('(')
                out.append('?')
                j = i + 2
                if j < n:
                    nxt = regex[j]
                    # Accept known constructs directly
                    if nxt in {':', '=', '!', '<', '|', '#'} or nxt.isdigit() or nxt in {'P', "'"}:
                        out.append(nxt)
                        i = j + 1
                    elif nxt == '-':
                        # Parse flag-unset sequence (?-letters...)
                        k = j + 1
                        valid = True
                        while k < n and regex[k].isalpha():
                            if regex[k] not in allowed_flag_letters:
                                valid = False
                                break
                            k += 1
                        # Next must be ':' or ')' or end; otherwise treat as invalid
                        if valid and (k < n and regex[k] in {':', ')'}):
                            out.append('-')
                            out.append(regex[j+1:k])
                            i = k
                        else:
                            # Make it non-capturing group
                            out.append(':')
                            out.append('-')
                            i = j + 1
                    elif nxt.isalpha():
                        # Could be flags like (?imx...) or special (?R) / (?C)
                        k = j
                        # Special single-letter constructs
                        if nxt in {'R', 'C'}:
                            # (?R) or (?C) or (?Cdigits)
                            out.append(nxt)
                            k += 1
                            while k < n and regex[k].isdigit():
                                out.append(regex[k])
                                k += 1
                            i = k
                        else:
                            # Parse flag sequence letters
                            valid = True
                            while k < n and regex[k].isalpha():
                                if regex[k] not in allowed_flag_letters:
                                    valid = False
                                    break
                                k += 1
                            if valid and (k < n and regex[k] in {':', ')'}):
                                out.append(regex[j:k])
                                i = k
                            else:
                                # Invalid flag letter found; convert to non-capturing '(?:'
                                out.append(':')
                                out.append(nxt)
                                i = j + 1
                    else:
                        # Unknown starter after '(?'; make it a non-capturing group
                        out.append(':')
                        out.append(nxt)
                        i = j + 1
                else:
                    # dangling '(?' -> make it '(?:'
                    out.append(':')
                    i = j
                continue

            out.append('(')
            i += 1

        return ''.join(out)

    def _balance_parentheses(self, regex: str) -> str:
        """Append missing ')' for any unclosed '(' outside character classes.

        - Respects backslash-run parity so escaped parens are literals.
        - Ignores parens inside classes, and correctly treats leading ']' as a literal inside classes.
        """
        in_class = 0
        class_pos = 0  # number of emitted chars since last '[' (ignores leading '^')
        depth = 0
        out: list[str] = []
        i = 0
        n = len(regex)
        while i < n:
            ch = regex[i]
            if ch == '\\':
                # copy backslash run and next char verbatim
                j = i
                while j < n and regex[j] == '\\':
                    j += 1
                run = j - i
                out.append('\\' * run)
                if j < n:
                    nxt = regex[j]
                    out.append(nxt)
                    if in_class:
                        class_pos += 1
                    i = j + 1
                else:
                    i = j
                continue

            if ch == '[' and not in_class:
                in_class = 1
                class_pos = 0
                out.append(ch)
                i += 1
                continue
            if ch == ']' and in_class:
                # literal ']' if it appears as the first content char (or immediately after '^')
                if class_pos == 0:
                    out.append(']')
                    class_pos += 1
                else:
                    in_class = 0
                    out.append(']')
                i += 1
                continue

            if in_class:
                out.append(ch)
                # Track leading '^'
                if class_pos == 0 and ch == '^':
                    # do not increment class_pos for leading '^'
                    pass
                else:
                    class_pos += 1
                i += 1
                continue

            # Outside class, handle parens
            if ch == '(':
                depth += 1
                out.append(ch)
                i += 1
                continue
            if ch == ')':
                if depth > 0:
                    depth -= 1
                out.append(ch)
                i += 1
                continue

            out.append(ch)
            i += 1

        if depth > 0:
            out.append(')' * depth)
        return ''.join(out)


class PCFGRegexGeneratorConfig(BaseRegexGeneratorConfig):
    def __init__(self, model_path: str | Path, random_seed: Optional[int] = None, max_depth: int = 30, **kwargs):
        super().__init__(**kwargs)
        self.model_path = Path(model_path)
        self.random_seed = random_seed
        self.max_depth = max_depth


class PCFGRegexGenerator(BaseRegexGenerator):
    """Generate regex patterns by sampling from a fitted PCFG model."""

    def __init__(self, config: PCFGRegexGeneratorConfig) -> None:
        super().__init__(config)
        self.config = config
        logger.info(f"Loading PCFG model from {config.model_path}")
        self.model = PCFGModel.load(config.model_path)
        self.rng = random.Random(config.random_seed)
        self.engine = PCFGDerivationEngine(self.model, self.rng)

    def generate(self, count: int):
        for i in range(count):
            try:
                yield self.engine.generate(max_depth=self.config.max_depth)
            except Exception as e:
                logger.warning(f"Failed to generate regex {i}: {e}")
                yield ".*"
