"""Grammar-aware mutator for regex fuzzing with subtree pool support.

This module implements a custom mutator for Atheris/libfuzzer that performs
grammar-aware mutations on regex patterns. It parses input patterns into ASTs,
selects nodes for mutation, and replaces them with semantically compatible
subtrees from the pool.

Supports multiple mutation strategies:
1. Grammar-aware: Replace AST subtrees with pool entries
2. Dictionary-based: Generate patterns from PCRE2 dictionary tokens
3. Dictionary injection: Insert dictionary tokens into existing patterns
4. Hybrid: Combine grammar-aware mutation with dictionary tokens
5. Fallback: Simple byte-level mutations
"""

from __future__ import annotations

import random
from enum import Enum, auto
from typing import Optional, TYPE_CHECKING

from loguru import logger

if TYPE_CHECKING:
    from .advanced_pattern_generator import AdvancedPatternGenerator

from yapp.ast import nodes

from .ast_operations import ASTOperations
from .dictionary import FuzzDictionary, get_pcre2_dictionary, TokenCategory
from .subtree_pool import SubtreePool


class MutationStrategy(Enum):
    """Available mutation strategies."""
    GRAMMAR_AWARE = auto()      # AST-based subtree replacement
    DICTIONARY_GENERATE = auto()  # Generate from dictionary tokens
    DICTIONARY_INJECT = auto()  # Inject dictionary tokens into pattern
    HYBRID = auto()             # Combine grammar + dictionary
    ADVANCED_GENERATE = auto()  # Template-based feature generation
    FALLBACK = auto()           # Byte-level mutation


class GrammarAwareMutator:
    """Custom mutator that performs grammar-aware AST mutations."""

    def __init__(
        self,
        subtree_pool: SubtreePool,
        mutation_probability: float = 0.8,
        dictionary: Optional[FuzzDictionary] = None,
        dictionary_weight: float = 0.3,
        advanced_generator: Optional["AdvancedPatternGenerator"] = None,
        advanced_weight: float = 0.0,
    ):
        """Initialize the grammar-aware mutator.

        Args:
            subtree_pool: Pool of subtrees for mutations
            mutation_probability: Probability of attempting grammar-aware mutation
                                 vs fallback (default 0.8)
            dictionary: PCRE2 fuzz dictionary (default: built-in)
            dictionary_weight: Weight for dictionary-based mutations (default 0.3)
            advanced_generator: Optional advanced pattern generator for ablation
            advanced_weight: Weight for advanced generation (0 = disabled, default)
        """
        self.subtree_pool = subtree_pool
        self.ast_ops = ASTOperations()
        self.mutation_probability = mutation_probability
        self.dictionary = dictionary or get_pcre2_dictionary()
        self.dictionary_weight = dictionary_weight
        self.advanced_generator = advanced_generator
        self.advanced_weight = advanced_weight

        # Statistics
        self.stats = {
            "total_mutations": 0,
            "successful_mutations": 0,
            "parse_failures": 0,
            "no_internal_nodes": 0,
            "no_replacement_found": 0,
            "fallback_mutations": 0,
            "dictionary_mutations": 0,
            "dictionary_injections": 0,
            "hybrid_mutations": 0,
            "grammar_aware_mutations": 0,  # Successful AST-based mutations
            "advanced_mutations": 0,       # Advanced pattern generation
        }

    def _select_strategy(self) -> MutationStrategy:
        """Select a mutation strategy based on weights."""
        r = random.random()

        # Advanced generator (when enabled for ablation)
        if self.advanced_generator is not None and self.advanced_weight > 0:
            if r < self.advanced_weight:
                return MutationStrategy.ADVANCED_GENERATE
            # Adjust r for remaining strategies
            r = (r - self.advanced_weight) / (1 - self.advanced_weight)

        if r < self.dictionary_weight * 0.5:
            return MutationStrategy.DICTIONARY_GENERATE
        elif r < self.dictionary_weight:
            return MutationStrategy.DICTIONARY_INJECT
        elif r < self.dictionary_weight + 0.1:
            return MutationStrategy.HYBRID
        elif r < self.mutation_probability:
            return MutationStrategy.GRAMMAR_AWARE
        else:
            return MutationStrategy.FALLBACK

    def mutate(self, data: bytes, max_size: int, seed: int) -> bytes:
        """Perform mutation on input data using selected strategy.

        This is the main entry point called by Atheris/libfuzzer.

        Args:
            data: Input data to mutate (regex pattern as bytes)
            max_size: Maximum size of mutated output
            seed: Random seed for this mutation

        Returns:
            Mutated data as bytes
        """
        self.stats["total_mutations"] += 1

        # Set random seed for reproducibility
        random.seed(seed)

        # Select mutation strategy
        strategy = self._select_strategy()

        # Convert bytes to string
        try:
            pattern = data.decode('utf-8')
        except UnicodeDecodeError:
            pattern = ""
            self.stats["parse_failures"] += 1

        # Apply selected strategy - wrap in try-except to handle parse errors gracefully
        try:
            if strategy == MutationStrategy.DICTIONARY_GENERATE:
                mutated_pattern = self._dictionary_generate(max_size)
                self.stats["dictionary_mutations"] += 1

            elif strategy == MutationStrategy.DICTIONARY_INJECT:
                mutated_pattern = self._dictionary_inject(pattern, max_size)
                self.stats["dictionary_injections"] += 1

            elif strategy == MutationStrategy.HYBRID:
                mutated_pattern = self._hybrid_mutation(pattern, max_size)
                self.stats["hybrid_mutations"] += 1

            elif strategy == MutationStrategy.GRAMMAR_AWARE:
                # Parse pattern to AST
                ast = self.ast_ops.parse_pattern(pattern) if pattern else None
                if ast is None:
                    self.stats["parse_failures"] += 1
                    return self._fallback_mutation(data, max_size)

                mutated_pattern = self._perform_mutation(ast, pattern)
                if mutated_pattern is None:
                    return self._fallback_mutation(data, max_size)
                self.stats["grammar_aware_mutations"] += 1

            elif strategy == MutationStrategy.ADVANCED_GENERATE:
                # Use advanced pattern generator (for ablation testing)
                if self.advanced_generator is not None:
                    mutated_pattern = self.advanced_generator.generate(max_size)
                    self.stats["advanced_mutations"] += 1
                else:
                    return self._fallback_mutation(data, max_size)

            else:  # FALLBACK
                return self._fallback_mutation(data, max_size)

        except Exception:
            # Any parsing/mutation error - fall back to simple byte mutation
            self.stats["parse_failures"] += 1
            return self._fallback_mutation(data, max_size)

        # Validate result
        if mutated_pattern is None:
            return self._fallback_mutation(data, max_size)

        # Convert back to bytes and check size
        mutated_bytes = mutated_pattern.encode('utf-8')
        if len(mutated_bytes) > max_size:
            mutated_bytes = mutated_bytes[:max_size]

        self.stats["successful_mutations"] += 1
        return mutated_bytes

    def _dictionary_generate(self, max_size: int) -> str:
        """Generate a pattern entirely from dictionary tokens."""
        max_tokens = min(15, max_size // 3)
        return self.dictionary.generate_random_pattern(max_tokens)

    def _dictionary_inject(self, pattern: str, max_size: int) -> str:
        """Inject dictionary tokens into an existing pattern using grammar-aware insertion."""
        if not pattern:
            return self._dictionary_generate(max_size)

        num_injections = random.randint(1, 3)
        return self.dictionary.inject_into_pattern(pattern, num_injections, strategy="random")

    def _hybrid_mutation(self, pattern: str, max_size: int) -> Optional[str]:
        """Combine grammar-aware mutation with dictionary enhancement."""
        # First try grammar-aware mutation
        if pattern:
            ast = self.ast_ops.parse_pattern(pattern)
            if ast:
                mutated = self._perform_mutation(ast, pattern)
                if mutated:
                    # Then inject dictionary tokens using grammar-aware insertion
                    return self.dictionary.inject_into_pattern(mutated, 1, strategy="random")

        # Fallback to dictionary generation
        return self._dictionary_generate(max_size)

    def _perform_mutation(self, ast, original_pattern: str) -> Optional[str]:
        """Perform grammar-aware mutation on an AST.

        Args:
            ast: Parsed regex AST
            original_pattern: Source pattern string (used for equality check)

        Returns:
            Mutated pattern string or None if mutation failed
        """
        # Collect all internal nodes with their parent maps
        internal_nodes = self.ast_ops.collect_internal_nodes(ast)
        if not internal_nodes:
            self.stats["no_internal_nodes"] += 1
            logger.debug("No internal nodes found for mutation")
            return None

        # Skip Regex root nodes since they cannot be replaced safely
        candidates = [
            (node, parent_map)
            for node, parent_map in internal_nodes
            if not isinstance(node, nodes.Regex)
        ]

        if not candidates:
            self.stats["no_internal_nodes"] += 1
            logger.debug("No eligible non-root nodes found for mutation")
            return None

        # Randomly select a node to mutate
        node, parent_map = random.choice(candidates)
        node_type = self.ast_ops.get_node_type(node)
        context = self.ast_ops.extract_context(node, parent_map)

        logger.debug(
            f"Selected node for mutation: type={node_type}, "
            f"context={context.to_tuple()}"
        )

        # Try to get a replacement from the subtree pool
        replacement = self.subtree_pool.get_subtree(node_type, context)

        # If exact context match fails, try with relaxed context
        if replacement is None:
            # Try with just parent context (ignore ancestors)
            from .subtree_pool import SubtreeContext
            relaxed_context = SubtreeContext(
                great_grandparent_type=None,
                grandparent_type=None,
                parent_type=context.parent_type,
                first_sibling=None
            )
            replacement = self.subtree_pool.get_subtree(node_type, relaxed_context)

            # If still no match, try to get any subtree of the same type
            if replacement is None:
                replacement = self.subtree_pool.get_any_subtree_of_type(node_type)

        if replacement is None:
            self.stats["no_replacement_found"] += 1
            logger.debug(f"No replacement found for type={node_type}, context={context}")
            return None

        # Replace the subtree in the AST using copy-on-write for better performance
        # Fall back to full deepcopy if COW fails (e.g., node not in parent_map)
        # Pool entries are safe to use without copy (immutable once stored)
        mutated_ast, replaced = self.ast_ops.replace_subtree_cow(
            ast, node, replacement, parent_map, skip_replacement_copy=True
        )
        if mutated_ast is None or not replaced:
            # Fallback to original deepcopy method
            mutated_ast, replaced = self.ast_ops.replace_subtree(ast, node, replacement)
            if mutated_ast is None or not replaced:
                logger.debug("Subtree replacement failed; falling back to byte mutation")
                return None

        # Convert back to pattern string
        try:
            mutated_pattern = self.ast_ops.pattern_to_string(mutated_ast)
            if mutated_pattern == original_pattern:
                logger.debug("Mutation produced identical pattern; skipping")
                return None
            logger.debug(f"Mutation successful: {mutated_pattern[:100]}...")
            return mutated_pattern
        except Exception as e:
            logger.error(f"Failed to serialize mutated AST: {e}")
            return None

    def _fallback_mutation(self, data: bytes, max_size: int) -> bytes:
        """Fallback mutation strategy when grammar-aware mutation fails.

        Combines byte-level mutations with dictionary token insertion.

        Args:
            data: Input data
            max_size: Maximum size

        Returns:
            Mutated data
        """
        self.stats["fallback_mutations"] += 1

        if len(data) == 0:
            # Generate from dictionary for empty input
            pattern = self._dictionary_generate(max_size)
            return pattern.encode('utf-8')[:max_size]

        # Choose a random mutation strategy - now includes dictionary options
        strategy = random.choice([
            'flip_bit',
            'flip_byte',
            'insert_byte',
            'delete_byte',
            'shuffle_bytes',
            'duplicate_bytes',
            'insert_dict_token',  # New: insert dictionary token
            'replace_with_dict',  # New: replace portion with dictionary token
        ])

        data_list = list(data)

        if strategy == 'flip_bit':
            # Flip a random bit
            if data_list:
                pos = random.randint(0, len(data_list) - 1)
                bit = random.randint(0, 7)
                data_list[pos] ^= (1 << bit)

        elif strategy == 'flip_byte':
            # Flip a random byte
            if data_list:
                pos = random.randint(0, len(data_list) - 1)
                data_list[pos] = random.randint(0, 255)

        elif strategy == 'insert_byte' and len(data_list) < max_size:
            # Insert a random byte
            pos = random.randint(0, len(data_list))
            data_list.insert(pos, random.randint(0, 255))

        elif strategy == 'delete_byte' and len(data_list) > 1:
            # Delete a random byte
            pos = random.randint(0, len(data_list) - 1)
            del data_list[pos]

        elif strategy == 'shuffle_bytes' and len(data_list) > 1:
            # Shuffle a portion of bytes
            start = random.randint(0, len(data_list) - 1)
            end = random.randint(start + 1, min(start + 10, len(data_list)))
            portion = data_list[start:end]
            random.shuffle(portion)
            data_list[start:end] = portion

        elif strategy == 'duplicate_bytes' and len(data_list) * 2 <= max_size:
            # Duplicate a portion of bytes
            start = random.randint(0, max(0, len(data_list) - 10))
            end = random.randint(start + 1, min(start + 10, len(data_list)))
            portion = data_list[start:end]
            insert_pos = random.randint(0, len(data_list))
            data_list[insert_pos:insert_pos] = portion

        elif strategy == 'insert_dict_token':
            # Insert a dictionary token using grammar-aware insertion
            try:
                pattern = bytes(data_list).decode('utf-8')
                token = self.dictionary.get_random()
                insert_strategy = random.choice(["first", "last", "random"])
                result = self.dictionary.smart_insert(pattern, token, strategy=insert_strategy)
                if result and len(result.encode('utf-8')) <= max_size:
                    return result.encode('utf-8')
            except (UnicodeDecodeError, Exception):
                # Fallback to byte-level insertion
                token = self.dictionary.get_random()
                token_bytes = list(token.encode('utf-8'))
                if len(data_list) + len(token_bytes) <= max_size:
                    pos = random.randint(0, len(data_list))
                    data_list[pos:pos] = token_bytes

        elif strategy == 'replace_with_dict':
            # Replace a portion with dictionary token using grammar-aware insertion
            try:
                pattern = bytes(data_list).decode('utf-8')
                token = self.dictionary.get_random_atom()
                # Use "all" strategy to apply to all positions for more aggressive mutation
                result = self.dictionary.smart_insert(pattern, token, strategy="random")
                if result and len(result.encode('utf-8')) <= max_size:
                    return result.encode('utf-8')
            except (UnicodeDecodeError, Exception):
                # Fallback to byte-level replacement
                token = self.dictionary.get_random_atom()
                token_bytes = list(token.encode('utf-8'))
                if data_list:
                    start = random.randint(0, max(0, len(data_list) - 5))
                    end = min(start + random.randint(1, 5), len(data_list))
                    data_list[start:end] = token_bytes

        return bytes(data_list[:max_size])

    def get_statistics(self) -> dict[str, int]:
        """Get mutation statistics.

        Returns:
            Dictionary of mutation statistics
        """
        success_rate = (
            self.stats["successful_mutations"] / self.stats["total_mutations"]
            if self.stats["total_mutations"] > 0
            else 0.0
        )

        return {
            **self.stats,
            "success_rate": success_rate,
        }

    def reset_statistics(self) -> None:
        """Reset mutation statistics."""
        self.stats = {
            "total_mutations": 0,
            "successful_mutations": 0,
            "parse_failures": 0,
            "no_internal_nodes": 0,
            "no_replacement_found": 0,
            "fallback_mutations": 0,
            "dictionary_mutations": 0,
            "dictionary_injections": 0,
            "hybrid_mutations": 0,
            "grammar_aware_mutations": 0,
            "advanced_mutations": 0,
        }
