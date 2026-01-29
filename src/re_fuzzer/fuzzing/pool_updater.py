"""Pool updater for extracting and storing subtrees from interesting inputs.

This module implements the PoolUpdater class that updates the subtree pool
when interesting inputs are found (i.e., inputs that trigger new coverage).
It extracts all subtrees from the input's AST and stores them with their
contexts in the pool.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Any, Optional

from loguru import logger
from yapp.ast import nodes
from yapp.ast.serialize import regex_to_pattern
from yapp.ast.traverse import NodeVisitor

from .ast_operations import ASTOperations
from .subtree_pool import SubtreePool


# LRU cache for parsed patterns to avoid re-parsing
@lru_cache(maxsize=1024)
def _cached_parse(pattern: str) -> Optional[nodes.Regex]:
    """Parse a pattern with LRU caching."""
    return ASTOperations.parse_pattern(pattern)


class PoolUpdater:
    """Updates subtree pool with subtrees from interesting inputs."""

    def __init__(
        self,
        subtree_pool: SubtreePool,
        max_subtree_bytes: int = 200,
        max_depth: int = 20
    ):
        """Initialize the pool updater.

        Args:
            subtree_pool: The subtree pool to update
            max_subtree_bytes: Maximum size in bytes for subtrees (default 200)
            max_depth: Maximum recursion depth for subtree extraction (default 20)
        """
        self.subtree_pool = subtree_pool
        self.ast_ops = ASTOperations()
        self.max_subtree_bytes = max_subtree_bytes
        self.max_depth = max_depth

        # Statistics
        self.stats = {
            "inputs_processed": 0,
            "parse_failures": 0,
            "subtrees_extracted": 0,
            "subtrees_rejected": 0,
            "cache_hits": 0,
        }

    def update_from_input(self, input_data: bytes) -> bool:
        """Update the pool with subtrees from an interesting input.

        This is called when libfuzzer/Atheris finds an input that triggers
        new coverage.

        Args:
            input_data: The interesting input as bytes

        Returns:
            True if pool was successfully updated, False otherwise
        """
        if self.subtree_pool.is_full():
            logger.debug("Skipping pool update: subtree pool at capacity")
            return False

        self.stats["inputs_processed"] += 1

        # Convert bytes to string
        try:
            pattern = input_data.decode('utf-8')
        except UnicodeDecodeError:
            self.stats["parse_failures"] += 1
            logger.debug("Failed to decode input data")
            return False

        # Parse to AST using cached parser
        cache_info_before = _cached_parse.cache_info()
        ast = _cached_parse(pattern)
        cache_info_after = _cached_parse.cache_info()

        # Track cache hits
        if cache_info_after.hits > cache_info_before.hits:
            self.stats["cache_hits"] += 1

        if ast is None:
            self.stats["parse_failures"] += 1
            logger.debug(f"Failed to parse pattern: {pattern[:100]}...")
            return False

        # Extract and store all subtrees
        extractor = SubtreeExtractor(
            self.subtree_pool,
            self.ast_ops,
            self.max_subtree_bytes
        )
        extractor.visit(ast)

        self.stats["subtrees_extracted"] += extractor.subtrees_added
        self.stats["subtrees_rejected"] += extractor.subtrees_rejected

        logger.info(
            f"Updated pool from input: extracted={extractor.subtrees_added}, "
            f"rejected={extractor.subtrees_rejected}, pool_size={self.subtree_pool.size()}"
        )

        return extractor.subtrees_added > 0

    def update_from_pattern(self, pattern: str) -> bool:
        """Update the pool with subtrees from a regex pattern string.

        Args:
            pattern: The regex pattern string

        Returns:
            True if pool was successfully updated, False otherwise
        """
        return self.update_from_input(pattern.encode('utf-8'))

    def bulk_update_from_patterns(self, patterns: list[str]) -> int:
        """Update the pool from multiple patterns (e.g., initial seed corpus).

        Args:
            patterns: List of regex pattern strings

        Returns:
            Number of patterns successfully processed
        """
        successful = 0
        for pattern in patterns:
            if self.update_from_pattern(pattern):
                successful += 1

        logger.info(
            f"Bulk update completed: {successful}/{len(patterns)} patterns processed, "
            f"pool_size={self.subtree_pool.size()}"
        )
        return successful

    def get_statistics(self) -> dict[str, int]:
        """Get pool update statistics.

        Returns:
            Dictionary of statistics
        """
        return dict(self.stats)

    def reset_statistics(self) -> None:
        """Reset statistics counters."""
        self.stats = {
            "inputs_processed": 0,
            "parse_failures": 0,
            "subtrees_extracted": 0,
            "subtrees_rejected": 0,
        }


class SubtreeExtractor(NodeVisitor):
    """Visitor that extracts and stores all subtrees from an AST."""

    # Maximum depth for traversal to prevent stack overflow
    MAX_DEPTH = 50

    def __init__(
        self,
        subtree_pool: SubtreePool,
        ast_ops: ASTOperations,
        max_subtree_bytes: int = 200
    ):
        """Initialize the extractor.

        Args:
            subtree_pool: Pool to store subtrees in
            ast_ops: AST operations utility
            max_subtree_bytes: Maximum size for subtrees
        """
        self.subtree_pool = subtree_pool
        self.ast_ops = ast_ops
        self.max_subtree_bytes = max_subtree_bytes

        # Track parent relationships during traversal
        self.parent_map = {}
        self.current_parent = None
        self.current_depth = 0

        # Statistics
        self.subtrees_added = 0
        self.subtrees_rejected = 0

    def generic_visit(self, node: Any) -> None:
        """Visit a node and extract its subtree if appropriate.

        Args:
            node: The AST node to visit
        """
        # Check depth limit to prevent stack overflow
        if self.current_depth > self.MAX_DEPTH:
            return

        # Record parent relationship using object ID as key
        if self.current_parent is not None:
            self.parent_map[id(node)] = self.current_parent

        # Only process internal nodes (not terminals)
        if not self.ast_ops.is_terminal(node):
            # Extract context for this node
            context = self.ast_ops.extract_context(node, self.parent_map)
            node_type = self.ast_ops.get_node_type(node)

            # Extract subtree and convert to string
            subtree = self.ast_ops.extract_subtree(node)
            if subtree is None:
                # Subtree too deep to extract safely
                self.subtrees_rejected += 1
                self._visit_children(node)
                return

            try:
                # Create a temporary Regex wrapper if needed
                if isinstance(subtree, nodes.Regex):
                    pattern_str = regex_to_pattern(subtree)
                else:
                    # For non-Regex nodes, we need to wrap them properly
                    # Some nodes can't be directly under Regex.alternation
                    # So we wrap them in an Alternation with a single branch
                    if isinstance(subtree, (nodes.Alternation, nodes.Sequence)):
                        temp_regex = nodes.Regex(alternation=subtree)
                    else:
                        # Wrap in Sequence then Alternation for proper structure
                        temp_seq = nodes.Sequence(elements=[subtree])
                        temp_alt = nodes.Alternation(branches=[temp_seq])
                        temp_regex = nodes.Regex(alternation=temp_alt)
                    pattern_str = regex_to_pattern(temp_regex)
            except Exception as e:
                logger.debug(f"Failed to serialize subtree: {e}")
                self.subtrees_rejected += 1
                # Still continue visiting children
                self._visit_children(node)
                return

            # Check size constraint
            if len(pattern_str.encode('utf-8')) <= self.max_subtree_bytes:
                # Add to pool
                added = self.subtree_pool.add_subtree(
                    subtree=subtree,
                    node_type=node_type,
                    context=context,
                    pattern_str=pattern_str
                )
                if added:
                    self.subtrees_added += 1
                    logger.debug(
                        f"Added subtree: type={node_type}, "
                        f"context={context.to_tuple()}, pattern={pattern_str[:50]}..."
                    )
            else:
                self.subtrees_rejected += 1
                logger.debug(
                    f"Rejected subtree (too large): {len(pattern_str.encode('utf-8'))} bytes"
                )

        # Continue traversal to children
        self._visit_children(node)

    def _visit_children(self, node: Any) -> None:
        """Visit all children of a node.

        Args:
            node: Parent node whose children to visit
        """
        # Save current parent and depth
        old_parent = self.current_parent
        self.current_parent = node
        self.current_depth += 1

        # Get and visit children
        children = self.ast_ops._get_children(node)
        for child in children:
            if child is not None:
                self.visit(child)

        # Restore parent and depth
        self.current_depth -= 1
        self.current_parent = old_parent
