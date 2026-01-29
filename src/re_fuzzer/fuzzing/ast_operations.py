"""AST operations for subtree extraction, replacement, and context computation.

This module provides utilities for manipulating regex ASTs using the yapp library.
It includes functions for extracting subtrees, computing node contexts, replacing
subtrees in ASTs, and other tree manipulation operations needed for grammar-aware
fuzzing.

Optimization: Includes caching for depth calculations to avoid redundant BFS traversals.
"""

from __future__ import annotations

import copy
import sys
from functools import lru_cache
from typing import Any, Optional

from loguru import logger
from yapp.ast import nodes
from yapp.ast.serialize import regex_to_pattern
from yapp.ast.traverse import NodeVisitor
from yapp.parser import parse_regex

from .subtree_pool import SubtreeContext

# Maximum AST depth to prevent stack overflow during deepcopy
MAX_AST_DEPTH = 50

# Cache for AST depth calculations keyed by (pattern_string or id(node))
# Using a simple dict with size limit to prevent memory bloat
_depth_cache: dict[int, int] = {}
_DEPTH_CACHE_MAX_SIZE = 1000
_depth_cache_stats = {"hits": 0, "misses": 0}


def _get_cached_depth(node: Any, max_depth: int = MAX_AST_DEPTH) -> int:
    """Get depth of a node with caching based on object id.

    Args:
        node: The root node to calculate depth from
        max_depth: Maximum depth to check before returning early

    Returns:
        The depth of the tree, capped at max_depth + 1
    """
    node_id = id(node)

    if node_id in _depth_cache:
        _depth_cache_stats["hits"] += 1
        return _depth_cache[node_id]

    _depth_cache_stats["misses"] += 1

    # Calculate depth
    depth = _calculate_depth(node, max_depth)

    # Add to cache with size limit
    if len(_depth_cache) < _DEPTH_CACHE_MAX_SIZE:
        _depth_cache[node_id] = depth
    elif len(_depth_cache) >= _DEPTH_CACHE_MAX_SIZE:
        # Clear half the cache when full (simple eviction strategy)
        items_to_remove = list(_depth_cache.keys())[:_DEPTH_CACHE_MAX_SIZE // 2]
        for key in items_to_remove:
            del _depth_cache[key]
        _depth_cache[node_id] = depth

    return depth


def clear_depth_cache() -> None:
    """Clear the depth calculation cache. Call this periodically to free memory."""
    _depth_cache.clear()


def get_depth_cache_stats() -> dict[str, int]:
    """Get cache statistics for monitoring."""
    return {
        "hits": _depth_cache_stats["hits"],
        "misses": _depth_cache_stats["misses"],
        "cache_size": len(_depth_cache),
        "hit_rate": _depth_cache_stats["hits"] / max(1, _depth_cache_stats["hits"] + _depth_cache_stats["misses"]),
    }


def _calculate_depth(node: Any, max_depth: int = MAX_AST_DEPTH) -> int:
    """Calculate the depth of an AST node iteratively to avoid stack overflow.

    Args:
        node: The root node to calculate depth from
        max_depth: Maximum depth to check before returning early

    Returns:
        The depth of the tree, capped at max_depth + 1
    """
    if node is None:
        return 0

    # Use iterative BFS to avoid stack overflow
    from collections import deque
    queue = deque([(node, 1)])
    max_seen = 0

    while queue:
        current, depth = queue.popleft()

        if depth > max_seen:
            max_seen = depth

        # Early exit if we've exceeded the limit
        if max_seen > max_depth:
            return max_seen

        # Get children based on node type
        children = []
        if isinstance(current, nodes.Regex):
            if current.alternation:
                children.append(current.alternation)
        elif isinstance(current, nodes.Alternation):
            children.extend(current.branches)
        elif isinstance(current, nodes.Sequence):
            children.extend(current.elements)
        elif isinstance(current, nodes.Quantified):
            if current.atom:
                children.append(current.atom)
        elif isinstance(current, nodes.Group):
            if current.content:
                children.append(current.content)
        elif isinstance(current, nodes.CharacterClass):
            children.extend(current.items)
        elif isinstance(current, nodes.LookAround):
            if current.content:
                children.append(current.content)
        elif isinstance(current, nodes.Conditional):
            if current.condition:
                children.append(current.condition)
            if current.yes:
                children.append(current.yes)
            if current.no:
                children.append(current.no)

        for child in children:
            if child is not None:
                queue.append((child, depth + 1))

    return max_seen


class ASTOperations:
    """Utilities for AST manipulation and analysis."""

    @staticmethod
    def parse_pattern(pattern: str) -> Optional[nodes.Regex]:
        """Parse a regex pattern into an AST.

        Args:
            pattern: Regex pattern string

        Returns:
            Parsed AST or None if parsing fails
        """
        try:
            return parse_regex(pattern)
        except Exception as e:
            logger.debug(f"Failed to parse pattern: {e}")
            return None

    @staticmethod
    def pattern_to_string(ast: nodes.Regex) -> str:
        """Convert an AST back to a regex pattern string.

        Args:
            ast: Regex AST

        Returns:
            Pattern string representation
        """
        return regex_to_pattern(ast)

    @staticmethod
    def extract_context(node: Any, parent_map: dict[int, Any]) -> SubtreeContext:
        """Extract the context for a given AST node.

        Context is defined as:
        [great-grandparent type, grandparent type, parent type, first sibling value/type]

        Args:
            node: The AST node to extract context for
            parent_map: Dictionary mapping node IDs to their parents

        Returns:
            SubtreeContext object representing the node's context
        """
        ancestors = []
        current = node

        # Walk up the tree to collect ancestors
        while id(current) in parent_map:
            parent = parent_map[id(current)]
            ancestors.append(parent)
            current = parent

        # Extract ancestor types
        parent_type = None
        grandparent_type = None
        great_grandparent_type = None

        if len(ancestors) > 0:
            parent_type = type(ancestors[0]).__name__
        if len(ancestors) > 1:
            grandparent_type = type(ancestors[1]).__name__
        if len(ancestors) > 2:
            great_grandparent_type = type(ancestors[2]).__name__

        # Find first sibling
        first_sibling = None
        if len(ancestors) > 0:
            parent = ancestors[0]
            siblings = ASTOperations._get_children(parent)

            # Find node's position among siblings
            node_index = -1
            for i, sibling in enumerate(siblings):
                if sibling is node:
                    node_index = i
                    break

            # Get first sibling if node is not the first child
            if node_index > 0:
                first_sib = siblings[0]
                # If it's a literal, use its value; otherwise use its type
                if isinstance(first_sib, nodes.Literal):
                    first_sibling = first_sib.value
                else:
                    first_sibling = type(first_sib).__name__

        return SubtreeContext(
            great_grandparent_type=great_grandparent_type,
            grandparent_type=grandparent_type,
            parent_type=parent_type,
            first_sibling=first_sibling
        )

    @staticmethod
    def _get_children(node: Any) -> list[Any]:
        """Get all children of a node.

        Args:
            node: AST node

        Returns:
            List of child nodes
        """
        children = []

        # Handle different node types
        if isinstance(node, nodes.Regex):
            if node.alternation:
                children.append(node.alternation)
        elif isinstance(node, nodes.Alternation):
            children.extend(node.branches)
        elif isinstance(node, nodes.Sequence):
            children.extend(node.elements)
        elif isinstance(node, nodes.Quantified):
            if node.atom:
                children.append(node.atom)
        elif isinstance(node, nodes.Group):
            if node.content:
                children.append(node.content)
        elif isinstance(node, nodes.CharacterClass):
            children.extend(node.items)
        elif isinstance(node, nodes.LookAround):
            if node.content:
                children.append(node.content)
        elif isinstance(node, nodes.Conditional):
            if node.condition:
                children.append(node.condition)
            if node.yes:
                children.append(node.yes)
            if node.no:
                children.append(node.no)

        return children

    @staticmethod
    def collect_internal_nodes(ast: nodes.Regex) -> list[tuple[Any, dict[Any, Any]]]:
        """Collect all internal (non-terminal) nodes from an AST.

        Returns both the nodes and a parent map for context extraction.

        Args:
            ast: The regex AST

        Returns:
            List of tuples (node, parent_map) for each internal node
        """
        # Check depth first to avoid stack overflow in visitor
        depth = _get_cached_depth(ast)
        if depth > MAX_AST_DEPTH:
            logger.debug(f"Skipping node collection: AST depth {depth} exceeds limit {MAX_AST_DEPTH}")
            return []

        collector = InternalNodeCollector(max_depth=MAX_AST_DEPTH)
        collector.visit(ast)
        return [(node, collector.parent_map) for node in collector.internal_nodes]

    @staticmethod
    def is_terminal(node: Any) -> bool:
        """Check if a node is a terminal (leaf) node.

        Args:
            node: AST node

        Returns:
            True if the node is terminal, False otherwise
        """
        # Terminal nodes are those without children
        terminal_types = (
            nodes.Literal,
            nodes.Dot,
            nodes.Anchor,
            nodes.Backref,
            nodes.SubroutineRef,
            nodes.BacktrackControl,
        )
        return isinstance(node, terminal_types)

    @staticmethod
    def extract_subtree(node: Any) -> Optional[Any]:
        """Create a deep copy of a subtree rooted at the given node.

        Args:
            node: Root of the subtree to extract

        Returns:
            Deep copy of the subtree, or None if too deep
        """
        # Check depth first to avoid stack overflow
        depth = _get_cached_depth(node)
        if depth > MAX_AST_DEPTH:
            logger.debug(f"Skipping subtree extraction: depth {depth} exceeds limit {MAX_AST_DEPTH}")
            return None

        try:
            return copy.deepcopy(node)
        except RecursionError:
            logger.warning("RecursionError during subtree extraction")
            return None

    @staticmethod
    def replace_subtree(
        ast: nodes.Regex,
        target_node: Any,
        replacement: Any
    ) -> tuple[Optional[nodes.Regex], bool]:
        """Replace a subtree in an AST with a replacement subtree.

        Args:
            ast: The original AST
            target_node: The node to replace
            replacement: The replacement subtree

        Returns:
            Tuple of (new AST with the replacement, whether replacement occurred)
            Returns (None, False) if the AST is too deep to process safely
        """
        # Check depth first to avoid stack overflow during deepcopy
        ast_depth = _get_cached_depth(ast)
        if ast_depth > MAX_AST_DEPTH:
            logger.debug(f"Skipping subtree replacement: AST depth {ast_depth} exceeds limit {MAX_AST_DEPTH}")
            return None, False

        try:
            # Create a deep copy to avoid modifying the original and keep a memo so
            # we can locate the copied target node inside the cloned AST.
            memo: dict[int, Any] = {}
            new_ast = copy.deepcopy(ast, memo)
            target_copy = memo.get(id(target_node))

            if target_copy is None:
                logger.warning("Target node not found while copying AST for replacement")
                return new_ast, False

            # Use the replacer visitor to perform replacement on the copied node
            replacer = SubtreeReplacer(target_copy, replacement)
            replacer.visit(new_ast)

            if not replacer.replaced:
                logger.warning("Target node not found in AST for replacement")

            return new_ast, replacer.replaced

        except RecursionError:
            logger.warning("RecursionError during subtree replacement")
            return None, False

    @staticmethod
    def get_node_type(node: Any) -> str:
        """Get the type name of a node.

        Args:
            node: AST node

        Returns:
            String name of the node type
        """
        return type(node).__name__

    @staticmethod
    def _shallow_copy_node(node: Any) -> Any:
        """Create a shallow copy of an AST node.

        This copies the node's attributes but not its children - child references
        point to the original children. Used for copy-on-write optimization.

        Args:
            node: AST node to copy

        Returns:
            Shallow copy of the node
        """
        if isinstance(node, nodes.Regex):
            new_node = nodes.Regex(alternation=node.alternation)
            # Copy start_options if present
            if hasattr(node, 'start_options') and node.start_options:
                new_node.start_options = list(node.start_options)
            return new_node
        elif isinstance(node, nodes.Alternation):
            # Copy the list but keep references to original branches
            return nodes.Alternation(branches=list(node.branches))
        elif isinstance(node, nodes.Sequence):
            return nodes.Sequence(elements=list(node.elements))
        elif isinstance(node, nodes.Quantified):
            # Quantified only takes atom and quantifier
            # lazy/possessive info is in quantifier.mode (QuantifierMode enum)
            return nodes.Quantified(
                atom=node.atom,
                quantifier=node.quantifier
            )
        elif isinstance(node, nodes.Group):
            # Group uses specific attributes - no 'flags' parameter
            new_node = nodes.Group(
                content=node.content,
                capturing=getattr(node, 'capturing', True),
                name=getattr(node, 'name', None),
                atomic=getattr(node, 'atomic', False),
                branch_reset=getattr(node, 'branch_reset', False)
            )
            # Copy flag sets if present
            if hasattr(node, 'local_set_flags'):
                new_node.local_set_flags = set(node.local_set_flags)
            if hasattr(node, 'local_unset_flags'):
                new_node.local_unset_flags = set(node.local_unset_flags)
            if hasattr(node, 'index'):
                new_node.index = node.index
            return new_node
        elif isinstance(node, nodes.CharacterClass):
            return nodes.CharacterClass(
                items=list(node.items),
                negated=node.negated
            )
        elif isinstance(node, nodes.LookAround):
            # LookAround uses 'kind' (LookKind enum) instead of ahead/positive
            return nodes.LookAround(
                content=node.content,
                kind=node.kind
            )
        elif isinstance(node, nodes.Conditional):
            return nodes.Conditional(
                condition=node.condition,
                yes=node.yes,
                no=getattr(node, 'no', None)
            )
        else:
            # For other node types (terminals), deepcopy is fine (they're small)
            return copy.deepcopy(node)

    @staticmethod
    def _find_path_to_node(
        root: Any,
        target: Any,
        parent_map: dict[int, Any]
    ) -> Optional[list[Any]]:
        """Find the path from root to target node using parent map.

        Args:
            root: Root node of the AST
            target: Target node to find
            parent_map: Dictionary mapping node IDs to their parents

        Returns:
            List of nodes from root to target (inclusive), or None if not found
        """
        # Build path from target to root by walking up parent chain
        path = [target]
        current = target

        while id(current) in parent_map:
            parent = parent_map[id(current)]
            path.append(parent)
            current = parent

        # Verify we reached the root
        if path[-1] is not root and id(path[-1]) != id(root):
            return None

        # Reverse to get path from root to target
        path.reverse()
        return path

    @staticmethod
    def _get_child_index(parent: Any, child: Any) -> Optional[tuple[str, int]]:
        """Get the attribute name and index of a child within its parent.

        Args:
            parent: Parent node
            child: Child node to find

        Returns:
            Tuple of (attribute_name, index) where index is -1 for single-child attrs,
            or None if child not found
        """
        if isinstance(parent, nodes.Regex):
            if parent.alternation is child:
                return ('alternation', -1)
        elif isinstance(parent, nodes.Alternation):
            for i, branch in enumerate(parent.branches):
                if branch is child:
                    return ('branches', i)
        elif isinstance(parent, nodes.Sequence):
            for i, element in enumerate(parent.elements):
                if element is child:
                    return ('elements', i)
        elif isinstance(parent, nodes.Quantified):
            if parent.atom is child:
                return ('atom', -1)
        elif isinstance(parent, nodes.Group):
            if parent.content is child:
                return ('content', -1)
        elif isinstance(parent, nodes.CharacterClass):
            for i, item in enumerate(parent.items):
                if item is child:
                    return ('items', i)
        elif isinstance(parent, nodes.LookAround):
            if parent.content is child:
                return ('content', -1)
        elif isinstance(parent, nodes.Conditional):
            if parent.condition is child:
                return ('condition', -1)
            if parent.yes is child:
                return ('yes', -1)
            if parent.no is child:
                return ('no', -1)
        return None

    @staticmethod
    def _set_child(parent: Any, attr_name: str, index: int, new_child: Any) -> None:
        """Set a child of a parent node.

        Args:
            parent: Parent node
            attr_name: Name of the attribute containing the child
            index: Index within the attribute (-1 for single-child attributes)
            new_child: New child to set
        """
        if index == -1:
            setattr(parent, attr_name, new_child)
        else:
            getattr(parent, attr_name)[index] = new_child

    @staticmethod
    def replace_subtree_cow(
        ast: nodes.Regex,
        target_node: Any,
        replacement: Any,
        parent_map: dict[int, Any],
        skip_replacement_copy: bool = False
    ) -> tuple[Optional[nodes.Regex], bool]:
        """Replace a subtree using copy-on-write optimization.

        This only copies nodes on the path from root to target, leaving the rest
        of the tree shared with the original. Much more efficient than full deepcopy.

        Args:
            ast: The original AST
            target_node: The node to replace
            replacement: The replacement subtree
            parent_map: Dictionary mapping node IDs to their parents
            skip_replacement_copy: If True, skip deepcopy of replacement (use when
                                   replacement comes from pool and is already safe)

        Returns:
            Tuple of (new AST with the replacement, whether replacement occurred)
        """
        # Check depths
        ast_depth = _get_cached_depth(ast)
        if ast_depth > MAX_AST_DEPTH:
            logger.debug(f"Skipping COW replacement: AST depth {ast_depth} exceeds limit")
            return None, False

        replacement_depth = _get_cached_depth(replacement)
        if replacement_depth > MAX_AST_DEPTH:
            logger.debug(f"Skipping COW replacement: replacement depth {replacement_depth} exceeds limit")
            return None, False

        try:
            # Find path from root to target
            path = ASTOperations._find_path_to_node(ast, target_node, parent_map)
            if path is None or len(path) < 2:
                # Target is root or not found
                if path and len(path) == 1 and path[0] is ast:
                    # Target is root - just wrap replacement
                    if isinstance(replacement, nodes.Regex):
                        return replacement, True
                    else:
                        new_root = nodes.Regex(alternation=replacement)
                        return new_root, True
                logger.debug("Target node not found in path for COW replacement")
                return None, False

            # Deep copy the replacement to avoid sharing (unless skip_replacement_copy)
            if skip_replacement_copy:
                replacement_copy = replacement
            else:
                try:
                    replacement_copy = copy.deepcopy(replacement)
                except RecursionError:
                    logger.warning("RecursionError copying replacement")
                    return None, False

            # Copy nodes along the path and update child references
            # path = [root, ..., parent_of_target, target]
            new_nodes = []
            for node in path[:-1]:  # Don't copy the target itself
                new_node = ASTOperations._shallow_copy_node(node)
                new_nodes.append(new_node)

            # Link the new nodes together
            for i in range(len(new_nodes) - 1):
                parent_new = new_nodes[i]
                child_old = path[i + 1]
                child_new = new_nodes[i + 1]

                # Find which child slot to update
                child_info = ASTOperations._get_child_index(parent_new, child_old)
                if child_info:
                    attr_name, idx = child_info
                    ASTOperations._set_child(parent_new, attr_name, idx, child_new)

            # Replace target with replacement in the last copied parent
            last_parent = new_nodes[-1]
            child_info = ASTOperations._get_child_index(last_parent, target_node)
            if child_info:
                attr_name, idx = child_info
                ASTOperations._set_child(last_parent, attr_name, idx, replacement_copy)
            else:
                logger.warning("Could not find target in parent for COW replacement")
                return None, False

            return new_nodes[0], True

        except Exception as e:
            logger.warning(f"Error during COW replacement: {e}")
            return None, False


class InternalNodeCollector(NodeVisitor):
    """Visitor to collect all internal (non-terminal) nodes from an AST."""

    def __init__(self, max_depth: int = MAX_AST_DEPTH):
        """Initialize the collector.

        Args:
            max_depth: Maximum depth to traverse
        """
        self.internal_nodes = []
        self.parent_map = {}
        self.current_parent = None
        self.current_depth = 0
        self.max_depth = max_depth

    def generic_visit(self, node):
        """Visit a node and collect it if it's internal."""
        # Check depth limit to prevent stack overflow
        if self.current_depth > self.max_depth:
            return

        # Check if this is an internal node
        if not ASTOperations.is_terminal(node):
            self.internal_nodes.append(node)

        # Record parent relationship using object ID as key
        if self.current_parent is not None:
            self.parent_map[id(node)] = self.current_parent

        # Visit children with this node as parent
        old_parent = self.current_parent
        self.current_parent = node
        self.current_depth += 1

        # Get children and visit them
        children = ASTOperations._get_children(node)
        for child in children:
            if child is not None:
                self.visit(child)

        self.current_depth -= 1
        self.current_parent = old_parent


class SubtreeReplacer(NodeVisitor):
    """Visitor to replace a specific subtree in an AST."""

    def __init__(self, target_node: Any, replacement: Any, max_depth: int = MAX_AST_DEPTH):
        """Initialize the replacer.

        Args:
            target_node: The node to find and replace (by identity)
            replacement: The replacement subtree
            max_depth: Maximum depth to traverse
        """
        self.target_node = target_node
        # Safely copy replacement with depth check
        repl_depth = _get_cached_depth(replacement)
        if repl_depth > max_depth:
            self.replacement = None
        else:
            try:
                self.replacement = copy.deepcopy(replacement)
            except RecursionError:
                self.replacement = None
        self.replaced = False
        self.current_depth = 0
        self.max_depth = max_depth

    def generic_visit(self, node):
        """Visit nodes and perform replacement when target is found."""
        # Check if replacement failed or depth limit exceeded
        if self.replacement is None or self.current_depth > self.max_depth:
            return

        self.current_depth += 1

        # Handle different node types with mutable children
        if isinstance(node, nodes.Alternation):
            for i, branch in enumerate(node.branches):
                if branch is self.target_node:
                    node.branches[i] = self.replacement
                    self.replaced = True
                    return
                self.visit(branch)

        elif isinstance(node, nodes.Sequence):
            for i, element in enumerate(node.elements):
                if element is self.target_node:
                    node.elements[i] = self.replacement
                    self.replaced = True
                    return
                self.visit(element)

        elif isinstance(node, nodes.Quantified):
            if node.atom is self.target_node:
                node.atom = self.replacement
                self.replaced = True
                return
            if node.atom:
                self.visit(node.atom)

        elif isinstance(node, nodes.Group):
            if node.content is self.target_node:
                node.content = self.replacement
                self.replaced = True
                return
            if node.content:
                self.visit(node.content)

        elif isinstance(node, nodes.Regex):
            if node.alternation is self.target_node:
                node.alternation = self.replacement
                self.replaced = True
                return
            if node.alternation:
                self.visit(node.alternation)

        elif isinstance(node, nodes.CharacterClass):
            for i, item in enumerate(node.items):
                if item is self.target_node:
                    node.items[i] = self.replacement
                    self.replaced = True
                    return
                self.visit(item)

        elif isinstance(node, nodes.LookAround):
            if node.content is self.target_node:
                node.content = self.replacement
                self.replaced = True
                return
            if node.content:
                self.visit(node.content)

        elif isinstance(node, nodes.Conditional):
            if node.condition is self.target_node:
                node.condition = self.replacement
                self.replaced = True
                return
            if node.yes is self.target_node:
                node.yes = self.replacement
                self.replaced = True
                return
            if node.no is self.target_node:
                node.no = self.replacement
                self.replaced = True
                return

            # Visit branches
            if node.condition:
                self.visit(node.condition)
            if node.yes:
                self.visit(node.yes)
            if node.no:
                self.visit(node.no)
        else:
            # For other node types, recursively visit children
            for child in ASTOperations._get_children(node):
                if child:
                    self.visit(child)

        self.current_depth -= 1
