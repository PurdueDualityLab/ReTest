from copy import deepcopy

from yapp.parser import parse_regex
from yapp.ast.nodes import Alternation, Group, Sequence, Quantified, Quantifier
from yapp.ast.serialize import regex_to_pattern
from yapp.util import is_k_regex
from re_fuzzer.transformations.base_transformer import BaseTransformer
from re_fuzzer.transformations.transformers_policy import TransformerPolicy

class AlternationAssociativityTransformer(BaseTransformer):
    def visit_Alternation(self, node: Alternation):
        # An alternation must have at least 2 branches
        if len(node.branches) < 2:
            return self.generic_visit(node)

        # We will check every pair of branches
        i = 0
        while i < len(node.branches) - 1:
            if self.should_stop:
                break

            left_branch = node.branches[i]
            right_branch = node.branches[i+1]

            # Pattern 1: a|(b|y) -> (a|b)|y
            # The right branch must be a group containing only an alternation
            if (
                len(right_branch.elements) == 1
                and isinstance(right_branch.elements[0], Group)
                and isinstance(right_branch.elements[0].content, Alternation)
            ):
                inner_alt = right_branch.elements[0].content
                if len(inner_alt.branches) == 2:
                    a = left_branch
                    b = inner_alt.branches[0]
                    y = inner_alt.branches[1]

                    index = i
                    left_branch_type = type(left_branch)

                    def apply_pattern_one(node=node, index=index, left_branch_type=left_branch_type, a=a, b=b, y=y):
                        new_alt = Alternation(branches=[a, b])
                        node.branches[index] = left_branch_type(elements=[Group(content=new_alt)])
                        node.branches[index + 1] = y

                    self.record_transformation(apply_pattern_one)

                    i += 1
                    continue

            # Pattern 2: (a|b)|y -> a|(b|y)
            # The left branch must be a group containing only an alternation
            if (
                len(left_branch.elements) == 1
                and isinstance(left_branch.elements[0], Group)
                and isinstance(left_branch.elements[0].content, Alternation)
            ):
                inner_alt = left_branch.elements[0].content
                if len(inner_alt.branches) == 2:
                    a = inner_alt.branches[0]
                    b = inner_alt.branches[1]
                    y = right_branch

                    index = i
                    right_branch_type = type(right_branch)

                    def apply_pattern_two(node=node, index=index, a=a, b=b, y=y, right_branch_type=right_branch_type):
                        new_alt = Alternation(branches=[b, y])
                        node.branches[index] = a
                        node.branches[index + 1] = right_branch_type(elements=[Group(content=new_alt)])

                    self.record_transformation(apply_pattern_two)

                    i += 1
                    continue

            i += 1

        self.generic_visit(node)

    def precondition(self, **regexes: str):
        # Is the regex a K-regex?
        regex1 = regexes["regex1"]
        if not is_k_regex(regex1):
            return False
        return True

    def transform(self, **regexes: str):
        # Start traversing the AST, we need to see the patterns:
        #   1. Alternation node's Branch 2 is a Sequnce->Group, Branch 1 is a Sequence
        #   2. Alternation node's Branch 1 is a Sequence-Group, Branch 2 is a Sequence
        #  It should transform:
        #    1. a|(b|y) -> (a|b)|y
        #    2. (a|b)|y -> a|(b|y)
        #
        regex1 = regexes["regex1"]

        if not self.precondition(**regexes):
            return regex1

        ast = parse_regex(regex1)
        self.reset_transformer_state()
        self.visit(ast)
        self.apply_pending_transformations()

        return regex_to_pattern(ast)

class ConcatenationAssociativityTransformer(BaseTransformer):
    def visit_Sequence(self, node: Sequence):
        if len(node.elements) < 2:
            return self.generic_visit(node)

        i = 0
        while i < len(node.elements) - 1:
            if self.should_stop:
                break

            left_el = node.elements[i]
            right_el = node.elements[i+1]

            # Pattern 1: (ab)c -> a(bc)
            if (
                isinstance(left_el, Group)
                and left_el.content and len(left_el.content.branches) == 1
            ):
                inner_seq = left_el.content.branches[0]
                if len(inner_seq.elements) > 1:
                    a = inner_seq.elements[0]
                    b_elements = inner_seq.elements[1:]
                    c = right_el

                    index = i

                    def apply_pattern_one(node=node, index=index, a=a, b_elements=b_elements, c=c):
                        new_inner_seq = Sequence(elements=b_elements + [c])
                        new_group = Group(content=Alternation(branches=[new_inner_seq]))

                        node.elements[index] = a
                        node.elements[index + 1] = new_group

                    self.record_transformation(apply_pattern_one)

                    i += 1
                    continue

            # Pattern 2: a(bc) -> (ab)c
            if (
                isinstance(right_el, Group)
                and right_el.content and len(right_el.content.branches) == 1
            ):
                inner_seq = right_el.content.branches[0]
                if len(inner_seq.elements) > 1:
                    a = left_el
                    b = inner_seq.elements[0]
                    c_elements = inner_seq.elements[1:]

                    index = i

                    def apply_pattern_two(node=node, index=index, a=a, b=b, c_elements=c_elements):
                        new_inner_seq = Sequence(elements=[a, b])
                        new_group = Group(content=Alternation(branches=[new_inner_seq]))

                        node.elements[index] = new_group
                        node.elements[index + 1:index + 2] = c_elements

                    self.record_transformation(apply_pattern_two)

                    i += 1
                    continue

            i += 1

        self.generic_visit(node)

    def precondition(self, **regexes: str):
        # Is the regex a K-regex?
        regex1 = regexes["regex1"]
        if not is_k_regex(regex1):
            return False
        return True

    def transform(self, **regexes: str):
        # Start traversing the AST, we need to see the patterns:
        #  1. Sequence->Group followed by a Sequence
        #  2. Sequence followed by a Sequence->Group
        #  It should transform:
        #    1. (ab)c -> a(bc)
        #    2. a(bc) -> (ab)c
        #
        regex1 = regexes["regex1"]

        if not self.precondition(**regexes):
            return regex1

        ast = parse_regex(regex1)
        self.reset_transformer_state()
        self.visit(ast)
        self.apply_pending_transformations()

        return regex_to_pattern(ast)

class AlternationCommutativityTransformer(BaseTransformer):
    def visit_Alternation(self, node: Alternation):
        if len(node.branches) < 2:
            return self.generic_visit(node)

        i = 0
        while i < len(node.branches) - 1:
            if self.should_stop:
                break

            left_branch = node.branches[i]
            right_branch = node.branches[i + 1]

            if isinstance(left_branch, Sequence) and isinstance(right_branch, Sequence):
                index = i

                def apply_swap(node=node, index=index):
                    node.branches[index], node.branches[index + 1] = node.branches[index + 1], node.branches[index]

                self.record_transformation(apply_swap)

                i += 1
                continue

            i += 1

        self.generic_visit(node)

    def precondition(self, **regexes: str):
        # Is the regex a K-regex?
        regex1 = regexes["regex1"]
        if not is_k_regex(regex1):
            return False
        return True

    def transform(self, **regexes: str):
        # Start traversing the AST, we need to see the patterns:
        #  1. Alternation node's Branch 1 is a Sequence, Branch 2 is a Sequence
        #  2. Alternation node's Branch 1 is a Sequence, Branch 2 is a Sequence
        #  It should transform:
        #    1. a|b -> b|a
        #    2. b|a -> a|b
        regex1 = regexes["regex1"]

        if not self.precondition(**regexes):
            return regex1

        ast = parse_regex(regex1)
        self.reset_transformer_state()
        self.visit(ast)
        self.apply_pending_transformations()

        return regex_to_pattern(ast)

class AlternationZeroIdentityTransformer(BaseTransformer):
    def __init__(self, policy: TransformerPolicy = TransformerPolicy.TRANSFORM_FIRST, use_lookaround: bool = False, use_non_capturing_group: bool = True):
        super().__init__(policy)
        self.use_lookaround = use_lookaround
        self.use_non_capturing_group = use_non_capturing_group  # some regex engines don't support non-capturing groups

    def precondition(self, **regexes: str):
        # Is the regex a K-regex?
        regex1 = regexes["regex1"]
        if not is_k_regex(regex1):
            return False
        return True

    def transform(self, **regexes: str):
        # If use_lookaround is True, convert regex1 to regex1|(?!)
        # If use_lookaround is False, convert regex1 to regex1|[^\d\D] (empty class)
        #

        # Adds an always-failing branch to the beginning and/or end of an alternation.
        regex1 = regexes["regex1"]

        if not self.precondition(**regexes):
            return regex1

        ast = parse_regex(regex1)

        base_pattern = regex_to_pattern(ast)

        zero_branch = "(?!)" if self.use_lookaround else r"[^\d\D]"
        prefix_token = f"{zero_branch}|"
        suffix_token = f"|{zero_branch}"

        core_pattern = base_pattern
        prefix_present = False
        if core_pattern.startswith(prefix_token):
            prefix_present = True
            core_pattern = core_pattern[len(prefix_token):]
        suffix_present = False
        if core_pattern.endswith(suffix_token):
            suffix_present = True
            core_pattern = core_pattern[:-len(suffix_token)]

        def wrap_body(pattern: str) -> str:
            if self.use_non_capturing_group:
                if pattern.startswith("(?:") and pattern.endswith(")"):
                    return pattern
                return f"(?:{pattern})"
            else:
                if pattern.startswith("(") and pattern.endswith(")"):
                    return pattern
                return f"({pattern})"

        state = {"prefix": prefix_present, "suffix": suffix_present}
        result = {"pattern": base_pattern}

        self.reset_transformer_state()

        def rebuild():
            segments = []
            if state["prefix"]:
                segments.append(zero_branch)
            segments.append(wrap_body(core_pattern))
            if state["suffix"]:
                segments.append(zero_branch)
            result["pattern"] = "|".join(segments)

        actions = []

        if not state["prefix"]:
            def add_prefix():
                if state["prefix"]:
                    return
                state["prefix"] = True
                rebuild()

            actions.append(add_prefix)

        if not state["suffix"]:
            def add_suffix():
                if state["suffix"]:
                    return
                state["suffix"] = True
                rebuild()

            actions.append(add_suffix)

        for action in actions:
            self.record_transformation(action)
            if self.should_stop:
                break

        self.apply_pending_transformations()

        return result["pattern"]

class ConcatenationZeroIdentityTransformer(BaseTransformer):
    def __init__(self, policy: TransformerPolicy = TransformerPolicy.TRANSFORM_FIRST, use_lookaround: bool = False, use_non_capturing_group: bool = True):
        super().__init__(policy)
        self.use_lookaround = use_lookaround
        self.use_non_capturing_group = use_non_capturing_group # some regex engines don't support non-capturing groups

    def precondition(self, **regexes: str):
        # Is the regex a K-regex?
        regex1 = regexes["regex1"]
        if not is_k_regex(regex1):
            return False
        return True

    def transform(self, **regexes: str):
        # If use_lookaround is True, convert regex1 to (?:regex1)(?!)
        # If use_lookaround is False, convert regex1 to (?:regex1)[^\d\D]
        #
        regex1 = regexes["regex1"]

        if not self.precondition(**regexes):
            return regex1

        ast = parse_regex(regex1)

        base_pattern = regex_to_pattern(ast)

        identity_suffix = "(?!)" if self.use_lookaround else r"[^\d\D]"
        self.reset_transformer_state()

        core_pattern = base_pattern
        prefix_present = False
        suffix_present = False

        if core_pattern.startswith(identity_suffix):
            prefix_present = True
            core_pattern = core_pattern[len(identity_suffix):]

        if core_pattern.endswith(identity_suffix):
            suffix_present = True
            core_pattern = core_pattern[:-len(identity_suffix)]

        def wrap_body(pattern: str) -> str:
            if not pattern:
                return pattern
            if self.use_non_capturing_group:
                if pattern.startswith("(?:") and pattern.endswith(")"):
                    return pattern
                return f"(?:{pattern})"
            if pattern.startswith("(") and pattern.endswith(")"):
                return pattern
            return f"({pattern})"

        state = {"prefix": prefix_present, "suffix": suffix_present}
        result = {"pattern": base_pattern}

        def rebuild():
            segments = []
            if state["prefix"]:
                segments.append(identity_suffix)
            body = wrap_body(core_pattern)
            if body:
                segments.append(body)
            if state["suffix"]:
                segments.append(identity_suffix)
            result["pattern"] = "".join(segments)

        actions = []

        if not state["prefix"]:
            def add_prefix():
                if state["prefix"]:
                    return
                state["prefix"] = True
                rebuild()

            actions.append(add_prefix)

        if not state["suffix"]:
            def add_suffix():
                if state["suffix"]:
                    return
                state["suffix"] = True
                rebuild()

            actions.append(add_suffix)

        for action in actions:
            self.record_transformation(action)
            if self.should_stop:
                break

        self.apply_pending_transformations()

        return result["pattern"]

class ConcatenationOneIdentityTransformer(BaseTransformer):
    def __init__(self, policy: TransformerPolicy = TransformerPolicy.TRANSFORM_FIRST, use_lookaround: bool = False, use_non_capturing_group: bool = True):
        super().__init__(policy)
        self.use_lookaround = use_lookaround
        self.use_non_capturing_group = use_non_capturing_group # some regex engines don't support non-capturing groups

    def precondition(self, **regexes: str):
        # Is the regex a K-regex?
        regex1 = regexes["regex1"]
        if not is_k_regex(regex1):
            return False
        return True

    def transform(self, **regexes: str):
        # If use_non_capturing_group is True, convert regex1 to (?:regex1)(?:)
        # If use_non_capturing_group is False, convert regex1 to (regex1)()
        #
        regex1 = regexes["regex1"]

        if not self.precondition(**regexes):
            return regex1

        ast = parse_regex(regex1)

        base_pattern = regex_to_pattern(ast)

        identity_group = "(?:)" if self.use_non_capturing_group else "()"
        self.reset_transformer_state()

        core_pattern = base_pattern
        prefix_present = False
        suffix_present = False

        if core_pattern.startswith(identity_group):
            prefix_present = True
            core_pattern = core_pattern[len(identity_group):]

        if core_pattern.endswith(identity_group):
            suffix_present = True
            core_pattern = core_pattern[:-len(identity_group)]

        def wrap_body(pattern: str) -> str:
            if not pattern:
                return pattern
            if self.use_non_capturing_group:
                if pattern.startswith("(?:") and pattern.endswith(")"):
                    return pattern
                return f"(?:{pattern})"
            if pattern.startswith("(") and pattern.endswith(")") and not pattern.startswith("(?:"):
                return pattern
            return f"({pattern})"

        state = {"prefix": prefix_present, "suffix": suffix_present}
        result = {"pattern": base_pattern}

        def rebuild():
            segments = []
            if state["prefix"]:
                segments.append(identity_group)
            body = wrap_body(core_pattern)
            if body:
                segments.append(body)
            if state["suffix"]:
                segments.append(identity_group)
            result["pattern"] = "".join(segments)

        actions = []

        if not state["prefix"]:
            def add_prefix():
                if state["prefix"]:
                    return
                state["prefix"] = True
                rebuild()

            actions.append(add_prefix)

        if not state["suffix"]:
            def add_suffix():
                if state["suffix"]:
                    return
                state["suffix"] = True
                rebuild()

            actions.append(add_suffix)

        for action in actions:
            self.record_transformation(action)
            if self.should_stop:
                break

        self.apply_pending_transformations()

        return result["pattern"]

class LeftDistributivityTransformer(BaseTransformer):
    def __init__(self, policy: TransformerPolicy = TransformerPolicy.TRANSFORM_FIRST, use_non_capturing_group: bool = True):
        super().__init__(policy)
        self.use_non_capturing_group = use_non_capturing_group  # some regex engines don't support non-capturing groups

    def visit_Sequence(self, node: Sequence):
        if len(node.elements) < 2:
            return self.generic_visit(node)

        i = 0
        while i < len(node.elements) - 1:
            if self.should_stop:
                break

            prefix_element = node.elements[i]
            candidate = node.elements[i + 1]

            if (
                isinstance(candidate, Group)
                and isinstance(candidate.content, Alternation)
                and len(candidate.content.branches) >= 2
            ):
                alt = candidate.content

                def apply_distribution(
                    parent=node,
                    prefix=prefix_element,
                    group=candidate,
                    alt=alt,
                ):
                    if prefix not in parent.elements:
                        return

                    try:
                        prefix_index = parent.elements.index(prefix)
                    except ValueError:
                        return

                    if prefix_index + 1 >= len(parent.elements):
                        return

                    if parent.elements[prefix_index + 1] is not group:
                        return

                    new_branches = []
                    for branch in alt.branches:
                        branch_elements = [deepcopy(prefix)]
                        branch_elements.extend(deepcopy(branch.elements))
                        new_branches.append(Sequence(elements=branch_elements))

                    distributed_alt = Alternation(branches=new_branches)
                    new_group = Group(
                        content=distributed_alt,
                        capturing=not self.use_non_capturing_group,
                    )

                    parent.elements[prefix_index] = new_group
                    parent.elements.pop(prefix_index + 1)

                self.record_transformation(apply_distribution)

            i += 1

        self.generic_visit(node)

    def precondition(self, **regexes: str):
        # Is the regex a K-regex?
        regex1 = regexes["regex1"]
        if not is_k_regex(regex1):
            return False
        return True

    def transform(self, **regexes: str):
        # Walk the AST and transform the pattern:
        #   1. Anything followed by a group with alternations to
        #       a(b|c|...|n) -> ab|ac|...|an
        #   Then wrap ab|ac|...|an in a group (capturing or non-capturing)
        regex1 = regexes["regex1"]

        if not self.precondition(**regexes):
            return regex1

        ast = parse_regex(regex1)

        self.reset_transformer_state()
        self.visit(ast)
        self.apply_pending_transformations()

        return regex_to_pattern(ast)

class RightDistributivityTransformer(BaseTransformer):
    def __init__(self, policy: TransformerPolicy = TransformerPolicy.TRANSFORM_FIRST, use_non_capturing_group: bool = True):
        super().__init__(policy)
        self.use_non_capturing_group = use_non_capturing_group # some regex engines don't support non-capturing groups

    def visit_Sequence(self, node: Sequence):
        if len(node.elements) < 2:
            return self.generic_visit(node)

        i = 1
        while i < len(node.elements):
            if self.should_stop:
                break

            left_element = node.elements[i - 1]
            right_element = node.elements[i]

            if (
                isinstance(left_element, Group)
                and isinstance(left_element.content, Alternation)
                and len(left_element.content.branches) >= 2
            ):

                def apply_distribution(
                    parent=node,
                    group=left_element,
                    suffix=right_element,
                ):
                    try:
                        idx = parent.elements.index(group)
                    except ValueError:
                        return

                    if idx + 1 >= len(parent.elements):
                        return

                    if parent.elements[idx + 1] is not suffix:
                        return

                    new_branches = []
                    for branch in group.content.branches:
                        branch_elements = deepcopy(branch.elements)
                        branch_elements.append(deepcopy(suffix))
                        new_branches.append(Sequence(elements=branch_elements))

                    new_alt = Alternation(branches=new_branches)
                    new_group = Group(
                        content=new_alt,
                        capturing=not self.use_non_capturing_group,
                    )

                    parent.elements[idx] = new_group
                    parent.elements.pop(idx + 1)

                self.record_transformation(apply_distribution)

            i += 1

        self.generic_visit(node)

    def precondition(self, **regexes: str):
        # Is the regex a K-regex?
        regex1 = regexes["regex1"]
        if not is_k_regex(regex1):
            return False
        return True

    def transform(self, **regexes: str):
        # Walk the AST and transform the pattern:
        #   1. Anything preceded by a group with alternations to
        #       (a|b|c|...|n)g -> ag|bg|cg|...|ng
        #   Then wrap ag|bg|cg|...|ng in a group (capturing or non-capturing)
        regex1 = regexes["regex1"]

        if not self.precondition(**regexes):
            return regex1

        ast = parse_regex(regex1)

        self.reset_transformer_state()
        self.visit(ast)
        self.apply_pending_transformations()

        return regex_to_pattern(ast)

class AlternationIdempotenceTransformer(BaseTransformer):
    def __init__(self, policy: TransformerPolicy = TransformerPolicy.TRANSFORM_FIRST, use_non_capturing_group: bool = True):
        super().__init__(policy)
        self.use_non_capturing_group = use_non_capturing_group # some regex engines don't support non-capturing groups

    def precondition(self, **regexes: str):
        # Is the regex a K-regex?
        regex1 = regexes["regex1"]
        if not is_k_regex(regex1):
            return False
        return True

    def transform(self, **regexes: str):
        # Transform regex1 to (?:regex1)|(?:regex1) if use_non_capturing_group is True
        # Transform regex1 to (regex1)|(regex1) if use_non_capturing_group is False
        #
        regex1 = regexes["regex1"]

        if not self.precondition(**regexes):
            return regex1

        ast = parse_regex(regex1)

        existing_pattern = regex_to_pattern(ast)

        if self.use_non_capturing_group:
            left = f"(?:{existing_pattern})"
            right = left
        else:
            left = f"({existing_pattern})"
            right = left

        desired = f"{left}|{right}"
        if existing_pattern == desired:
            return existing_pattern

        self.reset_transformer_state()

        result = {"pattern": existing_pattern}

        def apply_idempotence():
            result["pattern"] = desired

        self.record_transformation(apply_idempotence)
        self.apply_pending_transformations()

        return result["pattern"]

class LeftKleeneStarUnrollingTransformer(BaseTransformer):
    def __init__(self, policy: TransformerPolicy = TransformerPolicy.TRANSFORM_FIRST, use_non_capturing_group: bool = True):
        super().__init__(policy)
        self.use_non_capturing_group = use_non_capturing_group # some regex engines don't support non-capturing groups

    def visit_Sequence(self, node: Sequence):
        if not node.elements:
            return self.generic_visit(node)

        idx = 0
        while idx < len(node.elements):
            if self.should_stop:
                break

            element = node.elements[idx]

            if isinstance(element, Quantified) and element.quantifier:
                quantifier = element.quantifier
                if quantifier.minimum == 0 and quantifier.maximum is None and element.atom is not None:

                    def apply_unrolling(parent=node, index=idx, quantified=element):
                        if index >= len(parent.elements):
                            return

                        current = parent.elements[index]
                        if current is not quantified:
                            return

                        atom_copy_for_prefix = deepcopy(quantified.atom)
                        atom_copy_for_star = Quantified(
                            atom=deepcopy(quantified.atom),
                            quantifier=deepcopy(quantified.quantifier),
                        )

                        rr_sequence = Sequence(elements=[atom_copy_for_prefix, atom_copy_for_star])

                        epsilon_group = Group(
                            content=Alternation(branches=[Sequence(elements=[])]),
                            capturing=not self.use_non_capturing_group,
                        )

                        rr_group = Group(
                            content=Alternation(branches=[rr_sequence]),
                            capturing=not self.use_non_capturing_group,
                        )

                        distributed_alternation = Alternation(
                            branches=[
                                Sequence(elements=[epsilon_group]),
                                Sequence(elements=[rr_group]),
                            ]
                        )

                        parent.elements[index] = Group(
                            content=distributed_alternation,
                            capturing=not self.use_non_capturing_group,
                        )

                    self.record_transformation(apply_unrolling)

            idx += 1

        self.generic_visit(node)

    def precondition(self, **regexes: str):
        # Is the regex a K-regex?
        regex1 = regexes["regex1"]
        if not is_k_regex(regex1):
            return False
        return True

    def transform(self, **regexes: str):
        # Find star quantifed nodes and transform them to:
        #   R* -> RR*
        #   Then apply (?:)|(?:RR*) if use_non_capturing_group is True
        #   or ()|(RR*) if use_non_capturing_group is False
        # Lastly, wrap the result in a group (capturing or non-capturing)
        regex1 = regexes["regex1"]

        if not self.precondition(**regexes):
            return regex1

        ast = parse_regex(regex1)

        self.reset_transformer_state()
        self.visit(ast)
        self.apply_pending_transformations()

        return regex_to_pattern(ast)

class RightKleeneStarUnrollingTransformer(BaseTransformer):
    def __init__(self, policy: TransformerPolicy = TransformerPolicy.TRANSFORM_FIRST, use_non_capturing_group: bool = True):
        super().__init__(policy)
        self.use_non_capturing_group = use_non_capturing_group # some regex engines don't support non-capturing groups

    def visit_Sequence(self, node: Sequence):
        if not node.elements:
            return self.generic_visit(node)

        idx = 0
        while idx < len(node.elements):
            if self.should_stop:
                break

            element = node.elements[idx]

            if isinstance(element, Quantified) and element.quantifier:
                quantifier = element.quantifier
                if quantifier.minimum == 0 and quantifier.maximum is None and element.atom is not None:

                    def apply_unrolling(parent=node, index=idx, quantified=element):
                        if index >= len(parent.elements):
                            return

                        current = parent.elements[index]
                        if current is not quantified:
                            return

                        quant_copy_for_star = Quantified(
                            atom=deepcopy(quantified.atom),
                            quantifier=deepcopy(quantified.quantifier),
                        )
                        atom_copy_for_suffix = deepcopy(quantified.atom)

                        rstar_r_sequence = Sequence(elements=[quant_copy_for_star, atom_copy_for_suffix])

                        epsilon_group = Group(
                            content=Alternation(branches=[Sequence(elements=[])]),
                            capturing=not self.use_non_capturing_group,
                        )

                        rstar_r_group = Group(
                            content=Alternation(branches=[rstar_r_sequence]),
                            capturing=not self.use_non_capturing_group,
                        )

                        distributed_alternation = Alternation(
                            branches=[
                                Sequence(elements=[epsilon_group]),
                                Sequence(elements=[rstar_r_group]),
                            ]
                        )

                        parent.elements[index] = Group(
                            content=distributed_alternation,
                            capturing=not self.use_non_capturing_group,
                        )

                    self.record_transformation(apply_unrolling)

            idx += 1

        self.generic_visit(node)

    def precondition(self, **regexes: str):
        # Is the regex a K-regex?
        regex1 = regexes["regex1"]
        if not is_k_regex(regex1):
            return False
        return True

    def transform(self, **regexes: str):
        # Find star quantifed nodes and transform them to:
        #   R* -> R*R
        #   Then apply (?:)|(?:R*R) if use_non_capturing_group is True
        #   or ()|(R*R) if use_non_capturing_group is False
        # Lastly, wrap the result in a group (capturing or non-capturing)
        regex1 = regexes["regex1"]

        if not self.precondition(**regexes):
            return regex1

        ast = parse_regex(regex1)

        self.reset_transformer_state()
        self.visit(ast)
        self.apply_pending_transformations()

        return regex_to_pattern(ast)

class KleeneStarCollapsingIdempotenceTransformer(BaseTransformer):
    def __init__(self, policy: TransformerPolicy = TransformerPolicy.TRANSFORM_FIRST, use_non_capturing_group: bool = True):
        super().__init__(policy)
        self.use_non_capturing_group = use_non_capturing_group  # some regex engines don't support non-capturing groups

    @staticmethod
    def _is_kleene_quantified(node: Quantified) -> bool:
        quant = node.quantifier
        return quant is not None and quant.minimum == 0 and quant.maximum is None

    def _unwrap_to_inner_quant(self, group: Group) -> Quantified | None:
        current = group

        while True:
            if not isinstance(current.content, Alternation):
                return None
            branches = current.content.branches
            if len(branches) != 1:
                return None
            sequence = branches[0]
            if not isinstance(sequence, Sequence):
                return None
            if len(sequence.elements) != 1:
                return None
            element = sequence.elements[0]
            if isinstance(element, Group):
                current = element
                continue
            if isinstance(element, Quantified) and self._is_kleene_quantified(element):
                return element
            return None

    def visit_Sequence(self, node: Sequence):
        if not node.elements:
            return self.generic_visit(node)

        idx = 0
        while idx < len(node.elements):
            if self.should_stop:
                break

            element = node.elements[idx]

            if (
                isinstance(element, Quantified)
                and self._is_kleene_quantified(element)
                and isinstance(element.atom, Group)
            ):
                inner_quantified = self._unwrap_to_inner_quant(element.atom)
                if inner_quantified is None:
                    idx += 1
                    continue

                def apply_collapse(parent=node, index=idx, quantified=element, inner=inner_quantified):
                    if index >= len(parent.elements):
                        return
                    current = parent.elements[index]
                    if current is not quantified:
                        return

                    replacement_group = Group(
                        content=Alternation(
                            branches=[
                                Sequence(elements=[deepcopy(inner)])
                            ]
                        ),
                        capturing=not self.use_non_capturing_group,
                    )

                    parent.elements[index] = replacement_group

                self.record_transformation(apply_collapse)

            idx += 1

        self.generic_visit(node)

    def precondition(self, **regexes: str):
        # Is the regex a K-regex?
        regex1 = regexes["regex1"]
        if not is_k_regex(regex1):
            return False
        return True

    def transform(self, **regexes: str):
        # Look for this pattern in the AST:
        #  1. A group that has its most inner content as a star quantified node, and the group itself is quantified
        # If found:
        #   Transform -> (R*)* -> (?:R*) if use_non_capturing_group is True
        #   or -> (R*)* -> (R*) if use_non_capturing_group is False

        regex1 = regexes["regex1"]

        if not self.precondition(**regexes):
            return regex1

        ast = parse_regex(regex1)

        self.reset_transformer_state()
        self.visit(ast)
        self.apply_pending_transformations()

        return regex_to_pattern(ast)

class KleeneStarUnrollingIdempotenceTransformer(BaseTransformer):
    def __init__(self, policy: TransformerPolicy = TransformerPolicy.TRANSFORM_FIRST, use_non_capturing_group: bool = True):
        super().__init__(policy)
        self.use_non_capturing_group = use_non_capturing_group  # some regex engines don't support non-capturing groups

    @staticmethod
    def _is_kleene_quantified(node: Quantified) -> bool:
        """Check if a node is quantified with Kleene star (*)"""
        quant = node.quantifier
        return quant is not None and quant.minimum == 0 and quant.maximum is None

    def _is_already_wrapped(self, element: Quantified) -> bool:
        """
        Check if this Kleene star is already wrapped in another Kleene star.
        Returns True if the atom is a Group containing a Kleene-quantified element.
        """
        if not isinstance(element.atom, Group):
            return False

        # Check if the group contains a Kleene-quantified element
        group = element.atom
        if not isinstance(group.content, Alternation):
            return False

        branches = group.content.branches
        if len(branches) != 1:
            return False

        sequence = branches[0]
        if not isinstance(sequence, Sequence):
            return False

        if len(sequence.elements) != 1:
            return False

        inner_element = sequence.elements[0]
        if isinstance(inner_element, Quantified) and self._is_kleene_quantified(inner_element):
            return True

        return False

    def visit_Sequence(self, node: Sequence):
        if not node.elements:
            return self.generic_visit(node)

        idx = 0
        while idx < len(node.elements):
            if self.should_stop:
                break

            element = node.elements[idx]

            # Find simple Kleene star nodes that are NOT already wrapped
            if (
                isinstance(element, Quantified)
                and self._is_kleene_quantified(element)
                and not self._is_already_wrapped(element)
            ):
                def apply_unrolling(parent=node, index=idx, quantified=element):
                    if index >= len(parent.elements):
                        return

                    current = parent.elements[index]
                    if current is not quantified:
                        return

                    # Create a group containing the Kleene star: (R*)
                    inner_group = Group(
                        content=Alternation(
                            branches=[
                                Sequence(elements=[deepcopy(quantified)])
                            ]
                        ),
                        capturing=not self.use_non_capturing_group,
                    )

                    # Wrap the group with another Kleene star: (R*)*
                    outer_quantified = Quantified(
                        atom=inner_group,
                        quantifier=Quantifier(minimum=0, maximum=None),
                    )

                    parent.elements[index] = outer_quantified

                self.record_transformation(apply_unrolling)

            idx += 1

        self.generic_visit(node)

    def precondition(self, **regexes: str):
        # Is the regex a K-regex?
        regex1 = regexes["regex1"]
        if not is_k_regex(regex1):
            return False
        return True

    def transform(self, **regexes: str):
        # Look for simple Kleene star nodes (R*)
        # Transform R* -> (?:R*)* if use_non_capturing_group is True
        #            or (R*)* if use_non_capturing_group is False
        #
        # This is the idempotence property: R* ≡ (R*)*
        # This transformer does the "unrolling" direction (expanding)
        # while KleeneStarCollapsingIdempotenceTransformer does the "collapsing" direction

        regex1 = regexes["regex1"]

        if not self.precondition(**regexes):
            return regex1

        ast = parse_regex(regex1)

        self.reset_transformer_state()
        self.visit(ast)
        self.apply_pending_transformations()

        return regex_to_pattern(ast)


class SumStarLeftTransformer(BaseTransformer):
    """
    Sum-star (left) law: (α + β)* = α*(βα*)*
    Transforms alternation Kleene star to left-distributed form.
    Example: (a|b)* -> a*(ba*)*
    """
    def __init__(self, policy: TransformerPolicy = TransformerPolicy.TRANSFORM_FIRST, use_non_capturing_group: bool = True):
        super().__init__(policy)
        self.use_non_capturing_group = use_non_capturing_group

    @staticmethod
    def _is_kleene_quantified(node: Quantified) -> bool:
        """Check if a node is quantified with Kleene star (*)"""
        quant = node.quantifier
        return quant is not None and quant.minimum == 0 and quant.maximum is None

    def visit_Sequence(self, node: Sequence):
        if not node.elements:
            return self.generic_visit(node)

        idx = 0
        while idx < len(node.elements):
            if self.should_stop:
                break

            element = node.elements[idx]

            # Pattern: (α|β)*
            # Find Kleene star with alternation group
            if (
                isinstance(element, Quantified)
                and self._is_kleene_quantified(element)
                and isinstance(element.atom, Group)
            ):
                group = element.atom
                if isinstance(group.content, Alternation) and len(group.content.branches) == 2:
                    alpha = group.content.branches[0]
                    beta = group.content.branches[1]

                    def apply_sum_star_left(parent=node, index=idx, alpha=alpha, beta=beta):
                        if index >= len(parent.elements):
                            return

                        # Build α*
                        alpha_star = Quantified(
                            atom=Group(
                                content=Alternation(branches=[deepcopy(alpha)]),
                                capturing=not self.use_non_capturing_group,
                            ),
                            quantifier=Quantifier(minimum=0, maximum=None),
                        )

                        # Build βα*
                        beta_alpha_star_seq = Sequence(
                            elements=[
                                *deepcopy(beta.elements),
                                Group(
                                    content=Alternation(branches=[deepcopy(alpha)]),
                                    capturing=not self.use_non_capturing_group,
                                )
                            ]
                        )
                        # Add * to the last element
                        if beta_alpha_star_seq.elements:
                            last = beta_alpha_star_seq.elements[-1]
                            beta_alpha_star_seq.elements[-1] = Quantified(
                                atom=last,
                                quantifier=Quantifier(minimum=0, maximum=None),
                            )

                        # Build (βα*)*
                        beta_alpha_star_star = Quantified(
                            atom=Group(
                                content=Alternation(branches=[beta_alpha_star_seq]),
                                capturing=not self.use_non_capturing_group,
                            ),
                            quantifier=Quantifier(minimum=0, maximum=None),
                        )

                        # Replace with α*(βα*)*
                        parent.elements[index] = alpha_star
                        parent.elements.insert(index + 1, beta_alpha_star_star)

                    self.record_transformation(apply_sum_star_left)

            idx += 1

        self.generic_visit(node)

    def precondition(self, **regexes: str):
        regex1 = regexes["regex1"]
        if not is_k_regex(regex1):
            return False
        return True

    def transform(self, **regexes: str):
        """
        Sum-star (left) law: (α + β)* → α*(βα*)*
        Example: (a|b)* → a*(ba*)*
        """
        regex1 = regexes["regex1"]

        if not self.precondition(**regexes):
            return regex1

        ast = parse_regex(regex1)
        self.reset_transformer_state()
        self.visit(ast)
        self.apply_pending_transformations()

        return regex_to_pattern(ast)


class SumStarRightTransformer(BaseTransformer):
    """
    Sum-star (right) law: (α + β)* = (α*β)*α*
    Transforms alternation Kleene star to right-distributed form.
    Example: (a|b)* -> (a*b)*a*
    """
    def __init__(self, policy: TransformerPolicy = TransformerPolicy.TRANSFORM_FIRST, use_non_capturing_group: bool = True):
        super().__init__(policy)
        self.use_non_capturing_group = use_non_capturing_group

    @staticmethod
    def _is_kleene_quantified(node: Quantified) -> bool:
        """Check if a node is quantified with Kleene star (*)"""
        quant = node.quantifier
        return quant is not None and quant.minimum == 0 and quant.maximum is None

    def visit_Sequence(self, node: Sequence):
        if not node.elements:
            return self.generic_visit(node)

        idx = 0
        while idx < len(node.elements):
            if self.should_stop:
                break

            element = node.elements[idx]

            # Pattern: (α|β)*
            if (
                isinstance(element, Quantified)
                and self._is_kleene_quantified(element)
                and isinstance(element.atom, Group)
            ):
                group = element.atom
                if isinstance(group.content, Alternation) and len(group.content.branches) == 2:
                    alpha = group.content.branches[0]
                    beta = group.content.branches[1]

                    def apply_sum_star_right(parent=node, index=idx, alpha=alpha, beta=beta):
                        if index >= len(parent.elements):
                            return

                        # Build α*β sequence
                        alpha_star_beta_seq = Sequence(
                            elements=[
                                Quantified(
                                    atom=Group(
                                        content=Alternation(branches=[deepcopy(alpha)]),
                                        capturing=not self.use_non_capturing_group,
                                    ),
                                    quantifier=Quantifier(minimum=0, maximum=None),
                                ),
                                *deepcopy(beta.elements),
                            ]
                        )

                        # Build (α*β)*
                        alpha_star_beta_star = Quantified(
                            atom=Group(
                                content=Alternation(branches=[alpha_star_beta_seq]),
                                capturing=not self.use_non_capturing_group,
                            ),
                            quantifier=Quantifier(minimum=0, maximum=None),
                        )

                        # Build α*
                        alpha_star = Quantified(
                            atom=Group(
                                content=Alternation(branches=[deepcopy(alpha)]),
                                capturing=not self.use_non_capturing_group,
                            ),
                            quantifier=Quantifier(minimum=0, maximum=None),
                        )

                        # Replace with (α*β)*α*
                        parent.elements[index] = alpha_star_beta_star
                        parent.elements.insert(index + 1, alpha_star)

                    self.record_transformation(apply_sum_star_right)

            idx += 1

        self.generic_visit(node)

    def precondition(self, **regexes: str):
        regex1 = regexes["regex1"]
        if not is_k_regex(regex1):
            return False
        return True

    def transform(self, **regexes: str):
        """
        Sum-star (right) law: (α + β)* → (α*β)*α*
        Example: (a|b)* → (a*b)*a*
        """
        regex1 = regexes["regex1"]

        if not self.precondition(**regexes):
            return regex1

        ast = parse_regex(regex1)
        self.reset_transformer_state()
        self.visit(ast)
        self.apply_pending_transformations()

        return regex_to_pattern(ast)


class ProductStarTransformer(BaseTransformer):
    """
    Product-star law: (αβ)* = ε|α(βα)*β
    Transforms concatenation Kleene star to unrolled form with epsilon.
    Example: (ab)* -> ε|a(ba)*b
    """
    def __init__(self, policy: TransformerPolicy = TransformerPolicy.TRANSFORM_FIRST, use_non_capturing_group: bool = True):
        super().__init__(policy)
        self.use_non_capturing_group = use_non_capturing_group

    @staticmethod
    def _is_kleene_quantified(node: Quantified) -> bool:
        """Check if a node is quantified with Kleene star (*)"""
        quant = node.quantifier
        return quant is not None and quant.minimum == 0 and quant.maximum is None

    def visit_Sequence(self, node: Sequence):
        if not node.elements:
            return self.generic_visit(node)

        idx = 0
        while idx < len(node.elements):
            if self.should_stop:
                break

            element = node.elements[idx]

            # Pattern: (αβ)* where α and β are sequences
            if (
                isinstance(element, Quantified)
                and self._is_kleene_quantified(element)
                and isinstance(element.atom, Group)
            ):
                group = element.atom
                if (
                    isinstance(group.content, Alternation)
                    and len(group.content.branches) == 1
                ):
                    sequence = group.content.branches[0]
                    if isinstance(sequence, Sequence) and len(sequence.elements) >= 2:
                        # Split into α (first element) and β (rest)
                        alpha_elements = [sequence.elements[0]]
                        beta_elements = sequence.elements[1:]

                        def apply_product_star(parent=node, index=idx, alpha_elements=alpha_elements, beta_elements=beta_elements):
                            if index >= len(parent.elements):
                                return

                            # Build ε (empty group)
                            epsilon_branch = Sequence(elements=[])

                            # Build βα sequence
                            beta_alpha_seq = Sequence(
                                elements=[
                                    *deepcopy(beta_elements),
                                    *deepcopy(alpha_elements),
                                ]
                            )

                            # Build (βα)*
                            beta_alpha_star = Quantified(
                                atom=Group(
                                    content=Alternation(branches=[beta_alpha_seq]),
                                    capturing=not self.use_non_capturing_group,
                                ),
                                quantifier=Quantifier(minimum=0, maximum=None),
                            )

                            # Build α(βα)*β
                            unrolled_seq = Sequence(
                                elements=[
                                    *deepcopy(alpha_elements),
                                    beta_alpha_star,
                                    *deepcopy(beta_elements),
                                ]
                            )

                            # Build ε|α(βα)*β
                            alternation = Alternation(
                                branches=[
                                    epsilon_branch,
                                    unrolled_seq,
                                ]
                            )

                            # Wrap in group
                            result_group = Group(
                                content=alternation,
                                capturing=not self.use_non_capturing_group,
                            )

                            # Replace the original (αβ)* with (?:ε|α(βα)*β)
                            parent.elements[index] = result_group

                        self.record_transformation(apply_product_star)

            idx += 1

        self.generic_visit(node)

    def precondition(self, **regexes: str):
        regex1 = regexes["regex1"]
        if not is_k_regex(regex1):
            return False
        return True

    def transform(self, **regexes: str):
        """
        Product-star law: (αβ)* → ε|α(βα)*β
        Example: (ab)* → ε|a(ba)*b
        """
        regex1 = regexes["regex1"]

        if not self.precondition(**regexes):
            return regex1

        ast = parse_regex(regex1)
        self.reset_transformer_state()
        self.visit(ast)
        self.apply_pending_transformations()

        return regex_to_pattern(ast)

