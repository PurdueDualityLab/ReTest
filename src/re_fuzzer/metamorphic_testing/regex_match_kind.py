from enum import Enum

class RegexMatchKind(Enum):
    MATCH = "anchor_start_single"           # e.g., Python: re.match
    FULLMATCH = "entire_string_single"      # e.g., Python: re.fullmatch; Java: Matcher.matches()
    SEARCH = "first_occurrence_anywhere"    # e.g., Python: re.search; JS: String.search()
    # FIND_ALL = "all_non_overlapping"        # e.g., Python: re.findall; Ruby: String#scan; Perl: /g
    # FIND_ITER = "iterator_over_matches"     # e.g., Python: re.finditer; Java: while(m.find()); .NET: Regex.Matches
    # TEST = "boolean_exists"                 # e.g., JS: RegExp.test(); .NET: Regex.IsMatch()
    # EXEC = "stateful_next_match"            # e.g., JS: RegExp.exec() with /g or /y
    # LOOKING_AT = "anchor_start_prefix"      # e.g., Java: Matcher.lookingAt()
