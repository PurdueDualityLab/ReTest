"""PCRE SUT using CFFI to directly call the compiled library.

This allows using custom-compiled PCRE libraries with sanitizer instrumentation
for fuzzing without depending on third-party Python bindings.

PCRE (version 1) API differs from PCRE2:
- pcre_compile() vs pcre2_compile_8()
- pcre_exec() vs pcre2_match_8()
- pcre_study() enables JIT (vs pcre2_jit_compile_8())
- pcre_dfa_exec() for DFA matching
"""

import os
from typing import List, Optional, Tuple

from cffi import FFI

from re_fuzzer.sut.base_sut import BaseSUT
from re_fuzzer.sut.engine_match import EngineMatch

# CFFI definitions for PCRE 8-bit API
PCRE_CDEF = """
/* Opaque types */
typedef struct real_pcre8_or_16 pcre;

/* The pcre_extra structure for passing additional data to pcre_exec() */
typedef struct pcre_extra {
    unsigned long int flags;
    void *study_data;
    unsigned long int match_limit;
    void *callout_data;
    const unsigned char *tables;
    unsigned long int match_limit_recursion;
    unsigned char **mark;
    void *executable_jit;
} pcre_extra;

/* Compile a pattern */
pcre *pcre_compile(const char *pattern,
                   int options,
                   const char **errptr,
                   int *erroffset,
                   const unsigned char *tableptr);

/* Compile with error code (alternative API) */
pcre *pcre_compile2(const char *pattern,
                    int options,
                    int *errorcodeptr,
                    const char **errptr,
                    int *erroffset,
                    const unsigned char *tableptr);

/* Study a pattern (can enable JIT) */
pcre_extra *pcre_study(const pcre *code,
                       int options,
                       const char **errptr);

/* Free study data */
void pcre_free_study(pcre_extra *extra);

/* Free a compiled pattern - note: pcre_free is a function pointer in PCRE */
extern void (*pcre_free)(void *);

/* Execute a match (backtracking engine) */
int pcre_exec(const pcre *code,
              const pcre_extra *extra,
              const char *subject,
              int length,
              int startoffset,
              int options,
              int *ovector,
              int ovecsize);

/* Execute a match (DFA engine) */
int pcre_dfa_exec(const pcre *code,
                  const pcre_extra *extra,
                  const char *subject,
                  int length,
                  int startoffset,
                  int options,
                  int *ovector,
                  int ovecsize,
                  int *workspace,
                  int wscount);

/* Get information about a compiled pattern */
int pcre_fullinfo(const pcre *code,
                  const pcre_extra *extra,
                  int what,
                  void *where);

/* JIT stack allocation (optional) */
typedef struct real_pcre_jit_stack pcre_jit_stack;
pcre_jit_stack *pcre_jit_stack_alloc(int startsize, int maxsize);
void pcre_jit_stack_free(pcre_jit_stack *stack);
"""

# PCRE option flags (from pcre.h)
PCRE_CASELESS = 0x00000001
PCRE_MULTILINE = 0x00000002
PCRE_DOTALL = 0x00000004
PCRE_EXTENDED = 0x00000008
PCRE_ANCHORED = 0x00000010
PCRE_DOLLAR_ENDONLY = 0x00000020
PCRE_EXTRA = 0x00000040
PCRE_NOTBOL = 0x00000080
PCRE_NOTEOL = 0x00000100
PCRE_UNGREEDY = 0x00000200
PCRE_NOTEMPTY = 0x00000400
PCRE_UTF8 = 0x00000800
PCRE_NO_AUTO_CAPTURE = 0x00001000
PCRE_NO_UTF8_CHECK = 0x00002000
PCRE_AUTO_CALLOUT = 0x00004000
PCRE_PARTIAL_SOFT = 0x00008000
PCRE_PARTIAL = PCRE_PARTIAL_SOFT  # Alias
PCRE_DFA_SHORTEST = 0x00010000
PCRE_DFA_RESTART = 0x00020000
PCRE_FIRSTLINE = 0x00040000
PCRE_DUPNAMES = 0x00080000
PCRE_NEWLINE_CR = 0x00100000
PCRE_NEWLINE_LF = 0x00200000
PCRE_NEWLINE_CRLF = 0x00300000
PCRE_NEWLINE_ANY = 0x00400000
PCRE_NEWLINE_ANYCRLF = 0x00500000
PCRE_BSR_ANYCRLF = 0x00800000
PCRE_BSR_UNICODE = 0x01000000
PCRE_JAVASCRIPT_COMPAT = 0x02000000
PCRE_NO_START_OPTIMIZE = 0x04000000
PCRE_NO_START_OPTIMISE = PCRE_NO_START_OPTIMIZE  # Alias
PCRE_PARTIAL_HARD = 0x08000000
PCRE_NOTEMPTY_ATSTART = 0x10000000
PCRE_UCP = 0x20000000

# Study options
PCRE_STUDY_JIT_COMPILE = 0x0001
PCRE_STUDY_JIT_PARTIAL_SOFT_COMPILE = 0x0002
PCRE_STUDY_JIT_PARTIAL_HARD_COMPILE = 0x0004

# pcre_extra flags
PCRE_EXTRA_MATCH_LIMIT = 0x0002
PCRE_EXTRA_MATCH_LIMIT_RECURSION = 0x0010

# Error codes
PCRE_ERROR_NOMATCH = -1
PCRE_ERROR_NULL = -2
PCRE_ERROR_BADOPTION = -3
PCRE_ERROR_BADMAGIC = -4
PCRE_ERROR_NOMEMORY = -6
PCRE_ERROR_MATCHLIMIT = -8
PCRE_ERROR_PARTIAL = -12
PCRE_ERROR_RECURSIONLIMIT = -21
PCRE_ERROR_JIT_STACKLIMIT = -27

# Info requests
PCRE_INFO_CAPTURECOUNT = 2

# Newline mode options for rotation (coverage exploration)
NEWLINE_MODES = [
    0,  # Default (compile-time setting)
    PCRE_NEWLINE_CR,
    PCRE_NEWLINE_LF,
    PCRE_NEWLINE_CRLF,
    PCRE_NEWLINE_ANY,
    PCRE_NEWLINE_ANYCRLF,
]

# BSR (backslash R) modes for rotation
BSR_MODES = [
    0,  # Default
    PCRE_BSR_ANYCRLF,
    PCRE_BSR_UNICODE,
]


class PCREError(Exception):
    """Raised for PCRE engine errors (compile or match)."""
    pass


class PCRECFFI(BaseSUT):
    """PCRE SUT using CFFI to call the compiled library directly.

    This implementation allows using custom-compiled PCRE libraries,
    which is useful for fuzzing with sanitizer instrumentation.

    The library path can be specified via:
    1. Constructor parameter `library_path`
    2. Environment variable `PCRE_LIBRARY_PATH`
    3. Default system library name `libpcre.so`

    Unlike PCRE2, PCRE (version 1) uses stack-based backtracking which can
    cause stack overflow on deeply nested patterns. This SUT provides
    match_limit and recursion_limit to mitigate this.
    """

    name = "pcre_cffi"

    # Default limits to prevent catastrophic backtracking
    DEFAULT_MATCH_LIMIT = 10_000        # Max match operations
    DEFAULT_RECURSION_LIMIT = 500       # Max recursion depth (stack protection)

    def __init__(
        self,
        library_path: Optional[str] = None,
        compile_options: int = PCRE_UTF8 | PCRE_UCP,
        match_options: int = 0,
        match_limit: Optional[int] = None,
        recursion_limit: Optional[int] = None,
        use_jit: bool = True,
        use_dfa_percentage: float = 0.0,
        rotate_options: bool = False,
        partial_match_percentage: float = 0.0,
    ):
        """Initialize the PCRE CFFI wrapper.

        Args:
            library_path: Path to libpcre.so. If None, uses PCRE_LIBRARY_PATH
                         env var or falls back to system library.
            compile_options: Default compile options (PCRE_UTF8 | PCRE_UCP by default)
            match_options: Default match options (0 by default)
            match_limit: Max match operations (default: 10,000)
            recursion_limit: Max recursion depth (default: 500)
            use_jit: Whether to JIT compile patterns (default: True)
            use_dfa_percentage: Percentage of matches to run with DFA engine (0.0-1.0)
            rotate_options: Whether to rotate through different compile/match options
                           for coverage exploration (default: False)
            partial_match_percentage: Percentage of matches to try partial matching (0.0-1.0)
        """
        self._compile_options = compile_options
        self._match_options = match_options
        self._match_limit = match_limit or self.DEFAULT_MATCH_LIMIT
        self._recursion_limit = recursion_limit or self.DEFAULT_RECURSION_LIMIT
        self._use_jit = use_jit
        self._use_dfa_percentage = use_dfa_percentage
        self._rotate_options = rotate_options
        self._partial_match_percentage = partial_match_percentage
        self._call_count = 0  # Counter for option rotation

        # Determine library path
        if library_path is None:
            library_path = os.environ.get("PCRE_LIBRARY_PATH", "libpcre.so")

        # Initialize CFFI
        self._ffi = FFI()
        self._ffi.cdef(PCRE_CDEF)

        try:
            self._lib = self._ffi.dlopen(library_path)
        except OSError as e:
            raise PCREError(f"Failed to load PCRE library from '{library_path}': {e}")

        # Allocate workspace for DFA matching
        self._dfa_workspace_size = 1000
        self._dfa_workspace = self._ffi.new(f"int[{self._dfa_workspace_size}]")

    def _get_capture_count(self, code) -> int:
        """Get the number of capture groups in a compiled pattern."""
        capture_count = self._ffi.new("int[1]")
        rc = self._lib.pcre_fullinfo(code, self._ffi.NULL, PCRE_INFO_CAPTURECOUNT, capture_count)
        if rc != 0:
            return 0
        return capture_count[0]

    def _compile(self, pattern: str, flags: int = 0):
        """Compile a regex pattern.

        Args:
            pattern: The regex pattern string
            flags: Additional compile flags

        Returns:
            Tuple of (compiled code, pcre_extra with study data)

        Raises:
            PCREError: If compilation fails
        """
        pat_bytes = pattern.encode("utf-8")

        errptr = self._ffi.new("char*[1]")
        erroffset = self._ffi.new("int[1]")

        # Use rotated compile options for coverage exploration
        base_options = self._get_rotated_compile_options()
        options = base_options | flags

        code = self._lib.pcre_compile(
            pat_bytes,
            options,
            errptr,
            erroffset,
            self._ffi.NULL,
        )

        if code == self._ffi.NULL:
            err_msg = self._ffi.string(errptr[0]).decode("utf-8", "replace") if errptr[0] else "Unknown error"
            raise PCREError(
                f"Compile error at offset {erroffset[0]}: {err_msg}"
            )

        # Study the pattern (optionally with JIT)
        extra = self._ffi.NULL
        if self._use_jit:
            study_errptr = self._ffi.new("char*[1]")
            # Enable JIT for normal matching AND partial matching modes
            # This allows using PCRE_PARTIAL_SOFT and PCRE_PARTIAL_HARD at match time
            study_opts = (
                PCRE_STUDY_JIT_COMPILE |
                PCRE_STUDY_JIT_PARTIAL_SOFT_COMPILE |
                PCRE_STUDY_JIT_PARTIAL_HARD_COMPILE
            )
            extra = self._lib.pcre_study(code, study_opts, study_errptr)
            # JIT compile failure is not fatal - we can still use the pattern
            # extra may be NULL if study found nothing useful

        # Set up match limits via pcre_extra structure
        if extra == self._ffi.NULL:
            # Need to create pcre_extra for limits
            extra = self._ffi.new("pcre_extra*")
            extra.flags = 0

        # Apply match limits to prevent catastrophic backtracking
        extra.flags |= PCRE_EXTRA_MATCH_LIMIT | PCRE_EXTRA_MATCH_LIMIT_RECURSION
        extra.match_limit = self._match_limit
        extra.match_limit_recursion = self._recursion_limit

        return code, extra

    def _free_code(self, code) -> None:
        """Free a compiled pattern."""
        if code != self._ffi.NULL:
            # PCRE uses pcre_free function pointer
            free_func = self._lib.pcre_free
            if free_func != self._ffi.NULL:
                free_func(code)

    def _free_extra(self, extra) -> None:
        """Free study data."""
        if extra != self._ffi.NULL:
            self._lib.pcre_free_study(extra)

    def _match_at(
        self,
        code,
        extra,
        subject: bytes,
        ovecsize: int,
        start_offset: int = 0,
        use_dfa: bool = False,
    ) -> Tuple[int, Optional[List[int]]]:
        """Perform a single match at the given offset.

        Args:
            code: Compiled PCRE code
            extra: pcre_extra structure (can be NULL)
            subject: Subject string as bytes
            ovecsize: Size of ovector (must be multiple of 3)
            start_offset: Starting offset in bytes
            use_dfa: Whether to use DFA engine instead of backtracking

        Returns:
            Tuple of (return_code, ovector or None)
        """
        ovector = self._ffi.new(f"int[{ovecsize}]")

        # Get rotated match options for coverage exploration
        match_opts = self._get_rotated_match_options()

        if use_dfa:
            # DFA matching - add DFA-specific options if needed
            dfa_opts = match_opts
            # Occasionally try DFA_SHORTEST for coverage
            if self._rotate_options and (self._call_count % 5 == 0):
                dfa_opts |= PCRE_DFA_SHORTEST

            # DFA doesn't support match_limit/recursion_limit flags in pcre_extra.
            # Pass NULL for extra to avoid the PCRE_ERROR_BADNEWLINE (-18) error.
            # This means DFA runs without limits, but DFA matching is inherently
            # linear time O(nm) so it doesn't need catastrophic backtracking protection.
            rc = self._lib.pcre_dfa_exec(
                code,
                self._ffi.NULL,  # DFA doesn't support limits in extra
                subject,
                len(subject),
                start_offset,
                dfa_opts,
                ovector,
                ovecsize,
                self._dfa_workspace,
                self._dfa_workspace_size,
            )
        else:
            # Backtracking matching
            rc = self._lib.pcre_exec(
                code,
                extra,
                subject,
                len(subject),
                start_offset,
                match_opts,
                ovector,
                ovecsize,
            )

        if rc == PCRE_ERROR_NOMATCH:
            return rc, None
        elif rc < 0:
            return rc, None

        # Convert ovector to list
        # Note: DFA returns 0 when ovector overflows but matches exist
        # In that case, we still have valid match data in ovector
        if rc == 0 and use_dfa:
            # DFA overflow - at least one match exists at ovector[0:2]
            # Return 1 to indicate one match
            ovector_list = [ovector[0], ovector[1]]
            return 1, ovector_list

        ovector_list = [ovector[i] for i in range(min(rc * 2, ovecsize))]
        return rc, ovector_list

    def _should_use_dfa(self) -> bool:
        """Determine if this match should use DFA engine."""
        if self._use_dfa_percentage <= 0:
            return False
        # Use modulo for deterministic behavior
        return (self._call_count % 100) < (self._use_dfa_percentage * 100)

    def _should_use_partial(self) -> bool:
        """Determine if this match should try partial matching."""
        if self._partial_match_percentage <= 0:
            return False
        return (self._call_count % 100) < (self._partial_match_percentage * 100)

    def _get_rotated_compile_options(self) -> int:
        """Get compile options, rotating through different modes for coverage."""
        if not self._rotate_options:
            return self._compile_options

        # Start with base options, masking out newline/BSR bits to avoid conflicts
        # Newline bits are in 0x00700000, BSR bits are in 0x01800000
        NEWLINE_MASK = 0x00700000
        BSR_MASK = 0x01800000
        base = self._compile_options & ~(NEWLINE_MASK | BSR_MASK)

        # Rotate through newline modes (every 6 patterns)
        newline_mode = NEWLINE_MODES[self._call_count % len(NEWLINE_MODES)]

        # Rotate through BSR modes (every 3 patterns within each newline mode)
        bsr_mode = BSR_MODES[(self._call_count // len(NEWLINE_MODES)) % len(BSR_MODES)]

        # Additional options to occasionally test
        extra_opts = 0
        rotation_index = self._call_count // (len(NEWLINE_MODES) * len(BSR_MODES))

        # Rotate through additional coverage-expanding options (expanded set)
        mod = rotation_index % 14
        if mod == 1:
            extra_opts |= PCRE_NO_AUTO_CAPTURE
        elif mod == 2:
            extra_opts |= PCRE_UNGREEDY
        elif mod == 3:
            extra_opts |= PCRE_DOLLAR_ENDONLY
        elif mod == 4:
            extra_opts |= PCRE_FIRSTLINE
        elif mod == 5:
            extra_opts |= PCRE_DUPNAMES
        elif mod == 6:
            extra_opts |= PCRE_NO_START_OPTIMIZE
        elif mod == 7:
            extra_opts |= PCRE_JAVASCRIPT_COMPAT
        elif mod == 8:
            extra_opts |= PCRE_NO_UTF8_CHECK  # Skip UTF8 validation
        elif mod == 9:
            extra_opts |= PCRE_AUTO_CALLOUT  # Auto-insert callouts for coverage
        elif mod == 10:
            extra_opts |= PCRE_EXTRA  # Enable extra checks
        elif mod == 11:
            extra_opts |= PCRE_ANCHORED  # Force anchored matching
        elif mod == 12:
            extra_opts |= PCRE_EXTENDED  # Ignore whitespace in pattern
        elif mod == 13:
            # Combination: auto-callout with extended mode
            extra_opts |= PCRE_AUTO_CALLOUT | PCRE_EXTENDED

        return base | newline_mode | bsr_mode | extra_opts

    def _get_rotated_match_options(self) -> int:
        """Get match options, rotating through different modes for coverage."""
        if not self._rotate_options:
            return self._match_options

        extra_opts = 0
        rotation_index = self._call_count

        # Occasionally try different match options (non-conflicting)
        mod = rotation_index % 20
        if mod == 1:
            extra_opts |= PCRE_NOTBOL
        elif mod == 2:
            extra_opts |= PCRE_NOTEOL
        elif mod == 3:
            extra_opts |= PCRE_NOTBOL | PCRE_NOTEOL
        elif mod == 4:
            extra_opts |= PCRE_NOTEMPTY_ATSTART

        # Partial matching - rotates through soft/hard modes
        # (JIT is compiled with partial support, so this is safe)
        if self._should_use_partial():
            if rotation_index % 2 == 0:
                extra_opts |= PCRE_PARTIAL_SOFT
            else:
                extra_opts |= PCRE_PARTIAL_HARD

        return self._match_options | extra_opts

    MAX_MATCHES = 10

    def _find_all_matches(
        self,
        code,
        extra,
        subject: bytes,
        ovecsize: int,
        use_dfa: bool = False,
    ) -> List[Tuple[int, int]]:
        """Find all non-overlapping matches.

        Args:
            code: Compiled PCRE code
            extra: pcre_extra structure
            subject: Subject string as bytes
            ovecsize: Size of ovector
            use_dfa: Whether to use DFA engine

        Returns:
            List of (start, end) spans for all matches
        """
        spans = []
        offset = 0

        while offset <= len(subject):
            if len(spans) >= self.MAX_MATCHES:
                break

            rc, ovector = self._match_at(code, extra, subject, ovecsize, offset, use_dfa)

            if rc < 0:
                break

            if ovector is None or len(ovector) < 2:
                break

            start, end = ovector[0], ovector[1]

            # Skip empty matches at same position to avoid infinite loop
            if start == end:
                if end < len(subject):
                    offset = end + 1
                else:
                    break
            else:
                spans.append((start, end))
                offset = end

        return spans

    def search(self, pattern: str, text: str, flags: int = 0) -> EngineMatch:
        """Search for the pattern in text.

        Args:
            pattern: Regex pattern
            text: Text to search in
            flags: Additional compile flags

        Returns:
            EngineMatch with match results
        """
        # Increment call counter for option rotation
        self._call_count += 1

        code = self._ffi.NULL
        extra = self._ffi.NULL

        try:
            code, extra = self._compile(pattern, flags)
        except PCREError as e:
            return EngineMatch(
                matched=False,
                span=None,
                longest_span=None,
                spans=[],
                captures=None,
                error=str(e),
            )

        try:
            subject = text.encode("utf-8")

            # Get capture count for ovector sizing
            capture_count = self._get_capture_count(code)
            # ovecsize must be a multiple of 3
            ovecsize = (capture_count + 1) * 3

            # Decide whether to use DFA for this match
            use_dfa = self._should_use_dfa()

            # Get first match with captures
            rc, ovector = self._match_at(code, extra, subject, ovecsize, 0, use_dfa)

            if rc < 0:
                error_msg = None
                if rc == PCRE_ERROR_MATCHLIMIT:
                    error_msg = "Match limit exceeded"
                elif rc == PCRE_ERROR_RECURSIONLIMIT:
                    error_msg = "Recursion limit exceeded"
                elif rc == PCRE_ERROR_JIT_STACKLIMIT:
                    error_msg = "JIT stack limit exceeded"
                elif rc == PCRE_ERROR_PARTIAL:
                    # Partial match is not an error - it means we found a partial
                    # match but need more data. For fuzzing, treat as no match.
                    pass  # No error message, just no match
                elif rc != PCRE_ERROR_NOMATCH:
                    error_msg = f"Match error (code={rc})"

                return EngineMatch(
                    matched=False,
                    span=None,
                    longest_span=None,
                    spans=[],
                    captures=None,
                    error=error_msg,
                )

            if ovector is None or len(ovector) < 2:
                return EngineMatch(
                    matched=False,
                    span=None,
                    longest_span=None,
                    spans=[],
                    captures=None,
                    error=None,
                )

            first_span = (ovector[0], ovector[1])

            # Extract captures
            captures = []
            for i in range(1, rc):
                cap_start = ovector[2 * i]
                cap_end = ovector[2 * i + 1]
                if cap_start < 0 or cap_end < 0:
                    captures.append(None)
                else:
                    captures.append(subject[cap_start:cap_end].decode("utf-8", "replace"))

            # Find all matches for spans/longest_span
            all_spans = self._find_all_matches(code, extra, subject, ovecsize, use_dfa)

            # Filter out empty matches at position 0
            all_spans = [s for s in all_spans if s != (0, 0)]

            # Find longest span
            longest_span = None
            if all_spans:
                longest_span = max(all_spans, key=lambda s: s[1] - s[0])

            return EngineMatch(
                matched=True,
                span=first_span,
                longest_span=longest_span,
                spans=all_spans,
                captures=captures if captures else None,
                error=None,
            )

        except PCREError as e:
            return EngineMatch(
                matched=False,
                span=None,
                longest_span=None,
                spans=[],
                captures=None,
                error=str(e),
            )

        finally:
            self._free_extra(extra)
            self._free_code(code)

    def dfa_search(self, pattern: str, text: str, flags: int = 0) -> EngineMatch:
        """Search using the DFA engine explicitly.

        The DFA engine has different characteristics:
        - No backreferences or assertions
        - Finds the longest match first
        - Uses more memory but predictable time

        Args:
            pattern: Regex pattern
            text: Text to search in
            flags: Additional compile flags

        Returns:
            EngineMatch with match results
        """
        # Save original DFA setting
        orig_dfa_percentage = self._use_dfa_percentage
        self._use_dfa_percentage = 1.0  # Force DFA

        try:
            return self.search(pattern, text, flags)
        finally:
            self._use_dfa_percentage = orig_dfa_percentage
