"""PCRE2 SUT using CFFI to directly call the compiled library.

This allows using custom-compiled PCRE2 libraries with sanitizer instrumentation
for fuzzing without depending on third-party Python bindings.

PCRE2 API features:
- pcre2_compile_8() for compilation
- pcre2_match_8() for backtracking matching
- pcre2_dfa_match_8() for DFA matching (linear time, no backreferences)
- pcre2_jit_compile_8() for JIT compilation
- Match limits via pcre2_match_context for catastrophic backtracking protection
"""

import os
from typing import List, Optional, Tuple

from cffi import FFI

from re_fuzzer.sut.base_sut import BaseSUT
from re_fuzzer.sut.engine_match import EngineMatch

# CFFI definitions for PCRE2 8-bit API
PCRE2_CDEF = """
typedef unsigned char PCRE2_UCHAR;
typedef const PCRE2_UCHAR *PCRE2_SPTR;
typedef size_t PCRE2_SIZE;
typedef unsigned int uint32_t;

/* Opaque types for the 8-bit API */
typedef struct pcre2_real_code_8          pcre2_code;
typedef struct pcre2_real_match_data_8    pcre2_match_data;
typedef struct pcre2_real_match_context_8 pcre2_match_context;
typedef struct pcre2_real_general_context_8 pcre2_general_context;
typedef struct pcre2_real_compile_context_8 pcre2_compile_context;

/* Compile */
pcre2_code *pcre2_compile_8(PCRE2_SPTR pattern,
                            PCRE2_SIZE length,
                            uint32_t options,
                            int *errorcode,
                            PCRE2_SIZE *erroroffset,
                            pcre2_compile_context *ccontext);

/* Free compiled pattern */
void pcre2_code_free_8(pcre2_code *code);

/* Create match-data sized for this pattern */
pcre2_match_data *pcre2_match_data_create_from_pattern_8(
                            const pcre2_code *code,
                            pcre2_general_context *gcontext);

/* Free match-data */
void pcre2_match_data_free_8(pcre2_match_data *match_data);

/* Match context creation and configuration */
pcre2_match_context *pcre2_match_context_create_8(pcre2_general_context *gcontext);
void pcre2_match_context_free_8(pcre2_match_context *mcontext);
int pcre2_set_match_limit_8(pcre2_match_context *mcontext, uint32_t value);
int pcre2_set_recursion_limit_8(pcre2_match_context *mcontext, uint32_t value);
int pcre2_set_depth_limit_8(pcre2_match_context *mcontext, uint32_t value);
int pcre2_set_heap_limit_8(pcre2_match_context *mcontext, uint32_t value);

/* Run a match */
int pcre2_match_8(const pcre2_code *code,
                  PCRE2_SPTR subject,
                  PCRE2_SIZE length,
                  PCRE2_SIZE startoffset,
                  uint32_t options,
                  pcre2_match_data *match_data,
                  pcre2_match_context *mcontext);

/* Turn an error code into a human-readable message */
int pcre2_get_error_message_8(int errorcode,
                              PCRE2_UCHAR *buffer,
                              PCRE2_SIZE bufflen);

/* Access ovector for captures */
PCRE2_SIZE *pcre2_get_ovector_pointer_8(pcre2_match_data *match_data);
uint32_t    pcre2_get_ovector_count_8(pcre2_match_data *match_data);

/* JIT compilation */
int pcre2_jit_compile_8(pcre2_code *code, uint32_t options);
void pcre2_jit_free_unused_memory_8(pcre2_general_context *gcontext);

/* JIT stack management */
typedef struct pcre2_real_jit_stack_8 pcre2_jit_stack;
pcre2_jit_stack *pcre2_jit_stack_create_8(PCRE2_SIZE startsize, PCRE2_SIZE maxsize,
                                          pcre2_general_context *gcontext);
void pcre2_jit_stack_free_8(pcre2_jit_stack *jit_stack);
void pcre2_jit_stack_assign_8(pcre2_match_context *mcontext,
                              void *callback, void *callback_data);

/* DFA matching */
int pcre2_dfa_match_8(const pcre2_code *code,
                      PCRE2_SPTR subject,
                      PCRE2_SIZE length,
                      PCRE2_SIZE startoffset,
                      uint32_t options,
                      pcre2_match_data *match_data,
                      pcre2_match_context *mcontext,
                      int *workspace,
                      PCRE2_SIZE wscount);

/* Pattern info */
int pcre2_pattern_info_8(const pcre2_code *code, uint32_t what, void *where);
"""

# PCRE2 option flags (from pcre2.h)
PCRE2_CASELESS = 0x00000001
PCRE2_MULTILINE = 0x00000400
PCRE2_DOTALL = 0x00000020
PCRE2_EXTENDED = 0x00000080
PCRE2_UTF = 0x00080000
PCRE2_UCP = 0x00020000
PCRE2_NO_UTF_CHECK = 0x40000000
PCRE2_ANCHORED = 0x80000000
PCRE2_ENDANCHORED = 0x20000000

# Additional compile options for coverage rotation
PCRE2_NO_AUTO_CAPTURE = 0x00000800
PCRE2_UNGREEDY = 0x00040000
PCRE2_DOLLAR_ENDONLY = 0x00000010
PCRE2_FIRSTLINE = 0x00000100
PCRE2_DUPNAMES = 0x00000040
PCRE2_NO_START_OPTIMIZE = 0x04000000
PCRE2_ALT_BSUX = 0x00000002
PCRE2_MATCH_UNSET_BACKREF = 0x00000200
PCRE2_AUTO_CALLOUT = 0x00000004

# Newline modes (for coverage rotation)
PCRE2_NEWLINE_CR = 0x00100000
PCRE2_NEWLINE_LF = 0x00200000
PCRE2_NEWLINE_CRLF = 0x00300000
PCRE2_NEWLINE_ANY = 0x00400000
PCRE2_NEWLINE_ANYCRLF = 0x00500000
PCRE2_NEWLINE_NUL = 0x00600000

# BSR modes (backslash R behavior)
PCRE2_BSR_ANYCRLF = 0x00800000
PCRE2_BSR_UNICODE = 0x01000000

# Match options
PCRE2_NOTBOL = 0x00000001
PCRE2_NOTEOL = 0x00000002
PCRE2_NOTEMPTY = 0x00000004
PCRE2_NOTEMPTY_ATSTART = 0x00000008
PCRE2_PARTIAL_SOFT = 0x00000010
PCRE2_PARTIAL_HARD = 0x00000020
PCRE2_DFA_SHORTEST = 0x00000040
PCRE2_DFA_RESTART = 0x00000080

# JIT options
PCRE2_JIT_COMPLETE = 0x00000001
PCRE2_JIT_PARTIAL_SOFT = 0x00000002
PCRE2_JIT_PARTIAL_HARD = 0x00000004

# Error codes
PCRE2_ERROR_NOMATCH = -1
PCRE2_ERROR_PARTIAL = -2
PCRE2_ERROR_MATCHLIMIT = -47
PCRE2_ERROR_DEPTHLIMIT = -53
PCRE2_ERROR_HEAPLIMIT = -63
PCRE2_ERROR_JIT_STACKLIMIT = -46

# Pattern info
PCRE2_INFO_CAPTURECOUNT = 4

# Newline mode options for rotation (coverage exploration)
NEWLINE_MODES = [
    0,  # Default (compile-time setting)
    PCRE2_NEWLINE_CR,
    PCRE2_NEWLINE_LF,
    PCRE2_NEWLINE_CRLF,
    PCRE2_NEWLINE_ANY,
    PCRE2_NEWLINE_ANYCRLF,
]

# BSR (backslash R) modes for rotation
BSR_MODES = [
    0,  # Default
    PCRE2_BSR_ANYCRLF,
    PCRE2_BSR_UNICODE,
]

# Mask for clearing newline/BSR bits before rotation
NEWLINE_MASK = 0x00700000
BSR_MASK = 0x01800000


class PCRE2Error(Exception):
    """Raised for PCRE2 engine errors (compile or match)."""
    pass


class PCRE2CFFI(BaseSUT):
    """PCRE2 SUT using CFFI to call the compiled library directly.

    This implementation allows using custom-compiled PCRE2 libraries,
    which is useful for fuzzing with sanitizer instrumentation.

    The library path can be specified via:
    1. Constructor parameter `library_path`
    2. Environment variable `PCRE2_LIBRARY_PATH`
    3. Default system library name `libpcre2-8.so`

    Unlike basic usage, this implementation supports:
    - JIT compilation for faster matching
    - DFA matching (linear time, no backreferences)
    - Option rotation for coverage exploration
    - Partial matching modes
    """

    name = "pcre2_cffi"

    # Default limits to prevent catastrophic backtracking
    # Very aggressive limits for fast fuzzing - prevents individual matches from blocking
    DEFAULT_MATCH_LIMIT = 1_000   # Max match operations (very low to prevent hangs)
    DEFAULT_DEPTH_LIMIT = 100     # Max recursion depth (very low)
    DEFAULT_HEAP_LIMIT = 100_000  # Max heap memory (100KB)

    def __init__(
        self,
        library_path: Optional[str] = None,
        compile_options: int = PCRE2_UTF | PCRE2_UCP,
        match_options: int = 0,
        match_limit: Optional[int] = None,
        depth_limit: Optional[int] = None,
        heap_limit: Optional[int] = None,
        use_jit: bool = True,
        use_dfa_percentage: float = 0.0,
        rotate_options: bool = False,
        partial_match_percentage: float = 0.0,
    ):
        """Initialize the PCRE2 CFFI wrapper.

        Args:
            library_path: Path to libpcre2-8.so. If None, uses PCRE2_LIBRARY_PATH
                         env var or falls back to system library.
            compile_options: Default compile options (PCRE2_UTF | PCRE2_UCP by default)
            match_options: Default match options (0 by default)
            match_limit: Max match operations (default: 1,000)
            depth_limit: Max recursion depth (default: 100)
            heap_limit: Max heap memory in bytes (default: 100KB)
            use_jit: Whether to JIT compile patterns (default: True)
            use_dfa_percentage: Percentage of matches to run with DFA engine (0.0-1.0)
            rotate_options: Whether to rotate through different compile/match options
                           for coverage exploration (default: False)
            partial_match_percentage: Percentage of matches to try partial matching (0.0-1.0)
        """
        self._compile_options = compile_options
        self._match_options = match_options
        self._match_limit = match_limit or self.DEFAULT_MATCH_LIMIT
        self._depth_limit = depth_limit or self.DEFAULT_DEPTH_LIMIT
        self._heap_limit = heap_limit or self.DEFAULT_HEAP_LIMIT
        self._use_jit = use_jit
        self._use_dfa_percentage = use_dfa_percentage
        self._rotate_options = rotate_options
        self._partial_match_percentage = partial_match_percentage
        self._call_count = 0  # Counter for option rotation

        # Determine library path
        if library_path is None:
            library_path = os.environ.get("PCRE2_LIBRARY_PATH", "libpcre2-8.so")

        # Initialize CFFI
        self._ffi = FFI()
        self._ffi.cdef(PCRE2_CDEF)

        try:
            self._lib = self._ffi.dlopen(library_path)
        except OSError as e:
            raise PCRE2Error(f"Failed to load PCRE2 library from '{library_path}': {e}")

        # Create match context with limits
        self._match_context = self._lib.pcre2_match_context_create_8(self._ffi.NULL)
        if self._match_context == self._ffi.NULL:
            raise PCRE2Error("Failed to create match context")

        # Set limits to prevent catastrophic backtracking
        self._lib.pcre2_set_match_limit_8(self._match_context, self._match_limit)
        self._lib.pcre2_set_depth_limit_8(self._match_context, self._depth_limit)
        self._lib.pcre2_set_heap_limit_8(self._match_context, self._heap_limit)

        # Allocate workspace for DFA matching
        self._dfa_workspace_size = 1000
        self._dfa_workspace = self._ffi.new(f"int[{self._dfa_workspace_size}]")

    def _get_error_message(self, error_code: int) -> str:
        """Get human-readable error message for a PCRE2 error code."""
        buf = self._ffi.new("PCRE2_UCHAR[256]")
        self._lib.pcre2_get_error_message_8(error_code, buf, 256)
        return self._ffi.string(buf).decode("utf-8", "replace")

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
        base = self._compile_options & ~(NEWLINE_MASK | BSR_MASK)

        # Rotate through newline modes (every 6 patterns)
        newline_mode = NEWLINE_MODES[self._call_count % len(NEWLINE_MODES)]

        # Rotate through BSR modes (every 3 patterns within each newline mode)
        bsr_mode = BSR_MODES[(self._call_count // len(NEWLINE_MODES)) % len(BSR_MODES)]

        # Additional options to occasionally test
        extra_opts = 0
        rotation_index = self._call_count // (len(NEWLINE_MODES) * len(BSR_MODES))

        # Rotate through additional coverage-expanding options
        if rotation_index % 10 == 1:
            extra_opts |= PCRE2_NO_AUTO_CAPTURE
        if rotation_index % 10 == 2:
            extra_opts |= PCRE2_UNGREEDY
        if rotation_index % 10 == 3:
            extra_opts |= PCRE2_DOLLAR_ENDONLY
        if rotation_index % 10 == 4:
            extra_opts |= PCRE2_FIRSTLINE
        if rotation_index % 10 == 5:
            extra_opts |= PCRE2_DUPNAMES
        if rotation_index % 10 == 6:
            extra_opts |= PCRE2_NO_START_OPTIMIZE
        if rotation_index % 10 == 7:
            extra_opts |= PCRE2_ALT_BSUX
        if rotation_index % 10 == 8:
            extra_opts |= PCRE2_MATCH_UNSET_BACKREF

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
            extra_opts |= PCRE2_NOTBOL
        elif mod == 2:
            extra_opts |= PCRE2_NOTEOL
        elif mod == 3:
            extra_opts |= PCRE2_NOTBOL | PCRE2_NOTEOL
        elif mod == 4:
            extra_opts |= PCRE2_NOTEMPTY_ATSTART

        # Partial matching - rotates through soft/hard modes
        if self._should_use_partial():
            if rotation_index % 2 == 0:
                extra_opts |= PCRE2_PARTIAL_SOFT
            else:
                extra_opts |= PCRE2_PARTIAL_HARD

        return self._match_options | extra_opts

    def _compile(self, pattern: str, flags: int = 0):
        """Compile a regex pattern.

        Args:
            pattern: The regex pattern string
            flags: Additional compile flags

        Returns:
            Compiled PCRE2 code object

        Raises:
            PCRE2Error: If compilation fails
        """
        pat_bytes = pattern.encode("utf-8")
        pat = self._ffi.new("PCRE2_UCHAR[]", pat_bytes)

        error_code = self._ffi.new("int[1]")
        error_offset = self._ffi.new("PCRE2_SIZE[1]")

        # Use rotated compile options for coverage exploration
        base_options = self._get_rotated_compile_options()
        options = base_options | flags

        code = self._lib.pcre2_compile_8(
            self._ffi.cast("PCRE2_SPTR", pat),
            len(pat_bytes),
            options,
            error_code,
            error_offset,
            self._ffi.NULL,
        )

        if code == self._ffi.NULL:
            msg = self._get_error_message(error_code[0])
            raise PCRE2Error(
                f"Compile error at offset {int(error_offset[0])}: {msg} (code={error_code[0]})"
            )

        # JIT compile if enabled - enables JIT for all match modes
        if self._use_jit:
            jit_opts = PCRE2_JIT_COMPLETE | PCRE2_JIT_PARTIAL_SOFT | PCRE2_JIT_PARTIAL_HARD
            # JIT compile failure is not fatal - we can still use the pattern
            self._lib.pcre2_jit_compile_8(code, jit_opts)

        return code

    def _match_at(
        self,
        code,
        subject: bytes,
        start_offset: int = 0,
        use_dfa: bool = False,
    ) -> Tuple[Optional[Tuple[int, int]], Optional[List[Optional[str]]]]:
        """Perform a single match at the given offset.

        Args:
            code: Compiled PCRE2 code
            subject: Subject string as bytes
            start_offset: Starting offset in bytes
            use_dfa: Whether to use DFA engine instead of backtracking

        Returns:
            Tuple of (span, captures) or (None, None) if no match
        """
        subj = self._ffi.new("PCRE2_UCHAR[]", subject)

        match_data = self._lib.pcre2_match_data_create_from_pattern_8(
            code, self._ffi.NULL
        )
        if match_data == self._ffi.NULL:
            raise PCRE2Error("pcre2_match_data_create_from_pattern returned NULL")

        try:
            # Get rotated match options for coverage exploration
            match_opts = self._get_rotated_match_options()

            if use_dfa:
                # DFA matching - add DFA-specific options if needed
                dfa_opts = match_opts
                # Occasionally try DFA_SHORTEST for coverage
                if self._rotate_options and (self._call_count % 5 == 0):
                    dfa_opts |= PCRE2_DFA_SHORTEST

                # DFA doesn't support match_limit in the same way, pass NULL for context
                rc = self._lib.pcre2_dfa_match_8(
                    code,
                    self._ffi.cast("PCRE2_SPTR", subj),
                    len(subject),
                    start_offset,
                    dfa_opts,
                    match_data,
                    self._ffi.NULL,  # DFA doesn't need match context limits
                    self._dfa_workspace,
                    self._dfa_workspace_size,
                )
            else:
                # Backtracking matching
                rc = self._lib.pcre2_match_8(
                    code,
                    self._ffi.cast("PCRE2_SPTR", subj),
                    len(subject),
                    start_offset,
                    match_opts,
                    match_data,
                    self._match_context,
                )

            if rc == PCRE2_ERROR_NOMATCH:
                return None, None
            elif rc == PCRE2_ERROR_PARTIAL:
                # Partial match is not an error - treat as no match for fuzzing
                return None, None
            elif rc < 0:
                # Check for expected limit errors
                if rc in (PCRE2_ERROR_MATCHLIMIT, PCRE2_ERROR_DEPTHLIMIT,
                          PCRE2_ERROR_HEAPLIMIT, PCRE2_ERROR_JIT_STACKLIMIT):
                    # Limit exceeded is expected behavior, not an error
                    return None, None
                msg = self._get_error_message(rc)
                raise PCRE2Error(f"Match error: {msg} (code={rc})")

            # Extract ovector (match positions)
            ovector = self._lib.pcre2_get_ovector_pointer_8(match_data)
            ovector_count = self._lib.pcre2_get_ovector_count_8(match_data)

            # First pair is the overall match
            match_start = int(ovector[0])
            match_end = int(ovector[1])
            span = (match_start, match_end)

            # Extract capture groups (DFA doesn't support captures, but we still get ovector)
            captures = []
            if not use_dfa:
                for i in range(1, ovector_count):
                    cap_start = int(ovector[2 * i])
                    cap_end = int(ovector[2 * i + 1])

                    # PCRE2 uses PCRE2_UNSET (~0) for unmatched groups
                    if cap_start == 0xFFFFFFFFFFFFFFFF or cap_end == 0xFFFFFFFFFFFFFFFF:
                        captures.append(None)
                    else:
                        captures.append(subject[cap_start:cap_end].decode("utf-8", "replace"))

            return span, captures if captures else None

        finally:
            self._lib.pcre2_match_data_free_8(match_data)

    # Maximum matches to find before bailing out (prevents slow loops)
    MAX_MATCHES = 10

    def _find_all_matches(
        self,
        code,
        subject: bytes,
        use_dfa: bool = False,
    ) -> List[Tuple[int, int]]:
        """Find all non-overlapping matches.

        Args:
            code: Compiled PCRE2 code
            subject: Subject string as bytes
            use_dfa: Whether to use DFA engine

        Returns:
            List of (start, end) spans for all matches
        """
        spans = []
        offset = 0

        while offset <= len(subject):
            # Bail out if we've found too many matches (prevents slow loops)
            if len(spans) >= self.MAX_MATCHES:
                break

            span, _ = self._match_at(code, subject, offset, use_dfa)

            if span is None:
                break

            start, end = span

            # Skip empty matches at same position to avoid infinite loop
            if start == end:
                if end < len(subject):
                    offset = end + 1
                else:
                    break
            else:
                spans.append(span)
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

        try:
            code = self._compile(pattern, flags)
        except PCRE2Error as e:
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

            # Decide whether to use DFA for this match
            use_dfa = self._should_use_dfa()

            # Get first match with captures
            first_span, captures = self._match_at(code, subject, 0, use_dfa)

            if first_span is None:
                return EngineMatch(
                    matched=False,
                    span=None,
                    longest_span=None,
                    spans=[],
                    captures=None,
                    error=None,
                )

            # Find all matches for spans/longest_span
            all_spans = self._find_all_matches(code, subject, use_dfa)

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
                captures=captures,
                error=None,
            )

        except PCRE2Error as e:
            return EngineMatch(
                matched=False,
                span=None,
                longest_span=None,
                spans=[],
                captures=None,
                error=str(e),
            )

        finally:
            self._lib.pcre2_code_free_8(code)

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
