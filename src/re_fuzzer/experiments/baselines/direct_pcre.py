"""Minimal ctypes wrappers for PCRE and PCRE2 - no ReTest optimizations.

These wrappers are used by baseline fuzzers to ensure fair comparison.
They do NOT include:
- Option rotation for coverage exploration
- JIT compilation
- DFA matching
- Partial matching modes
- Any other ReTest-specific optimizations
"""

import ctypes
from ctypes import (
    POINTER,
    byref,
    c_char_p,
    c_int,
    c_size_t,
    c_uint32,
    c_void_p,
    create_string_buffer,
)
from pathlib import Path
from typing import Optional, Tuple


class DirectPCRE:
    """Minimal ctypes wrapper for PCRE (libpcre) - no ReTest optimizations."""

    # PCRE compile options
    PCRE_UTF8 = 0x00000800
    PCRE_UCP = 0x20000000

    # Error codes
    PCRE_ERROR_NOMATCH = -1
    PCRE_ERROR_MATCHLIMIT = -8

    # pcre_extra flags
    PCRE_EXTRA_MATCH_LIMIT = 0x00000002

    # V8 FuzzTest uses 1,000,000 backtrack limit (regexp-fuzzer.cc line 133)
    BACKTRACK_LIMIT = 1_000_000

    def __init__(self, library_path: str):
        """Initialize with path to libpcre.so."""
        self.lib = ctypes.CDLL(library_path)
        self._setup_functions()
        self._setup_match_limit()
        self._study_extra = None

    def _setup_functions(self) -> None:
        """Setup ctypes function signatures."""
        # pcre_compile
        self.lib.pcre_compile.argtypes = [
            c_char_p,  # pattern
            c_int,  # options
            POINTER(c_char_p),  # errptr
            POINTER(c_int),  # erroffset
            c_void_p,  # tableptr
        ]
        self.lib.pcre_compile.restype = c_void_p

        # pcre_exec
        self.lib.pcre_exec.argtypes = [
            c_void_p,  # code
            c_void_p,  # extra (study data)
            c_char_p,  # subject
            c_int,  # length
            c_int,  # startoffset
            c_int,  # options
            POINTER(c_int),  # ovector
            c_int,  # ovecsize
        ]
        self.lib.pcre_exec.restype = c_int

        # pcre_free (function pointer, need to handle specially)
        try:
            self._pcre_free = ctypes.cast(
                ctypes.c_void_p.in_dll(self.lib, "pcre_free"),
                ctypes.CFUNCTYPE(None, c_void_p),
            )
        except (ValueError, AttributeError):
            # Fallback: use standard free
            libc = ctypes.CDLL(None)
            self._pcre_free = libc.free
            self._pcre_free.argtypes = [c_void_p]
            self._pcre_free.restype = None

    def _setup_match_limit(self) -> None:
        """Setup pcre_extra structure with match limit.

        V8 FuzzTest uses a 1M backtrack limit to prevent DoS with
        pathological patterns (regexp-fuzzer.cc line 133).
        """
        # pcre_extra structure (from pcre.h)
        # struct pcre_extra {
        #     unsigned long int flags;
        #     void *study_data;
        #     unsigned long int match_limit;
        #     void *callout_data;
        #     const unsigned char *tables;
        #     unsigned long int match_limit_recursion;
        #     unsigned char **mark;
        #     void *executable_jit;
        # }

        class pcre_extra(ctypes.Structure):
            _fields_ = [
                ("flags", ctypes.c_ulong),
                ("study_data", c_void_p),
                ("match_limit", ctypes.c_ulong),
                ("callout_data", c_void_p),
                ("tables", c_char_p),
                ("match_limit_recursion", ctypes.c_ulong),
                ("mark", c_void_p),
                ("executable_jit", c_void_p),
            ]

        self._extra = pcre_extra()
        self._extra.flags = self.PCRE_EXTRA_MATCH_LIMIT
        self._extra.match_limit = self.BACKTRACK_LIMIT
        self._extra_ptr = ctypes.pointer(self._extra)

    def compile_and_match(
        self,
        pattern: bytes,
        subject: bytes,
        options: int = 0,
    ) -> Tuple[bool, Optional[str]]:
        """Compile pattern and match against subject.

        Args:
            pattern: The regex pattern (bytes)
            subject: The subject string to match against (bytes)
            options: PCRE compile options (default: 0)

        Returns:
            Tuple of (matched: bool, error: Optional[str])
        """
        errptr = c_char_p()
        erroffset = c_int(0)

        # Compile
        code = self.lib.pcre_compile(
            pattern,
            options | self.PCRE_UTF8,
            byref(errptr),
            byref(erroffset),
            None,
        )

        if not code:
            error_msg = errptr.value.decode("utf-8", errors="replace") if errptr.value else "unknown"
            return False, f"compile_error:{error_msg}@{erroffset.value}"

        try:
            # Match with backtrack limit (V8 uses 1M - regexp-fuzzer.cc line 133)
            ovector_size = 30  # 10 capturing groups * 3
            ovector = (c_int * ovector_size)()

            result = self.lib.pcre_exec(
                code,
                self._extra_ptr,  # pcre_extra with match limit
                subject,
                len(subject),
                0,  # startoffset
                0,  # options
                ovector,
                ovector_size,
            )

            if result >= 0:
                return True, None
            elif result == self.PCRE_ERROR_NOMATCH:
                return False, None
            elif result == self.PCRE_ERROR_MATCHLIMIT:
                return False, "match_limit_exceeded"
            else:
                return False, f"match_error:{result}"

        finally:
            # Free compiled pattern
            if code:
                self._pcre_free(code)

    def match_only(
        self,
        code: c_void_p,
        subject: bytes,
    ) -> Tuple[bool, Optional[str]]:
        """Match against a pre-compiled pattern.

        Args:
            code: Pre-compiled pattern handle
            subject: The subject string to match against (bytes)

        Returns:
            Tuple of (matched: bool, error: Optional[str])
        """
        ovector_size = 30
        ovector = (c_int * ovector_size)()

        result = self.lib.pcre_exec(
            code,
            self._extra_ptr,  # pcre_extra with match limit
            subject,
            len(subject),
            0,
            0,
            ovector,
            ovector_size,
        )

        if result >= 0:
            return True, None
        elif result == self.PCRE_ERROR_NOMATCH:
            return False, None
        elif result == self.PCRE_ERROR_MATCHLIMIT:
            return False, "match_limit_exceeded"
        else:
            return False, f"match_error:{result}"


class DirectPCRE2:
    """Minimal ctypes wrapper for PCRE2 (libpcre2-8) - no ReTest optimizations."""

    # PCRE2 compile options
    PCRE2_UTF = 0x00080000
    PCRE2_UCP = 0x00020000

    # Error codes
    PCRE2_ERROR_NOMATCH = -1
    PCRE2_ERROR_MATCHLIMIT = -47

    # V8 FuzzTest uses 1,000,000 backtrack limit (regexp-fuzzer.cc line 133)
    BACKTRACK_LIMIT = 1_000_000

    def __init__(self, library_path: str):
        """Initialize with path to libpcre2-8.so."""
        self.lib = ctypes.CDLL(library_path)
        self._setup_functions()
        self._general_context = None
        self._compile_context = None
        self._match_context = self._setup_match_context()

    def _setup_functions(self) -> None:
        """Setup ctypes function signatures for PCRE2."""
        # pcre2_compile_8
        self.lib.pcre2_compile_8.argtypes = [
            c_char_p,  # pattern
            c_size_t,  # length (PCRE2_ZERO_TERMINATED = ~0)
            c_uint32,  # options
            POINTER(c_int),  # errorcode
            POINTER(c_size_t),  # erroroffset
            c_void_p,  # ccontext
        ]
        self.lib.pcre2_compile_8.restype = c_void_p

        # pcre2_match_8
        self.lib.pcre2_match_8.argtypes = [
            c_void_p,  # code
            c_char_p,  # subject
            c_size_t,  # length
            c_size_t,  # startoffset
            c_uint32,  # options
            c_void_p,  # match_data
            c_void_p,  # mcontext
        ]
        self.lib.pcre2_match_8.restype = c_int

        # pcre2_match_data_create_from_pattern_8
        self.lib.pcre2_match_data_create_from_pattern_8.argtypes = [
            c_void_p,  # code
            c_void_p,  # gcontext
        ]
        self.lib.pcre2_match_data_create_from_pattern_8.restype = c_void_p

        # pcre2_match_data_free_8
        self.lib.pcre2_match_data_free_8.argtypes = [c_void_p]
        self.lib.pcre2_match_data_free_8.restype = None

        # pcre2_code_free_8
        self.lib.pcre2_code_free_8.argtypes = [c_void_p]
        self.lib.pcre2_code_free_8.restype = None

        # pcre2_get_error_message_8
        self.lib.pcre2_get_error_message_8.argtypes = [
            c_int,  # errorcode
            c_char_p,  # buffer
            c_size_t,  # bufflen
        ]
        self.lib.pcre2_get_error_message_8.restype = c_int

        # pcre2_match_context_create_8
        self.lib.pcre2_match_context_create_8.argtypes = [c_void_p]
        self.lib.pcre2_match_context_create_8.restype = c_void_p

        # pcre2_set_match_limit_8
        self.lib.pcre2_set_match_limit_8.argtypes = [c_void_p, c_uint32]
        self.lib.pcre2_set_match_limit_8.restype = c_int

        # pcre2_match_context_free_8
        self.lib.pcre2_match_context_free_8.argtypes = [c_void_p]
        self.lib.pcre2_match_context_free_8.restype = None

    def _setup_match_context(self) -> c_void_p:
        """Create match context with backtrack limit.

        V8 FuzzTest uses a 1M backtrack limit to prevent DoS with
        pathological patterns (regexp-fuzzer.cc line 133).

        Returns:
            Match context pointer with limit set, or None if failed
        """
        match_context = self.lib.pcre2_match_context_create_8(None)
        if match_context:
            self.lib.pcre2_set_match_limit_8(match_context, self.BACKTRACK_LIMIT)
        return match_context

    def _get_error_message(self, error_code: int) -> str:
        """Get human-readable error message for error code."""
        buffer = create_string_buffer(256)
        result = self.lib.pcre2_get_error_message_8(error_code, buffer, 256)
        if result > 0:
            return buffer.value.decode("utf-8", errors="replace")
        return f"error_code_{error_code}"

    def compile_and_match(
        self,
        pattern: bytes,
        subject: bytes,
        options: int = 0,
    ) -> Tuple[bool, Optional[str]]:
        """Compile pattern and match against subject.

        Args:
            pattern: The regex pattern (bytes)
            subject: The subject string to match against (bytes)
            options: PCRE2 compile options (default: 0)

        Returns:
            Tuple of (matched: bool, error: Optional[str])
        """
        error_code = c_int(0)
        error_offset = c_size_t(0)

        # Compile
        code = self.lib.pcre2_compile_8(
            pattern,
            len(pattern),
            options | self.PCRE2_UTF | self.PCRE2_UCP,
            byref(error_code),
            byref(error_offset),
            self._compile_context,
        )

        if not code:
            error_msg = self._get_error_message(error_code.value)
            return False, f"compile_error:{error_msg}@{error_offset.value}"

        match_data = None
        try:
            # Create match data
            match_data = self.lib.pcre2_match_data_create_from_pattern_8(
                code, self._general_context
            )
            if not match_data:
                return False, "match_data_create_failed"

            # Match
            result = self.lib.pcre2_match_8(
                code,
                subject,
                len(subject),
                0,  # startoffset
                0,  # options
                match_data,
                self._match_context,
            )

            if result >= 0:
                return True, None
            elif result == self.PCRE2_ERROR_NOMATCH:
                return False, None
            elif result == self.PCRE2_ERROR_MATCHLIMIT:
                return False, "match_limit_exceeded"
            else:
                error_msg = self._get_error_message(result)
                return False, f"match_error:{error_msg}"

        finally:
            # Free resources
            if match_data:
                self.lib.pcre2_match_data_free_8(match_data)
            if code:
                self.lib.pcre2_code_free_8(code)

    def compile(
        self,
        pattern: bytes,
        options: int = 0,
    ) -> Tuple[Optional[c_void_p], Optional[str]]:
        """Compile pattern and return code handle.

        Args:
            pattern: The regex pattern (bytes)
            options: PCRE2 compile options (default: 0)

        Returns:
            Tuple of (code: Optional[c_void_p], error: Optional[str])
        """
        error_code = c_int(0)
        error_offset = c_size_t(0)

        code = self.lib.pcre2_compile_8(
            pattern,
            len(pattern),
            options | self.PCRE2_UTF | self.PCRE2_UCP,
            byref(error_code),
            byref(error_offset),
            self._compile_context,
        )

        if not code:
            error_msg = self._get_error_message(error_code.value)
            return None, f"compile_error:{error_msg}@{error_offset.value}"

        return code, None

    def match_only(
        self,
        code: c_void_p,
        subject: bytes,
    ) -> Tuple[bool, Optional[str]]:
        """Match against a pre-compiled pattern.

        Args:
            code: Pre-compiled pattern handle
            subject: The subject string to match against (bytes)

        Returns:
            Tuple of (matched: bool, error: Optional[str])
        """
        match_data = self.lib.pcre2_match_data_create_from_pattern_8(
            code, self._general_context
        )
        if not match_data:
            return False, "match_data_create_failed"

        try:
            result = self.lib.pcre2_match_8(
                code,
                subject,
                len(subject),
                0,
                0,
                match_data,
                self._match_context,
            )

            if result >= 0:
                return True, None
            elif result == self.PCRE2_ERROR_NOMATCH:
                return False, None
            elif result == self.PCRE2_ERROR_MATCHLIMIT:
                return False, "match_limit_exceeded"
            else:
                error_msg = self._get_error_message(result)
                return False, f"match_error:{error_msg}"

        finally:
            self.lib.pcre2_match_data_free_8(match_data)

    def free_code(self, code: c_void_p) -> None:
        """Free a compiled pattern."""
        if code:
            self.lib.pcre2_code_free_8(code)


class DirectPCREReTest(DirectPCRE):
    """Enhanced DirectPCRE with coverage-expanding features for ReTest.

    This adds:
    - Option rotation for compile options (newline modes, BSR modes, flags)
    - Option rotation for match options
    - DFA matching (pcre_dfa_exec)
    - Partial matching modes
    - Study with JIT support
    - Match limits to prevent catastrophic backtracking
    """

    # Additional compile options for rotation
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
    PCRE_NO_AUTO_CAPTURE = 0x00001000
    PCRE_AUTO_CALLOUT = 0x00004000
    PCRE_PARTIAL_SOFT = 0x00008000
    PCRE_PARTIAL_HARD = 0x08000000
    PCRE_DFA_SHORTEST = 0x00010000
    PCRE_FIRSTLINE = 0x00040000
    PCRE_DUPNAMES = 0x00080000
    PCRE_JAVASCRIPT_COMPAT = 0x02000000
    PCRE_NO_START_OPTIMIZE = 0x04000000
    PCRE_NO_UTF8_CHECK = 0x00002000
    PCRE_NOTEMPTY_ATSTART = 0x10000000

    # Newline modes
    PCRE_NEWLINE_CR = 0x00100000
    PCRE_NEWLINE_LF = 0x00200000
    PCRE_NEWLINE_CRLF = 0x00300000
    PCRE_NEWLINE_ANY = 0x00400000
    PCRE_NEWLINE_ANYCRLF = 0x00500000

    # BSR modes
    PCRE_BSR_ANYCRLF = 0x00800000
    PCRE_BSR_UNICODE = 0x01000000

    # Study flags
    PCRE_STUDY_JIT_COMPILE = 0x0001
    PCRE_STUDY_JIT_PARTIAL_SOFT_COMPILE = 0x0002
    PCRE_STUDY_JIT_PARTIAL_HARD_COMPILE = 0x0004

    # pcre_extra flags
    PCRE_EXTRA_MATCH_LIMIT = 0x00000002
    PCRE_EXTRA_MATCH_LIMIT_RECURSION = 0x00000010

    # Rotation sequences
    NEWLINE_MODES = [0, PCRE_NEWLINE_CR, PCRE_NEWLINE_LF, PCRE_NEWLINE_CRLF,
                     PCRE_NEWLINE_ANY, PCRE_NEWLINE_ANYCRLF]
    BSR_MODES = [0, PCRE_BSR_ANYCRLF, PCRE_BSR_UNICODE]

    def __init__(
        self,
        library_path: str,
        use_jit: bool = True,
        use_dfa_percentage: float = 0.2,
        rotate_options: bool = True,
        partial_match_percentage: float = 0.1,
        match_limit: int = 10_000,
        recursion_limit: int = 500,
    ):
        """Initialize enhanced DirectPCRE with ReTest features.

        Args:
            library_path: Path to libpcre.so
            use_jit: Whether to JIT compile patterns (default: True)
            use_dfa_percentage: Percentage of matches to use DFA engine (0.0-1.0)
            rotate_options: Whether to rotate compile/match options for coverage
            partial_match_percentage: Percentage to try partial matching (0.0-1.0)
            match_limit: Maximum match operations (default: 10,000)
            recursion_limit: Maximum recursion depth (default: 500)
        """
        super().__init__(library_path)
        self._use_jit = use_jit
        self._use_dfa_percentage = use_dfa_percentage
        self._rotate_options = rotate_options
        self._partial_match_percentage = partial_match_percentage
        self._match_limit = match_limit
        self._recursion_limit = recursion_limit
        self._call_count = 0
        self._setup_extra_functions()

        # DFA workspace
        self._dfa_workspace_size = 1000
        self._dfa_workspace = (c_int * self._dfa_workspace_size)()

    def _setup_extra_functions(self) -> None:
        """Setup additional ctypes function signatures for enhanced features."""
        # pcre_study
        self.lib.pcre_study.argtypes = [
            c_void_p,  # code
            c_int,  # options
            POINTER(c_char_p),  # errptr
        ]
        self.lib.pcre_study.restype = c_void_p

        # pcre_free_study
        self.lib.pcre_free_study.argtypes = [c_void_p]
        self.lib.pcre_free_study.restype = None

        # pcre_dfa_exec
        self.lib.pcre_dfa_exec.argtypes = [
            c_void_p,  # code
            c_void_p,  # extra
            c_char_p,  # subject
            c_int,  # length
            c_int,  # startoffset
            c_int,  # options
            POINTER(c_int),  # ovector
            c_int,  # ovecsize
            POINTER(c_int),  # workspace
            c_int,  # wscount
        ]
        self.lib.pcre_dfa_exec.restype = c_int

    def _should_use_dfa(self) -> bool:
        """Determine if this match should use DFA engine."""
        if self._use_dfa_percentage <= 0:
            return False
        return (self._call_count % 100) < (self._use_dfa_percentage * 100)

    def _should_use_partial(self) -> bool:
        """Determine if this match should try partial matching."""
        if self._partial_match_percentage <= 0:
            return False
        return (self._call_count % 100) < (self._partial_match_percentage * 100)

    def _get_rotated_compile_options(self) -> int:
        """Get compile options, rotating through different modes for coverage."""
        if not self._rotate_options:
            return self.PCRE_UTF8 | self.PCRE_UCP

        # Mask out newline/BSR bits to avoid conflicts
        NEWLINE_MASK = 0x00700000
        BSR_MASK = 0x01800000
        base = self.PCRE_UTF8 | self.PCRE_UCP

        # Rotate through newline modes
        newline_mode = self.NEWLINE_MODES[self._call_count % len(self.NEWLINE_MODES)]

        # Rotate through BSR modes
        bsr_mode = self.BSR_MODES[(self._call_count // len(self.NEWLINE_MODES)) % len(self.BSR_MODES)]

        # Additional options to occasionally test
        extra_opts = 0
        rotation_index = self._call_count // (len(self.NEWLINE_MODES) * len(self.BSR_MODES))

        mod = rotation_index % 14
        if mod == 1:
            extra_opts |= self.PCRE_NO_AUTO_CAPTURE
        elif mod == 2:
            extra_opts |= self.PCRE_UNGREEDY
        elif mod == 3:
            extra_opts |= self.PCRE_DOLLAR_ENDONLY
        elif mod == 4:
            extra_opts |= self.PCRE_FIRSTLINE
        elif mod == 5:
            extra_opts |= self.PCRE_DUPNAMES
        elif mod == 6:
            extra_opts |= self.PCRE_NO_START_OPTIMIZE
        elif mod == 7:
            extra_opts |= self.PCRE_JAVASCRIPT_COMPAT
        elif mod == 8:
            extra_opts |= self.PCRE_NO_UTF8_CHECK
        elif mod == 9:
            extra_opts |= self.PCRE_AUTO_CALLOUT
        elif mod == 10:
            extra_opts |= self.PCRE_EXTRA
        elif mod == 11:
            extra_opts |= self.PCRE_ANCHORED
        elif mod == 12:
            extra_opts |= self.PCRE_EXTENDED
        elif mod == 13:
            extra_opts |= self.PCRE_AUTO_CALLOUT | self.PCRE_EXTENDED

        return base | newline_mode | bsr_mode | extra_opts

    def _get_rotated_match_options(self) -> int:
        """Get match options, rotating through different modes for coverage."""
        if not self._rotate_options:
            return 0

        extra_opts = 0
        rotation_index = self._call_count

        mod = rotation_index % 20
        if mod == 1:
            extra_opts |= self.PCRE_NOTBOL
        elif mod == 2:
            extra_opts |= self.PCRE_NOTEOL
        elif mod == 3:
            extra_opts |= self.PCRE_NOTBOL | self.PCRE_NOTEOL
        elif mod == 4:
            extra_opts |= self.PCRE_NOTEMPTY_ATSTART

        # Partial matching
        if self._should_use_partial():
            if rotation_index % 2 == 0:
                extra_opts |= self.PCRE_PARTIAL_SOFT
            else:
                extra_opts |= self.PCRE_PARTIAL_HARD

        return extra_opts

    def compile_and_match(
        self,
        pattern: bytes,
        subject: bytes,
        options: int = 0,
    ) -> Tuple[bool, Optional[str]]:
        """Compile pattern and match with enhanced features.

        This version includes option rotation, DFA matching, partial matching,
        and JIT compilation for increased coverage.
        """
        self._call_count += 1

        errptr = c_char_p()
        erroffset = c_int(0)

        # Get rotated compile options
        compile_opts = self._get_rotated_compile_options() | options

        # Compile
        code = self.lib.pcre_compile(
            pattern,
            compile_opts,
            byref(errptr),
            byref(erroffset),
            None,
        )

        if not code:
            error_msg = errptr.value.decode("utf-8", errors="replace") if errptr.value else "unknown"
            return False, f"Compile error at offset {erroffset.value}: {error_msg}"

        extra = None
        try:
            # Study with JIT if enabled
            if self._use_jit:
                study_errptr = c_char_p()
                study_opts = (
                    self.PCRE_STUDY_JIT_COMPILE |
                    self.PCRE_STUDY_JIT_PARTIAL_SOFT_COMPILE |
                    self.PCRE_STUDY_JIT_PARTIAL_HARD_COMPILE
                )
                extra = self.lib.pcre_study(code, study_opts, byref(study_errptr))
                # JIT failure is not fatal

            # Get match options
            match_opts = self._get_rotated_match_options()
            use_dfa = self._should_use_dfa()

            ovector_size = 30
            ovector = (c_int * ovector_size)()

            if use_dfa:
                # DFA matching - doesn't support pcre_extra
                dfa_opts = match_opts
                if self._rotate_options and (self._call_count % 5 == 0):
                    dfa_opts |= self.PCRE_DFA_SHORTEST

                result = self.lib.pcre_dfa_exec(
                    code,
                    None,  # DFA doesn't support extra
                    subject,
                    len(subject),
                    0,
                    dfa_opts,
                    ovector,
                    ovector_size,
                    self._dfa_workspace,
                    self._dfa_workspace_size,
                )
            else:
                # Backtracking matching with extra
                result = self.lib.pcre_exec(
                    code,
                    extra,
                    subject,
                    len(subject),
                    0,
                    match_opts,
                    ovector,
                    ovector_size,
                )

            if result >= 0:
                return True, None
            elif result == self.PCRE_ERROR_NOMATCH:
                return False, None
            else:
                return False, f"match_error:{result}"

        finally:
            # Free resources
            if extra:
                self.lib.pcre_free_study(extra)
            if code:
                self._pcre_free(code)


def create_direct_wrapper(
    engine_type: str,
    library_path: Path,
) -> "DirectPCRE | DirectPCRE2":
    """Factory function to create the appropriate direct wrapper (minimal).

    Args:
        engine_type: Either "pcre" or "pcre2"
        library_path: Path to the shared library

    Returns:
        DirectPCRE or DirectPCRE2 instance (without ReTest optimizations)
    """
    if engine_type == "pcre":
        return DirectPCRE(str(library_path))
    elif engine_type == "pcre2":
        return DirectPCRE2(str(library_path))
    else:
        raise ValueError(f"Unknown engine type: {engine_type}")


def create_retest_wrapper(
    engine_type: str,
    library_path: Path,
    use_jit: bool = True,
    use_dfa_percentage: float = 0.2,
    rotate_options: bool = True,
    partial_match_percentage: float = 0.1,
) -> "DirectPCREReTest | DirectPCRE2":
    """Factory function to create an enhanced wrapper for ReTest.

    Args:
        engine_type: Either "pcre" or "pcre2"
        library_path: Path to the shared library
        use_jit: Whether to JIT compile patterns
        use_dfa_percentage: Percentage of matches to use DFA engine
        rotate_options: Whether to rotate compile/match options
        partial_match_percentage: Percentage to try partial matching

    Returns:
        DirectPCREReTest or DirectPCRE2 instance (with ReTest optimizations)
    """
    if engine_type == "pcre":
        return DirectPCREReTest(
            str(library_path),
            use_jit=use_jit,
            use_dfa_percentage=use_dfa_percentage,
            rotate_options=rotate_options,
            partial_match_percentage=partial_match_percentage,
        )
    elif engine_type == "pcre2":
        # TODO: Create DirectPCRE2ReTest with similar features
        return DirectPCRE2(str(library_path))
    else:
        raise ValueError(f"Unknown engine type: {engine_type}")
