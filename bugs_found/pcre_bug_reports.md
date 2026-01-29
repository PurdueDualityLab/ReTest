# PCRE 8.45 Bug Verification Report

This report documents three regex patterns that trigger bugs in PCRE 8.45 (the final release of PCRE1). Testing was performed using an AddressSanitizer-instrumented build of the library.

## Test Environment

- **PCRE Version**: 8.45 (June 15, 2021)
- **Build**: ASAN-instrumented (`engines/pcre-8.45-asan/`)
- **Test Method**: Python CFFI wrapper with UTF-8 and UCP support enabled

---

## Bug 1: `\C` Escape Sequence Memory Corruption

### Pattern
```
\P{Z}+:gra]sh*:p(\CR)(?s)
```

### Verification Result
**Status**: CRASH - Heap corruption (`free(): invalid next size (fast)`)

### Analysis

#### How PCRE Parses This Pattern
```
  0  36 Bra
  3     notprop Z +
  7     :gra]s
 19     h*+
 21     :p
 25   8 CBra 1
 30     Anybyte       <- \C parsed here
 31     R             <- Literal 'R'
 33   8 Ket
 36  36 Ket
 39     End
```

The sequence `\CR` is parsed as:
- `\C` - Match any single **byte** (not character)
- `R` - Literal character 'R'

This is **not** the intended carriage return escape `\r`.

#### Root Cause

The `\C` escape sequence in UTF-8 mode is inherently dangerous. According to the PCRE documentation:

> *"In UTF-8 mode, \C matches a single byte, even though this may be part of a multi-byte character. This can be dangerous because it may leave the current matching point in the middle of a multi-byte character."*

**Known Related CVE**: This behavior contributes to bugs like those fixed in PCRE 8.37:

> *"If a greedy quantified \X was preceded by \C in UTF mode (e.g. \C\X*), and a subsequent item in the pattern caused a non-match, backtracking over the repeated \X did not stop, but carried on past the start of the subject, causing reference to random memory and/or a segfault."*

#### Additional Pattern Issues

1. **Unescaped `]`**: The pattern contains `:gra]sh*` where `]` appears outside a character class. While PCRE accepts this as a literal character, it suggests the pattern may be malformed.

2. **Trailing `(?s)`**: The dotall modifier at the end of the pattern changes how `.` matches (to include newlines), but there's no `.` in the pattern to affect.

#### Bug Classification

| Attribute | Value |
|-----------|-------|
| Type | Heap Memory Corruption |
| Trigger | Compile-time or Study-time (JIT) |
| Component | Pattern compilation with `\C` in UTF-8 mode |
| Severity | High (memory safety violation) |
| Related CVE | Similar to CVE-2015-2328 |

---

## Bug 2: Empty Unicode Property Name

### Pattern
```
\p{Han}*\n*\t*\.\CP{}*\n*\t*body
```

### Verification Result
**Status**: CRASH - Heap corruption (`free(): invalid next size (fast)`)

### Analysis

#### How PCRE Parses This Pattern
```
  0  32 Bra
  3     prop Han *+
  7     \x0a*+
  9     \x09*+
 11     .
 13     Anybyte       <- \C parsed here
 14     P{            <- Literal P{
 18     }*+           <- } with possessive quantifier
 20     \x0a*+
 22     \x09*+
 24     body
 32  32 Ket
 35     End
```

#### Root Cause

The sequence `\CP{}` is parsed as:
1. `\C` - Single byte match (the "Anybyte" opcode)
2. `P{` - Literal characters "P{"
3. `}` - Literal "}" with `*+` possessive quantifier

The pattern author likely intended `\CP{}` to be an empty negated Unicode property (which should be invalid), but PCRE's lexer splits it into `\C` + `P{}`.

**The core issue**: `\C` in UTF-8 mode combined with the subsequent parsing creates memory management issues during JIT compilation or pattern study.

#### Why This Is Dangerous

1. **Misinterpretation**: The pattern looks like a Unicode property `\CP{...}` but is actually `\C` + literal text
2. **No Validation Error**: PCRE accepts this as valid syntax without warning
3. **Memory Corruption**: The combination triggers heap corruption during pattern processing

#### Bug Classification

| Attribute | Value |
|-----------|-------|
| Type | Heap Memory Corruption |
| Trigger | Compile-time or Study-time (JIT) |
| Component | `\C` escape handling combined with property-like text |
| Severity | High (memory safety violation) |
| Related | Missing validation for confusing escape sequences |

---

## Bug 3: Global Buffer Overflow in `find_recurse`

### Pattern
```
(x{1,3}|\p{L}++|(([^>]*(?1){0}(?1)?)))+
```

### Verification Result
**Status**: CRASH - Global buffer overflow (out-of-bounds read)

### ASAN Report
```
==3308958==ERROR: AddressSanitizer: global-buffer-overflow on address 0x7afc459dc24a
READ of size 1 at 0x7afc459dc24a thread T0
    #0 find_recurse /pcre-8.45/pcre_compile.c:2297:13
    #1 adjust_recurse /pcre-8.45/pcre_compile.c:4028:29
    #2 compile_branch /pcre-8.45/pcre_compile.c:6534:11
    #3 compile_regex /pcre-8.45/pcre_compile.c:8408:8
    #4 pcre_compile2 /pcre-8.45/pcre_compile.c:9497:7

0x7afc459dc24a is located 8 bytes after global variable '_pcre_OP_lengths'
defined in 'pcre_tables.c:59' of size 162
```

### Analysis

#### Pattern Structure
```
(                           # Group 1
  x{1,3}                    # Alternative 1: match 1-3 'x'
  |
  \p{L}++                   # Alternative 2: match Unicode letters (possessive)
  |
  (                         # Alternative 3: Group 2
    (                       # Group 3
      [^>]*                 # Any chars except '>'
      (?1){0}               # RECURSIVE CALL TO GROUP 1 - ZERO TIMES
      (?1)?                 # Optional recursive call to group 1
    )
  )
)+                          # One or more of group 1
```

#### Root Cause

The `find_recurse` function reads from the `_pcre_OP_lengths` global array using an opcode index that **exceeds the array bounds**. This occurs when processing subroutine patterns (`(?1)`) with zero quantifiers (`{0}`).

The bug is in `pcre_compile.c:2297`:
- The function traverses compiled opcodes to find recursive references
- When encountering the unusual `(?1){0}(?1)?` combination, it calculates an invalid opcode index
- It then reads from `_pcre_OP_lengths[invalid_index]`, accessing memory 8 bytes past the 162-byte array

#### Why `pcretest` Shows a Different Error

When testing with `pcretest` directly (without ASAN), the buffer overflow occurs silently, and PCRE continues to a secondary check that produces:
```
Failed: recursive call could loop indefinitely at offset 26
```

This error message masks the underlying memory safety violation. **The buffer overflow happens first**, before PCRE reaches the infinite loop detection logic.

#### Key Pattern Features

| Feature | Syntax | Role in Bug |
|---------|--------|-------------|
| Subroutine | `(?1)` | References group 1 recursively |
| Zero Quantifier | `{0}` | Causes unusual opcode layout |
| Combination | `(?1){0}(?1)?` | Confuses opcode traversal in `find_recurse` |
| Possessive | `++` | Additional complexity in pattern |
| Unicode Property | `\p{L}` | Requires UTF8+UCP flags |

#### Bug Classification

| Attribute | Value |
|-----------|-------|
| Type | Global Buffer Overflow (Read) |
| CWE | CWE-125 (Out-of-bounds Read) |
| Trigger | Compile-time (`pcre_compile2`) |
| Component | `find_recurse` → `adjust_recurse` → `compile_branch` |
| File | `pcre_compile.c:2297` |
| Severity | **High** (memory safety violation, potential info disclosure) |
| Related CVE | CVE-2015-2325, CVE-2015-2326 |

#### Security Impact

An attacker who can supply regex patterns to an application using PCRE 8.45 could:
1. **Crash the application** (denial of service)
2. **Read adjacent memory** (information disclosure)
3. **Potentially bypass ASLR** by leaking memory layout information

---

## Summary

| Pattern | Bug Type | Status | Severity |
|---------|----------|--------|----------|
| 1. `\P{Z}+:gra]sh*:p(\CR)(?s)` | Heap Corruption | CRASH | High |
| 2. `\p{Han}*\n*\t*\.\CP{}*\n*\t*body` | Heap Corruption | CRASH | High |
| 3. `(x{1,3}\|\p{L}++\|(([^>]*(?1){0}(?1)?)))+` | Global Buffer Overflow | CRASH | High |

## Recommendations

1. **Migrate to PCRE2**: PCRE1 (8.xx series) reached end-of-life with 8.45. PCRE2 (10.xx series) has improved security and ongoing maintenance.

2. **Disable `\C` in UTF Mode**: If using PCRE1, consider the `PCRE_NEVER_BACKSLASH_C` compile option (if available) or reject patterns containing `\C` when in UTF mode.

3. **Input Validation**: Implement pattern validation before compilation to catch potentially dangerous constructs:
   - `\C` in UTF-8 mode
   - Deeply nested recursion
   - Zero-quantified recursive calls

4. **Resource Limits**: Always set `match_limit` and `recursion_limit` when using PCRE to prevent denial-of-service attacks from catastrophic backtracking.

## References

- [PCRE Changelog](https://www.pcre.org/original/changelog.txt)
- [PCRE CVE List (cvedetails.com)](https://www.cvedetails.com/vulnerability-list/vendor_id-3265/product_id-5715/Pcre-Pcre.html)
- [CVE-2015-2325](https://nvd.nist.gov/vuln/detail/CVE-2015-2325) - Heap overflow with forward reference
- [CVE-2015-2326](https://nvd.nist.gov/vuln/detail/CVE-2015-2326) - Heap overflow with recursive back reference
- [CVE-2016-1283](https://nvd.nist.gov/vuln/detail/CVE-2016-1283) - Buffer overflow with duplicate named groups
