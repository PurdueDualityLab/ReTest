// PCRE-compatible regex grammar for fuzzing
// Simplified from V8's fuzzer_regexp_grammar.g4 for ANTLR4 Python compatibility

grammar PCRERegex;

// Entry point
pattern
    : disjunction EOF
    ;

// Disjunction: alternatives separated by |
disjunction
    : alternative ('|' alternative)*
    ;

// Alternative: sequence of terms
alternative
    : term*
    ;

// Term: assertion or atom with optional quantifier
term
    : assertion
    | atom quantifier?
    ;

// Assertions
assertion
    : '^'
    | '$'
    | '\\b'
    | '\\B'
    | '(?=' disjunction ')'
    | '(?!' disjunction ')'
    | '(?<=' disjunction ')'
    | '(?<!' disjunction ')'
    ;

// Quantifiers
quantifier
    : quantifierPrefix '?'?
    ;

quantifierPrefix
    : '*'
    | '+'
    | '?'
    | '{' DIGITS '}'
    | '{' DIGITS ',}'
    | '{' DIGITS ',' DIGITS '}'
    ;

// Atoms
atom
    : patternChar
    | '.'
    | '\\' atomEscape
    | characterClass
    | '(' groupSpecifier? disjunction ')'
    | '(?:' disjunction ')'
    ;

// Group specifier for named groups
groupSpecifier
    : '?' '<' IDENTIFIER '>'
    ;

// Atom escapes
atomEscape
    : decimalEscape
    | characterClassEscape
    | characterEscape
    | 'k<' IDENTIFIER '>'
    ;

// Decimal escape (backreference)
decimalEscape
    : NONZERO_DIGIT DIGITS?
    ;

// Character class escapes
characterClassEscape
    : 'd'
    | 'D'
    | 's'
    | 'S'
    | 'w'
    | 'W'
    | 'p{' unicodeProperty '}'
    | 'P{' unicodeProperty '}'
    ;

// Unicode property
unicodeProperty
    : IDENTIFIER ('=' IDENTIFIER)?
    ;

// Character escapes
characterEscape
    : controlEscape
    | 'c' ASCII_LETTER
    | '0'
    | 'x' HEX_DIGIT HEX_DIGIT
    | 'u' HEX_DIGIT HEX_DIGIT HEX_DIGIT HEX_DIGIT
    | 'u{' HEX_DIGITS '}'
    | identityEscape
    ;

controlEscape
    : 'f'
    | 'n'
    | 'r'
    | 't'
    | 'v'
    ;

identityEscape
    : SYNTAX_CHAR
    | '/'
    ;

// Character class [...]
characterClass
    : '[' '^'? classContents ']'
    ;

classContents
    : classAtom*
    | classAtom '-' classAtom classContents?
    ;

classAtom
    : classChar
    | '\\' classEscape
    ;

classChar
    : ~[\]\\-]
    ;

classEscape
    : 'b'
    | '-'
    | characterClassEscape
    | characterEscape
    ;

// Pattern character (non-syntax)
patternChar
    : ~[^$\\.*+?()[\]{}|]
    ;

// Lexer rules
SYNTAX_CHAR
    : [^$\\.*+?()[\]{}|]
    ;

ASCII_LETTER
    : [a-zA-Z]
    ;

NONZERO_DIGIT
    : [1-9]
    ;

DIGITS
    : [0-9]+
    ;

HEX_DIGITS
    : HEX_DIGIT+
    ;

HEX_DIGIT
    : [0-9a-fA-F]
    ;

IDENTIFIER
    : [a-zA-Z_] [a-zA-Z0-9_]*
    ;

// Any other character
ANY_CHAR
    : .
    ;
