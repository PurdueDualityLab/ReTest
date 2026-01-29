# Roadmap for Regex Generator Module

## Features to implement

-   [] Predicate logic

## Input generation tools (i.e., random regex generators)

-   [] https://github.com/posidron/dharma
-   [] https://github.com/MozillaSecurity/avalanche # How is it related to dharma? Both are from Mozilla.
-   [] https://github.com/FAU-Inf2/FuzzPEG
-   [] https://github.com/codelion/gramtest
-   [] https://github.com/dmbaturin/bnfgen
-   [] https://github.com/z2-2z/chameleon
-   [] https://www.quut.com/abnfgen/
-   [] https://github.com/bakkot/cfgrammar-tool
-   [] https://github.com/Rog3rSm1th/kharma
-   [] https://github.com/siberianbluerobin/bulk-examples-generator # Looks easy to implement
-   [] https://www.nltk.org/howto/grammar.html # Vanilla one is determinstic. If we want weights and random generation:
    https://github.com/thomasbreydo/pcfg

## Grammar-based fuzzing tools

Those tools also include input generation capabilities obviously, but they extend to be full-fledged fuzzers. I am not
saying that we should or can implement all of them, but it is worth to take a look at them to see what they do and how
we can include in our project, if possible.

### Priority level: High

-   [] https://www.fuzzingbook.org/html/Grammars.html
-   [] https://github.com/StanimirIglev/syntax-symphony # ^ This work has been greatly influenced by the concepts and
    ideas outlined in the Fuzzing Book.
-   [] https://github.com/nautilus-fuzz/nautilus
-   [] https://github.com/vrthra/F1 # Is it the same as fuzzing book?
-   [] https://github.com/gamozolabs/fzero_fuzzer # F1 in rust
-   [] https://github.com/MartynaSobolewska/F2 # F2 is a grammar based fuzzzer that builds on F1 and fzero
-   [] https://github.com/d0c-s4vage/gramfuzz
-   [] https://github.com/HexHive/Gramatron
-   [] https://github.com/z2-2z/peacock # Reimplementation of Gramatron that is performant, versatile, etc.
-   [] https://github.com/zhunki/Superion
-   [] https://github.com/redcrabs/FSA # ^ same as Superion?
-   [] https://github.com/martineberlein/evogfuzz
-   [] https://github.com/langston-barrett/tree-crasher
-   [] https://github.com/yavuzkoroglu/gfuzzer-release

### Priority level: Medium

-   [] https://github.com/CIFASIS/QuickFuzz
-   [] https://github.com/atnwalk/atnwalk # Example grammars: https://github.com/atnwalk/grammars

### Priority level: Low

-   [] https://github.com/bahruzjabiyev/t-reqs
-   [] https://github.com/bahruzjabiyev/frameshifter
-   [] https://github.com/silviocesare/Fuzzer
-   [] https://github.com/R9295/autarkie
-   [] https://github.com/timtadh/fuzzbuzz
-   [] https://github.com/AzulSystems/FuzzGen
-   [] https://github.com/havrikov/tribble
-   [] https://github.com/PFGimenez/poirot
-   [] https://github.com/TartarusLabs/tsukumogami
-   [] https://github.com/PrVrSs/idl2js
