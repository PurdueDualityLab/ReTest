# Generated from fuzzer_regexp_grammar.g4 by ANTLR 4.13.2
from antlr4 import *
if "." in __name__:
    from .fuzzer_regexp_grammarParser import fuzzer_regexp_grammarParser
else:
    from fuzzer_regexp_grammarParser import fuzzer_regexp_grammarParser

# This class defines a complete listener for a parse tree produced by fuzzer_regexp_grammarParser.
class fuzzer_regexp_grammarListener(ParseTreeListener):

    # Enter a parse tree produced by fuzzer_regexp_grammarParser#pattern.
    def enterPattern(self, ctx:fuzzer_regexp_grammarParser.PatternContext):
        pass

    # Exit a parse tree produced by fuzzer_regexp_grammarParser#pattern.
    def exitPattern(self, ctx:fuzzer_regexp_grammarParser.PatternContext):
        pass



del fuzzer_regexp_grammarParser