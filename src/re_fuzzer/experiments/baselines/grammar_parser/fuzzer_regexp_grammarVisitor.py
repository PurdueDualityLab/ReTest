# Generated from fuzzer_regexp_grammar.g4 by ANTLR 4.13.2
from antlr4 import *
if "." in __name__:
    from .fuzzer_regexp_grammarParser import fuzzer_regexp_grammarParser
else:
    from fuzzer_regexp_grammarParser import fuzzer_regexp_grammarParser

# This class defines a complete generic visitor for a parse tree produced by fuzzer_regexp_grammarParser.

class fuzzer_regexp_grammarVisitor(ParseTreeVisitor):

    # Visit a parse tree produced by fuzzer_regexp_grammarParser#pattern.
    def visitPattern(self, ctx:fuzzer_regexp_grammarParser.PatternContext):
        return self.visitChildren(ctx)



del fuzzer_regexp_grammarParser