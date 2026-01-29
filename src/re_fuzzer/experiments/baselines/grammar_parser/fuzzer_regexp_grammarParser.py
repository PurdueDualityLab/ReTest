# Generated from fuzzer_regexp_grammar.g4 by ANTLR 4.13.2
# encoding: utf-8
from antlr4 import *
from io import StringIO
import sys
if sys.version_info[1] > 5:
	from typing import TextIO
else:
	from typing.io import TextIO

def serializedATN():
    return [
        4,1,69,5,2,0,7,0,1,0,1,0,1,0,0,0,1,0,0,0,3,0,2,1,0,0,0,2,3,5,14,
        0,0,3,1,1,0,0,0,0
    ]

class fuzzer_regexp_grammarParser ( Parser ):

    grammarFileName = "fuzzer_regexp_grammar.g4"

    atn = ATNDeserializer().deserialize(serializedATN())

    decisionsToDFA = [ DFA(ds, i) for i, ds in enumerate(atn.decisionToState) ]

    sharedContextCache = PredictionContextCache()

    literalNames = [ "<INVALID>", "<INVALID>", "<INVALID>", "<INVALID>", 
                     "<INVALID>", "'_'" ]

    symbolicNames = [ "<INVALID>", "SourceCharacter", "IdentifierStartChar", 
                      "IdentifierPartChar", "AsciiLetter", "NumericLiteralSeparator", 
                      "DecimalDigits", "DecimalDigit", "NonZeroDigit", "HexDigit", 
                      "HexDigits", "CodePoint", "HexEscapeSequence", "Hex4Digits", 
                      "Disjunction", "Alternative", "Term", "Assertion", 
                      "Quantifier", "QuantifierPrefix", "Atom", "SyntaxCharacter", 
                      "PatternCharacter", "AtomEscape", "CharacterEscape", 
                      "ControlEscape", "GroupSpecifier", "GroupName", "RegExpIdentifierName", 
                      "RegExpIdentifierStart", "RegExpIdentifierPart", "RegExpUnicodeEscapeSequence", 
                      "UnicodeLeadSurrogate", "UnicodeTrailSurrogate", "HexLeadSurrogate", 
                      "HexTrailSurrogate", "HexNonSurrogate", "IdentityEscape", 
                      "DecimalEscape", "CharacterClassEscape", "UnicodePropertyValueExpression", 
                      "UnicodePropertyName", "UnicodePropertyNameCharacters", 
                      "UnicodePropertyValue", "LoneUnicodePropertyNameOrValue", 
                      "UnicodePropertyValueCharacters", "UnicodePropertyValueCharacter", 
                      "UnicodePropertyNameCharacter", "CharacterClass", 
                      "ClassContents", "NonemptyClassRanges", "NonemptyClassRangesNoDash", 
                      "ClassAtom", "ClassAtomNoDash", "ClassEscape", "ClassSetExpression", 
                      "ClassUnion", "ClassIntersection", "ClassSubtraction", 
                      "ClassSetRange", "ClassSetOperand", "NestedClass", 
                      "ClassStringDisjunction", "ClassStringDisjunctionContents", 
                      "ClassString", "NonEmptyClassString", "ClassSetCharacter", 
                      "ClassSetReservedDoublePunctuator", "ClassSetSyntaxCharacter", 
                      "ClassSetReservedPunctuator" ]

    RULE_pattern = 0

    ruleNames =  [ "pattern" ]

    EOF = Token.EOF
    SourceCharacter=1
    IdentifierStartChar=2
    IdentifierPartChar=3
    AsciiLetter=4
    NumericLiteralSeparator=5
    DecimalDigits=6
    DecimalDigit=7
    NonZeroDigit=8
    HexDigit=9
    HexDigits=10
    CodePoint=11
    HexEscapeSequence=12
    Hex4Digits=13
    Disjunction=14
    Alternative=15
    Term=16
    Assertion=17
    Quantifier=18
    QuantifierPrefix=19
    Atom=20
    SyntaxCharacter=21
    PatternCharacter=22
    AtomEscape=23
    CharacterEscape=24
    ControlEscape=25
    GroupSpecifier=26
    GroupName=27
    RegExpIdentifierName=28
    RegExpIdentifierStart=29
    RegExpIdentifierPart=30
    RegExpUnicodeEscapeSequence=31
    UnicodeLeadSurrogate=32
    UnicodeTrailSurrogate=33
    HexLeadSurrogate=34
    HexTrailSurrogate=35
    HexNonSurrogate=36
    IdentityEscape=37
    DecimalEscape=38
    CharacterClassEscape=39
    UnicodePropertyValueExpression=40
    UnicodePropertyName=41
    UnicodePropertyNameCharacters=42
    UnicodePropertyValue=43
    LoneUnicodePropertyNameOrValue=44
    UnicodePropertyValueCharacters=45
    UnicodePropertyValueCharacter=46
    UnicodePropertyNameCharacter=47
    CharacterClass=48
    ClassContents=49
    NonemptyClassRanges=50
    NonemptyClassRangesNoDash=51
    ClassAtom=52
    ClassAtomNoDash=53
    ClassEscape=54
    ClassSetExpression=55
    ClassUnion=56
    ClassIntersection=57
    ClassSubtraction=58
    ClassSetRange=59
    ClassSetOperand=60
    NestedClass=61
    ClassStringDisjunction=62
    ClassStringDisjunctionContents=63
    ClassString=64
    NonEmptyClassString=65
    ClassSetCharacter=66
    ClassSetReservedDoublePunctuator=67
    ClassSetSyntaxCharacter=68
    ClassSetReservedPunctuator=69

    def __init__(self, input:TokenStream, output:TextIO = sys.stdout):
        super().__init__(input, output)
        self.checkVersion("4.13.2")
        self._interp = ParserATNSimulator(self, self.atn, self.decisionsToDFA, self.sharedContextCache)
        self._predicates = None




    class PatternContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def Disjunction(self):
            return self.getToken(fuzzer_regexp_grammarParser.Disjunction, 0)

        def getRuleIndex(self):
            return fuzzer_regexp_grammarParser.RULE_pattern

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterPattern" ):
                listener.enterPattern(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitPattern" ):
                listener.exitPattern(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitPattern" ):
                return visitor.visitPattern(self)
            else:
                return visitor.visitChildren(self)




    def pattern(self):

        localctx = fuzzer_regexp_grammarParser.PatternContext(self, self._ctx, self.state)
        self.enterRule(localctx, 0, self.RULE_pattern)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 2
            self.match(fuzzer_regexp_grammarParser.Disjunction)
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx





