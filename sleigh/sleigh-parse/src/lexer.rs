use std::{convert::TryInto, iter::Peekable, str::CharIndices};

use crate::{error::Error, Span};

pub type SourceId = u32;

#[derive(Copy, Clone, Debug)]
pub struct Token {
    pub kind: TokenKind,
    pub span: Span,
}

impl Token {
    pub fn error(&self, msg: impl Into<String>) -> Error {
        Error { message: msg.into(), span: self.span, cause: None }
    }

    /// Create a new error message for an unexpected token kind error
    #[cold]
    pub fn error_unexpected(&self, expected: &[TokenKind]) -> Error {
        assert!(!expected.contains(&self.kind));

        let message = match self.kind {
            TokenKind::UnclosedString if expected == [TokenKind::String] => {
                String::from("Unterminated string")
            }
            TokenKind::Eof => format!("Unexpected end of file (expected: {:?})", expected),
            _ => format!("Unexpected token: {:?} (expected {:?})", self.kind, expected),
        };

        self.error(message)
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum MacroKind {
    Include,
    Define,
    Undef,
    If,
    IfDef,
    IfNotDef,
    Else,
    Elif,
    EndIf,
    Expand,
    Unknown,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum TokenKind {
    Preprocessor(MacroKind),
    Defined,

    // A symbol for one or more white-space characters
    Whitespace,

    // End of line character
    Line,

    // End of file
    Eof,

    Comment,

    // Keywords
    Define,
    Alignment,
    Endian,
    BitRange,
    Space,
    Size,
    Type,
    Default,
    WordSize,

    Offset,

    PcodeOp,
    Attach,
    Token,
    Context,
    Variables,
    Names,
    Values,

    Signed,
    Hex,
    Dec,
    NoFlow,

    With,
    Macro,

    Unimpl,
    TripleDot,

    // Special identifiers for table expressions
    GlobalSet,
    Export,
    Local,
    Build,
    If,
    Goto,
    Call,
    Return,

    Is,
    And,
    Or,
    Xor,

    // Symbols
    Plus,
    Minus,
    Star,
    ForwardSlash,
    Percent,
    Hat,
    Bar,
    Ampersand,
    ExclamationMark,
    Tilde,
    Equal,
    LessThan,
    GreaterThan,
    SemiColon,
    Colon,
    Comma,
    LeftBrace,
    RightBrace,
    LeftParen,
    RightParen,
    LeftBracket,
    RightBracket,

    // Multi character symbols
    FMinus,
    FPlus,
    FForwardSlash,
    FStar,
    FLessThan,
    FGreaterThan,
    FExclamationMark,
    FEqual,
    SForwardSlash,
    SPercent,
    SLessThan,
    SGreaterThan,

    Ident,

    // Literals
    String,
    Number,

    // Errors
    UnclosedString,
    Unknown,
    ParseError,
}

impl From<MacroKind> for TokenKind {
    fn from(v: MacroKind) -> Self {
        TokenKind::Preprocessor(v)
    }
}

pub struct Lexer<'a> {
    /// The offset of the start of every line we have seen.
    pub lines: Vec<u32>,

    /// An identifier corresponding to the source associated with this lexer
    src: SourceId,

    /// The original input string
    input: &'a str,

    /// An iterator over the characters in the input string with their associated indices
    chars: Peekable<CharIndices<'a>>,

    /// The offset of the start of the token
    token_start: u32,

    /// The offset of the most recent character processed
    prev: u32,
}

impl<'a> Lexer<'a> {
    pub fn new(src: SourceId, input: &'a str) -> Self {
        Self {
            lines: vec![0],
            src,
            input,
            chars: input.char_indices().peekable(),
            token_start: 0,
            prev: 0,
        }
    }

    /// Lex the next token from the input stream
    pub fn next_token(&mut self) -> Option<Token> {
        macro_rules! symbol {
            ($kind:expr) => {{
                self.bump();
                self.create_token($kind)
            }};
        }

        let &(offset, value) = self.chars.peek()?;
        self.token_start = offset.try_into().expect("Exceeded max file size.");

        let token = match value {
            // Line-ending characters
            '\n' | '\r' => {
                self.eat_line_end();
                self.lines.push(self.current_span().start);
                self.create_token(TokenKind::Line)
            }

            // Any other whitespace characters
            c if c.is_whitespace() => {
                self.eat_whitespace();
                self.create_token(TokenKind::Whitespace)
            }

            // Comments start with the '#' character and continue to the end of the line.
            '#' => {
                self.eat_line();
                self.create_token(TokenKind::Comment)
            }

            // Symbols
            '+' => symbol!(TokenKind::Plus),
            '-' => symbol!(TokenKind::Minus),
            '*' => symbol!(TokenKind::Star),
            '/' => symbol!(TokenKind::ForwardSlash),
            '%' => symbol!(TokenKind::Percent),
            '^' => symbol!(TokenKind::Hat),
            '|' => symbol!(TokenKind::Bar),
            '&' => symbol!(TokenKind::Ampersand),
            '!' => symbol!(TokenKind::ExclamationMark),
            '~' => symbol!(TokenKind::Tilde),
            '=' => symbol!(TokenKind::Equal),
            '<' => symbol!(TokenKind::LessThan),
            '>' => symbol!(TokenKind::GreaterThan),
            ';' => symbol!(TokenKind::SemiColon),
            ',' => symbol!(TokenKind::Comma),
            '{' => symbol!(TokenKind::LeftBrace),
            '}' => symbol!(TokenKind::RightBrace),
            '(' => symbol!(TokenKind::LeftParen),
            ')' => symbol!(TokenKind::RightParen),
            '[' => symbol!(TokenKind::LeftBracket),
            ']' => symbol!(TokenKind::RightBracket),
            ':' => symbol!(TokenKind::Colon),

            // Preprocessor macros
            '@' => {
                self.bump();

                // Whitespace is allowed before the macro identifier (e.g. `@  if <cond>`)
                self.eat_whitespace();

                let ident_span = self.eat_ident();
                let kind = match &self.input[ident_span] {
                    "include" => MacroKind::Include,
                    "define" => MacroKind::Define,
                    "undef" => MacroKind::Undef,
                    "if" => MacroKind::If,
                    "ifdef" => MacroKind::IfDef,
                    "ifndef" => MacroKind::IfNotDef,
                    "else" => MacroKind::Else,
                    "elif" => MacroKind::Elif,
                    "endif" => MacroKind::EndIf,
                    _ => MacroKind::Unknown,
                };

                self.create_token(kind)
            }

            // Special keywords (e.g. $xor) or macro expansions (e.g. $(IDENT))
            '$' => {
                self.bump();

                if self.peek_char() == Some('(') {
                    // Macro expansion
                    self.create_token(MacroKind::Expand)
                }
                else {
                    // Special keyword
                    let ident_span = self.eat_ident();
                    let kind = match &self.input[ident_span] {
                        "and" => TokenKind::And,
                        "or" => TokenKind::Or,
                        "xor" => TokenKind::Xor,
                        _ => TokenKind::Unknown,
                    };
                    self.create_token(kind)
                }
            }

            // String literal
            '"' => match self.eat_string() {
                true => self.create_token(TokenKind::String),
                false => self.create_token(TokenKind::UnclosedString),
            },

            // Numeric literal
            '0'..='9' => {
                // @fixme: not all identifiers are valid numbers
                self.eat_ident();
                self.create_token(TokenKind::Number)
            }

            // Keyword or identifier
            '_' | '.' | 'a'..='z' | 'A'..='Z' => {
                let ident_span = self.eat_ident();
                let kind = match &self.input[ident_span] {
                    "defined" => TokenKind::Defined,

                    "define" => TokenKind::Define,
                    "alignment" => TokenKind::Alignment,
                    "endian" => TokenKind::Endian,
                    "bitrange" => TokenKind::BitRange,
                    "space" => TokenKind::Space,
                    "size" => TokenKind::Size,
                    "type" => TokenKind::Type,
                    "default" => TokenKind::Default,
                    "wordsize" => TokenKind::WordSize,

                    "offset" => TokenKind::Offset,

                    "pcodeop" => TokenKind::PcodeOp,
                    "attach" => TokenKind::Attach,
                    "token" => TokenKind::Token,
                    "context" => TokenKind::Context,
                    "variables" => TokenKind::Variables,
                    "names" => TokenKind::Names,
                    "values" => TokenKind::Values,

                    "signed" => TokenKind::Signed,
                    "hex" => TokenKind::Hex,
                    "dec" => TokenKind::Dec,
                    "noflow" => TokenKind::NoFlow,

                    "unimpl" => TokenKind::Unimpl,
                    "..." => TokenKind::TripleDot,
                    "with" => TokenKind::With,
                    "macro" => TokenKind::Macro,

                    "globalset" => TokenKind::GlobalSet,
                    "export" => TokenKind::Export,
                    "local" => TokenKind::Local,
                    "build" => TokenKind::Build,
                    "if" => TokenKind::If,
                    "goto" => TokenKind::Goto,
                    "call" => TokenKind::Call,
                    "return" => TokenKind::Return,

                    "is" => TokenKind::Is,

                    // Multi-character symbols
                    "f" if self.peek_char().map_or(false, |x| "-+/*<>!=".contains(x)) => {
                        match self.bump().unwrap() {
                            '-' => TokenKind::FMinus,
                            '+' => TokenKind::FPlus,
                            '/' => TokenKind::FForwardSlash,
                            '*' => TokenKind::FStar,
                            '<' => TokenKind::FLessThan,
                            '>' => TokenKind::FGreaterThan,
                            '!' => TokenKind::FExclamationMark,
                            '=' => TokenKind::FEqual,
                            _ => unreachable!(),
                        }
                    }
                    "s" if self.peek_char().map_or(false, |x| "/%<>".contains(x)) => {
                        match self.bump().unwrap() {
                            '/' => TokenKind::SForwardSlash,
                            '%' => TokenKind::SPercent,
                            '<' => TokenKind::SLessThan,
                            '>' => TokenKind::SGreaterThan,
                            _ => unreachable!(),
                        }
                    }

                    _ => TokenKind::Ident,
                };

                self.create_token(kind)
            }

            _ => {
                self.bump();
                self.create_token(TokenKind::Unknown)
            }
        };

        Some(token)
    }

    /// Gets the location with the current token
    fn current_span(&self) -> Span {
        Span { src: self.src, start: self.token_start, end: self.prev }
    }

    /// Create a new token of type `kind` at the current location
    fn create_token(&self, kind: impl Into<TokenKind>) -> Token {
        Token { kind: kind.into(), span: self.current_span() }
    }

    /// Gets the char from the input stream, updating the lexer's metadata that is used for keeping
    /// track of the next span
    #[inline(always)]
    fn bump(&mut self) -> Option<char> {
        let (offset, val) = self.chars.next()?;
        self.prev = offset.try_into().ok()?;
        Some(val)
    }

    /// Peeks at the next char to be processed
    fn peek_char(&mut self) -> Option<char> {
        self.chars.peek().map(|x| x.1)
    }

    /// Bumps the current offset if the character matches `value`. Returns `true` on a match
    fn bump_if(&mut self, value: char) -> bool {
        match self.peek_char() {
            Some(x) if x == value => {
                self.bump();
                true
            }
            _ => false,
        }
    }

    /// Eat the end of a line, correctly handling different line endings
    fn eat_line_end(&mut self) {
        self.bump_if('\r');
        self.bump_if('\n');
    }

    /// Eat the rest of the line
    fn eat_line(&mut self) {
        self.bump_while(|c| c != '\n' && c != '\r');
    }

    /// Skip characters while `predicate` is true
    fn bump_while(&mut self, mut predicate: impl FnMut(char) -> bool) {
        while let Some(next) = self.peek_char() {
            if !predicate(next) {
                break;
            }
            self.bump();
        }
    }

    /// Eat any whitespace characters except for new line characters
    fn eat_whitespace(&mut self) {
        self.bump_while(|c| c.is_whitespace() && c != '\r' && c != '\n');
    }

    /// Eat a valid identifier returning
    fn eat_ident(&mut self) -> std::ops::RangeInclusive<usize> {
        /// Identifiers are made up of letters a-z, capitals A-Z, digits 0-9 and the characters '.'
        /// and '_'. An identifier can use these characters in any order and for any length, but it
        /// must not start with a digit.
        #[inline(always)]
        fn is_ident_char(c: char) -> bool {
            if !c.is_ascii() {
                return false;
            }

            // abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890._
            match c as u8 {
                b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'.' | b'_' => true,
                _ => false,
            }
        }

        if !self.bump().map_or(false, is_ident_char) {
            panic!("called `eat_ident` at an invalid location");
        }

        let start = self.prev;
        self.bump_while(is_ident_char);
        (start as usize)..=(self.prev as usize)
    }

    /// Eat a string surrounded by `"` characters
    fn eat_string(&mut self) -> bool {
        assert_eq!(self.bump(), Some('"'));
        self.bump_while(|c| c != '"' && c != '\n' && c != '\r');
        self.bump_if('"')
    }
}

impl<'a> Iterator for &mut Lexer<'a> {
    type Item = Token;

    fn next(&mut self) -> Option<Self::Item> {
        self.next_token()
    }
}

#[cfg(test)]
fn tokenize_all(input: &str) -> Vec<TokenKind> {
    Lexer::new(0, input).map(|x| x.kind).collect()
}

#[test]
fn parse_ident() {
    let token = tokenize_all("ident.123.ABC")[0];
    assert_eq!(token, TokenKind::Ident);

    let token = tokenize_all(".IDENT_123_abc")[0];
    assert_eq!(token, TokenKind::Ident);

    let token = tokenize_all("123_invalid_ident")[0];
    assert_ne!(token, TokenKind::Ident);
}

#[test]
fn parse_comment() {
    let tokens = tokenize_all("# this is a comment");
    assert_eq!(tokens, vec![TokenKind::Comment]);

    let tokens = tokenize_all("# this is a\n# multi-line comment\nident.123.ABC");
    assert_eq!(tokens, vec![
        TokenKind::Comment,
        TokenKind::Line,
        TokenKind::Comment,
        TokenKind::Line,
        TokenKind::Ident
    ]);
}

#[test]
fn parse_multi_character_tokens() {
    let check = |input: &str, expected: TokenKind| {
        let tokens: Vec<_> =
            tokenize_all(input).into_iter().filter(|&x| x != TokenKind::Whitespace).collect();
        assert_eq!(tokens, vec![TokenKind::Ident, expected, TokenKind::Ident]);
    };

    check("a f- b", TokenKind::FMinus);
    check("a f+ b", TokenKind::FPlus);
    check("a f/ b", TokenKind::FForwardSlash);
    check("a f* b", TokenKind::FStar);
    check("a f< b", TokenKind::FLessThan);
    check("a f> b", TokenKind::FGreaterThan);
    check("a f! b", TokenKind::FExclamationMark);
    check("a f= b", TokenKind::FEqual);
    check("a s/ b", TokenKind::SForwardSlash);
    check("a s% b", TokenKind::SPercent);
    check("a s< b", TokenKind::SLessThan);
    check("a s> b", TokenKind::SGreaterThan);
}
