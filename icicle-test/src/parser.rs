//! Parser for test cases

use std::{iter::Peekable, str::CharIndices};

use anyhow::Context;
use icicle_vm::cpu::mem::perm;

use crate::{Assignment, DecodeTest, SemanticsTest, TestCase};

#[derive(Copy, Clone, Debug)]
struct Token {
    kind: TokenKind,
    start: usize,
    end: usize,
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
enum TokenKind {
    /// `// comment`
    Comment,

    /// ` `
    Whitespace,

    /// `\r\n`, `\n`, `\r`
    Line,

    /// '['
    OpenBracket,
    /// ']'
    CloseBracket,

    /// '{'
    OpenBrace,
    /// '}'
    CloseBrace,

    /// ':'
    Colon,
    /// ';'
    Semicolon,
    /// '='
    Equals,
    /// '=>'
    RightArrow,
    /// ','
    Comma,

    /// |
    Bar,

    /// '-'
    Minus,

    /// `0123abc`
    HexNum,
    /// `1234`
    Num,
    /// `"String"`
    String,
    /// `Ident`
    Ident,

    /// `@skip` annotation
    Skip,

    /// `mem` keyword
    Mem,

    /// Represents the end of the input
    Eof,

    /// Unknown or invalid token
    Unknown,
}

struct Lexer<'a> {
    /// The original input string
    input: &'a str,

    /// An iterator over the characters in the input string with their associated indices
    chars: Peekable<CharIndices<'a>>,

    /// The last token peeked from the lexer
    peeked: Option<Token>,

    /// Controls whether digits should be parsed as hex even without an `0x` prefix
    parse_hex: bool,

    /// The offset of the start of the token
    token_start: usize,

    /// The offset of the most recent character processed
    prev: usize,
}

impl<'a> Lexer<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            input,
            chars: input.char_indices().peekable(),
            peeked: None,
            parse_hex: false,
            token_start: 0,
            prev: 0,
        }
    }

    /// Gets the span associated with the current token
    fn current_span(&self) -> std::ops::RangeInclusive<usize> {
        self.token_start..=self.prev
    }

    /// Create a new token
    fn create_token(&self, kind: TokenKind) -> Token {
        let span = self.current_span();
        Token { kind, start: *span.start(), end: *span.end() }
    }

    /// Gets the char from the input stream, updating the lexer's metadata that is used for keeping
    /// track of the next span
    fn bump(&mut self) -> Option<char> {
        let (offset, val) = self.chars.next()?;
        self.prev = offset;
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
    fn bump_line_end(&mut self) {
        self.bump_if('\r');
        self.bump_if('\n');
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

    fn peek(&mut self) -> Option<Token> {
        if self.peeked.is_some() {
            return self.peeked;
        }
        self.peeked = self.next();
        self.peeked
    }

    fn next(&mut self) -> Option<Token> {
        const HEX_CHARS: &str = "abcdefABCDEF0123456789_";
        const DEC_CHARS: &str = "0123456789_";

        const fn is_ident_char(c: char) -> bool {
            matches!(c, 'a'..='z' | 'A'..='Z' | '0'..='9' | '_' | '.')
        }

        macro_rules! symbol {
            ($kind:expr) => {{
                self.bump();
                Some(self.create_token($kind))
            }};
        }

        if let Some(token) = self.peeked.take() {
            return Some(token);
        }

        let &(offset, value) = self.chars.peek()?;
        self.token_start = offset;

        match value {
            '\r' | '\n' => {
                self.bump_line_end();
                Some(self.create_token(TokenKind::Line))
            }

            c if c.is_whitespace() => {
                self.bump_while(|c| c.is_whitespace() && c != '\r' && c != '\n');
                Some(self.create_token(TokenKind::Whitespace))
            }

            '/' => {
                self.bump();
                if !self.bump_if('/') {
                    return Some(self.create_token(TokenKind::Unknown));
                }
                self.bump_while(|c| c != '\n' && c != '\r');
                Some(self.create_token(TokenKind::Comment))
            }

            '[' => symbol!(TokenKind::OpenBracket),
            ']' => symbol!(TokenKind::CloseBracket),
            '{' => symbol!(TokenKind::OpenBrace),
            '}' => symbol!(TokenKind::CloseBrace),
            ':' => symbol!(TokenKind::Colon),
            ';' => symbol!(TokenKind::Semicolon),
            '=' => {
                self.bump();
                match self.bump_if('>') {
                    true => Some(self.create_token(TokenKind::RightArrow)),
                    false => Some(self.create_token(TokenKind::Equals)),
                }
            }
            ',' => symbol!(TokenKind::Comma),
            '-' => symbol!(TokenKind::Minus),
            '|' => symbol!(TokenKind::Bar),

            '"' => {
                self.bump();
                let start = self.prev + 1;
                self.bump_while(|c| c != '"' && c != '\n' && c != '\r');
                let end = self.prev;
                self.bump(); // Closing quote character
                Some(Token { kind: TokenKind::String, start, end })
            }

            c if self.parse_hex && HEX_CHARS.contains(c) => {
                self.bump_while(|c| HEX_CHARS.contains(c));
                Some(self.create_token(TokenKind::HexNum))
            }

            c if DEC_CHARS.contains(c) => {
                self.bump();

                // Check whether this is a hex literal
                if self.bump_if('x') {
                    let start = self.prev + 1;
                    self.bump_while(|c| HEX_CHARS.contains(c));
                    return Some(Token { kind: TokenKind::HexNum, start, end: self.prev });
                }

                self.bump_while(|c| DEC_CHARS.contains(c));
                Some(self.create_token(TokenKind::Num))
            }

            '@' => {
                self.bump();
                self.bump_while(is_ident_char);
                match &self.input[self.current_span()] {
                    "@skip" => Some(self.create_token(TokenKind::Skip)),
                    _ => Some(self.create_token(TokenKind::Unknown)),
                }
            }
            'a'..='z' | 'A'..='Z' => {
                self.bump_while(is_ident_char);
                match &self.input[self.current_span()] {
                    "mem" => Some(self.create_token(TokenKind::Mem)),
                    _ => Some(self.create_token(TokenKind::Ident)),
                }
            }

            _ => {
                self.bump();
                Some(self.create_token(TokenKind::Unknown))
            }
        }
    }
}

fn trim_leading_zeros(input: &str) -> &str {
    let trimmed = input.trim_start_matches('0');

    // If input was non-empty, and now is empty then the input must be entirely zeros. The
    // last zero is significant, so just return the literal '0'
    if !input.is_empty() && trimmed.is_empty() {
        return "0";
    }

    trimmed
}

pub struct Parser<'a> {
    pub lines: Vec<usize>,
    input: &'a str,
    lexer: Lexer<'a>,
}

impl<'a> Parser<'a> {
    pub fn new(input: &'a str) -> Self {
        Self { input, lexer: Lexer::new(input), lines: vec![] }
    }

    pub fn parse_next(&mut self) -> Option<anyhow::Result<TestCase<'a>>> {
        self.peek_token(true)?;
        Some(self.parse_test_case())
    }

    /// Parse a full test case
    fn parse_test_case(&mut self) -> anyhow::Result<TestCase<'a>> {
        let skip = self.peek_token(true).map_or(false, |tok| tok.kind == TokenKind::Skip);
        if skip {
            self.bump();
        }

        let load_addr = self.parse_num().context("parsing base address")?;
        let mut isa_mode = 0;
        if self.peek_token(true).map_or(false, |tok| tok.kind == TokenKind::Bar) {
            self.bump();
            isa_mode = self.parse_num().context("parsing ISA Mode")?
        }
        let start_line = self.current_line();

        let instructions = match self.peek_token(true).map(|x| x.kind) {
            Some(TokenKind::OpenBrace) => {
                self.parse_enclosed(TokenKind::OpenBrace, TokenKind::CloseBrace, |parser| {
                    parser.parse_instruction()
                })?
            }
            _ => vec![self.parse_instruction()?],
        };

        let mut semantics = vec![];
        match self.peek_token(true).map(|x| x.kind) {
            None | Some(TokenKind::Semicolon) => {
                self.expect(TokenKind::Semicolon)?;
            }
            Some(TokenKind::OpenBrace) => {
                semantics =
                    self.parse_enclosed(TokenKind::OpenBrace, TokenKind::CloseBrace, |parser| {
                        let result = parser.parse_semantics()?;
                        parser.expect(TokenKind::Semicolon)?;
                        Ok(result)
                    })?;
            }
            _ => {
                semantics = vec![self.parse_semantics()?];
                self.expect(TokenKind::Semicolon)?;
            }
        }

        Ok(TestCase { load_addr, isa_mode, instructions, start_line, semantics, skip })
    }

    fn parse_instruction(&mut self) -> anyhow::Result<DecodeTest<'a>> {
        let bytes = self.parse_byte_array().context("parsing byte array")?;

        let expected_len = if self.peek_token(true).map(|x| x.kind) == Some(TokenKind::Equals) {
            self.expect(TokenKind::Equals)?;
            self.parse_num().context("parsing expected length")?
        }
        else {
            bytes.len()
        };

        let line = self.current_line();
        let disasm = {
            let string = self.expect(TokenKind::String)?;
            &self.input[string.start..=string.end]
        };

        Ok(DecodeTest { bytes, expected_len, disasm, line })
    }

    /// Parses a byte array (e.g. [ff 35 82 71 22 00])
    fn parse_byte_array(&mut self) -> anyhow::Result<Vec<u8>> {
        self.lexer.parse_hex = true;
        let result =
            self.parse_enclosed(TokenKind::OpenBracket, TokenKind::CloseBracket, |parser| {
                let token = parser.expect(TokenKind::HexNum)?;
                let value = trim_leading_zeros(parser.token_str(token));
                u8::from_str_radix(value, 16)
                    .map_err(|e| parser.error(&e.to_string(), token.start, token.end))
            });
        self.lexer.parse_hex = false;
        result
    }

    fn parse_semantics(&mut self) -> anyhow::Result<SemanticsTest<'a>> {
        let line = self.current_line();
        let mut inputs = vec![];
        if self.peek_token(true).map_or(true, |x| x.kind != TokenKind::RightArrow) {
            inputs = self.parse_separated(TokenKind::Comma, Self::parse_assignment)?;
        }
        self.expect(TokenKind::RightArrow)?;
        let outputs = self.parse_separated(TokenKind::Comma, Self::parse_assignment)?;
        Ok(SemanticsTest { inputs, outputs, line })
    }

    fn parse_assignment(&mut self) -> anyhow::Result<Assignment<'a>> {
        let token = self.expect_any(&[TokenKind::Ident, TokenKind::Mem])?;
        match token.kind {
            TokenKind::Ident => {
                self.expect(TokenKind::Equals)?;
                let value = self.parse_num()?;
                Ok(Assignment::Register { name: self.token_str(token), value })
            }
            TokenKind::Mem => {
                self.expect(TokenKind::OpenBracket)?;
                let addr = self.parse_num()?;
                self.expect(TokenKind::CloseBracket)?;

                let token = self.expect_any(&[TokenKind::Colon, TokenKind::Equals])?;
                let perm = match token.kind {
                    TokenKind::Colon => {
                        let ident = self.expect(TokenKind::Ident)?;
                        let perm = match self.token_str(ident) {
                            "NONE" => perm::NONE,
                            "READ" => perm::READ,
                            "WRITE" => perm::WRITE,
                            "READ_WRITE" => perm::READ | perm::WRITE,
                            "ALL" => perm::ALL,
                            unknown => {
                                return Err(self.error(
                                    &format!("Unexpected permission type: {}", unknown),
                                    ident.start,
                                    ident.end,
                                ));
                            }
                        };
                        self.expect(TokenKind::Equals)?;
                        perm
                    }
                    TokenKind::Equals => perm::NONE,
                    _ => unreachable!(),
                };

                let value = if self
                    .peek_token(true)
                    .map_or(false, |tok| tok.kind == TokenKind::OpenBracket)
                {
                    self.parse_byte_array()?
                }
                else {
                    let len = self.parse_num()?;
                    vec![0x0; len]
                };

                Ok(Assignment::Mem { addr, perm, value })
            }
            _ => unreachable!(),
        }
    }

    fn parse_num<T>(&mut self) -> anyhow::Result<T>
    where
        T: TryFrom<u128>,
    {
        let has_minus = self.peek_token(true).map_or(false, |tok| tok.kind == TokenKind::Minus);
        if has_minus {
            self.bump();
        }

        let token = self.expect_any(&[TokenKind::HexNum, TokenKind::Num])?;
        let value = self.token_str(token).replace("_", "");
        let result = match token.kind {
            TokenKind::HexNum => u128::from_str_radix(trim_leading_zeros(&value), 16),
            TokenKind::Num => value.parse(),
            _ => unreachable!(),
        };
        let value = result.map_err(|e| self.error(&e.to_string(), token.start, token.end))?;
        let signed_value = if has_minus { -(value as i128) as u128 } else { value };
        Ok(T::try_from(signed_value)
            .map_err(|_| self.error("value too large", token.start, token.end))?)
    }

    /// Get the current line number
    pub fn current_line(&self) -> usize {
        self.lines.len() + 1
    }

    /// Given the character offset compute the column and line offset
    fn compute_offset(&self, char_offset: usize) -> (usize, usize) {
        match self.lines.binary_search(&char_offset) {
            Err(0) => (1, char_offset + 1),
            Err(x) => (x + 1, char_offset - self.lines[x - 1]),
            Ok(x) => (x + 1, 1),
        }
    }

    /// Create a new error message spanning from `start` to `end`
    fn error(&self, msg: &str, start: usize, end: usize) -> anyhow::Error {
        let (line, col) = self.compute_offset(start);
        let (end_line, _) = self.compute_offset(end);
        if line == end_line {
            let line_str = &self.input.get(start..=end).unwrap_or("EOF");
            anyhow::format_err!("{line}:{col} \"{}\": {msg}", line_str.as_bytes().escape_ascii())
        }
        else {
            anyhow::format_err!("{line}:{col} {msg}")
        }
    }

    fn expect(&mut self, expected: TokenKind) -> anyhow::Result<Token> {
        self.expect_any(&[expected])
    }

    fn expect_any(&mut self, expected: &[TokenKind]) -> anyhow::Result<Token> {
        let token = self.peek_token(true).unwrap_or(Token {
            kind: TokenKind::Eof,
            start: self.lexer.prev + 1,
            end: self.lexer.prev + 1,
        });
        if !expected.contains(&token.kind) {
            let err = format!("unexpected token `{:?}` (expected: {:?})", token.kind, expected);
            return Err(self.error(&err, token.start, token.end));
        }
        self.bump();
        Ok(token)
    }

    fn bump(&mut self) {
        self.lexer.next();
    }

    fn peek_token(&mut self, skip_whitespace: bool) -> Option<Token> {
        loop {
            let next = self.lexer.peek()?;
            match next.kind {
                TokenKind::Comment | TokenKind::Whitespace => {}
                TokenKind::Line => self.lines.push(next.end),
                _ => return Some(next),
            }
            if !skip_whitespace {
                return Some(next);
            }
            self.bump();
        }
    }

    fn token_str(&self, token: Token) -> &'a str {
        &self.input[token.start..=token.end]
    }

    fn parse_enclosed<T>(
        &mut self,
        open: TokenKind,
        close: TokenKind,
        callback: impl FnMut(&mut Self) -> anyhow::Result<T>,
    ) -> anyhow::Result<Vec<T>> {
        self.parse_delimited(Some(open), Some(close), None, false, callback)
    }

    fn parse_separated<T>(
        &mut self,
        separator: TokenKind,
        callback: impl FnMut(&mut Self) -> anyhow::Result<T>,
    ) -> anyhow::Result<Vec<T>> {
        self.parse_delimited(None, None, Some(separator), false, callback)
    }

    /// `allow_trailing` must only be set if a `close` token exists
    fn parse_delimited<T>(
        &mut self,
        open: Option<TokenKind>,
        close: Option<TokenKind>,
        sep: Option<TokenKind>,
        allow_trailing: bool,
        mut callback: impl FnMut(&mut Self) -> anyhow::Result<T>,
    ) -> anyhow::Result<Vec<T>> {
        if let Some(open) = open {
            self.expect(open)?;
        }

        let mut result = vec![];
        loop {
            if let Some(close) = close {
                if self.peek_token(true).map(|x| x.kind) == Some(close) {
                    break;
                }
            }

            result.push(callback(self)?);

            if let Some(sep) = sep {
                if self.peek_token(true).map(|x| x.kind) != Some(sep) {
                    break;
                }

                if allow_trailing {
                    let token = self.expect_any(&[sep, close.unwrap()])?;
                    if token.kind == close.unwrap() {
                        break;
                    }
                }
                else {
                    self.expect(sep)?;
                }
            }
        }

        if let Some(close) = close {
            self.expect(close)?;
        }

        Ok(result)
    }
}
