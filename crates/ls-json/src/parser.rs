//! A strict recursive-descent JSON parser.
//!
//! Strict on purpose: request bodies are attacker controlled, so anything
//! ambiguous is rejected rather than guessed at. Duplicate object keys, trailing
//! commas, leading zeros, raw control characters in strings, lone surrogates and
//! trailing content are all errors, and recursion is bounded.

use crate::{JsonError, MAX_DEPTH, Value};

/// Parse a complete JSON document.
pub fn parse(input: &str) -> Result<Value, JsonError> {
    let mut parser = Parser {
        bytes: input.as_bytes(),
        position: 0,
        depth: 0,
    };

    parser.skip_whitespace();
    if parser.at_end() {
        return Err(JsonError::UnexpectedEnd);
    }

    let value = parser.value()?;

    parser.skip_whitespace();
    if !parser.at_end() {
        return Err(JsonError::TrailingContent);
    }

    Ok(value)
}

struct Parser<'a> {
    bytes: &'a [u8],
    position: usize,
    depth: usize,
}

impl<'a> Parser<'a> {
    fn at_end(&self) -> bool {
        self.position >= self.bytes.len()
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.position).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let byte = self.peek()?;
        self.position += 1;
        Some(byte)
    }

    fn expect(&mut self, byte: u8) -> Result<(), JsonError> {
        match self.bump() {
            Some(found) if found == byte => Ok(()),
            Some(_) => Err(JsonError::Unexpected(self.position - 1)),
            None => Err(JsonError::UnexpectedEnd),
        }
    }

    fn skip_whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.position += 1;
        }
    }

    fn literal(&mut self, word: &str, value: Value) -> Result<Value, JsonError> {
        if self.bytes[self.position..].starts_with(word.as_bytes()) {
            self.position += word.len();
            Ok(value)
        } else {
            Err(JsonError::Unexpected(self.position))
        }
    }

    fn value(&mut self) -> Result<Value, JsonError> {
        match self.peek().ok_or(JsonError::UnexpectedEnd)? {
            b'n' => self.literal("null", Value::Null),
            b't' => self.literal("true", Value::Bool(true)),
            b'f' => self.literal("false", Value::Bool(false)),
            b'"' => self.string().map(Value::String),
            b'[' => self.array(),
            b'{' => self.object(),
            b'-' | b'0'..=b'9' => self.number(),
            _ => Err(JsonError::Unexpected(self.position)),
        }
    }

    fn enter(&mut self) -> Result<(), JsonError> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err(JsonError::TooDeep);
        }
        Ok(())
    }

    fn array(&mut self) -> Result<Value, JsonError> {
        self.enter()?;
        self.expect(b'[')?;

        let mut items = Vec::new();
        self.skip_whitespace();
        if self.peek() == Some(b']') {
            self.position += 1;
            self.depth -= 1;
            return Ok(Value::Array(items));
        }

        loop {
            self.skip_whitespace();
            items.push(self.value()?);
            self.skip_whitespace();
            match self.bump() {
                Some(b',') => {}
                Some(b']') => break,
                Some(_) => return Err(JsonError::Unexpected(self.position - 1)),
                None => return Err(JsonError::UnexpectedEnd),
            }
        }

        self.depth -= 1;
        Ok(Value::Array(items))
    }

    fn object(&mut self) -> Result<Value, JsonError> {
        self.enter()?;
        self.expect(b'{')?;

        let mut fields: Vec<(String, Value)> = Vec::new();
        self.skip_whitespace();
        if self.peek() == Some(b'}') {
            self.position += 1;
            self.depth -= 1;
            return Ok(Value::Object(fields));
        }

        loop {
            self.skip_whitespace();
            if self.peek() != Some(b'"') {
                return Err(JsonError::Unexpected(self.position));
            }
            let name = self.string()?;
            if fields.iter().any(|(existing, _)| existing == &name) {
                return Err(JsonError::DuplicateKey(name));
            }

            self.skip_whitespace();
            self.expect(b':')?;
            self.skip_whitespace();
            let value = self.value()?;
            fields.push((name, value));

            self.skip_whitespace();
            match self.bump() {
                Some(b',') => {}
                Some(b'}') => break,
                Some(_) => return Err(JsonError::Unexpected(self.position - 1)),
                None => return Err(JsonError::UnexpectedEnd),
            }
        }

        self.depth -= 1;
        Ok(Value::Object(fields))
    }

    fn string(&mut self) -> Result<String, JsonError> {
        self.expect(b'"')?;
        let mut out = String::new();

        loop {
            let start = self.position;
            match self.bump().ok_or(JsonError::UnexpectedEnd)? {
                b'"' => return Ok(out),
                b'\\' => out.push(self.escape()?),
                // Raw control characters are not allowed inside a JSON string.
                byte if byte < 0x20 => return Err(JsonError::Unexpected(start)),
                byte if byte < 0x80 => out.push(byte as char),
                _ => {
                    // A multi-byte UTF-8 sequence. The input is a &str, so it is
                    // already valid UTF-8; find the end of this character.
                    let mut end = self.position;
                    while end < self.bytes.len() && (self.bytes[end] & 0xC0) == 0x80 {
                        end += 1;
                    }
                    let text = std::str::from_utf8(&self.bytes[start..end])
                        .map_err(|_| JsonError::Unexpected(start))?;
                    out.push_str(text);
                    self.position = end;
                }
            }
        }
    }

    fn escape(&mut self) -> Result<char, JsonError> {
        let start = self.position;
        match self.bump().ok_or(JsonError::UnexpectedEnd)? {
            b'"' => Ok('"'),
            b'\\' => Ok('\\'),
            b'/' => Ok('/'),
            b'b' => Ok('\u{8}'),
            b'f' => Ok('\u{c}'),
            b'n' => Ok('\n'),
            b'r' => Ok('\r'),
            b't' => Ok('\t'),
            b'u' => self.unicode_escape(),
            _ => Err(JsonError::Unexpected(start)),
        }
    }

    fn unicode_escape(&mut self) -> Result<char, JsonError> {
        let first = self.hex4()?;

        // Low surrogate without a preceding high one.
        if (0xDC00..=0xDFFF).contains(&first) {
            return Err(JsonError::Unexpected(self.position));
        }

        if (0xD800..=0xDBFF).contains(&first) {
            // High surrogate: a \uXXXX low surrogate must follow.
            let start = self.position;
            if self.bump() != Some(b'\\') || self.bump() != Some(b'u') {
                return Err(JsonError::Unexpected(start));
            }
            let second = self.hex4()?;
            if !(0xDC00..=0xDFFF).contains(&second) {
                return Err(JsonError::Unexpected(start));
            }
            let combined = 0x10000 + ((first - 0xD800) << 10) + (second - 0xDC00);
            return char::from_u32(combined).ok_or(JsonError::Unexpected(start));
        }

        char::from_u32(first).ok_or(JsonError::Unexpected(self.position))
    }

    fn hex4(&mut self) -> Result<u32, JsonError> {
        let start = self.position;
        let mut value: u32 = 0;
        for _ in 0..4 {
            let byte = self.bump().ok_or(JsonError::UnexpectedEnd)?;
            let digit = match byte {
                b'0'..=b'9' => u32::from(byte - b'0'),
                b'a'..=b'f' => u32::from(byte - b'a') + 10,
                b'A'..=b'F' => u32::from(byte - b'A') + 10,
                _ => return Err(JsonError::Unexpected(start)),
            };
            value = (value << 4) | digit;
        }
        Ok(value)
    }

    fn number(&mut self) -> Result<Value, JsonError> {
        let start = self.position;

        if self.peek() == Some(b'-') {
            self.position += 1;
        }

        // Integer part: a single zero, or a digit sequence not starting with zero.
        match self.peek() {
            Some(b'0') => self.position += 1,
            Some(b'1'..=b'9') => {
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.position += 1;
                }
            }
            _ => return Err(JsonError::Unexpected(self.position)),
        }

        let mut is_float = false;

        if self.peek() == Some(b'.') {
            self.position += 1;
            is_float = true;
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(JsonError::Unexpected(self.position));
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.position += 1;
            }
        }

        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.position += 1;
            is_float = true;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.position += 1;
            }
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(JsonError::Unexpected(self.position));
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.position += 1;
            }
        }

        let text = std::str::from_utf8(&self.bytes[start..self.position])
            .map_err(|_| JsonError::Unexpected(start))?;

        if is_float {
            text.parse::<f64>()
                .map(Value::Float)
                .map_err(|_| JsonError::Unexpected(start))
        } else {
            // An integer too large for i64 is kept as a float rather than
            // rejected, which matches what most JSON readers do.
            match text.parse::<i64>() {
                Ok(i) => Ok(Value::Int(i)),
                Err(_) => text
                    .parse::<f64>()
                    .map(Value::Float)
                    .map_err(|_| JsonError::Unexpected(start)),
            }
        }
    }
}
