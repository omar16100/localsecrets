//! Reading and parsing an HTTP/1.1 request.

use crate::{HttpError, Limits};
use std::io::{BufRead, Read};
use std::time::Instant;

/// A parsed request.
pub struct Request {
    /// The method, uppercase as sent.
    pub method: String,
    /// The path, percent-decoded.
    pub path: String,
    /// Query parameters, percent-decoded, in the order sent.
    pub query: Vec<(String, String)>,
    /// Headers, in the order sent. Names are lowercased.
    pub headers: Vec<(String, String)>,
    /// The body, empty unless a `Content-Length` said otherwise.
    pub body: Vec<u8>,
}

impl Request {
    /// Read one request from `reader`, refusing anything outside `limits`.
    pub fn read<R: BufRead>(reader: &mut R, limits: &Limits) -> Result<Self, HttpError> {
        let started = Instant::now();
        let head = read_head(reader, limits, started)?;
        let mut lines = head.split(|&b| b == b'\n');

        let request_line = lines.next().ok_or(HttpError::Incomplete)?;
        let (method, target) = parse_request_line(strip_cr(request_line)?)?;

        let mut headers: Vec<(String, String)> = Vec::new();
        let mut content_length: Option<usize> = None;

        for raw in lines {
            let line = strip_cr(raw)?;
            if line.is_empty() {
                break;
            }
            if headers.len() == limits.max_headers {
                return Err(HttpError::TooManyHeaders);
            }

            let (name, value) = parse_header(line)?;

            if name == "transfer-encoding" {
                return Err(HttpError::UnsupportedTransferEncoding);
            }
            if name == "content-length" {
                if content_length.is_some() {
                    return Err(HttpError::AmbiguousLength);
                }
                content_length = Some(parse_content_length(&value)?);
            }

            headers.push((name, value));
        }

        let (path, query) = split_target(&target)?;

        let body = match content_length {
            None | Some(0) => Vec::new(),
            Some(declared) => {
                if declared > limits.max_body {
                    return Err(HttpError::BodyTooLarge {
                        declared,
                        limit: limits.max_body,
                    });
                }
                read_body(reader, declared, limits, started)?
            }
        };

        Ok(Self {
            method,
            path,
            query,
            headers,
            body,
        })
    }

    /// Look up a header, ignoring case.
    pub fn header(&self, name: &str) -> Option<&str> {
        let wanted = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(header, _)| *header == wanted)
            .map(|(_, value)| value.as_str())
    }

    /// Look up a query parameter.
    pub fn query(&self, name: &str) -> Option<&str> {
        self.query
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    /// The body as text, if it is valid UTF-8.
    pub fn body_text(&self) -> Option<&str> {
        std::str::from_utf8(&self.body).ok()
    }
}

impl std::fmt::Debug for Request {
    /// Shows enough to trace a request and nothing that could be a credential:
    /// no body, and header names without their values.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let header_names: Vec<&str> = self.headers.iter().map(|(name, _)| name.as_str()).collect();
        let query_names: Vec<&str> = self.query.iter().map(|(key, _)| key.as_str()).collect();

        f.debug_struct("Request")
            .field("method", &self.method)
            .field("path", &self.path)
            .field("query", &query_names)
            .field("headers", &header_names)
            .field("body_len", &self.body.len())
            .finish()
    }
}

/// Read the request line and headers, stopping at the blank line.
///
/// The reader is capped at `max_head` bytes, so an endless header line cannot
/// grow the buffer without bound.
fn read_head<R: BufRead>(
    reader: &mut R,
    limits: &Limits,
    started: Instant,
) -> Result<Vec<u8>, HttpError> {
    let mut limited = reader.take(limits.max_head as u64);
    let mut head = Vec::with_capacity(512);

    loop {
        if started.elapsed() > limits.head_deadline {
            return Err(HttpError::TimedOut);
        }
        let before = head.len();
        let read = limited.read_until(b'\n', &mut head)?;
        if read == 0 {
            return Err(if head.is_empty() {
                HttpError::Incomplete
            } else {
                HttpError::HeadTooLarge
            });
        }
        if head[head.len() - 1] != b'\n' {
            return Err(HttpError::HeadTooLarge);
        }
        if head[before..] == *b"\r\n" {
            return Ok(head);
        }
    }
}

/// Read exactly `declared` bytes, giving up if the whole request runs past its
/// deadline. Reading in chunks is what makes that check possible: `read_exact`
/// would block until the per-read timeout on every dribbled byte.
fn read_body<R: BufRead>(
    reader: &mut R,
    declared: usize,
    limits: &Limits,
    started: Instant,
) -> Result<Vec<u8>, HttpError> {
    let mut body = vec![0u8; declared];
    let mut filled = 0usize;

    while filled < declared {
        if started.elapsed() > limits.head_deadline {
            return Err(HttpError::TimedOut);
        }
        match reader.read(&mut body[filled..]) {
            Ok(0) => return Err(HttpError::IncompleteBody),
            Ok(read) => filled += read,
            Err(_) => return Err(HttpError::IncompleteBody),
        }
    }

    Ok(body)
}

/// Require CRLF line endings. A bare newline is two different requests to two
/// different parsers, which is exactly the ambiguity to avoid.
fn strip_cr(line: &[u8]) -> Result<&[u8], HttpError> {
    match line {
        [] => Ok(line),
        [head @ .., b'\r'] => Ok(head),
        _ => Err(HttpError::Malformed("line does not end with CRLF")),
    }
}

fn parse_request_line(line: &[u8]) -> Result<(String, String), HttpError> {
    let text = std::str::from_utf8(line).map_err(|_| HttpError::Malformed("request line"))?;
    let mut parts = text.split(' ');

    let method = parts.next().unwrap_or_default();
    let target = parts.next().ok_or(HttpError::Malformed("missing target"))?;
    let version = parts.next().ok_or(HttpError::Malformed("missing version"))?;
    if parts.next().is_some() {
        return Err(HttpError::Malformed("extra words in request line"));
    }

    if method.is_empty() || !method.bytes().all(is_token_byte) {
        return Err(HttpError::Malformed("method"));
    }
    if !target.starts_with('/') {
        // Only origin-form targets. Absolute-form and the asterisk form exist
        // for proxies, which this is not.
        return Err(HttpError::Malformed("target must be an absolute path"));
    }
    match version {
        "HTTP/1.1" | "HTTP/1.0" => {}
        other if other.starts_with("HTTP/") => {
            return Err(HttpError::UnsupportedVersion(other.to_owned()));
        }
        _ => return Err(HttpError::Malformed("version")),
    }

    Ok((method.to_owned(), target.to_owned()))
}

fn parse_header(line: &[u8]) -> Result<(String, String), HttpError> {
    if matches!(line.first(), Some(b' ' | b'\t')) {
        // Obsolete line folding: one header readable as two different values.
        return Err(HttpError::Malformed("folded header line"));
    }

    let text = std::str::from_utf8(line).map_err(|_| HttpError::Malformed("header encoding"))?;
    let colon = text.find(':').ok_or(HttpError::Malformed("header without a colon"))?;

    let name = &text[..colon];
    if name.is_empty() || !name.bytes().all(is_token_byte) {
        return Err(HttpError::Malformed("header name"));
    }

    let value = text[colon + 1..].trim_matches([' ', '\t']);
    if value.bytes().any(|b| b < 0x20 && b != b'\t') {
        return Err(HttpError::Malformed("control character in header value"));
    }

    Ok((name.to_ascii_lowercase(), value.to_owned()))
}

fn parse_content_length(value: &str) -> Result<usize, HttpError> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(HttpError::Malformed("Content-Length"));
    }
    value
        .parse()
        .map_err(|_| HttpError::Malformed("Content-Length"))
}

/// Split a target into its decoded path and decoded query parameters.
fn split_target(target: &str) -> Result<(String, Vec<(String, String)>), HttpError> {
    let (raw_path, raw_query) = match target.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (target, None),
    };

    let path = percent_decode(raw_path, false)?;

    let mut query = Vec::new();
    if let Some(raw) = raw_query {
        for pair in raw.split('&').filter(|p| !p.is_empty()) {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            query.push((percent_decode(key, true)?, percent_decode(value, true)?));
        }
    }

    Ok((path, query))
}

/// Decode percent escapes. In a query string, `+` means a space.
fn percent_decode(input: &str, plus_is_space: bool) -> Result<String, HttpError> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;

    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                let hex = bytes
                    .get(i + 1..i + 3)
                    .ok_or(HttpError::Malformed("truncated percent escape"))?;
                let high = hex_value(hex[0]).ok_or(HttpError::Malformed("percent escape"))?;
                let low = hex_value(hex[1]).ok_or(HttpError::Malformed("percent escape"))?;
                out.push((high << 4) | low);
                i += 3;
            }
            b'+' if plus_is_space => {
                out.push(b' ');
                i += 1;
            }
            byte => {
                out.push(byte);
                i += 1;
            }
        }
    }

    if out.contains(&0) {
        return Err(HttpError::Malformed("null byte in target"));
    }

    String::from_utf8(out).map_err(|_| HttpError::Malformed("target is not valid UTF-8"))
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// RFC 9110 token characters, the only ones allowed in a method or header name.
fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}
