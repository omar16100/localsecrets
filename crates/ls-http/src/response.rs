//! Building and writing an HTTP/1.1 response.

use std::io::Write;

/// A response ready to be written to a connection.
pub struct Response {
    /// Status code.
    pub status: u16,
    /// Headers, lowercase names, in the order added.
    pub headers: Vec<(String, String)>,
    /// The body.
    pub body: Vec<u8>,
}

impl Response {
    /// A response with a raw body and no content type.
    pub fn new(status: u16, body: Vec<u8>) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body,
        }
    }

    /// A `text/plain` response.
    pub fn text(status: u16, body: &str) -> Self {
        Self::new(status, body.as_bytes().to_vec())
            .header("content-type", "text/plain; charset=utf-8")
    }

    /// An `application/json` response.
    pub fn json(status: u16, body: &str) -> Self {
        Self::new(status, body.as_bytes().to_vec()).header("content-type", "application/json")
    }

    /// Add a header.
    ///
    /// A name or value containing a carriage return or newline is dropped
    /// rather than written. Writing it through would let anything that reaches
    /// a header value add headers of its own, or a second body.
    #[must_use]
    pub fn header(mut self, name: &str, value: &str) -> Self {
        if is_safe_field(name) && is_safe_field(value) && !name.is_empty() {
            self.headers
                .push((name.to_ascii_lowercase(), value.to_owned()));
        }
        self
    }

    /// Write the whole response.
    pub fn write_to<W: Write>(&self, out: &mut W) -> std::io::Result<()> {
        let mut head = String::with_capacity(128);
        head.push_str("HTTP/1.1 ");
        head.push_str(&self.status.to_string());
        head.push(' ');
        head.push_str(reason(self.status));
        head.push_str("\r\n");

        for (name, value) in &self.headers {
            head.push_str(name);
            head.push_str(": ");
            head.push_str(value);
            head.push_str("\r\n");
        }

        head.push_str("content-length: ");
        head.push_str(&self.body.len().to_string());
        head.push_str("\r\nconnection: close\r\n\r\n");

        out.write_all(head.as_bytes())?;
        out.write_all(&self.body)?;
        out.flush()
    }
}

impl std::fmt::Debug for Response {
    /// Shows the shape of the response, never its body: a body is usually the
    /// secret the caller asked for.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let header_names: Vec<&str> = self.headers.iter().map(|(name, _)| name.as_str()).collect();

        f.debug_struct("Response")
            .field("status", &self.status)
            .field("headers", &header_names)
            .field("body_len", &self.body.len())
            .finish()
    }
}

fn is_safe_field(text: &str) -> bool {
    !text.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0)
}

/// Reason phrases for the statuses this project uses. Anything else gets a
/// generic phrase, which is still a valid status line.
fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        413 => "Content Too Large",
        415 => "Unsupported Media Type",
        421 => "Misdirected Request",
        422 => "Unprocessable Content",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        503 => "Service Unavailable",
        505 => "HTTP Version Not Supported",
        _ => "Status",
    }
}
