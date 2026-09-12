//! A blocking HTTP/1.1 client, just enough for the CLI to talk to the server.

use crate::{HttpError, Limits};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(30);

/// A client pointed at one server address.
#[derive(Debug, Clone)]
pub struct Client {
    address: SocketAddr,
    limits: Limits,
}

/// A response received from a server.
pub struct ClientResponse {
    /// Status code.
    pub status: u16,
    /// Headers, lowercase names.
    pub headers: Vec<(String, String)>,
    /// The body.
    pub body: Vec<u8>,
}

impl ClientResponse {
    /// Look up a header, ignoring case.
    pub fn header(&self, name: &str) -> Option<&str> {
        let wanted = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(header, _)| *header == wanted)
            .map(|(_, value)| value.as_str())
    }

    /// The body as text, if it is valid UTF-8.
    pub fn body_text(&self) -> Option<&str> {
        std::str::from_utf8(&self.body).ok()
    }
}

impl std::fmt::Debug for ClientResponse {
    /// Never shows the body: for this client, the body is usually a secret.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientResponse")
            .field("status", &self.status)
            .field("body_len", &self.body.len())
            .finish()
    }
}

impl Client {
    /// Point a client at a server.
    pub fn new(address: SocketAddr) -> Self {
        Self {
            address,
            limits: Limits::default(),
        }
    }

    /// The address this client talks to.
    pub fn address(&self) -> SocketAddr {
        self.address
    }

    /// Send a GET.
    pub fn get(&self, path: &str, headers: &[(&str, &str)]) -> Result<ClientResponse, HttpError> {
        self.send("GET", path, headers, &[])
    }

    /// Send a POST.
    pub fn post(
        &self,
        path: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Result<ClientResponse, HttpError> {
        self.send("POST", path, headers, body)
    }

    /// Send a request and read the whole response.
    pub fn send(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Result<ClientResponse, HttpError> {
        let stream = TcpStream::connect(self.address)?;
        stream.set_read_timeout(Some(TIMEOUT))?;
        stream.set_write_timeout(Some(TIMEOUT))?;

        let mut head = String::with_capacity(128);
        head.push_str(method);
        head.push(' ');
        head.push_str(path);
        head.push_str(" HTTP/1.1\r\nhost: ");
        head.push_str(&self.address.to_string());
        head.push_str("\r\nconnection: close\r\n");
        for (name, value) in headers {
            if name.contains(['\r', '\n']) || value.contains(['\r', '\n']) {
                return Err(HttpError::Malformed("header contains a line break"));
            }
            head.push_str(name);
            head.push_str(": ");
            head.push_str(value);
            head.push_str("\r\n");
        }
        head.push_str("content-length: ");
        head.push_str(&body.len().to_string());
        head.push_str("\r\n\r\n");

        let mut writer = stream.try_clone()?;
        writer.write_all(head.as_bytes())?;
        writer.write_all(body)?;
        writer.flush()?;

        read_response(&mut BufReader::new(stream), &self.limits)
    }
}

fn read_response<R: BufRead>(
    reader: &mut R,
    limits: &Limits,
) -> Result<ClientResponse, HttpError> {
    let mut line = String::new();
    read_line(reader, &mut line, limits)?;

    let mut parts = line.trim_end().splitn(3, ' ');
    let version = parts.next().unwrap_or_default();
    if !version.starts_with("HTTP/1.") {
        return Err(HttpError::Malformed("status line"));
    }
    let status: u16 = parts
        .next()
        .ok_or(HttpError::Malformed("missing status code"))?
        .parse()
        .map_err(|_| HttpError::Malformed("status code"))?;

    let mut headers = Vec::new();
    let mut content_length = 0usize;
    loop {
        line.clear();
        read_line(reader, &mut line, limits)?;
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break;
        }
        if headers.len() == limits.max_headers {
            return Err(HttpError::TooManyHeaders);
        }
        let (name, value) = trimmed
            .split_once(':')
            .ok_or(HttpError::Malformed("response header"))?;
        let name = name.to_ascii_lowercase();
        let value = value.trim_matches([' ', '\t']).to_owned();
        if name == "content-length" {
            content_length = value
                .parse()
                .map_err(|_| HttpError::Malformed("response Content-Length"))?;
        }
        headers.push((name, value));
    }

    if content_length > limits.max_body {
        return Err(HttpError::BodyTooLarge {
            declared: content_length,
            limit: limits.max_body,
        });
    }

    let mut body = vec![0u8; content_length];
    reader
        .read_exact(&mut body)
        .map_err(|_| HttpError::IncompleteBody)?;

    Ok(ClientResponse {
        status,
        headers,
        body,
    })
}

fn read_line<R: BufRead>(
    reader: &mut R,
    out: &mut String,
    limits: &Limits,
) -> Result<(), HttpError> {
    let mut raw = Vec::new();
    let read = reader.take(limits.max_head as u64).read_until(b'\n', &mut raw)?;
    if read == 0 {
        return Err(HttpError::Incomplete);
    }
    out.clear();
    out.push_str(
        std::str::from_utf8(&raw).map_err(|_| HttpError::Malformed("response is not UTF-8"))?,
    );
    Ok(())
}
