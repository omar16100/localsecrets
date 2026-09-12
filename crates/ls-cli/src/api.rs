//! Talking to the server.

use ls_http::Client;
use ls_json::{Value, parse};
use std::net::ToSocketAddrs as _;

/// A thin wrapper over the HTTP client that speaks this API.
#[derive(Debug)]
pub struct Api {
    client: Client,
    token: Option<String>,
}

impl Api {
    /// Point at a server. `address` is `host:port`.
    pub fn connect(address: &str, token: Option<String>) -> Result<Self, String> {
        let resolved = address
            .to_socket_addrs()
            .map_err(|e| format!("could not resolve {address}: {e}"))?
            .next()
            .ok_or_else(|| format!("{address} resolved to nothing"))?;

        Ok(Self {
            client: Client::new(resolved),
            token,
        })
    }

    /// Whether a token is available for this call.
    pub fn has_token(&self) -> bool {
        self.token.is_some()
    }

    /// Send a request and parse the answer, turning an error status into an
    /// `Err` carrying the server's message.
    pub fn call(&self, method: &str, path: &str, body: Option<Value>) -> Result<Value, String> {
        let rendered = body.map(|value| value.to_string()).unwrap_or_default();

        let bearer = self.token.as_ref().map(|token| format!("Bearer {token}"));
        let mut headers: Vec<(&str, &str)> = Vec::new();

        // Sent on everything that changes state, empty body or not: the server
        // insists on it so that a page on another site cannot reach these
        // endpoints without a preflight it can never satisfy.
        if method != "GET" {
            headers.push(("content-type", "application/json"));
        }
        if let Some(bearer) = &bearer {
            headers.push(("authorization", bearer));
        }

        let response = self
            .client
            .send(method, path, &headers, rendered.as_bytes())
            .map_err(|e| {
                format!(
                    "could not reach the server at {}: {e}",
                    self.client.address()
                )
            })?;

        let text = response.body_text().unwrap_or("").trim();
        let value = if text.is_empty() {
            Value::Null
        } else {
            parse(text).map_err(|e| format!("the server sent something unreadable: {e}"))?
        };

        if (200..300).contains(&response.status) {
            return Ok(value);
        }

        let message = value
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("the server refused the request");
        Err(format!("{message} (status {})", response.status))
    }
}

/// Read a string field, or fail with a clear message.
pub fn field(value: &Value, name: &str) -> Result<String, String> {
    value
        .get(name)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| format!("the server did not send a {name}"))
}
