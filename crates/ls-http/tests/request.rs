#![allow(clippy::unwrap_used, clippy::expect_used)]

use ls_http::{HttpError, Limits, Request};
use std::io::Cursor;

fn read(raw: &str) -> Result<Request, HttpError> {
    Request::read(&mut Cursor::new(raw.as_bytes().to_vec()), &Limits::default())
}

const GET: &str = "GET /v1/sys/health HTTP/1.1\r\nHost: localhost\r\n\r\n";

#[test]
fn reads_a_simple_request() {
    let request = read(GET).unwrap();

    assert_eq!(request.method, "GET");
    assert_eq!(request.path, "/v1/sys/health");
    assert!(request.body.is_empty());
    assert_eq!(request.header("host"), Some("localhost"));
}

#[test]
fn header_lookup_ignores_case() {
    let request = read("GET / HTTP/1.1\r\nHost: h\r\nContent-Type: application/json\r\n\r\n").unwrap();

    assert_eq!(request.header("content-type"), Some("application/json"));
    assert_eq!(request.header("CONTENT-TYPE"), Some("application/json"));
    assert_eq!(request.header("Content-Type"), Some("application/json"));
}

#[test]
fn reads_a_body_of_the_declared_length() {
    let request = read(
        "POST /v1/auth/login HTTP/1.1\r\nHost: h\r\nContent-Length: 9\r\n\r\n{\"a\": 1}\n",
    )
    .unwrap();

    assert_eq!(request.body, b"{\"a\": 1}\n");
}

#[test]
fn a_body_shorter_than_its_declared_length_is_an_error() {
    let result = read("POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 100\r\n\r\nshort");
    assert!(matches!(result, Err(HttpError::IncompleteBody)));
}

#[test]
fn a_request_without_content_length_has_no_body() {
    let request = read("POST / HTTP/1.1\r\nHost: h\r\n\r\nignored").unwrap();
    assert!(request.body.is_empty());
}

#[test]
fn splits_the_query_string_off_the_path() {
    let request = read("GET /v1/secrets?env=dev&format=dotenv HTTP/1.1\r\nHost: h\r\n\r\n").unwrap();

    assert_eq!(request.path, "/v1/secrets");
    assert_eq!(request.query("env"), Some("dev"));
    assert_eq!(request.query("format"), Some("dotenv"));
    assert_eq!(request.query("missing"), None);
}

#[test]
fn decodes_percent_escapes_in_the_path() {
    let request = read("GET /v1/secrets/DB%5FURL HTTP/1.1\r\nHost: h\r\n\r\n").unwrap();
    assert_eq!(request.path, "/v1/secrets/DB_URL");
}

#[test]
fn decodes_percent_escapes_and_plus_in_the_query() {
    let request = read("GET /x?q=a%20b+c HTTP/1.1\r\nHost: h\r\n\r\n").unwrap();
    assert_eq!(request.query("q"), Some("a b c"));
}

#[test]
fn rejects_a_malformed_percent_escape() {
    assert!(read("GET /v1/%ZZ HTTP/1.1\r\nHost: h\r\n\r\n").is_err());
    assert!(read("GET /v1/%4 HTTP/1.1\r\nHost: h\r\n\r\n").is_err());
    assert!(read("GET /v1/% HTTP/1.1\r\nHost: h\r\n\r\n").is_err());
}

#[test]
fn rejects_a_percent_escape_that_decodes_to_invalid_utf8() {
    assert!(read("GET /v1/%FF%FE HTTP/1.1\r\nHost: h\r\n\r\n").is_err());
}

#[test]
fn rejects_a_null_byte_in_the_path() {
    assert!(read("GET /v1/%00 HTTP/1.1\r\nHost: h\r\n\r\n").is_err());
}

#[test]
fn rejects_a_target_that_is_not_an_absolute_path() {
    assert!(read("GET v1/health HTTP/1.1\r\nHost: h\r\n\r\n").is_err());
    assert!(read("GET http://elsewhere/x HTTP/1.1\r\nHost: h\r\n\r\n").is_err());
    assert!(read("GET * HTTP/1.1\r\nHost: h\r\n\r\n").is_err());
}

#[test]
fn rejects_two_content_length_headers() {
    // Disagreeing lengths are the classic request smuggling primitive.
    let result = read("POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\nContent-Length: 7\r\n\r\nhello");
    assert!(matches!(result, Err(HttpError::AmbiguousLength)));
}

#[test]
fn rejects_transfer_encoding() {
    // Chunked bodies are not supported, and accepting the header while
    // ignoring it is how smuggling happens.
    let result = read("POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n");
    assert!(matches!(result, Err(HttpError::UnsupportedTransferEncoding)));
}

#[test]
fn rejects_a_non_numeric_content_length() {
    assert!(read("POST / HTTP/1.1\r\nHost: h\r\nContent-Length: abc\r\n\r\n").is_err());
    assert!(read("POST / HTTP/1.1\r\nHost: h\r\nContent-Length: -1\r\n\r\n").is_err());
    assert!(read("POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 1 1\r\n\r\n").is_err());
}

#[test]
fn rejects_a_body_over_the_limit_without_reading_it() {
    let limits = Limits {
        max_body: 16,
        ..Limits::default()
    };
    let raw = format!(
        "POST / HTTP/1.1\r\nHost: h\r\nContent-Length: {}\r\n\r\n",
        limits.max_body + 1
    );

    let result = Request::read(&mut Cursor::new(raw.into_bytes()), &limits);

    assert!(matches!(result, Err(HttpError::BodyTooLarge { .. })));
}

#[test]
fn rejects_a_head_over_the_limit() {
    let padding = "X-Pad: ".to_owned() + &"a".repeat(20_000) + "\r\n";
    let raw = format!("GET / HTTP/1.1\r\nHost: h\r\n{padding}\r\n");

    assert!(matches!(
        Request::read(&mut Cursor::new(raw.into_bytes()), &Limits::default()),
        Err(HttpError::HeadTooLarge)
    ));
}

#[test]
fn rejects_too_many_headers() {
    let limits = Limits::default();
    let headers: String = (0..limits.max_headers + 1)
        .map(|i| format!("X-{i}: v\r\n"))
        .collect();
    let raw = format!("GET / HTTP/1.1\r\n{headers}\r\n");

    assert!(matches!(
        Request::read(&mut Cursor::new(raw.into_bytes()), &limits),
        Err(HttpError::TooManyHeaders)
    ));
}

#[test]
fn rejects_a_malformed_request_line() {
    assert!(read("GET\r\n\r\n").is_err());
    assert!(read("GET /\r\n\r\n").is_err());
    assert!(read("GET / HTTP/1.1 extra\r\n\r\n").is_err());
    assert!(read("").is_err());
    assert!(read("\r\n").is_err());
}

#[test]
fn rejects_an_unsupported_http_version() {
    assert!(matches!(
        read("GET / HTTP/2.0\r\nHost: h\r\n\r\n"),
        Err(HttpError::UnsupportedVersion(_))
    ));
    assert!(read("GET / HTTP/0.9\r\nHost: h\r\n\r\n").is_err());
    assert!(read("GET / NOTHTTP/1.1\r\nHost: h\r\n\r\n").is_err());
}

#[test]
fn rejects_a_method_containing_separators() {
    assert!(read("GE T / HTTP/1.1\r\nHost: h\r\n\r\n").is_err());
    assert!(read("G\u{1}T / HTTP/1.1\r\nHost: h\r\n\r\n").is_err());
}

#[test]
fn rejects_a_malformed_header_line() {
    assert!(read("GET / HTTP/1.1\r\nNoColon\r\n\r\n").is_err());
    assert!(read("GET / HTTP/1.1\r\n: empty name\r\n\r\n").is_err());
    assert!(read("GET / HTTP/1.1\r\nBad Name: v\r\n\r\n").is_err());
}

#[test]
fn rejects_an_obsolete_folded_header() {
    // Line folding lets one header be read as two different values.
    assert!(read("GET / HTTP/1.1\r\nHost: h\r\n  folded\r\n\r\n").is_err());
}

#[test]
fn strips_optional_whitespace_around_header_values() {
    let request = read("GET / HTTP/1.1\r\nHost:   spaced   \r\n\r\n").unwrap();
    assert_eq!(request.header("host"), Some("spaced"));
}

#[test]
fn accepts_a_header_with_an_empty_value() {
    let request = read("GET / HTTP/1.1\r\nHost: h\r\nX-Empty:\r\n\r\n").unwrap();
    assert_eq!(request.header("x-empty"), Some(""));
}

#[test]
fn debug_output_of_a_request_does_not_include_the_body() {
    let request = read("POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 17\r\n\r\nsecret-value-here").unwrap();
    let rendered = format!("{request:?}");

    assert!(
        !rendered.contains("secret-value-here"),
        "request body leaked via Debug: {rendered}"
    );
}

#[test]
fn debug_output_of_a_request_does_not_include_the_authorization_header() {
    let request = read("GET / HTTP/1.1\r\nHost: h\r\nAuthorization: Bearer lsec_secret\r\n\r\n").unwrap();
    let rendered = format!("{request:?}");

    assert!(
        !rendered.contains("lsec_secret"),
        "token leaked via Debug: {rendered}"
    );
}
