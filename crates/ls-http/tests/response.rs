#![allow(clippy::unwrap_used, clippy::expect_used)]

use ls_http::Response;

fn rendered(response: &Response) -> String {
    let mut out = Vec::new();
    response.write_to(&mut out).unwrap();
    String::from_utf8(out).unwrap()
}

#[test]
fn writes_a_status_line_with_a_reason_phrase() {
    assert!(rendered(&Response::text(200, "ok")).starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(rendered(&Response::text(201, "")).starts_with("HTTP/1.1 201 Created\r\n"));
    assert!(rendered(&Response::text(400, "")).starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(rendered(&Response::text(401, "")).starts_with("HTTP/1.1 401 Unauthorized\r\n"));
    assert!(rendered(&Response::text(403, "")).starts_with("HTTP/1.1 403 Forbidden\r\n"));
    assert!(rendered(&Response::text(404, "")).starts_with("HTTP/1.1 404 Not Found\r\n"));
    assert!(rendered(&Response::text(503, "")).starts_with("HTTP/1.1 503 Service Unavailable\r\n"));
}

#[test]
fn an_unknown_status_still_produces_a_valid_status_line() {
    assert!(rendered(&Response::text(599, "")).starts_with("HTTP/1.1 599 "));
}

#[test]
fn always_declares_the_body_length() {
    let out = rendered(&Response::text(200, "hello"));
    assert!(out.contains("content-length: 5\r\n"), "got {out}");

    let empty = rendered(&Response::text(204, ""));
    assert!(empty.contains("content-length: 0\r\n"), "got {empty}");
}

#[test]
fn declares_the_length_in_bytes_not_characters() {
    let out = rendered(&Response::text(200, "日本"));
    assert!(out.contains("content-length: 6\r\n"), "got {out}");
}

#[test]
fn json_responses_carry_a_json_content_type() {
    let out = rendered(&Response::json(200, "{\"a\":1}"));
    assert!(out.contains("content-type: application/json\r\n"), "got {out}");
    assert!(out.ends_with("\r\n\r\n{\"a\":1}"), "got {out}");
}

#[test]
fn the_head_is_separated_from_the_body_by_a_blank_line() {
    let out = rendered(&Response::text(200, "body"));
    let (head, body) = out.split_once("\r\n\r\n").expect("blank line");

    assert!(head.contains("content-length: 4"));
    assert_eq!(body, "body");
}

#[test]
fn extra_headers_are_written() {
    let response = Response::text(200, "x").header("x-request-id", "abc123");
    assert!(rendered(&response).contains("x-request-id: abc123\r\n"));
}

#[test]
fn a_header_value_cannot_inject_another_header() {
    // If this were written through, anyone able to influence a header value
    // could add a Set-Cookie or a second body.
    let response = Response::text(200, "x").header("x-thing", "a\r\nX-Injected: yes");
    let out = rendered(&response);

    assert!(!out.contains("X-Injected"), "header injection succeeded: {out}");
    assert!(!out.contains("x-injected"), "header injection succeeded: {out}");
}

#[test]
fn a_header_name_cannot_inject_another_header() {
    let response = Response::text(200, "x").header("x-thing\r\nX-Injected", "yes");
    let out = rendered(&response);

    assert!(!out.contains("X-Injected"), "header injection succeeded: {out}");
}

#[test]
fn a_body_is_never_truncated_at_a_null_byte() {
    let response = Response::new(200, vec![b'a', 0, b'b']);
    let mut out = Vec::new();
    response.write_to(&mut out).unwrap();

    assert!(out.ends_with(&[b'a', 0, b'b']));
}

#[test]
fn debug_output_does_not_include_the_body() {
    let response = Response::json(200, "{\"value\":\"secret-value-here\"}");
    let shown = format!("{response:?}");

    assert!(
        !shown.contains("secret-value-here"),
        "response body leaked via Debug: {shown}"
    );
}
