#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use ls_http::{Client, Limits, Response, Server};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Start a server on an ephemeral port with the given handler.
fn serve(
    handler: impl Fn(ls_http::Request) -> Response + Send + Sync + 'static,
) -> (ls_http::ServerHandle, Client) {
    serve_with(Limits::default(), handler)
}

fn serve_with(
    limits: Limits,
    handler: impl Fn(ls_http::Request) -> Response + Send + Sync + 'static,
) -> (ls_http::ServerHandle, Client) {
    let server = Server::bind("127.0.0.1:0", limits).unwrap();
    let address = server.local_addr().unwrap();
    let handle = server.spawn(2, handler);
    (handle, Client::new(address))
}

fn echo(request: ls_http::Request) -> Response {
    Response::json(
        200,
        &format!(
            "{{\"method\":\"{}\",\"path\":\"{}\",\"body\":\"{}\"}}",
            request.method,
            request.path,
            request.body_text().unwrap_or("")
        ),
    )
}

#[test]
fn a_request_reaches_the_handler_and_the_answer_comes_back() {
    let (handle, client) = serve(echo);

    let response = client.get("/v1/sys/health", &[]).unwrap();

    assert_eq!(response.status, 200);
    assert!(
        response
            .body_text()
            .unwrap()
            .contains("\"path\":\"/v1/sys/health\"")
    );
    handle.shutdown();
}

#[test]
fn a_post_body_arrives_intact() {
    let (handle, client) = serve(echo);

    let response = client
        .post("/v1/secrets", &[], b"{\"key\":\"DB_URL\"}")
        .unwrap();

    assert_eq!(response.status, 200);
    assert!(response.body_text().unwrap().contains("DB_URL"));
    handle.shutdown();
}

#[test]
fn request_headers_reach_the_handler() {
    let (handle, client) =
        serve(|request| Response::text(200, request.header("authorization").unwrap_or("none")));

    let response = client
        .get("/", &[("authorization", "Bearer lsec_token")])
        .unwrap();

    assert_eq!(response.body_text().unwrap(), "Bearer lsec_token");
    handle.shutdown();
}

#[test]
fn response_headers_reach_the_client() {
    let (handle, client) = serve(|_| Response::text(200, "x").header("x-request-id", "r-1"));

    let response = client.get("/", &[]).unwrap();

    assert_eq!(response.header("x-request-id"), Some("r-1"));
    handle.shutdown();
}

#[test]
fn the_handlers_status_code_is_preserved() {
    let (handle, client) = serve(|_| Response::json(404, "{\"error\":\"not found\"}"));

    let response = client.get("/nope", &[]).unwrap();

    assert_eq!(response.status, 404);
    assert_eq!(response.body_text().unwrap(), "{\"error\":\"not found\"}");
    handle.shutdown();
}

#[test]
fn a_body_over_the_limit_is_refused_without_reaching_the_handler() {
    let reached = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&reached);
    let limits = Limits {
        max_body: 16,
        ..Limits::default()
    };

    let (handle, client) = serve_with(limits, move |_| {
        counter.fetch_add(1, Ordering::SeqCst);
        Response::text(200, "should not happen")
    });

    let response = client.post("/", &[], &[b'x'; 64]).unwrap();

    assert_eq!(response.status, 413);
    assert_eq!(reached.load(Ordering::SeqCst), 0, "handler was reached");
    handle.shutdown();
}

#[test]
fn a_malformed_request_gets_a_bad_request_answer() {
    use std::io::{Read, Write};
    let (handle, client) = serve(echo);

    let mut socket = std::net::TcpStream::connect(client.address()).unwrap();
    socket.write_all(b"NOT-A-REQUEST\r\n\r\n").unwrap();
    let mut answer = String::new();
    socket.read_to_string(&mut answer).unwrap();

    assert!(answer.starts_with("HTTP/1.1 400 "), "got {answer}");
    handle.shutdown();
}

#[test]
fn a_refusal_always_reaches_a_client_that_sent_a_body() {
    // The server refuses this before reading the body. Closing with those bytes
    // still unread makes the operating system reset the connection, which
    // throws away the answer already written. The race is timing dependent, so
    // this runs enough times to catch it.
    let (handle, client) = serve(echo);

    for attempt in 0..200 {
        let result = client.send(
            "PUT",
            "/has a space",
            &[("content-type", "application/json")],
            br#"{"value":"do-not-lose-the-answer"}"#,
        );

        match result {
            Ok(response) => assert_eq!(response.status, 400),
            Err(e) => panic!("attempt {attempt} lost the answer: {e:?}"),
        }
    }

    handle.shutdown();
}

#[test]
fn a_refusal_reaches_a_client_whose_body_arrives_late() {
    // The head and the body arrive in separate segments, so the server decides
    // to refuse before the body is on the socket. If it then closes with those
    // bytes unread, the connection is reset and the answer it already wrote is
    // thrown away. This is the timing that makes such a bug intermittent.
    use std::io::{Read, Write};
    let (handle, client) = serve(echo);

    let body = br#"{"value":"do-not-lose-the-answer"}"#;
    let mut socket = std::net::TcpStream::connect(client.address()).unwrap();
    socket
        .write_all(
            format!(
                "PUT /has a space HTTP/1.1\r\nhost: h\r\ncontent-length: {}\r\n\r\n",
                body.len()
            )
            .as_bytes(),
        )
        .unwrap();
    socket.flush().unwrap();

    std::thread::sleep(std::time::Duration::from_millis(150));
    let _ = socket.write_all(body);
    let _ = socket.flush();

    let mut answer = String::new();
    socket.read_to_string(&mut answer).unwrap();

    assert!(
        answer.starts_with("HTTP/1.1 400 "),
        "the client never received the refusal: {answer:?}"
    );
    handle.shutdown();
}

#[test]
fn a_refused_request_that_carried_a_body_still_gets_its_answer() {
    // The server rejects this before reading the body. If it closes with that
    // body still unread, the connection is reset and the client loses the
    // response it was already sent.
    use std::io::{Read, Write};
    let (handle, client) = serve(echo);

    let mut socket = std::net::TcpStream::connect(client.address()).unwrap();
    socket
        .write_all(
            b"PUT /has a space HTTP/1.1\r\nHost: h\r\nContent-Length: 24\r\n\r\n              {\"value\":\"some value\"}",
        )
        .unwrap();
    socket.flush().unwrap();

    let mut answer = String::new();
    socket.read_to_string(&mut answer).unwrap();

    assert!(
        answer.starts_with("HTTP/1.1 400 "),
        "the client never received the refusal: {answer:?}"
    );
    handle.shutdown();
}

#[test]
fn a_body_over_the_limit_still_gets_its_answer() {
    use std::io::{Read, Write};
    let limits = Limits {
        max_body: 16,
        ..Limits::default()
    };
    let (handle, client) = serve_with(limits, echo);

    let mut socket = std::net::TcpStream::connect(client.address()).unwrap();
    let body = vec![b'x'; 4096];
    socket
        .write_all(
            format!(
                "POST / HTTP/1.1\r\nHost: h\r\nContent-Length: {}\r\n\r\n",
                body.len()
            )
            .as_bytes(),
        )
        .unwrap();
    let _ = socket.write_all(&body);
    let _ = socket.flush();

    let mut answer = String::new();
    socket.read_to_string(&mut answer).unwrap();

    assert!(
        answer.starts_with("HTTP/1.1 413 "),
        "the client never received the refusal: {answer:?}"
    );
    handle.shutdown();
}

#[test]
fn several_clients_are_served_concurrently() {
    let served = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&served);
    let (handle, client) = serve(move |_| {
        counter.fetch_add(1, Ordering::SeqCst);
        Response::text(200, "ok")
    });

    let client = Arc::new(client);
    let workers: Vec<_> = (0..8)
        .map(|i| {
            let client = Arc::clone(&client);
            std::thread::spawn(move || {
                let response = client.get(&format!("/{i}"), &[]).unwrap();
                assert_eq!(response.status, 200);
            })
        })
        .collect();

    for worker in workers {
        worker.join().unwrap();
    }

    assert_eq!(served.load(Ordering::SeqCst), 8);
    handle.shutdown();
}

#[test]
fn a_handler_that_panics_does_not_take_the_server_down() {
    let (handle, client) = serve(|request| {
        if request.path == "/boom" {
            panic!("handler exploded");
        }
        Response::text(200, "fine")
    });

    // Dropping the connection is also an acceptable answer to a panic.
    if let Ok(response) = client.get("/boom", &[]) {
        assert_eq!(
            response.status, 500,
            "a panicking handler should answer 500, not succeed"
        );
    }

    let after = client.get("/ok", &[]).unwrap();
    assert_eq!(after.status, 200, "server stopped serving after a panic");
    handle.shutdown();
}

#[test]
fn a_client_that_dribbles_its_head_is_cut_off() {
    // Without a deadline on the whole head, a client sending one byte just
    // inside the per-read timeout holds a worker forever. Four of those and
    // the server serves nobody.
    use std::io::{Read, Write};
    let limits = Limits {
        head_deadline: std::time::Duration::from_millis(200),
        ..Limits::default()
    };
    let (handle, client) = serve_with(limits, echo);

    let mut socket = std::net::TcpStream::connect(client.address()).unwrap();
    socket.write_all(b"GET / HTTP/1.1\r\n").unwrap();
    socket.flush().unwrap();

    let started = std::time::Instant::now();
    for _ in 0..20 {
        std::thread::sleep(std::time::Duration::from_millis(50));
        if socket.write_all(b"x: y\r\n").is_err() || socket.flush().is_err() {
            break;
        }
    }

    let mut answer = String::new();
    let _ = socket.read_to_string(&mut answer);

    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "the server held the connection for {:?}",
        started.elapsed()
    );
    assert!(
        answer.is_empty() || answer.starts_with("HTTP/1.1 408 "),
        "expected a timeout, got {answer:?}"
    );
    handle.shutdown();
}

#[test]
fn a_client_that_dribbles_its_body_is_cut_off() {
    use std::io::{Read, Write};
    let limits = Limits {
        head_deadline: std::time::Duration::from_millis(200),
        ..Limits::default()
    };
    let (handle, client) = serve_with(limits, echo);

    let mut socket = std::net::TcpStream::connect(client.address()).unwrap();
    socket
        .write_all(b"POST / HTTP/1.1\r\nhost: h\r\ncontent-length: 500\r\n\r\n")
        .unwrap();
    socket.flush().unwrap();

    let started = std::time::Instant::now();
    for _ in 0..20 {
        std::thread::sleep(std::time::Duration::from_millis(50));
        if socket.write_all(b"x").is_err() || socket.flush().is_err() {
            break;
        }
    }

    let mut answer = String::new();
    let _ = socket.read_to_string(&mut answer);

    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "the server held the connection for {:?}",
        started.elapsed()
    );
    assert!(
        answer.is_empty() || answer.starts_with("HTTP/1.1 408 "),
        "expected a timeout, got {answer:?}"
    );
    handle.shutdown();
}

#[test]
fn a_prompt_request_is_not_cut_off_by_the_deadline() {
    let limits = Limits {
        head_deadline: std::time::Duration::from_millis(200),
        ..Limits::default()
    };
    let (handle, client) = serve_with(limits, echo);

    for _ in 0..5 {
        assert_eq!(client.get("/fine", &[]).unwrap().status, 200);
    }

    handle.shutdown();
}

#[test]
fn shutdown_stops_the_server() {
    let (handle, client) = serve(echo);
    assert_eq!(client.get("/", &[]).unwrap().status, 200);

    handle.shutdown();

    assert!(
        client.get("/", &[]).is_err(),
        "the server kept accepting connections after shutdown"
    );
}
