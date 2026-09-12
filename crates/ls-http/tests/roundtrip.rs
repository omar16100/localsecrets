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
    assert!(response.body_text().unwrap().contains("\"path\":\"/v1/sys/health\""));
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
    let (handle, client) = serve(|request| {
        Response::text(200, request.header("authorization").unwrap_or("none"))
    });

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
fn shutdown_stops_the_server() {
    let (handle, client) = serve(echo);
    assert_eq!(client.get("/", &[]).unwrap().status, 200);

    handle.shutdown();

    assert!(
        client.get("/", &[]).is_err(),
        "the server kept accepting connections after shutdown"
    );
}
