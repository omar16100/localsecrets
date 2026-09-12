//! A blocking HTTP/1.1 server: one listener, a fixed pool of worker threads,
//! one request per connection.
//!
//! Connection reuse is deliberately not supported. Every response says
//! `connection: close`, which removes a whole class of framing ambiguity for a
//! server whose clients are a CLI and a handful of machines.

use crate::{HttpError, Limits, Request, Response};
use std::io::{BufReader, Read as _, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::time::Duration;

/// How long a response may take to go out before the connection is dropped.
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// How long a single read may block while clearing a refused request.
///
/// A refused client that has already sent everything and is waiting for the
/// answer closes as soon as it has read it, which ends the drain at once. This
/// only bounds the wait for one that does not, so it can afford to be generous
/// enough that a slow client's last segment still arrives in time.
const DRAIN_TIMEOUT: Duration = Duration::from_millis(500);

/// How long to spend clearing a refused request in total.
///
/// A per-read limit is not a limit: a byte every two hundred milliseconds
/// keeps every read inside its timeout, and the byte ceiling is far enough
/// away that the two together come to hours. This is the number that stops it.
const DRAIN_DEADLINE: Duration = Duration::from_secs(2);

/// Most bytes to clear off the socket before closing anyway.
const MAX_DRAIN: usize = 64 * 1024;

/// Connections allowed to wait for a worker. Beyond this the listener refuses,
/// which is a clearer answer than an unbounded queue that eventually exhausts
/// memory.
const QUEUE_DEPTH: usize = 128;

/// A bound listener, not yet serving.
#[derive(Debug)]
pub struct Server {
    listener: TcpListener,
    limits: Limits,
}

impl Server {
    /// Bind to an address. Use port 0 to let the operating system choose.
    pub fn bind<A: ToSocketAddrs>(address: A, limits: Limits) -> std::io::Result<Self> {
        Ok(Self {
            listener: TcpListener::bind(address)?,
            limits,
        })
    }

    /// The address actually bound, which is how a caller learns an ephemeral port.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Start accepting, handing each request to `handler` on a worker thread.
    pub fn spawn<H>(self, workers: usize, handler: H) -> ServerHandle
    where
        H: Fn(Request) -> Response + Send + Sync + 'static,
    {
        let address = self.listener.local_addr().ok();
        let running = Arc::new(AtomicBool::new(true));
        let handler = Arc::new(handler);
        let limits = self.limits;

        let (sender, receiver): (SyncSender<TcpStream>, Receiver<TcpStream>) =
            sync_channel(QUEUE_DEPTH);
        let receiver = Arc::new(Mutex::new(receiver));

        let mut threads = Vec::with_capacity(workers.max(1) + 1);
        for _ in 0..workers.max(1) {
            let receiver = Arc::clone(&receiver);
            let handler = Arc::clone(&handler);
            threads.push(std::thread::spawn(move || {
                loop {
                    // Hold the lock only long enough to take the next connection.
                    let next = match receiver.lock() {
                        Ok(guard) => guard.recv(),
                        Err(_) => return,
                    };
                    match next {
                        Ok(stream) => serve_connection(stream, &limits, handler.as_ref()),
                        Err(_) => return,
                    }
                }
            }));
        }

        let accepting = Arc::clone(&running);
        threads.push(std::thread::spawn(move || {
            for incoming in self.listener.incoming() {
                if !accepting.load(Ordering::SeqCst) {
                    break;
                }
                match incoming {
                    Ok(stream) => {
                        // Applied here rather than in the worker, so a
                        // connection cannot sit in the queue without one.
                        //
                        // The read timeout is the request deadline itself. The
                        // in-loop check only fires when bytes arrive, so a
                        // client that sends half a request and then goes quiet
                        // would otherwise hold a worker until the socket timed
                        // out, which is a much longer wait.
                        let _ = stream.set_read_timeout(Some(limits.head_deadline));
                        let _ = stream.set_write_timeout(Some(WRITE_TIMEOUT));

                        // A bounded queue: when every worker is busy and the
                        // backlog is full, refuse rather than accumulate.
                        if sender.try_send(stream).is_err() {
                            continue;
                        }
                    }
                    Err(_) => continue,
                }
            }
            drop(sender);
        }));

        ServerHandle {
            running,
            address,
            threads,
        }
    }
}

/// A running server. Dropping it does not stop the server; call
/// [`ServerHandle::shutdown`].
#[derive(Debug)]
pub struct ServerHandle {
    running: Arc<AtomicBool>,
    address: Option<SocketAddr>,
    threads: Vec<std::thread::JoinHandle<()>>,
}

impl ServerHandle {
    /// Stop accepting and wait for the workers to finish.
    pub fn shutdown(self) {
        self.running.store(false, Ordering::SeqCst);

        // The accept loop is blocked in `incoming()`. One connection to
        // ourselves wakes it so it can notice the flag and return.
        if let Some(address) = self.address
            && let Ok(stream) = TcpStream::connect(address)
        {
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }

        for thread in self.threads {
            let _ = thread.join();
        }
    }

    /// The address being served.
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.address
    }
}

fn serve_connection<H>(stream: TcpStream, limits: &Limits, handler: &H)
where
    H: Fn(Request) -> Response + Send + Sync,
{
    let mut writer = match stream.try_clone() {
        Ok(clone) => clone,
        Err(_) => return,
    };
    let mut reader = BufReader::new(stream);

    // A refused request may still have a body on the way, which has to be
    // cleared off the socket before closing. A served one has been read whole.
    let (response, refused) = match Request::read(&mut reader, limits) {
        Ok(request) => (run_handler(handler, request), false),
        Err(HttpError::Incomplete) => return, // a probe that sent nothing
        Err(error) => (
            Response::json(
                error.status(),
                &format!("{{\"error\":\"{}\"}}", escape(&error.to_string())),
            ),
            true,
        ),
    };

    let _ = response.write_to(&mut writer);
    let _ = writer.flush();

    if refused {
        // Send our end of the close first, so the client can finish reading the
        // answer and close in turn, which ends the drain below promptly.
        let _ = writer.shutdown(std::net::Shutdown::Write);
        drain(&mut reader);
    }
}

/// Read and throw away whatever the client is still sending.
///
/// A request refused before its body was read leaves those bytes unread on the
/// socket. Closing then makes the operating system reset the connection, which
/// discards the answer already written: the client sees the connection drop
/// rather than the 400 explaining what was wrong. Reading them first lets the
/// close be orderly.
///
/// Bounded in both bytes and time, so this cannot be turned into a way to make
/// the server read an unlimited amount from a caller it has already refused.
fn drain(reader: &mut BufReader<TcpStream>) {
    let _ = reader.get_ref().set_read_timeout(Some(DRAIN_TIMEOUT));

    let started = std::time::Instant::now();
    let mut sink = [0u8; 4096];
    let mut total = 0usize;

    while total < MAX_DRAIN && started.elapsed() < DRAIN_DEADLINE {
        match reader.read(&mut sink) {
            Ok(0) | Err(_) => break,
            Ok(read) => total += read,
        }
    }
}

/// Run the handler, turning a panic into a 500 rather than a dead worker.
fn run_handler<H>(handler: &H, request: Request) -> Response
where
    H: Fn(Request) -> Response + Send + Sync,
{
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handler(request)));
    outcome.unwrap_or_else(|_| Response::json(500, "{\"error\":\"internal error\"}"))
}

/// Minimal JSON string escaping, enough for an error message this crate wrote.
fn escape(text: &str) -> String {
    text.chars()
        .filter(|c| *c != '"' && *c != '\\' && (*c as u32) >= 0x20)
        .collect()
}
