//! A blocking HTTP/1.1 server: one listener, a fixed pool of worker threads,
//! one request per connection.
//!
//! Connection reuse is deliberately not supported. Every response says
//! `connection: close`, which removes a whole class of framing ambiguity for a
//! server whose clients are a CLI and a handful of machines.

use crate::{HttpError, Limits, Request, Response};
use std::io::{BufReader, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::Mutex;
use std::time::Duration;

/// How long a connection may take to deliver its request before it is dropped.
const READ_TIMEOUT: Duration = Duration::from_secs(30);

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

        let (sender, receiver): (Sender<TcpStream>, Receiver<TcpStream>) = channel();
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
                        if sender.send(stream).is_err() {
                            break;
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
    let _ = stream.set_read_timeout(Some(READ_TIMEOUT));
    let _ = stream.set_write_timeout(Some(READ_TIMEOUT));

    let mut writer = match stream.try_clone() {
        Ok(clone) => clone,
        Err(_) => return,
    };
    let mut reader = BufReader::new(stream);

    let response = match Request::read(&mut reader, limits) {
        Ok(request) => run_handler(handler, request),
        Err(HttpError::Incomplete) => return, // a probe that sent nothing
        Err(error) => Response::json(
            error.status(),
            &format!("{{\"error\":\"{}\"}}", escape(&error.to_string())),
        ),
    };

    let _ = response.write_to(&mut writer);
    let _ = writer.flush();
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
