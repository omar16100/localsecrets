//! `localsecretsd`, the localsecrets server.

use ls_http::{Limits, Server};
use ls_server::{Vault, handler};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

const USAGE: &str = "\
localsecretsd, the localsecrets server

Usage: localsecretsd [options]

Options:
  --data-dir <path>   Where to keep the store (default ~/.local/share/localsecrets)
  --listen <addr>     Address to bind (default 127.0.0.1:8787)
  --workers <n>       Worker threads (default 4)
  -h, --help          Show this message

The server binds to the loopback address. Serving it to a network means
putting a reverse proxy in front of it to terminate TLS: without that, tokens
and secret values travel in the clear.

Logging goes to standard error. Set LS_LOG to error, warn, info or debug.
";

struct Options {
    data_dir: PathBuf,
    listen: String,
    workers: usize,
}

fn main() -> std::process::ExitCode {
    ls_log::init_from_env();

    let options = match parse_arguments(std::env::args().skip(1)) {
        Ok(Some(options)) => options,
        Ok(None) => {
            println!("{USAGE}");
            return std::process::ExitCode::SUCCESS;
        }
        Err(message) => {
            eprintln!("localsecretsd: {message}\n\n{USAGE}");
            return std::process::ExitCode::FAILURE;
        }
    };

    match run(options) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(message) => {
            ls_log::error!("could not start", reason = message);
            eprintln!("localsecretsd: {message}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn run(options: Options) -> Result<(), String> {
    std::fs::create_dir_all(&options.data_dir)
        .map_err(|e| format!("could not create {}: {e}", options.data_dir.display()))?;
    restrict(&options.data_dir);

    let store = options.data_dir.join("store.log");
    let vault = Vault::open(&store).map_err(|e| format!("could not open the store: {e}"))?;
    let initialized = vault.is_initialized();

    let server = Server::bind(&options.listen, Limits::default())
        .map_err(|e| format!("could not bind {}: {e}", options.listen))?;
    let address = server
        .local_addr()
        .map_err(|e| format!("could not read the bound address: {e}"))?;

    ls_log::info!(
        "listening",
        address = address,
        store = store.display(),
        initialized = initialized
    );
    if !initialized {
        ls_log::warn!("the vault has not been initialised; run `lsec init`");
    } else {
        ls_log::info!("the vault is sealed; run `lsec unseal`");
    }

    // The handle is deliberately leaked: the pool serves until the process is
    // stopped, and there is no other work for this thread to do.
    std::mem::forget(server.spawn(options.workers, handler(Arc::new(Mutex::new(vault)))));

    loop {
        std::thread::park();
    }
}

/// Keep the data directory to its owner.
fn restrict(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700));
    }
    #[cfg(not(unix))]
    let _ = path;
}

fn parse_arguments<I: Iterator<Item = String>>(mut args: I) -> Result<Option<Options>, String> {
    let mut options = Options {
        data_dir: default_data_dir(),
        listen: "127.0.0.1:8787".to_owned(),
        workers: 4,
    };

    while let Some(argument) = args.next() {
        match argument.as_str() {
            "-h" | "--help" => return Ok(None),
            "--data-dir" => {
                options.data_dir = PathBuf::from(value(&mut args, "--data-dir")?);
            }
            "--listen" => options.listen = value(&mut args, "--listen")?,
            "--workers" => {
                options.workers = value(&mut args, "--workers")?
                    .parse()
                    .map_err(|_| "--workers needs a number".to_owned())?;
                if options.workers == 0 {
                    return Err("--workers must be at least 1".to_owned());
                }
            }
            other => return Err(format!("unknown option {other}")),
        }
    }

    Ok(Some(options))
}

fn value<I: Iterator<Item = String>>(args: &mut I, name: &str) -> Result<String, String> {
    args.next().ok_or_else(|| format!("{name} needs a value"))
}

fn default_data_dir() -> PathBuf {
    match std::env::var_os("HOME") {
        Some(home) => PathBuf::from(home).join(".local/share/localsecrets"),
        None => PathBuf::from("./localsecrets-data"),
    }
}
