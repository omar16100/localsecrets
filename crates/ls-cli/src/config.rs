//! Where the CLI keeps its token and which project it is pointed at.
//!
//! Three places, in order of precedence: a flag, an environment variable, then
//! a file. The token file is written 0600 and nothing else is cached.

use std::path::{Path, PathBuf};

/// The file in the working directory that pins a project and environment.
pub const PIN_FILE: &str = ".localsecrets";

/// Default server address.
pub const DEFAULT_SERVER: &str = "127.0.0.1:8787";

/// Which project and environment commands apply to.
#[derive(Debug, Default, Clone)]
pub struct Pin {
    /// Project slug.
    pub project: Option<String>,
    /// Environment slug.
    pub environment: Option<String>,
}

/// The directory holding the token, under the user's config directory.
pub fn config_dir() -> PathBuf {
    match std::env::var_os("HOME") {
        Some(home) => PathBuf::from(home).join(".config/localsecrets"),
        None => PathBuf::from(".localsecrets-config"),
    }
}

fn token_path() -> PathBuf {
    config_dir().join("token")
}

/// Read the cached token, if there is one.
pub fn cached_token() -> Option<String> {
    let text = std::fs::read_to_string(token_path()).ok()?;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_owned())
    }
}

/// Cache a token, readable only by its owner.
pub fn store_token(token: &str) -> std::io::Result<()> {
    let directory = config_dir();
    std::fs::create_dir_all(&directory)?;
    restrict(&directory, 0o700);

    let path = token_path();
    write_private(&path, token)?;
    Ok(())
}

/// Forget the cached token.
pub fn forget_token() -> std::io::Result<()> {
    match std::fs::remove_file(token_path()) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Read the project and environment pinned in the working directory.
pub fn read_pin() -> Pin {
    let Ok(text) = std::fs::read_to_string(PIN_FILE) else {
        return Pin::default();
    };

    let mut pin = Pin::default();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((name, value)) = line.split_once('=') {
            match name.trim() {
                "project" => pin.project = Some(value.trim().to_owned()),
                "environment" => pin.environment = Some(value.trim().to_owned()),
                _ => {}
            }
        }
    }
    pin
}

/// Pin a project and environment in the working directory.
pub fn write_pin(project: &str, environment: &str) -> std::io::Result<()> {
    std::fs::write(
        PIN_FILE,
        format!("project={project}\nenvironment={environment}\n"),
    )
}

/// The server address: `LS_SERVER`, else the default.
pub fn server_address() -> String {
    std::env::var("LS_SERVER").unwrap_or_else(|_| DEFAULT_SERVER.to_owned())
}

fn write_private(path: &Path, contents: &str) -> std::io::Result<()> {
    use std::io::Write as _;

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }

    let mut file = options.open(path)?;
    file.write_all(contents.as_bytes())?;
    file.flush()?;

    // If the file already existed with looser permissions, creating it with a
    // mode does nothing, so set them explicitly as well.
    restrict(path, 0o600);
    Ok(())
}

fn restrict(path: &Path, mode: u32) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
    }
}
