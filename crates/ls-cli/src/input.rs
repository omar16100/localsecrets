//! Reading values and passwords from the terminal.
//!
//! Secrets should not sit in shell history or be visible to anyone who can
//! list processes, so the usual path is to type or pipe them instead of
//! passing them as arguments.

use std::io::{BufRead as _, Write as _};

/// Read one line from standard input, without the newline.
pub fn line(prompt: &str) -> Result<String, String> {
    if is_a_terminal() {
        eprint!("{prompt}");
        let _ = std::io::stderr().flush();
    }

    let mut buffer = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut buffer)
        .map_err(|e| format!("could not read input: {e}"))?;

    Ok(buffer.trim_end_matches(['\n', '\r']).to_owned())
}

/// Read a line without echoing it.
///
/// Turning off the echo needs a terminal call that the standard library does
/// not offer, so this asks `stty`. If that is not available the input is read
/// anyway, with a warning, rather than refusing to work at all.
pub fn secret_line(prompt: &str) -> Result<String, String> {
    if !is_a_terminal() {
        // Being piped in: there is no echo to turn off.
        return line("");
    }

    eprint!("{prompt}");
    let _ = std::io::stderr().flush();

    let echo_off = stty(&["-echo"]);
    if !echo_off {
        eprintln!("\nlsec: could not turn off the terminal echo; what you type will be visible");
    }

    let value = line("");

    if echo_off {
        stty(&["echo"]);
        eprintln!();
    }

    value
}

/// Read everything on standard input.
pub fn all_of_stdin() -> Result<Vec<u8>, String> {
    use std::io::Read as _;
    let mut buffer = Vec::new();
    std::io::stdin()
        .lock()
        .read_to_end(&mut buffer)
        .map_err(|e| format!("could not read input: {e}"))?;
    Ok(buffer)
}

fn stty(arguments: &[&str]) -> bool {
    std::process::Command::new("stty")
        .args(arguments)
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

/// Whether standard input is a terminal rather than a pipe.
///
/// Asking `stty` is the standard-library-only way to find out; a pipe makes it
/// fail.
fn is_a_terminal() -> bool {
    stty(&["-a"])
}
