//! One function per command.

use crate::api::{Api, field};
use crate::{Common, config, input, option_value};
use ls_json::Value;
use std::process::ExitCode;

/// Route a command line to its handler.
pub fn dispatch(arguments: &[String]) -> Result<ExitCode, String> {
    let (common, rest) = Common::extract(arguments);
    let command = rest.first().map(String::as_str).unwrap_or("");
    let args = &rest[1.min(rest.len())..];

    match command {
        "init" => init(&common, args),
        "unseal" => unseal(&common, args),
        "seal" => seal(&common),
        "status" => status(&common),

        "user" => match args.first().map(String::as_str) {
            Some("create") => create_user(&common, &args[1..]),
            other => Err(unknown("user", other)),
        },
        "login" => login(&common, args),
        "logout" => logout(&common),

        "use" => use_here(args),
        "project" => match args.first().map(String::as_str) {
            Some("create") => create_project(&common, &args[1..]),
            Some("list") => list_projects(&common),
            other => Err(unknown("project", other)),
        },
        "env" => match args.first().map(String::as_str) {
            Some("create") => create_environment(&common, &args[1..]),
            Some("list") => list_environments(&common),
            other => Err(unknown("env", other)),
        },

        "set" => set(&common, args),
        "get" => get(&common, args),
        "list" => list(&common),
        "delete" => delete(&common, args),
        "export" => export(&common, args),
        "import" => import(&common, args),
        "run" => run(&common, args),

        "token" => match args.first().map(String::as_str) {
            Some("create") => create_token(&common, &args[1..]),
            Some("revoke") => revoke_token(&common, &args[1..]),
            other => Err(unknown("token", other)),
        },
        "audit" => audit(&common),

        other => Err(format!("unknown command {other}; try `lsec --help`")),
    }
}

fn unknown(group: &str, given: Option<&str>) -> String {
    match given {
        Some(name) => format!("unknown {group} command {name}"),
        None => format!("`lsec {group}` needs a subcommand"),
    }
}

// --- system ----------------------------------------------------------------

fn init(common: &Common, args: &[String]) -> Result<ExitCode, String> {
    let threshold = number(args, "--threshold").unwrap_or(1);
    let shares = number(args, "--shares").unwrap_or(1);

    let api = common.connect()?;
    let answer = api.call(
        "POST",
        "/v1/sys/init",
        Some(Value::object([
            ("threshold", Value::Int(threshold)),
            ("shares", Value::Int(shares)),
        ])),
    )?;

    let listed = answer
        .get("shares")
        .and_then(Value::as_array)
        .ok_or("the server did not send any shares")?;

    println!("Vault initialised. {threshold} of {shares} shares are needed to unseal it.");
    println!();
    println!("These are shown once and are not stored anywhere. Write them down now,");
    println!("and keep them apart from each other and from the server.");
    println!();
    for share in listed {
        if let Some(text) = share.as_str() {
            println!("  {text}");
        }
    }
    println!();
    println!("root token: {}", field(&answer, "root_token")?);
    println!();
    println!("Use the root token once, to create the first account. It is asked");
    println!("for at a prompt, so it does not land in your shell history:");
    println!("  lsec user create you@example.com");

    Ok(ExitCode::SUCCESS)
}

fn unseal(common: &Common, args: &[String]) -> Result<ExitCode, String> {
    let share = match args.first() {
        Some(share) => share.clone(),
        None => input::secret_line("unseal share: ")?,
    };

    let api = common.connect()?;
    let answer = api.call(
        "POST",
        "/v1/sys/unseal",
        Some(Value::object([("share", Value::from(share.trim()))])),
    )?;

    let sealed = answer.get("sealed").and_then(Value::as_bool).unwrap_or(true);
    let progress = answer.get("progress").and_then(Value::as_i64).unwrap_or(0);
    let threshold = answer.get("threshold").and_then(Value::as_i64).unwrap_or(0);

    if sealed {
        println!("still sealed: {progress} of {threshold} shares");
    } else {
        println!("unsealed");
    }
    Ok(ExitCode::SUCCESS)
}

fn seal(common: &Common) -> Result<ExitCode, String> {
    common
        .connect_authenticated()?
        .call("POST", "/v1/sys/seal", None)?;
    println!("sealed");
    Ok(ExitCode::SUCCESS)
}

fn status(common: &Common) -> Result<ExitCode, String> {
    let answer = common.connect()?.call("GET", "/v1/sys/health", None)?;

    let sealed = answer.get("sealed").and_then(Value::as_bool).unwrap_or(true);
    let initialized = answer
        .get("initialized")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    println!("server:  {}", config::server_address());
    println!("state:   {}", if sealed { "sealed" } else { "unsealed" });
    println!(
        "vault:   {}",
        if initialized {
            "initialised"
        } else {
            "not initialised"
        }
    );
    if let Some(version) = answer.get("version").and_then(Value::as_str) {
        println!("version: {version}");
    }

    let pin = config::read_pin();
    if let (Some(project), Some(environment)) = (pin.project, pin.environment) {
        println!("here:    {project}/{environment}");
    }

    Ok(ExitCode::SUCCESS)
}

// --- accounts --------------------------------------------------------------

fn create_user(common: &Common, args: &[String]) -> Result<ExitCode, String> {
    let email = args
        .first()
        .cloned()
        .ok_or("usage: lsec user create EMAIL")?;

    // Before there is an account there is no session, only the root token from
    // init. Asking for it here keeps it out of the shell history and out of
    // the process list.
    let api = match common.token() {
        Some(token) => Api::connect(&config::server_address(), Some(token))?,
        None => {
            let root = input::secret_line("root token: ")?;
            if root.trim().is_empty() {
                return Err("a token is needed to create an account".to_owned());
            }
            Api::connect(&config::server_address(), Some(root.trim().to_owned()))?
        }
    };

    let password = input::secret_line("password: ")?;
    api.call(
        "POST",
        "/v1/users",
        Some(Value::object([
            ("email", Value::from(email.as_str())),
            ("password", Value::from(password.as_str())),
        ])),
    )?;

    println!("created {email}");
    Ok(ExitCode::SUCCESS)
}

fn login(common: &Common, args: &[String]) -> Result<ExitCode, String> {
    let email = match args.first() {
        Some(email) => email.clone(),
        None => input::line("email: ")?,
    };
    let password = input::secret_line("password: ")?;

    let api = common.connect()?;
    let answer = api.call(
        "POST",
        "/v1/auth/login",
        Some(Value::object([
            ("email", Value::from(email.as_str())),
            ("password", Value::from(password.as_str())),
        ])),
    )?;

    let token = field(&answer, "token")?;
    config::store_token(&token).map_err(|e| format!("could not store the token: {e}"))?;

    println!("logged in as {email}");
    Ok(ExitCode::SUCCESS)
}

fn logout(common: &Common) -> Result<ExitCode, String> {
    // Tell the server first, so the token is dead even if the file removal
    // fails; then forget it locally either way.
    if let Ok(api) = common.connect_authenticated() {
        let _ = api.call("POST", "/v1/auth/logout", None);
    }
    config::forget_token().map_err(|e| format!("could not remove the cached token: {e}"))?;

    println!("logged out");
    Ok(ExitCode::SUCCESS)
}

// --- projects --------------------------------------------------------------

fn use_here(args: &[String]) -> Result<ExitCode, String> {
    let (Some(project), Some(environment)) = (args.first(), args.get(1)) else {
        return Err("usage: lsec use PROJECT ENVIRONMENT".to_owned());
    };

    config::write_pin(project, environment)
        .map_err(|e| format!("could not write {}: {e}", config::PIN_FILE))?;

    println!("using {project}/{environment} here");
    Ok(ExitCode::SUCCESS)
}

fn create_project(common: &Common, args: &[String]) -> Result<ExitCode, String> {
    let slug = args
        .first()
        .cloned()
        .ok_or("usage: lsec project create SLUG")?;
    let name = option_value(args, "--name").unwrap_or_else(|| slug.clone());

    common.connect_authenticated()?.call(
        "POST",
        "/v1/projects",
        Some(Value::object([
            ("slug", Value::from(slug.as_str())),
            ("name", Value::from(name.as_str())),
        ])),
    )?;

    println!("created project {slug}");
    Ok(ExitCode::SUCCESS)
}

fn list_projects(common: &Common) -> Result<ExitCode, String> {
    let answer = common
        .connect_authenticated()?
        .call("GET", "/v1/projects", None)?;
    print_list(&answer, "projects");
    Ok(ExitCode::SUCCESS)
}

fn create_environment(common: &Common, args: &[String]) -> Result<ExitCode, String> {
    let slug = args.first().cloned().ok_or("usage: lsec env create SLUG")?;
    let name = option_value(args, "--name").unwrap_or_else(|| slug.clone());
    let project = common.project()?;

    common.connect_authenticated()?.call(
        "POST",
        &format!("/v1/projects/{project}/envs"),
        Some(Value::object([
            ("slug", Value::from(slug.as_str())),
            ("name", Value::from(name.as_str())),
        ])),
    )?;

    println!("created environment {slug} in {project}");
    Ok(ExitCode::SUCCESS)
}

fn list_environments(common: &Common) -> Result<ExitCode, String> {
    let project = common.project()?;
    let answer = common
        .connect_authenticated()?
        .call("GET", &format!("/v1/projects/{project}/envs"), None)?;
    print_list(&answer, "environments");
    Ok(ExitCode::SUCCESS)
}

// --- secrets ---------------------------------------------------------------

fn set(common: &Common, args: &[String]) -> Result<ExitCode, String> {
    let key = args.first().cloned().ok_or("usage: lsec set KEY [VALUE]")?;

    let value = match args.get(1) {
        Some(value) => {
            eprintln!(
                "lsec: a value on the command line goes into your shell history and is \
                 visible to anyone who can list processes; prefer `lsec set {key}`"
            );
            value.clone()
        }
        None => input::secret_line(&format!("value for {key}: "))?,
    };

    let (project, environment) = (common.project()?, common.environment()?);
    common.connect_authenticated()?.call(
        "PUT",
        &format!("/v1/projects/{project}/envs/{environment}/secrets/{key}"),
        Some(Value::object([("value", Value::from(value.as_str()))])),
    )?;

    println!("set {key}");
    Ok(ExitCode::SUCCESS)
}

fn get(common: &Common, args: &[String]) -> Result<ExitCode, String> {
    let key = args.first().cloned().ok_or("usage: lsec get KEY")?;
    let (project, environment) = (common.project()?, common.environment()?);

    let answer = common
        .connect_authenticated()?
        .call(
            "GET",
            &format!("/v1/projects/{project}/envs/{environment}/secrets/{key}"),
            None,
        )
        .map_err(|e| format!("{key}: {e}"))?;

    println!("{}", field(&answer, "value")?);
    Ok(ExitCode::SUCCESS)
}

fn list(common: &Common) -> Result<ExitCode, String> {
    let secrets = fetch_secrets(common)?;
    for (key, _) in &secrets {
        println!("{key}");
    }
    Ok(ExitCode::SUCCESS)
}

fn delete(common: &Common, args: &[String]) -> Result<ExitCode, String> {
    let key = args.first().cloned().ok_or("usage: lsec delete KEY")?;
    let (project, environment) = (common.project()?, common.environment()?);

    common.connect_authenticated()?.call(
        "DELETE",
        &format!("/v1/projects/{project}/envs/{environment}/secrets/{key}"),
        None,
    )?;

    println!("deleted {key}");
    Ok(ExitCode::SUCCESS)
}

fn export(common: &Common, args: &[String]) -> Result<ExitCode, String> {
    let format = option_value(args, "--format").unwrap_or_else(|| "dotenv".to_owned());
    let secrets = fetch_secrets(common)?;

    match format.as_str() {
        "dotenv" => {
            for (key, value) in secrets {
                println!("{key}={}", dotenv_quote(&value));
            }
        }
        "json" => {
            let fields: Vec<(String, Value)> = secrets
                .into_iter()
                .map(|(key, value)| (key, Value::from(value)))
                .collect();
            println!("{}", Value::Object(fields));
        }
        other => return Err(format!("unknown format {other}; use dotenv or json")),
    }

    Ok(ExitCode::SUCCESS)
}

fn import(common: &Common, args: &[String]) -> Result<ExitCode, String> {
    let path = args.first().cloned().ok_or("usage: lsec import FILE")?;
    let text = if path == "-" {
        String::from_utf8(input::all_of_stdin()?)
            .map_err(|_| "input is not valid UTF-8".to_owned())?
    } else {
        std::fs::read_to_string(&path).map_err(|e| format!("could not read {path}: {e}"))?
    };

    let parsed = parse_dotenv(&text);
    if parsed.is_empty() {
        return Err(format!("{path} held nothing to import"));
    }

    let fields: Vec<(String, Value)> = parsed
        .iter()
        .map(|(key, value)| (key.clone(), Value::from(value.as_str())))
        .collect();
    let count = fields.len();

    let (project, environment) = (common.project()?, common.environment()?);
    common.connect_authenticated()?.call(
        "POST",
        &format!("/v1/projects/{project}/envs/{environment}/secrets"),
        Some(Value::object([("secrets", Value::Object(fields))])),
    )?;

    let plural = if count == 1 { "secret" } else { "secrets" };
    println!("imported {count} {plural} into {project}/{environment}");
    Ok(ExitCode::SUCCESS)
}

fn run(common: &Common, args: &[String]) -> Result<ExitCode, String> {
    let command: Vec<String> = args
        .iter()
        .skip_while(|argument| *argument != "--")
        .skip(1)
        .cloned()
        .collect();

    let Some((program, rest)) = command.split_first() else {
        return Err("usage: lsec run -- COMMAND [ARGS...]".to_owned());
    };

    let secrets = fetch_secrets(common)?;

    let status = std::process::Command::new(program)
        .args(rest)
        .envs(secrets)
        .status()
        .map_err(|e| format!("could not run {program}: {e}"))?;

    // Pass the child's exit code on, so this is transparent in a script.
    Ok(match status.code() {
        Some(code) => ExitCode::from(u8::try_from(code).unwrap_or(1)),
        None => ExitCode::FAILURE,
    })
}

// --- machines and audit ----------------------------------------------------

fn create_token(common: &Common, args: &[String]) -> Result<ExitCode, String> {
    let label = option_value(args, "--label").unwrap_or_else(|| "machine".to_owned());
    let (project, environment) = (common.project()?, common.environment()?);

    let mut body = vec![
        ("project", Value::from(project.as_str())),
        ("environment", Value::from(environment.as_str())),
        ("label", Value::from(label.as_str())),
    ];
    if let Some(ttl) = number(args, "--ttl") {
        body.push(("ttl_seconds", Value::Int(ttl)));
    }

    let answer = common
        .connect_authenticated()?
        .call("POST", "/v1/tokens", Some(Value::object(body)))?;

    println!("token: {}", field(&answer, "token")?);
    println!("id:    {}", field(&answer, "id")?);
    println!();
    println!("Shown once. It can read {project}/{environment} and nothing else.");

    Ok(ExitCode::SUCCESS)
}

fn revoke_token(common: &Common, args: &[String]) -> Result<ExitCode, String> {
    let id = args.first().cloned().ok_or("usage: lsec token revoke ID")?;

    common
        .connect_authenticated()?
        .call("DELETE", &format!("/v1/tokens/{id}"), None)?;

    println!("revoked {id}");
    Ok(ExitCode::SUCCESS)
}

fn audit(common: &Common) -> Result<ExitCode, String> {
    let answer = common
        .connect_authenticated()?
        .call("GET", "/v1/audit", None)?;

    for entry in answer
        .get("entries")
        .and_then(Value::as_array)
        .unwrap_or(&[])
    {
        let read = |name: &str| entry.get(name).and_then(Value::as_str).unwrap_or("");
        println!(
            "{}  {:<14} {:<28} {:<8} {}",
            read("at"),
            read("action"),
            read("target"),
            read("outcome"),
            read("actor"),
        );
    }

    Ok(ExitCode::SUCCESS)
}

// --- shared ----------------------------------------------------------------

fn fetch_secrets(common: &Common) -> Result<Vec<(String, String)>, String> {
    let (project, environment) = (common.project()?, common.environment()?);
    let answer = common.connect_authenticated()?.call(
        "GET",
        &format!("/v1/projects/{project}/envs/{environment}/secrets"),
        None,
    )?;

    let Some(Value::Object(pairs)) = answer.get("secrets") else {
        return Ok(Vec::new());
    };

    Ok(pairs
        .iter()
        .filter_map(|(key, value)| value.as_str().map(|text| (key.clone(), text.to_owned())))
        .collect())
}

fn print_list(answer: &Value, name: &str) {
    for item in answer.get(name).and_then(Value::as_array).unwrap_or(&[]) {
        if let Some(text) = item.as_str() {
            println!("{text}");
        }
    }
}

fn number(args: &[String], name: &str) -> Option<i64> {
    option_value(args, name).and_then(|text| text.parse().ok())
}

/// Quote a value for a `.env` file, only when it needs it.
fn dotenv_quote(value: &str) -> String {
    let needs_quotes = value.is_empty()
        || value
            .chars()
            .any(|c| c.is_whitespace() || matches!(c, '"' | '\'' | '\\' | '#' | '$' | '='));

    if !needs_quotes {
        return value.to_owned();
    }

    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Read a `.env` file: `KEY=value`, optional `export`, `#` comments, and
/// values that may be quoted.
fn parse_dotenv(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line).trim();

        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if key.is_empty() {
            continue;
        }

        out.push((key.to_owned(), unquote(value.trim())));
    }

    out
}

fn unquote(value: &str) -> String {
    let bytes = value.as_bytes();
    let quoted = bytes.len() >= 2
        && ((bytes[0] == b'"' && bytes[bytes.len() - 1] == b'"')
            || (bytes[0] == b'\'' && bytes[bytes.len() - 1] == b'\''));

    if !quoted {
        return value.to_owned();
    }

    let inner = &value[1..value.len() - 1];
    if bytes[0] == b'\'' {
        // Single quotes are literal, as in a shell.
        return inner.to_owned();
    }

    let mut out = String::with_capacity(inner.len());
    let mut characters = inner.chars();
    while let Some(c) = characters.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match characters.next() {
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some('t') => out.push('\t'),
            Some(other) => out.push(other),
            None => out.push('\\'),
        }
    }
    out
}
