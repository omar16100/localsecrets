//! `lsec`, the localsecrets command line client.

mod api;
mod commands;
mod config;
mod input;

use api::Api;

const USAGE: &str = "\
lsec, the localsecrets client

Usage: lsec <command> [options]

Getting started
  init [--threshold N] [--shares N]   Create the vault; prints the unseal shares once
  unseal [SHARE]                      Offer one unseal share
  unseal --reset                      Throw away a part-finished attempt
  rekey [--threshold N] [--shares N]  Split the master key again; the old
                                      shares stop working, secrets are untouched
  seal                                Drop the root key until the next unseal
  status                              Show whether the server is sealed

Accounts
  user create EMAIL                   Create a user (needs the root token)
  login EMAIL                         Log in and cache a session token
  logout                              Forget the cached token

Projects
  use PROJECT ENV                     Pin a project and environment here
  project create SLUG [--name NAME]
  project list
  env create SLUG [--name NAME]
  env list

Secrets
  set KEY [VALUE]                     Write a secret; without VALUE it is read from stdin
  get KEY                             Print one value
  list                                List keys, without values
  delete KEY                          Remove a secret
  export [--format dotenv|json]       Print the whole environment
  import FILE                         Load a .env file
  run -- COMMAND...                   Run a command with the secrets in its environment

Machines
  token create [--label NAME] [--ttl SECONDS]
  token revoke ID
  audit                               Show the audit trail

Options
  --project SLUG    --env SLUG        Override the pinned project or environment
  --token TOKEN                       Use this token instead of the cached one
  -h, --help                          Show this message

Environment
  LS_SERVER    Server address, default 127.0.0.1:8787
  LS_TOKEN     Token to use, overriding the cached one

Passing a value on the command line puts it in your shell history and makes it
visible to anyone who can list processes. Prefer `lsec set KEY` and type or
pipe the value instead.
";

fn main() -> std::process::ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();

    if arguments.is_empty()
        || arguments[0] == "-h"
        || arguments[0] == "--help"
        || arguments[0] == "help"
    {
        println!("{USAGE}");
        return std::process::ExitCode::SUCCESS;
    }

    match commands::dispatch(&arguments) {
        Ok(code) => code,
        Err(message) => {
            eprintln!("lsec: {message}");
            std::process::ExitCode::FAILURE
        }
    }
}

/// Options that apply to most commands.
#[derive(Debug)]
pub struct Common {
    pub project: Option<String>,
    pub environment: Option<String>,
    pub token: Option<String>,
}

impl Common {
    /// Pull the shared options out of the argument list, leaving the rest.
    pub fn extract(arguments: &[String]) -> (Self, Vec<String>) {
        let mut common = Self {
            project: None,
            environment: None,
            token: None,
        };
        let mut rest = Vec::with_capacity(arguments.len());

        let mut index = 0;
        while index < arguments.len() {
            let argument = arguments[index].as_str();
            let mut take = |target: &mut Option<String>| {
                *target = arguments.get(index + 1).cloned();
                index += 2;
            };

            match argument {
                "--project" | "-p" => take(&mut common.project),
                "--env" | "-e" => take(&mut common.environment),
                "--token" => take(&mut common.token),
                _ => {
                    rest.push(arguments[index].clone());
                    index += 1;
                }
            }
        }

        (common, rest)
    }

    /// The token to use: the flag, then `LS_TOKEN`, then the cached one.
    pub fn token(&self) -> Option<String> {
        self.token
            .clone()
            .or_else(|| std::env::var("LS_TOKEN").ok().filter(|t| !t.is_empty()))
            .or_else(config::cached_token)
    }

    /// The project to act on: the flag, then the pin in this directory.
    pub fn project(&self) -> Result<String, String> {
        self.project
            .clone()
            .or_else(|| config::read_pin().project)
            .ok_or_else(|| {
                "no project; pass --project or run `lsec use PROJECT ENV` here".to_owned()
            })
    }

    /// The environment to act on: the flag, then the pin in this directory.
    pub fn environment(&self) -> Result<String, String> {
        self.environment
            .clone()
            .or_else(|| config::read_pin().environment)
            .ok_or_else(|| {
                "no environment; pass --env or run `lsec use PROJECT ENV` here".to_owned()
            })
    }

    /// Connect, with whatever token is available.
    pub fn connect(&self) -> Result<Api, String> {
        Api::connect(&config::server_address(), self.token())
    }

    /// Connect, insisting on a token.
    pub fn connect_authenticated(&self) -> Result<Api, String> {
        let api = self.connect()?;
        if !api.has_token() {
            return Err("not logged in; run `lsec login EMAIL`".to_owned());
        }
        Ok(api)
    }
}

/// Read an option that takes a value out of a list of arguments.
pub fn option_value(arguments: &[String], name: &str) -> Option<String> {
    arguments
        .iter()
        .position(|argument| argument == name)
        .and_then(|index| arguments.get(index + 1))
        .cloned()
}
