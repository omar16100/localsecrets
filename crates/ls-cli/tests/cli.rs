#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use ls_http::{Limits, Server, ServerHandle};
use ls_server::{Vault, handler};
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::{Arc, Mutex};

/// A running server plus a scratch home for the CLI's config.
struct Cli {
    dir: PathBuf,
    address: String,
    handle: Option<ServerHandle>,
}

impl Cli {
    fn start(label: &str) -> Self {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("ls-cli-{label}-{unique}"));
        std::fs::create_dir_all(&dir).unwrap();

        let vault = Vault::open(&dir.join("store.log")).unwrap();
        let server = Server::bind("127.0.0.1:0", Limits::default()).unwrap();
        let address = server.local_addr().unwrap().to_string();
        let handle = server.spawn(4, handler(Arc::new(Mutex::new(vault))));

        Self {
            dir,
            address,
            handle: Some(handle),
        }
    }

    fn run(&self, args: &[&str]) -> Output {
        self.run_with_stdin(args, "")
    }

    fn run_with_stdin(&self, args: &[&str], input: &str) -> Output {
        use std::io::Write as _;

        let mut child = Command::new(env!("CARGO_BIN_EXE_lsec"))
            .args(args)
            .env("HOME", &self.dir)
            .env("LS_SERVER", &self.address)
            .current_dir(&self.dir)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("lsec should start");

        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();

        child.wait_with_output().expect("lsec should finish")
    }

    fn stdout(&self, args: &[&str]) -> String {
        let output = self.run(args);
        assert!(
            output.status.success(),
            "lsec {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).into_owned()
    }

    /// Initialise, create a user, log in, and make a project and environment.
    fn ready(&self) -> Vec<String> {
        let init = self.stdout(&["init", "--threshold", "2", "--shares", "3"]);
        let shares: Vec<String> = init
            .lines()
            .filter(|line| line.trim().starts_with("lss1."))
            .map(|line| line.trim().to_owned())
            .collect();
        assert_eq!(shares.len(), 3, "init did not print three shares:\n{init}");

        let root = init
            .lines()
            .find_map(|line| line.trim().strip_prefix("root token: "))
            .expect("init should print a root token")
            .to_owned();

        let created = self.run_with_stdin(
            &["user", "create", "dev@example.com", "--token", &root],
            "correct horse battery staple\n",
        );
        assert!(
            created.status.success(),
            "user create failed: {}",
            String::from_utf8_lossy(&created.stderr)
        );

        let logged_in = self.run_with_stdin(
            &["login", "dev@example.com"],
            "correct horse battery staple\n",
        );
        assert!(
            logged_in.status.success(),
            "login failed: {}",
            String::from_utf8_lossy(&logged_in.stderr)
        );

        self.stdout(&["project", "create", "demo"]);
        self.stdout(&["env", "create", "dev", "--project", "demo"]);
        self.stdout(&["use", "demo", "dev"]);

        shares
    }
}

impl Drop for Cli {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.shutdown();
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[test]
fn help_explains_the_commands() {
    let cli = Cli::start("help");

    let output = cli.run(&["--help"]);

    assert!(output.status.success());
    let text = String::from_utf8_lossy(&output.stdout);
    for command in ["init", "unseal", "login", "set", "get", "run"] {
        assert!(text.contains(command), "help does not mention {command}");
    }
}

#[test]
fn an_unknown_command_fails_with_a_message() {
    let cli = Cli::start("unknown");

    let output = cli.run(&["frobnicate"]);

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("frobnicate"));
}

#[test]
fn status_reports_the_server_state() {
    let cli = Cli::start("status");

    let before = cli.stdout(&["status"]);
    assert!(before.contains("sealed"), "got {before}");
    assert!(before.contains("not initialised"), "got {before}");

    cli.ready();

    let after = cli.stdout(&["status"]);
    assert!(after.contains("unsealed"), "got {after}");
}

#[test]
fn init_prints_the_shares_and_says_they_are_shown_once() {
    let cli = Cli::start("init");

    let output = cli.stdout(&["init", "--threshold", "2", "--shares", "3"]);

    assert_eq!(output.matches("lss1.").count(), 3);
    assert!(output.contains("root token: lsec_"));
    assert!(
        output.to_lowercase().contains("once"),
        "the operator should be told these are not shown again:\n{output}"
    );
}

#[test]
fn the_first_account_can_be_created_without_putting_the_token_on_the_command_line() {
    let cli = Cli::start("root-prompt");
    let init = cli.stdout(&["init", "--threshold", "1", "--shares", "1"]);
    let root = init
        .lines()
        .find_map(|line| line.trim().strip_prefix("root token: "))
        .expect("init should print a root token")
        .to_owned();

    // No --token: the root token is asked for, then the password.
    let created = cli.run_with_stdin(
        &["user", "create", "dev@example.com"],
        &format!("{root}\ncorrect horse battery staple\n"),
    );

    assert!(
        created.status.success(),
        "user create failed: {}",
        String::from_utf8_lossy(&created.stderr)
    );

    let logged_in = cli.run_with_stdin(
        &["login", "dev@example.com"],
        "correct horse battery staple\n",
    );
    assert!(logged_in.status.success());
}

#[test]
fn creating_an_account_without_any_token_fails_rather_than_hanging() {
    let cli = Cli::start("root-missing");
    cli.stdout(&["init", "--threshold", "1", "--shares", "1"]);

    let output = cli.run_with_stdin(&["user", "create", "dev@example.com"], "\n");

    assert!(!output.status.success());
}

#[test]
fn the_init_output_does_not_tell_the_operator_to_paste_the_token_into_a_command() {
    let cli = Cli::start("init-advice");

    let output = cli.stdout(&["init"]);

    assert!(
        !output.contains("--token"),
        "init should not suggest putting the root token in argv:\n{output}"
    );
}

#[test]
fn a_secret_can_be_written_and_read_back() {
    let cli = Cli::start("set-get");
    cli.ready();

    cli.run_with_stdin(&["set", "DB_URL"], "postgres://user:pw@host/db\n");

    assert_eq!(
        cli.stdout(&["get", "DB_URL"]).trim(),
        "postgres://user:pw@host/db"
    );
}

#[test]
fn a_value_given_on_the_command_line_warns_about_shell_history() {
    let cli = Cli::start("argv-warning");
    cli.ready();

    let output = cli.run(&["set", "KEY", "value-on-argv"]);

    assert!(output.status.success());
    let warning = String::from_utf8_lossy(&output.stderr).to_lowercase();
    assert!(
        warning.contains("history") || warning.contains("visible"),
        "passing a value on argv should warn: {warning}"
    );
}

#[test]
fn reading_a_missing_secret_fails() {
    let cli = Cli::start("missing");
    cli.ready();

    let output = cli.run(&["get", "NOT_THERE"]);

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("NOT_THERE"));
}

#[test]
fn list_shows_the_keys_without_their_values() {
    let cli = Cli::start("list");
    cli.ready();
    cli.run_with_stdin(&["set", "DB_URL"], "postgres://secret\n");
    cli.run_with_stdin(&["set", "API_KEY"], "another secret\n");

    let listed = cli.stdout(&["list"]);

    assert!(listed.contains("API_KEY"), "got {listed}");
    assert!(listed.contains("DB_URL"), "got {listed}");
    assert!(
        !listed.contains("postgres://secret"),
        "list printed a value: {listed}"
    );
    assert!(
        listed.find("API_KEY") < listed.find("DB_URL"),
        "keys should be sorted: {listed}"
    );
}

#[test]
fn export_writes_a_dotenv_file_that_quotes_awkward_values() {
    let cli = Cli::start("export");
    cli.ready();
    cli.run_with_stdin(&["set", "PLAIN"], "simple\n");
    cli.run_with_stdin(&["set", "AWKWARD"], "has spaces and \"quotes\"\n");

    let exported = cli.stdout(&["export"]);

    assert!(exported.contains("PLAIN=simple"), "got {exported}");
    assert!(
        exported.contains(r#"AWKWARD="has spaces and \"quotes\"""#),
        "got {exported}"
    );
}

#[test]
fn export_can_produce_json() {
    let cli = Cli::start("export-json");
    cli.ready();
    cli.run_with_stdin(&["set", "K"], "v\n");

    let exported = cli.stdout(&["export", "--format", "json"]);

    assert!(exported.contains(r#""K":"v""#), "got {exported}");
}

#[test]
fn import_reads_a_dotenv_file() {
    let cli = Cli::start("import");
    cli.ready();
    let file = cli.dir.join("in.env");
    std::fs::write(
        &file,
        "# a comment\n\nA=one\nexport B=two\nC=\"quoted value\"\n",
    )
    .unwrap();

    cli.stdout(&["import", file.to_str().unwrap()]);

    assert_eq!(cli.stdout(&["get", "A"]).trim(), "one");
    assert_eq!(cli.stdout(&["get", "B"]).trim(), "two");
    assert_eq!(cli.stdout(&["get", "C"]).trim(), "quoted value");
}

#[test]
fn import_can_read_from_standard_input() {
    let cli = Cli::start("import-stdin");
    cli.ready();

    let output = cli.run_with_stdin(&["import", "-"], "FROM_STDIN=piped value\n");
    assert!(
        output.status.success(),
        "import - failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    assert_eq!(cli.stdout(&["get", "FROM_STDIN"]).trim(), "piped value");
}

#[test]
fn an_environment_can_be_copied_to_another_one() {
    let cli = Cli::start("copy-env");
    cli.ready();
    cli.run_with_stdin(&["set", "A"], "one\n");
    cli.run_with_stdin(&["set", "B"], "two words\n");
    cli.stdout(&["env", "create", "staging", "--project", "demo"]);

    let exported = cli.stdout(&["export"]);
    let output = cli.run_with_stdin(&["import", "-", "--env", "staging"], &exported);
    assert!(
        output.status.success(),
        "copying an environment failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    assert_eq!(cli.stdout(&["get", "A", "--env", "staging"]).trim(), "one");
    assert_eq!(
        cli.stdout(&["get", "B", "--env", "staging"]).trim(),
        "two words"
    );
}

#[test]
fn run_injects_the_secrets_into_a_child_process() {
    let cli = Cli::start("run");
    cli.ready();
    cli.run_with_stdin(&["set", "INJECTED"], "the value\n");

    let output = cli.stdout(&["run", "--", "sh", "-c", "printf %s \"$INJECTED\""]);

    assert_eq!(output, "the value");
}

#[test]
fn run_passes_on_the_exit_code_of_the_child() {
    let cli = Cli::start("run-exit");
    cli.ready();

    let output = cli.run(&["run", "--", "sh", "-c", "exit 3"]);

    assert_eq!(output.status.code(), Some(3));
}

#[test]
fn run_needs_a_command() {
    let cli = Cli::start("run-empty");
    cli.ready();

    assert!(!cli.run(&["run", "--"]).status.success());
}

#[test]
fn a_project_and_environment_can_be_created_and_listed() {
    let cli = Cli::start("projects");
    cli.ready();

    assert!(cli.stdout(&["project", "list"]).contains("demo"));
    assert!(cli.stdout(&["env", "list"]).contains("dev"));
}

#[test]
fn the_working_directory_pins_the_project_and_environment() {
    let cli = Cli::start("pin");
    cli.ready();

    assert!(cli.dir.join(".localsecrets").exists());
    let pinned = std::fs::read_to_string(cli.dir.join(".localsecrets")).unwrap();
    assert!(pinned.contains("demo"));
    assert!(pinned.contains("dev"));
}

#[test]
fn sealing_and_unsealing_works_from_the_command_line() {
    let cli = Cli::start("seal");
    let shares = cli.ready();

    cli.stdout(&["seal"]);
    assert!(cli.stdout(&["status"]).contains("sealed"));

    cli.stdout(&["unseal", &shares[0]]);
    let output = cli.stdout(&["unseal", &shares[1]]);

    assert!(output.contains("unsealed"), "got {output}");
}

#[test]
fn the_shares_can_be_re_split_from_the_command_line() {
    let cli = Cli::start("rekey");
    let old = cli.ready();
    cli.run_with_stdin(&["set", "K"], "kept\n");

    let output = cli.stdout(&["rekey", "--threshold", "1", "--shares", "2"]);
    let fresh: Vec<String> = output
        .lines()
        .filter(|line| line.trim().starts_with("lss1."))
        .map(|line| line.trim().to_owned())
        .collect();

    assert_eq!(fresh.len(), 2, "expected two new shares:\n{output}");
    assert!(
        output.to_lowercase().contains("no longer"),
        "the operator should be told the old shares are dead:\n{output}"
    );
    assert_eq!(cli.stdout(&["get", "K"]).trim(), "kept");

    cli.stdout(&["seal"]);
    assert!(
        !cli.run(&["unseal", &old[0]]).status.success(),
        "an old share should no longer be accepted"
    );
    assert!(cli.stdout(&["unseal", &fresh[0]]).contains("unsealed"));
}

#[test]
fn an_unseal_share_on_the_command_line_warns() {
    // A share is worth more than most secrets, and argv is visible to anyone
    // who can list processes and lands in shell history.
    let cli = Cli::start("unseal-argv");
    let shares = cli.ready();
    cli.stdout(&["seal"]);

    let output = cli.run(&["unseal", &shares[0]]);

    assert!(output.status.success());
    let warning = String::from_utf8_lossy(&output.stderr).to_lowercase();
    assert!(
        warning.contains("history") || warning.contains("visible"),
        "passing a share on argv should warn: {warning}"
    );
}

#[test]
fn an_unseal_share_read_from_stdin_does_not_warn() {
    let cli = Cli::start("unseal-stdin");
    let shares = cli.ready();
    cli.stdout(&["seal"]);

    let output = cli.run_with_stdin(&["unseal"], &format!("{}\n", shares[0]));

    assert!(output.status.success());
    assert!(
        !String::from_utf8_lossy(&output.stderr)
            .to_lowercase()
            .contains("history")
    );
}

#[test]
fn a_machine_token_can_be_issued_and_used() {
    let cli = Cli::start("token");
    cli.ready();
    cli.run_with_stdin(&["set", "K"], "machine readable\n");

    let issued = cli.stdout(&["token", "create", "--label", "ci"]);
    let token = issued
        .lines()
        .find_map(|line| line.trim().strip_prefix("token: "))
        .expect("token create should print a token")
        .to_owned();

    let output = cli.run(&["get", "K", "--token", &token]);

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "machine readable"
    );
}

#[test]
fn the_token_file_is_not_readable_by_anyone_else() {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let cli = Cli::start("token-perms");
        cli.ready();

        let token_file = cli.dir.join(".config/localsecrets/token");
        assert!(token_file.exists(), "login should cache a token");
        let mode = std::fs::metadata(&token_file).unwrap().permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "token file mode was {:o}",
            mode & 0o777
        );
    }
}

#[test]
fn logging_out_removes_the_cached_token() {
    let cli = Cli::start("logout");
    cli.ready();

    cli.stdout(&["logout"]);

    assert!(!cli.dir.join(".config/localsecrets/token").exists());
    assert!(!cli.run(&["list"]).status.success());
}

#[test]
fn a_failed_command_never_prints_a_value_it_was_carrying() {
    let cli = Cli::start("no-echo");
    cli.ready();

    let output = cli.run(&["set", "bad key", "do-not-echo-me"]);

    assert!(!output.status.success());
    let all = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !all.contains("do-not-echo-me"),
        "the value was echoed: {all}"
    );
}
