#![allow(clippy::unwrap_used, clippy::expect_used)]

use ls_core::time::Timestamp;
use ls_log::{Level, format_line};

fn at(message: &str, fields: &[(&str, String)]) -> String {
    format_line(Timestamp::from_unix(1_757_635_200), Level::Info, message, fields)
}

#[test]
fn a_line_starts_with_a_timestamp_and_a_level() {
    // Level names are padded to a fixed width, so INFO is followed by two spaces.
    assert_eq!(at("started", &[]), "2025-09-12T00:00:00Z INFO  started");
}

#[test]
fn every_level_has_a_fixed_width_name() {
    let timestamp = Timestamp::from_unix(0);
    for level in [Level::Error, Level::Warn, Level::Info, Level::Debug] {
        let line = format_line(timestamp, level, "x", &[]);
        // The timestamp is 20 characters, then a space, then the level.
        assert_eq!(&line[21..26], level.name(), "level {level:?} in {line}");
        assert_eq!(level.name().len(), 5);
    }
}

#[test]
fn fields_are_appended_as_key_value_pairs() {
    let line = at(
        "secret read",
        &[
            ("project", "demo".to_owned()),
            ("key", "DB_URL".to_owned()),
        ],
    );

    assert_eq!(
        line,
        "2025-09-12T00:00:00Z INFO  secret read project=demo key=DB_URL"
    );
}

#[test]
fn a_value_with_a_space_is_quoted() {
    let line = at("x", &[("detail", "two words".to_owned())]);
    assert!(line.ends_with(r#"detail="two words""#), "got {line}");
}

#[test]
fn an_empty_value_is_quoted_so_it_is_visible() {
    let line = at("x", &[("detail", String::new())]);
    assert!(line.ends_with(r#"detail="""#), "got {line}");
}

#[test]
fn a_value_cannot_forge_a_second_log_line() {
    // Anything reaching a field value may be attacker controlled: a key name, a
    // path, a user agent. A newline in one must not become a new record.
    let line = at(
        "x",
        &[(
            "path",
            "/ok\n2025-09-12T00:00:00Z ERROR  forged entry".to_owned(),
        )],
    );

    assert_eq!(line.lines().count(), 1, "value broke out of its line: {line}");
    assert!(line.contains(r"\n"), "newline should be escaped, got {line}");
    // The forged text survives, but only inside the quoted value where it is
    // plainly one field of one record rather than a record of its own.
    assert!(
        line.ends_with(r#"path="/ok\n2025-09-12T00:00:00Z ERROR  forged entry""#),
        "got {line}"
    );
}

#[test]
fn a_value_with_a_quote_or_backslash_is_escaped() {
    let line = at("x", &[("detail", r#"a"b\c"#.to_owned())]);
    assert!(line.ends_with(r#"detail="a\"b\\c""#), "got {line}");
}

#[test]
fn a_carriage_return_and_a_tab_are_escaped_too() {
    let line = at("x", &[("detail", "a\rb\tc".to_owned())]);

    assert_eq!(line.lines().count(), 1);
    assert!(line.contains(r"\r"), "got {line}");
    assert!(line.contains(r"\t"), "got {line}");
}

#[test]
fn the_message_itself_cannot_forge_a_line() {
    let line = at("first\nsecond", &[]);
    assert_eq!(line.lines().count(), 1, "message broke out: {line}");
}

#[test]
fn levels_are_ordered_from_least_to_most_verbose() {
    assert!(Level::Error < Level::Warn);
    assert!(Level::Warn < Level::Info);
    assert!(Level::Info < Level::Debug);
}

#[test]
fn a_level_can_be_read_from_text_in_any_case() {
    assert_eq!(Level::parse("error"), Some(Level::Error));
    assert_eq!(Level::parse("WARN"), Some(Level::Warn));
    assert_eq!(Level::parse("Info"), Some(Level::Info));
    assert_eq!(Level::parse("debug"), Some(Level::Debug));
    assert_eq!(Level::parse("trace"), None);
    assert_eq!(Level::parse(""), None);
}

#[test]
fn setting_a_level_controls_what_is_enabled() {
    ls_log::set_level(Level::Warn);
    assert!(ls_log::enabled(Level::Error));
    assert!(ls_log::enabled(Level::Warn));
    assert!(!ls_log::enabled(Level::Info));
    assert!(!ls_log::enabled(Level::Debug));

    ls_log::set_level(Level::Debug);
    assert!(ls_log::enabled(Level::Debug));
}
