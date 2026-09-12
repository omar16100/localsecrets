#![allow(clippy::unwrap_used, clippy::expect_used)]

use ls_json::{JsonError, Value, parse};

#[test]
fn parses_the_literals() {
    assert_eq!(parse("null").unwrap(), Value::Null);
    assert_eq!(parse("true").unwrap(), Value::Bool(true));
    assert_eq!(parse("false").unwrap(), Value::Bool(false));
}

#[test]
fn parses_integers_including_negatives_and_zero() {
    assert_eq!(parse("0").unwrap(), Value::Int(0));
    assert_eq!(parse("-0").unwrap(), Value::Int(0));
    assert_eq!(parse("42").unwrap(), Value::Int(42));
    assert_eq!(parse("-17").unwrap(), Value::Int(-17));
    assert_eq!(
        parse("9223372036854775807").unwrap(),
        Value::Int(i64::MAX),
        "the largest i64 must survive"
    );
    assert_eq!(parse("-9223372036854775808").unwrap(), Value::Int(i64::MIN));
}

#[test]
fn parses_floats() {
    assert_eq!(parse("1.5").unwrap(), Value::Float(1.5));
    assert_eq!(parse("-0.25").unwrap(), Value::Float(-0.25));
    assert_eq!(parse("1e3").unwrap(), Value::Float(1000.0));
    assert_eq!(parse("1.5E-2").unwrap(), Value::Float(0.015));
}

#[test]
fn parses_strings_with_every_escape() {
    assert_eq!(parse(r#""""#).unwrap(), Value::from(""));
    assert_eq!(parse(r#""plain""#).unwrap(), Value::from("plain"));
    assert_eq!(parse(r#""a\"b""#).unwrap(), Value::from("a\"b"));
    assert_eq!(parse(r#""a\\b""#).unwrap(), Value::from("a\\b"));
    assert_eq!(parse(r#""a\/b""#).unwrap(), Value::from("a/b"));
    assert_eq!(parse(r#""a\nb""#).unwrap(), Value::from("a\nb"));
    assert_eq!(parse(r#""a\tb""#).unwrap(), Value::from("a\tb"));
    assert_eq!(parse(r#""a\rb""#).unwrap(), Value::from("a\rb"));
    assert_eq!(parse(r#""a\bb""#).unwrap(), Value::from("a\u{8}b"));
    assert_eq!(parse(r#""a\fb""#).unwrap(), Value::from("a\u{c}b"));
    assert_eq!(parse(r#""A""#).unwrap(), Value::from("A"));
    assert_eq!(parse(r#""é""#).unwrap(), Value::from("é"));
}

#[test]
fn parses_a_surrogate_pair_into_one_character() {
    assert_eq!(parse(r#""😀""#).unwrap(), Value::from("😀"));
}

#[test]
fn parses_non_ascii_text_directly() {
    assert_eq!(parse("\"日本語\"").unwrap(), Value::from("日本語"));
}

#[test]
fn parses_arrays() {
    assert_eq!(parse("[]").unwrap(), Value::Array(vec![]));
    assert_eq!(
        parse("[1, 2, 3]").unwrap(),
        Value::Array(vec![Value::Int(1), Value::Int(2), Value::Int(3)])
    );
    assert_eq!(
        parse(r#"[null, true, "x", [1]]"#).unwrap(),
        Value::Array(vec![
            Value::Null,
            Value::Bool(true),
            Value::from("x"),
            Value::Array(vec![Value::Int(1)]),
        ])
    );
}

#[test]
fn parses_objects_and_looks_up_fields() {
    let value = parse(r#"{"key": "DB_URL", "value": "postgres://x", "n": 3}"#).unwrap();

    assert_eq!(value.get("key").and_then(Value::as_str), Some("DB_URL"));
    assert_eq!(
        value.get("value").and_then(Value::as_str),
        Some("postgres://x")
    );
    assert_eq!(value.get("n").and_then(Value::as_i64), Some(3));
    assert_eq!(value.get("missing"), None);
}

#[test]
fn parses_an_empty_object() {
    assert_eq!(parse("{}").unwrap(), Value::Object(vec![]));
}

#[test]
fn ignores_insignificant_whitespace() {
    let value = parse(" \t\r\n { \"a\" : [ 1 , 2 ] } \n ").unwrap();
    assert_eq!(
        value.get("a"),
        Some(&Value::Array(vec![Value::Int(1), Value::Int(2)]))
    );
}

#[test]
fn rejects_trailing_content() {
    assert!(matches!(parse("1 2"), Err(JsonError::TrailingContent)));
    assert!(matches!(parse("{} {}"), Err(JsonError::TrailingContent)));
}

#[test]
fn rejects_empty_input() {
    assert!(matches!(parse(""), Err(JsonError::UnexpectedEnd)));
    assert!(matches!(parse("   "), Err(JsonError::UnexpectedEnd)));
}

#[test]
fn rejects_duplicate_object_keys() {
    // Accepting these invites parser-differential bugs: two readers can
    // disagree about which value won.
    assert!(matches!(
        parse(r#"{"a": 1, "a": 2}"#),
        Err(JsonError::DuplicateKey(_))
    ));
}

#[test]
fn rejects_trailing_commas() {
    assert!(parse("[1, 2,]").is_err());
    assert!(parse(r#"{"a": 1,}"#).is_err());
}

#[test]
fn rejects_malformed_numbers() {
    assert!(parse("01").is_err(), "leading zero");
    assert!(parse("-").is_err());
    assert!(parse("1.").is_err());
    assert!(parse(".5").is_err());
    assert!(parse("1e").is_err());
    assert!(parse("+1").is_err());
    assert!(parse("NaN").is_err());
    assert!(parse("Infinity").is_err());
}

#[test]
fn rejects_malformed_strings() {
    assert!(parse(r#""unterminated"#).is_err());
    assert!(parse(r#""bad \q escape""#).is_err());
    assert!(parse(r#""short \u12""#).is_err());
    assert!(parse(r#""bad \uZZZZ""#).is_err());
    assert!(parse("\"raw \u{1} control\"").is_err());
    assert!(parse("\"raw \n newline\"").is_err());
}

#[test]
fn rejects_a_lone_surrogate() {
    assert!(parse(r#""\ud83d""#).is_err());
    assert!(parse(r#""\ude00\ud83d""#).is_err());
}

#[test]
fn rejects_malformed_structures() {
    assert!(parse("[1, 2").is_err());
    assert!(parse(r#"{"a" 1}"#).is_err());
    assert!(parse(r#"{"a": }"#).is_err());
    assert!(parse("{a: 1}").is_err());
    assert!(parse("[,]").is_err());
    assert!(parse("}").is_err());
}

#[test]
fn rejects_deeply_nested_input_instead_of_overflowing_the_stack() {
    // A request body is attacker controlled; recursion has to be bounded.
    let deep = "[".repeat(10_000) + &"]".repeat(10_000);
    assert!(matches!(parse(&deep), Err(JsonError::TooDeep)));
}

#[test]
fn accepts_nesting_up_to_the_documented_limit() {
    let depth = ls_json::MAX_DEPTH;
    let ok = "[".repeat(depth) + &"]".repeat(depth);
    assert!(parse(&ok).is_ok(), "depth {depth} should be accepted");

    let too_much = "[".repeat(depth + 1) + &"]".repeat(depth + 1);
    assert!(matches!(parse(&too_much), Err(JsonError::TooDeep)));
}
