#![allow(clippy::unwrap_used, clippy::expect_used)]

use ls_json::{Value, parse};

#[test]
fn renders_the_literals() {
    assert_eq!(Value::Null.to_string(), "null");
    assert_eq!(Value::Bool(true).to_string(), "true");
    assert_eq!(Value::Bool(false).to_string(), "false");
}

#[test]
fn renders_numbers_without_losing_integer_precision() {
    assert_eq!(Value::Int(0).to_string(), "0");
    assert_eq!(Value::Int(-17).to_string(), "-17");
    assert_eq!(
        Value::Int(i64::MAX).to_string(),
        "9223372036854775807",
        "large integers must not go through f64"
    );
    assert_eq!(Value::Float(1.5).to_string(), "1.5");
}

#[test]
fn renders_a_float_that_happens_to_be_whole_as_valid_json() {
    let rendered = Value::Float(2.0).to_string();
    assert!(
        parse(&rendered).is_ok(),
        "produced invalid JSON: {rendered}"
    );
}

#[test]
fn escapes_the_characters_that_must_be_escaped() {
    assert_eq!(Value::from("a\"b").to_string(), r#""a\"b""#);
    assert_eq!(Value::from("a\\b").to_string(), r#""a\\b""#);
    assert_eq!(Value::from("a\nb").to_string(), r#""a\nb""#);
    assert_eq!(Value::from("a\tb").to_string(), r#""a\tb""#);
    assert_eq!(Value::from("a\rb").to_string(), r#""a\rb""#);
    assert_eq!(Value::from("a\u{8}b").to_string(), r#""a\bb""#);
    assert_eq!(Value::from("a\u{c}b").to_string(), r#""a\fb""#);
}

#[test]
fn escapes_other_control_characters_as_unicode() {
    assert_eq!(Value::from("\u{1}").to_string(), "\"\\u0001\"");
    assert_eq!(Value::from("\u{1f}").to_string(), "\"\\u001f\"");
}

#[test]
fn leaves_non_ascii_text_as_utf8() {
    assert_eq!(Value::from("日本語").to_string(), "\"日本語\"");
    assert_eq!(Value::from("😀").to_string(), "\"😀\"");
}

#[test]
fn renders_arrays_and_objects() {
    assert_eq!(Value::Array(vec![]).to_string(), "[]");
    assert_eq!(
        Value::Array(vec![Value::Int(1), Value::from("x")]).to_string(),
        r#"[1,"x"]"#
    );
    assert_eq!(Value::Object(vec![]).to_string(), "{}");
    assert_eq!(
        Value::object([("a", Value::Int(1)), ("b", Value::Null)]).to_string(),
        r#"{"a":1,"b":null}"#
    );
}

#[test]
fn object_field_order_is_preserved() {
    let value = Value::object([
        ("z", Value::Int(1)),
        ("a", Value::Int(2)),
        ("m", Value::Int(3)),
    ]);
    assert_eq!(value.to_string(), r#"{"z":1,"a":2,"m":3}"#);
}

#[test]
fn everything_it_renders_can_be_parsed_back() {
    let value = Value::object([
        ("null", Value::Null),
        ("bool", Value::Bool(false)),
        ("int", Value::Int(-9_007_199_254_740_993)),
        ("float", Value::Float(0.1)),
        (
            "tricky",
            Value::from("quote \" backslash \\ newline \n tab \t"),
        ),
        ("control", Value::from("\u{0}\u{1f}")),
        ("unicode", Value::from("日本語 😀")),
        (
            "nested",
            Value::Array(vec![Value::object([("deep", Value::Bool(true))])]),
        ),
    ]);

    let rendered = value.to_string();
    assert_eq!(
        parse(&rendered).unwrap(),
        value,
        "round trip failed for {rendered}"
    );
}

#[test]
fn a_string_containing_a_closing_brace_cannot_break_out_of_an_object() {
    let value = Value::object([("k", Value::from(r#"","injected":"yes"#))]);
    let parsed = parse(&value.to_string()).unwrap();

    assert_eq!(parsed.get("injected"), None);
    assert_eq!(
        parsed.get("k").and_then(Value::as_str),
        Some(r#"","injected":"yes"#)
    );
}

#[test]
fn accessors_return_none_for_the_wrong_type() {
    assert_eq!(Value::Int(1).as_str(), None);
    assert_eq!(Value::from("x").as_i64(), None);
    assert_eq!(Value::Null.as_bool(), None);
    assert_eq!(Value::Null.get("anything"), None);
    assert_eq!(Value::from("x").as_array(), None);
}

#[test]
fn accessors_read_the_right_type() {
    assert_eq!(Value::from("x").as_str(), Some("x"));
    assert_eq!(Value::Int(7).as_i64(), Some(7));
    assert_eq!(Value::Bool(true).as_bool(), Some(true));
    assert_eq!(
        Value::Array(vec![Value::Null]).as_array().map(<[_]>::len),
        Some(1)
    );
}
