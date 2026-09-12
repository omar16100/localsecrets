//! The JSON value type and its rendering.

/// A JSON value.
///
/// Objects keep their fields in insertion order and are searched linearly.
/// Request and response bodies here hold a handful of fields, so an ordered
/// list is simpler than a map and renders deterministically.
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    /// `null`.
    Null,
    /// `true` or `false`.
    Bool(bool),
    /// A whole number. Kept separate from [`Value::Float`] so large integers
    /// survive a round trip that `f64` would round.
    Int(i64),
    /// A number with a fraction or exponent.
    Float(f64),
    /// A string.
    String(String),
    /// An array.
    Array(Vec<Value>),
    /// An object, in insertion order.
    Object(Vec<(String, Value)>),
}

impl Value {
    /// Build an object from pairs.
    pub fn object<K: Into<String>, I: IntoIterator<Item = (K, Value)>>(fields: I) -> Self {
        Self::Object(
            fields
                .into_iter()
                .map(|(name, value)| (name.into(), value))
                .collect(),
        )
    }

    /// Look up an object field. `None` for any other kind of value.
    pub fn get(&self, name: &str) -> Option<&Value> {
        match self {
            Self::Object(fields) => fields
                .iter()
                .find(|(field, _)| field == name)
                .map(|(_, value)| value),
            _ => None,
        }
    }

    /// The string, if this is one.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(s) => Some(s),
            _ => None,
        }
    }

    /// The integer, if this is one. Floats are not coerced.
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Self::Int(i) => Some(*i),
            _ => None,
        }
    }

    /// The boolean, if this is one.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// The array, if this is one.
    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Self::Array(items) => Some(items),
            _ => None,
        }
    }
}

impl From<&str> for Value {
    fn from(s: &str) -> Self {
        Self::String(s.to_owned())
    }
}

impl From<String> for Value {
    fn from(s: String) -> Self {
        Self::String(s)
    }
}

impl From<bool> for Value {
    fn from(b: bool) -> Self {
        Self::Bool(b)
    }
}

impl From<i64> for Value {
    fn from(i: i64) -> Self {
        Self::Int(i)
    }
}

impl From<usize> for Value {
    fn from(n: usize) -> Self {
        Self::Int(i64::try_from(n).unwrap_or(i64::MAX))
    }
}

impl std::fmt::Display for Value {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Null => f.write_str("null"),
            Self::Bool(true) => f.write_str("true"),
            Self::Bool(false) => f.write_str("false"),
            Self::Int(i) => write!(f, "{i}"),
            // JSON has no way to write a NaN or an infinity, so those become
            // null rather than something that will not parse back.
            Self::Float(x) if !x.is_finite() => f.write_str("null"),
            Self::Float(x) => write!(f, "{x}"),
            Self::String(s) => write_string(f, s),
            Self::Array(items) => {
                f.write_str("[")?;
                for (position, item) in items.iter().enumerate() {
                    if position > 0 {
                        f.write_str(",")?;
                    }
                    write!(f, "{item}")?;
                }
                f.write_str("]")
            }
            Self::Object(fields) => {
                f.write_str("{")?;
                for (position, (name, value)) in fields.iter().enumerate() {
                    if position > 0 {
                        f.write_str(",")?;
                    }
                    write_string(f, name)?;
                    write!(f, ":{value}")?;
                }
                f.write_str("}")
            }
        }
    }
}

fn write_string(f: &mut std::fmt::Formatter<'_>, s: &str) -> std::fmt::Result {
    f.write_str("\"")?;
    for c in s.chars() {
        match c {
            '"' => f.write_str("\\\"")?,
            '\\' => f.write_str("\\\\")?,
            '\n' => f.write_str("\\n")?,
            '\r' => f.write_str("\\r")?,
            '\t' => f.write_str("\\t")?,
            '\u{8}' => f.write_str("\\b")?,
            '\u{c}' => f.write_str("\\f")?,
            c if (c as u32) < 0x20 => write!(f, "\\u{:04x}", c as u32)?,
            c => f.write_char(c)?,
        }
    }
    f.write_str("\"")
}

use std::fmt::Write as _;
