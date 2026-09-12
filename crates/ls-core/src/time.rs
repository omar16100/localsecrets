//! UTC timestamps at one-second resolution, rendered as RFC 3339.
//!
//! Small on purpose: this project stores creation times and expiry times, and
//! nothing here needs time zones, sub-second precision or a calendar library.
//!
//! The civil-date conversions follow Howard Hinnant's `days_from_civil` and
//! `civil_from_days`, which are exact for the proleptic Gregorian calendar and
//! behave correctly before 1970, where naive integer division does not.

/// Seconds since the Unix epoch, UTC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(i64);

impl Timestamp {
    /// The current time, read from the system clock.
    ///
    /// A clock set before 1970 yields a negative value rather than an error;
    /// nothing here depends on the clock being right, only on it being read.
    pub fn now() -> Self {
        let epoch = std::time::UNIX_EPOCH;
        match std::time::SystemTime::now().duration_since(epoch) {
            Ok(elapsed) => Self(i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX)),
            Err(before) => Self(-i64::try_from(before.duration().as_secs()).unwrap_or(i64::MAX)),
        }
    }

    /// Build from seconds since the epoch.
    pub const fn from_unix(seconds: i64) -> Self {
        Self(seconds)
    }

    /// Seconds since the epoch.
    pub const fn unix_seconds(self) -> i64 {
        self.0
    }

    /// Move forward (or back, for a negative amount) by whole seconds.
    pub const fn plus_seconds(self, seconds: i64) -> Self {
        Self(self.0.saturating_add(seconds))
    }

    /// Render as `YYYY-MM-DDTHH:MM:SSZ`.
    pub fn to_rfc3339(self) -> String {
        let days = self.0.div_euclid(86_400);
        let second_of_day = self.0.rem_euclid(86_400);
        let (year, month, day) = civil_from_days(days);

        format!(
            "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
            second_of_day / 3600,
            (second_of_day % 3600) / 60,
            second_of_day % 60,
        )
    }

    /// Parse `YYYY-MM-DDTHH:MM:SSZ` exactly. Anything else is `None`.
    pub fn parse_rfc3339(text: &str) -> Option<Self> {
        let bytes = text.as_bytes();
        if bytes.len() != 20 {
            return None;
        }
        if bytes[4] != b'-' || bytes[7] != b'-' || bytes[10] != b'T' {
            return None;
        }
        if bytes[13] != b':' || bytes[16] != b':' || bytes[19] != b'Z' {
            return None;
        }

        let year = number(&bytes[0..4])?;
        let month = number(&bytes[5..7])?;
        let day = number(&bytes[8..10])?;
        let hour = number(&bytes[11..13])?;
        let minute = number(&bytes[14..16])?;
        let second = number(&bytes[17..19])?;

        if !(1..=12).contains(&month) || day < 1 || day > days_in_month(year, month) {
            return None;
        }
        if hour > 23 || minute > 59 || second > 59 {
            return None;
        }

        let days = days_from_civil(year, month as u32, day as u32);
        Some(Self(
            days * 86_400 + hour * 3_600 + minute * 60 + second,
        ))
    }
}

impl std::fmt::Display for Timestamp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_rfc3339())
    }
}

/// Parse a fixed-width run of ASCII digits. Rejects anything else, so an
/// unpadded or signed field does not slip through.
fn number(digits: &[u8]) -> Option<i64> {
    let mut value: i64 = 0;
    for &byte in digits {
        if !byte.is_ascii_digit() {
            return None;
        }
        value = value * 10 + i64::from(byte - b'0');
    }
    Some(value)
}

const fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

const fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

/// Days since 1970-01-01 for a civil date.
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    // Shift the year so that March is the first month, which makes the leap
    // day the last day of the year and removes it from every other calculation.
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;

    let month = i64::from(month);
    let day_of_year = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;

    era * 146_097 + day_of_era - 719_468
}

/// The civil date for a count of days since 1970-01-01.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let days = days + 719_468;
    let era = if days >= 0 { days } else { days - 146_096 } / 146_097;
    let day_of_era = days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = shifted_month + if shifted_month < 10 { 3 } else { -9 };

    (year + i64::from(month <= 2), month, day)
}
