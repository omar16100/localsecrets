#![allow(clippy::unwrap_used, clippy::expect_used)]

use ls_core::time::Timestamp;

/// Seconds since the epoch, and the RFC 3339 text they must produce.
const VECTORS: &[(i64, &str)] = &[
    (0, "1970-01-01T00:00:00Z"),
    (1, "1970-01-01T00:00:01Z"),
    (59, "1970-01-01T00:00:59Z"),
    (60, "1970-01-01T00:01:00Z"),
    (3599, "1970-01-01T00:59:59Z"),
    (3600, "1970-01-01T01:00:00Z"),
    (86_399, "1970-01-01T23:59:59Z"),
    (86_400, "1970-01-02T00:00:00Z"),
    // 1972 was a leap year: 29 February existed.
    (68_169_600, "1972-02-29T00:00:00Z"),
    // 1900 was not a leap year but 2000 was, which is where naive rules break.
    (951_782_400, "2000-02-29T00:00:00Z"),
    (951_868_800, "2000-03-01T00:00:00Z"),
    (1_709_164_800, "2024-02-29T00:00:00Z"),
    (1_000_000_000, "2001-09-09T01:46:40Z"),
    (1_757_635_200, "2025-09-12T00:00:00Z"),
    (2_147_483_647, "2038-01-19T03:14:07Z"),
    // Before the epoch, where naive integer division goes wrong.
    (-1, "1969-12-31T23:59:59Z"),
    (-86_400, "1969-12-31T00:00:00Z"),
];

#[test]
fn renders_the_known_vectors() {
    for (seconds, text) in VECTORS {
        assert_eq!(
            Timestamp::from_unix(*seconds).to_rfc3339(),
            *text,
            "rendering {seconds}"
        );
    }
}

#[test]
fn parses_the_known_vectors() {
    for (seconds, text) in VECTORS {
        assert_eq!(
            Timestamp::parse_rfc3339(text).map(Timestamp::unix_seconds),
            Some(*seconds),
            "parsing {text}"
        );
    }
}

#[test]
fn round_trips_every_day_across_two_centuries() {
    // One sample per day is cheap and catches leap-year and month-length bugs.
    let mut seconds = -3_000_000_000i64;
    while seconds < 4_000_000_000 {
        let text = Timestamp::from_unix(seconds).to_rfc3339();
        assert_eq!(
            Timestamp::parse_rfc3339(&text).map(Timestamp::unix_seconds),
            Some(seconds),
            "round trip failed at {seconds} ({text})"
        );
        seconds += 86_400 + 3_607;
    }
}

#[test]
fn rejects_text_that_is_not_a_timestamp() {
    assert_eq!(Timestamp::parse_rfc3339(""), None);
    assert_eq!(Timestamp::parse_rfc3339("not a time"), None);
    assert_eq!(Timestamp::parse_rfc3339("2026-09-12"), None);
    assert_eq!(Timestamp::parse_rfc3339("2026-09-12T00:00:00"), None, "no zone");
    assert_eq!(Timestamp::parse_rfc3339("2026-09-12 00:00:00Z"), None, "no T");
    assert_eq!(Timestamp::parse_rfc3339("2026-13-01T00:00:00Z"), None, "month 13");
    assert_eq!(Timestamp::parse_rfc3339("2026-00-01T00:00:00Z"), None, "month 0");
    assert_eq!(Timestamp::parse_rfc3339("2026-09-31T00:00:00Z"), None, "31 September");
    assert_eq!(Timestamp::parse_rfc3339("2025-02-29T00:00:00Z"), None, "not a leap year");
    assert_eq!(Timestamp::parse_rfc3339("2026-09-12T24:00:00Z"), None, "hour 24");
    assert_eq!(Timestamp::parse_rfc3339("2026-09-12T00:60:00Z"), None, "minute 60");
    assert_eq!(Timestamp::parse_rfc3339("2026-09-12T00:00:60Z"), None, "second 60");
    assert_eq!(Timestamp::parse_rfc3339("2026-9-12T00:00:00Z"), None, "unpadded");
    assert_eq!(Timestamp::parse_rfc3339("2026-09-12T00:00:00Z "), None, "trailing space");
}

#[test]
fn accepts_the_leap_year_rule_at_century_boundaries() {
    assert!(Timestamp::parse_rfc3339("2000-02-29T00:00:00Z").is_some());
    assert_eq!(Timestamp::parse_rfc3339("2100-02-29T00:00:00Z"), None);
    assert!(Timestamp::parse_rfc3339("2400-02-29T00:00:00Z").is_some());
}

#[test]
fn timestamps_compare_in_time_order() {
    let earlier = Timestamp::from_unix(1_000);
    let later = Timestamp::from_unix(2_000);

    assert!(earlier < later);
    assert_eq!(later.unix_seconds() - earlier.unix_seconds(), 1_000);
}

#[test]
fn now_is_somewhere_plausible() {
    // Between 2020 and 2100. Loose on purpose: this is a sanity check on the
    // clock reading, not on the clock.
    let now = Timestamp::now().unix_seconds();
    assert!(
        (1_577_836_800..4_102_444_800).contains(&now),
        "clock returned {now}"
    );
}

#[test]
fn a_timestamp_can_be_moved_forward_by_a_duration() {
    let start = Timestamp::from_unix(1_000);
    assert_eq!(start.plus_seconds(3_600).unix_seconds(), 4_600);
    assert_eq!(start.plus_seconds(-1_000).unix_seconds(), 0);
}

#[test]
fn display_is_the_rfc_3339_form() {
    assert_eq!(
        Timestamp::from_unix(1_757_635_200).to_string(),
        "2025-09-12T00:00:00Z"
    );
}
