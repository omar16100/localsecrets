#![allow(clippy::unwrap_used, clippy::expect_used)]

use ls_core::crypto::shamir::{self, Share, ShamirError};

const SECRET: &[u8] = b"0123456789abcdef0123456789abcdef";

/// Every combination of `k` items from `items`, as index lists.
fn combinations(n: usize, k: usize) -> Vec<Vec<usize>> {
    if k == 0 {
        return vec![vec![]];
    }
    if n < k {
        return vec![];
    }
    let mut out = Vec::new();
    for first in 0..=(n - k) {
        for mut rest in combinations(n - first - 1, k - 1) {
            for r in &mut rest {
                *r += first + 1;
            }
            let mut combo = vec![first];
            combo.extend(rest);
            out.push(combo);
        }
    }
    out
}

#[test]
fn splitting_produces_the_requested_number_of_shares() {
    let shares = shamir::split(SECRET, 3, 5).unwrap();
    assert_eq!(shares.len(), 5);
}

#[test]
fn no_share_is_ever_issued_at_index_zero() {
    // x = 0 evaluates the polynomial at the secret itself.
    let shares = shamir::split(SECRET, 3, 5).unwrap();
    assert!(shares.iter().all(|s| s.index() != 0));
}

#[test]
fn share_indexes_are_distinct() {
    let shares = shamir::split(SECRET, 3, 255).unwrap();
    let mut seen: Vec<u8> = shares.iter().map(Share::index).collect();
    seen.sort_unstable();
    seen.dedup();
    assert_eq!(seen.len(), 255);
}

#[test]
fn a_single_share_does_not_reveal_the_secret() {
    let shares = shamir::split(SECRET, 3, 5).unwrap();
    for share in &shares {
        assert_ne!(share.data(), SECRET);
    }
}

#[test]
fn any_threshold_subset_recovers_the_secret() {
    let shares = shamir::split(SECRET, 3, 5).unwrap();

    for combo in combinations(5, 3) {
        let subset: Vec<Share> = combo.iter().map(|&i| shares[i].clone()).collect();
        assert_eq!(
            shamir::combine(&subset).unwrap().as_slice(),
            SECRET,
            "subset {combo:?} failed to recombine"
        );
    }
}

#[test]
fn more_than_the_threshold_also_recovers_the_secret() {
    let shares = shamir::split(SECRET, 3, 5).unwrap();
    assert_eq!(shamir::combine(&shares).unwrap().as_slice(), SECRET);
}

#[test]
fn fewer_than_the_threshold_does_not_recover_the_secret() {
    let shares = shamir::split(SECRET, 3, 5).unwrap();

    for combo in combinations(5, 2) {
        let subset: Vec<Share> = combo.iter().map(|&i| shares[i].clone()).collect();
        assert_ne!(
            shamir::combine(&subset).unwrap().as_slice(),
            SECRET,
            "subset {combo:?} recovered the secret below the threshold"
        );
    }
}

#[test]
fn a_threshold_of_one_makes_every_share_the_secret() {
    let shares = shamir::split(SECRET, 1, 3).unwrap();
    for share in &shares {
        assert_eq!(
            shamir::combine(std::slice::from_ref(share)).unwrap().as_slice(),
            SECRET
        );
    }
}

#[test]
fn secrets_of_any_length_round_trip() {
    for len in [1usize, 2, 15, 16, 31, 32, 64, 257] {
        let secret: Vec<u8> = (0..len).map(|i| (i * 31 + 7) as u8).collect();
        let shares = shamir::split(&secret, 2, 3).unwrap();
        assert_eq!(
            shamir::combine(&shares[..2]).unwrap().as_slice(),
            secret,
            "length {len}"
        );
    }
}

#[test]
fn an_all_zero_secret_round_trips() {
    let secret = vec![0u8; 32];
    let shares = shamir::split(&secret, 3, 5).unwrap();
    assert_eq!(shamir::combine(&shares[..3]).unwrap().as_slice(), secret);
}

#[test]
fn splitting_rejects_nonsensical_parameters() {
    assert!(matches!(
        shamir::split(SECRET, 0, 5),
        Err(ShamirError::ThresholdTooLow)
    ));
    assert!(matches!(
        shamir::split(SECRET, 6, 5),
        Err(ShamirError::ThresholdAboveShareCount { .. })
    ));
    assert!(matches!(
        shamir::split(SECRET, 1, 0),
        Err(ShamirError::ThresholdAboveShareCount { .. })
    ));
    assert!(matches!(
        shamir::split(b"", 2, 3),
        Err(ShamirError::EmptySecret)
    ));
}

#[test]
fn combining_rejects_an_empty_set() {
    assert!(matches!(
        shamir::combine(&[]),
        Err(ShamirError::NotEnoughShares)
    ));
}

#[test]
fn combining_rejects_a_repeated_share() {
    let shares = shamir::split(SECRET, 3, 5).unwrap();
    let repeated = vec![shares[0].clone(), shares[0].clone(), shares[1].clone()];

    assert!(matches!(
        shamir::combine(&repeated),
        Err(ShamirError::DuplicateIndex(_))
    ));
}

#[test]
fn combining_rejects_shares_of_different_lengths() {
    let a = shamir::split(SECRET, 2, 3).unwrap();
    let b = shamir::split(b"shorter secret", 2, 3).unwrap();

    assert!(matches!(
        shamir::combine(&[a[0].clone(), b[1].clone()]),
        Err(ShamirError::LengthMismatch)
    ));
}

#[test]
fn a_share_round_trips_through_its_printed_form() {
    let shares = shamir::split(SECRET, 3, 5).unwrap();

    for share in &shares {
        let printed = share.to_string();
        let parsed = Share::parse(&printed).unwrap();
        assert_eq!(parsed.index(), share.index());
        assert_eq!(parsed.data(), share.data());
    }
}

#[test]
fn a_printed_share_is_recognisable_and_carries_its_index() {
    let shares = shamir::split(SECRET, 2, 3).unwrap();
    let printed = shares[0].to_string();

    assert!(printed.starts_with("lss1."), "got {printed}");
    assert!(printed.contains(&format!(".{}.", shares[0].index())));
}

#[test]
fn a_mistyped_share_is_caught_by_its_checksum() {
    let shares = shamir::split(SECRET, 3, 5).unwrap();
    let printed = shares[0].to_string();

    // Flip one character of the payload.
    let parts: Vec<&str> = printed.split('.').collect();
    let mut payload: Vec<char> = parts[2].chars().collect();
    payload[0] = if payload[0] == 'A' { 'B' } else { 'A' };
    let mangled = format!(
        "{}.{}.{}.{}",
        parts[0],
        parts[1],
        payload.into_iter().collect::<String>(),
        parts[3]
    );

    assert!(matches!(
        Share::parse(&mangled),
        Err(ShamirError::ChecksumMismatch)
    ));
}

#[test]
fn a_share_with_a_swapped_index_is_caught_by_its_checksum() {
    let shares = shamir::split(SECRET, 3, 5).unwrap();
    let parts: Vec<String> = shares[0].to_string().split('.').map(String::from).collect();
    let mangled = format!("{}.{}.{}.{}", parts[0], 9, parts[2], parts[3]);

    assert!(matches!(
        Share::parse(&mangled),
        Err(ShamirError::ChecksumMismatch)
    ));
}

#[test]
fn malformed_share_strings_are_rejected() {
    assert!(matches!(
        Share::parse("nonsense"),
        Err(ShamirError::MalformedShare)
    ));
    assert!(matches!(
        Share::parse("lss2.1.AAAA.00000000"),
        Err(ShamirError::MalformedShare)
    ));
    assert!(matches!(
        Share::parse("lss1.0.AAAA.00000000"),
        Err(ShamirError::MalformedShare)
    ));
    assert!(matches!(
        Share::parse("lss1.1.not base64.00000000"),
        Err(ShamirError::MalformedShare)
    ));
    assert!(matches!(Share::parse(""), Err(ShamirError::MalformedShare)));
}

#[test]
fn a_printed_share_never_contains_the_secret() {
    let shares = shamir::split(SECRET, 3, 5).unwrap();
    for share in &shares {
        assert!(!share.to_string().contains("0123456789abcdef"));
    }
}

#[test]
fn debug_output_never_prints_share_data() {
    let shares = shamir::split(SECRET, 3, 5).unwrap();
    let rendered = format!("{:?}", shares[0]);
    let payload = ls_core::encoding::hex::encode(shares[0].data());
    assert!(!rendered.contains(&payload), "share leaked via Debug: {rendered}");
}

#[test]
fn shares_at_the_highest_indexes_still_interpolate() {
    let shares = shamir::split(SECRET, 3, 255).unwrap();
    let top: Vec<Share> = shares[252..].to_vec();

    assert_eq!(top.iter().map(Share::index).collect::<Vec<_>>(), vec![253, 254, 255]);
    assert_eq!(shamir::combine(&top).unwrap().as_slice(), SECRET);
}

#[test]
fn shares_recombine_after_a_round_trip_through_their_printed_form() {
    let printed: Vec<String> = shamir::split(SECRET, 3, 5)
        .unwrap()
        .iter()
        .map(ToString::to_string)
        .collect();

    let parsed: Vec<Share> = printed[1..4]
        .iter()
        .map(|p| Share::parse(p).unwrap())
        .collect();

    assert_eq!(shamir::combine(&parsed).unwrap().as_slice(), SECRET);
}
