#![allow(clippy::unwrap_used, clippy::expect_used)]

use ls_core::crypto::aead::DataKey;
use ls_store::{Log, StoreError};
use std::io::Write;
use std::path::PathBuf;

/// A temporary directory that removes itself.
struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("ls-store-{label}-{unique}"));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn file(&self) -> PathBuf {
        self.0.join("store.log")
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn key() -> DataKey {
    DataKey::from_bytes(&[9u8; 32]).unwrap()
}

#[test]
fn opening_a_new_path_creates_an_empty_log() {
    let dir = TempDir::new("create");

    let mut log = Log::open(&dir.file()).unwrap();

    assert_eq!(log.len(), 0);
    assert!(log.read_all(&key()).unwrap().is_empty());
    assert!(dir.file().exists());
}

#[cfg(unix)]
#[test]
fn the_log_file_is_not_readable_by_anyone_else() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = TempDir::new("perms");

    Log::open(&dir.file()).unwrap();

    let mode = std::fs::metadata(dir.file()).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600, "log mode was {:o}", mode & 0o777);
}

#[test]
fn appended_records_come_back_in_order() {
    let dir = TempDir::new("order");
    let mut log = Log::open(&dir.file()).unwrap();

    log.append(&key(), b"first").unwrap();
    log.append(&key(), b"second").unwrap();
    log.append(&key(), b"third").unwrap();

    let records = log.read_all(&key()).unwrap();
    assert_eq!(
        records,
        vec![b"first".to_vec(), b"second".to_vec(), b"third".to_vec()]
    );
    assert_eq!(log.len(), 3);
}

#[test]
fn records_survive_closing_and_reopening() {
    let dir = TempDir::new("reopen");
    {
        let mut log = Log::open(&dir.file()).unwrap();
        log.append(&key(), b"durable").unwrap();
    }

    let mut reopened = Log::open(&dir.file()).unwrap();

    assert_eq!(
        reopened.read_all(&key()).unwrap(),
        vec![b"durable".to_vec()]
    );
}

#[test]
fn appending_to_a_reopened_log_does_not_lose_what_was_there() {
    let dir = TempDir::new("append-after-reopen");
    {
        let mut log = Log::open(&dir.file()).unwrap();
        log.append(&key(), b"before").unwrap();
    }

    let mut log = Log::open(&dir.file()).unwrap();
    log.append(&key(), b"after").unwrap();

    assert_eq!(
        log.read_all(&key()).unwrap(),
        vec![b"before".to_vec(), b"after".to_vec()]
    );
}

#[test]
fn a_plain_record_is_readable_without_any_key() {
    // The barrier record holds the wrapped root key, so it has to be readable
    // before there is a key to read anything else with.
    let dir = TempDir::new("plain");
    let mut log = Log::open(&dir.file()).unwrap();

    log.append_plain(b"barrier").unwrap();
    log.append(&key(), b"sealed").unwrap();

    assert_eq!(log.read_plain().unwrap(), vec![b"barrier".to_vec()]);
}

#[test]
fn read_all_returns_plain_and_sealed_records_together_in_order() {
    let dir = TempDir::new("mixed");
    let mut log = Log::open(&dir.file()).unwrap();

    log.append_plain(b"barrier").unwrap();
    log.append(&key(), b"one").unwrap();
    log.append(&key(), b"two").unwrap();

    assert_eq!(
        log.read_all(&key()).unwrap(),
        vec![b"barrier".to_vec(), b"one".to_vec(), b"two".to_vec()]
    );
}

#[test]
fn the_wrong_key_cannot_read_the_log() {
    let dir = TempDir::new("wrong-key");
    let mut log = Log::open(&dir.file()).unwrap();
    log.append(&key(), b"secret").unwrap();

    let other = DataKey::from_bytes(&[1u8; 32]).unwrap();

    assert!(matches!(
        log.read_all(&other),
        Err(StoreError::Unreadable { .. })
    ));
}

#[test]
fn a_record_cannot_be_moved_to_another_position() {
    // Each record is bound to its sequence number, so replaying a stale record
    // or reordering two of them fails instead of quietly changing the state.
    let dir = TempDir::new("reorder");
    let mut log = Log::open(&dir.file()).unwrap();
    log.append(&key(), b"aaaaaaaa").unwrap();
    log.append(&key(), b"bbbbbbbb").unwrap();
    drop(log);

    let raw = std::fs::read(dir.file()).unwrap();
    let header = ls_store::HEADER_LEN;
    let body = &raw[header..];
    let framed = body.len() / 2;
    let mut swapped = raw[..header].to_vec();
    swapped.extend_from_slice(&body[framed..]);
    swapped.extend_from_slice(&body[..framed]);
    std::fs::write(dir.file(), swapped).unwrap();

    let mut log = Log::open(&dir.file()).unwrap();
    assert!(matches!(
        log.read_all(&key()),
        Err(StoreError::Unreadable { .. })
    ));
}

#[test]
fn an_edited_record_is_refused_rather_than_skipped() {
    let dir = TempDir::new("tamper");
    let mut log = Log::open(&dir.file()).unwrap();
    log.append(&key(), b"important").unwrap();
    drop(log);

    let mut raw = std::fs::read(dir.file()).unwrap();
    let last = raw.len() - 1;
    raw[last] ^= 0x01;
    std::fs::write(dir.file(), raw).unwrap();

    let mut log = Log::open(&dir.file()).unwrap();
    assert!(
        matches!(log.read_all(&key()), Err(StoreError::Unreadable { .. })),
        "a tampered record must stop the replay, not be skipped"
    );
}

#[test]
fn a_half_written_record_at_the_end_is_dropped() {
    // A crash during an append leaves a partial record. Everything before it is
    // still good, and the partial tail is discarded.
    let dir = TempDir::new("torn");
    let mut log = Log::open(&dir.file()).unwrap();
    log.append(&key(), b"complete").unwrap();
    drop(log);

    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(dir.file())
        .unwrap();
    file.write_all(&[0, 0, 0, 200, 1, 2, 3]).unwrap();
    drop(file);

    let mut log = Log::open(&dir.file()).unwrap();

    assert_eq!(log.read_all(&key()).unwrap(), vec![b"complete".to_vec()]);
    assert_eq!(log.len(), 1);
}

#[test]
fn a_repaired_log_can_be_appended_to_again() {
    let dir = TempDir::new("repair");
    let mut log = Log::open(&dir.file()).unwrap();
    log.append(&key(), b"complete").unwrap();
    drop(log);

    std::fs::OpenOptions::new()
        .append(true)
        .open(dir.file())
        .unwrap()
        .write_all(&[0, 0, 0, 200, 1])
        .unwrap();

    let mut log = Log::open(&dir.file()).unwrap();
    log.append(&key(), b"after repair").unwrap();

    assert_eq!(
        log.read_all(&key()).unwrap(),
        vec![b"complete".to_vec(), b"after repair".to_vec()]
    );
}

#[test]
fn a_file_that_is_not_a_log_is_refused() {
    let dir = TempDir::new("not-a-log");
    std::fs::write(dir.file(), b"this is not a localsecrets log at all").unwrap();

    assert!(matches!(Log::open(&dir.file()), Err(StoreError::NotALog)));
}

#[test]
fn a_log_written_by_a_newer_version_is_refused() {
    let dir = TempDir::new("future");
    Log::open(&dir.file()).unwrap();

    let mut raw = std::fs::read(dir.file()).unwrap();
    raw[ls_store::HEADER_LEN - 1] = 99;
    std::fs::write(dir.file(), raw).unwrap();

    assert!(matches!(
        Log::open(&dir.file()),
        Err(StoreError::UnsupportedVersion(99))
    ));
}

#[test]
fn an_oversized_record_is_refused() {
    let dir = TempDir::new("oversized");
    let mut log = Log::open(&dir.file()).unwrap();

    let huge = vec![b'x'; ls_store::MAX_RECORD_LEN + 1];

    assert!(matches!(
        log.append(&key(), &huge),
        Err(StoreError::RecordTooLarge { .. })
    ));
    assert_eq!(log.len(), 0, "a refused record must not be written");
}

#[test]
fn compaction_keeps_the_records_it_is_given_and_drops_the_rest() {
    let dir = TempDir::new("compact");
    let mut log = Log::open(&dir.file()).unwrap();
    log.append_plain(b"barrier").unwrap();
    for i in 0..20 {
        log.append(&key(), format!("record {i}").as_bytes())
            .unwrap();
    }
    let before = std::fs::metadata(dir.file()).unwrap().len();

    log.compact(&key(), &[b"barrier".to_vec()], &[b"kept".to_vec()])
        .unwrap();

    assert_eq!(
        log.read_all(&key()).unwrap(),
        vec![b"barrier".to_vec(), b"kept".to_vec()]
    );
    assert!(
        std::fs::metadata(dir.file()).unwrap().len() < before,
        "compaction should shrink the file"
    );
}

#[test]
fn a_compacted_log_survives_reopening() {
    let dir = TempDir::new("compact-reopen");
    let mut log = Log::open(&dir.file()).unwrap();
    log.append(&key(), b"old").unwrap();
    log.compact(&key(), &[], &[b"new".to_vec()]).unwrap();
    drop(log);

    let mut reopened = Log::open(&dir.file()).unwrap();

    assert_eq!(reopened.read_all(&key()).unwrap(), vec![b"new".to_vec()]);
}

#[test]
fn an_empty_record_round_trips() {
    let dir = TempDir::new("empty-record");
    let mut log = Log::open(&dir.file()).unwrap();

    log.append(&key(), b"").unwrap();

    assert_eq!(log.read_all(&key()).unwrap(), vec![Vec::<u8>::new()]);
}

#[test]
fn the_file_on_disk_never_contains_a_sealed_payload_in_the_clear() {
    let dir = TempDir::new("at-rest");
    let mut log = Log::open(&dir.file()).unwrap();

    log.append(&key(), b"postgres://user:pw@host/db").unwrap();

    let raw = std::fs::read(dir.file()).unwrap();
    assert!(
        !raw.windows(8).any(|w| w == b"postgres"),
        "payload is readable at rest"
    );
}
