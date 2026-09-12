//! The append-only log file.
//!
//! Layout:
//!
//! ```text
//! header:  "LSLOG1" 0x00 <format version>          8 bytes
//! record:  <length: u32 be> <kind: u8> <payload>   length counts kind + payload
//! ```
//!
//! `kind` is 0 for a plain record and 1 for a sealed one. A sealed payload is a
//! 12-byte nonce followed by AES-256-GCM ciphertext, with associated data that
//! names the file format and the record's sequence number. That binding is what
//! makes a reordered or replayed record fail rather than quietly take effect.

use crate::{HEADER_LEN, MAX_RECORD_LEN, StoreError};
use ls_core::crypto::aead::{Aad, DataKey, Envelope, NONCE_LEN};
use std::fs::{File, OpenOptions};
use std::io::{BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

const MAGIC: &[u8; 6] = b"LSLOG1";
const FORMAT_VERSION: u8 = 1;

const KIND_PLAIN: u8 = 0;
const KIND_SEALED: u8 = 1;

/// One record read back from the log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// Whether it was stored sealed. The barrier is the only plain record.
    pub sealed: bool,
    /// The payload, decrypted if it was sealed.
    pub payload: Vec<u8>,
}

/// An open append-only log.
#[derive(Debug)]
pub struct Log {
    path: PathBuf,
    file: File,
    count: usize,
    /// Set when an append failed partway. The record count can no longer be
    /// trusted, and since every record is sealed against its position, writing
    /// another one could reuse a sequence number and make the log unreadable.
    broken: bool,
    /// Whether opening this log had to discard a partial record.
    repaired: bool,
}

impl Log {
    /// Open a log, creating it if it is not there.
    ///
    /// A partial record left by a crash is truncated away, so the file is
    /// always left in a state that can be appended to.
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        let existed = path.exists();
        let mut file = open_private(path)?;

        if !existed || file.metadata()?.len() == 0 {
            let mut header = Vec::with_capacity(HEADER_LEN);
            header.extend_from_slice(MAGIC);
            header.push(0);
            header.push(FORMAT_VERSION);
            file.write_all(&header)?;
            file.sync_data()?;
            return Ok(Self {
                path: path.to_path_buf(),
                file,
                count: 0,
                broken: false,
                repaired: false,
            });
        }

        check_header(&mut file)?;
        let (count, good_len) = scan(&mut file)?;

        let repaired = file.metadata()?.len() != good_len;
        if repaired {
            // A crash during an append. Everything before the partial record is
            // intact, so keep that and drop the tail.
            //
            // This cannot tell a crash from someone editing the last record's
            // length: both look like a tail that does not parse. An attacker
            // with write access to this file can therefore roll the last
            // record back, which is stated plainly in docs/security.md.
            file.set_len(good_len)?;
            file.sync_data()?;
        }
        file.seek(SeekFrom::End(0))?;

        Ok(Self {
            path: path.to_path_buf(),
            file,
            count,
            broken: false,
            repaired,
        })
    }

    /// How many records the log holds.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Whether the log holds no records.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Whether opening this log discarded a partial record at the end.
    ///
    /// Worth telling the operator about: it means either a crash during a
    /// write, or someone editing the file.
    pub fn repaired(&self) -> bool {
        self.repaired
    }

    /// Append a record readable without a key. Only the barrier uses this.
    pub fn append_plain(&mut self, payload: &[u8]) -> Result<(), StoreError> {
        self.write_record(KIND_PLAIN, payload)
    }

    /// Append a record sealed under `key`.
    pub fn append(&mut self, key: &DataKey, payload: &[u8]) -> Result<(), StoreError> {
        if payload.len() > MAX_RECORD_LEN {
            return Err(StoreError::RecordTooLarge {
                len: payload.len(),
                limit: MAX_RECORD_LEN,
            });
        }

        let sealed = seal(key, self.count, payload)?;
        self.write_record(KIND_SEALED, &sealed)
    }

    /// Every record that can be read without a key, in order.
    ///
    /// Sealed records are stepped over rather than decrypted, so this works on
    /// a sealed server.
    pub fn read_plain(&mut self) -> Result<Vec<Vec<u8>>, StoreError> {
        let mut out = Vec::new();
        for_each_record(&self.path, |_, kind, payload| {
            if kind == KIND_PLAIN {
                out.push(payload.to_vec());
            }
            Ok(())
        })?;
        Ok(out)
    }

    /// Every record in order, decrypting the sealed ones with `key`.
    pub fn read_all(&mut self, key: &DataKey) -> Result<Vec<Vec<u8>>, StoreError> {
        Ok(self
            .read_records(key)?
            .into_iter()
            .map(|record| record.payload)
            .collect())
    }

    /// Every record in order, keeping track of which were sealed.
    ///
    /// A replay needs the distinction: the barrier is stored plain and is not
    /// an event, so it has to be stepped over rather than parsed.
    pub fn read_records(&mut self, key: &DataKey) -> Result<Vec<Record>, StoreError> {
        let mut out = Vec::new();
        for_each_record(&self.path, |sequence, kind, payload| {
            if kind == KIND_PLAIN {
                out.push(Record {
                    sealed: false,
                    payload: payload.to_vec(),
                });
            } else {
                out.push(Record {
                    sealed: true,
                    payload: open(key, sequence, payload)?,
                });
            }
            Ok(())
        })?;
        Ok(out)
    }

    /// Rewrite the log with only these records, discarding the history.
    ///
    /// The new file is built beside the old one and renamed over it, so an
    /// interrupted compaction leaves the original untouched.
    pub fn compact(
        &mut self,
        key: &DataKey,
        plain: &[Vec<u8>],
        sealed: &[Vec<u8>],
    ) -> Result<(), StoreError> {
        let temporary = self.path.with_extension("compacting");
        {
            let mut fresh = Log::open(&temporary)?;
            fresh.file.set_len(HEADER_LEN as u64)?;
            fresh.file.seek(SeekFrom::End(0))?;
            fresh.count = 0;

            for record in plain {
                fresh.append_plain(record)?;
            }
            for record in sealed {
                fresh.append(key, record)?;
            }
            fresh.file.sync_all()?;
        }

        std::fs::rename(&temporary, &self.path)?;

        let reopened = Log::open(&self.path)?;
        self.file = reopened.file;
        self.count = reopened.count;
        self.broken = false;
        Ok(())
    }

    fn write_record(&mut self, kind: u8, payload: &[u8]) -> Result<(), StoreError> {
        if self.broken {
            return Err(StoreError::Broken);
        }

        let length = payload.len() + 1;
        if length > MAX_RECORD_LEN {
            // Refused before anything was written, so the log is still fine.
            return Err(StoreError::RecordTooLarge {
                len: payload.len(),
                limit: MAX_RECORD_LEN,
            });
        }

        // One write, so a torn record can only ever be a torn tail.
        let mut framed = Vec::with_capacity(4 + length);
        framed.extend_from_slice(&(length as u32).to_be_bytes());
        framed.push(kind);
        framed.extend_from_slice(payload);

        // Past this point a failure may have left part of a record on disk, so
        // the count is no longer reliable and nothing more may be appended
        // until the log is reopened and rescanned.
        if let Err(error) = self
            .file
            .write_all(&framed)
            .and_then(|()| self.file.sync_data())
        {
            self.broken = true;
            return Err(StoreError::Io(error));
        }

        self.count += 1;
        Ok(())
    }
}

/// Open with owner-only permissions, creating the file if needed.
fn open_private(path: &Path) -> Result<File, StoreError> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }

    Ok(options.open(path)?)
}

fn check_header(file: &mut File) -> Result<(), StoreError> {
    file.seek(SeekFrom::Start(0))?;
    let mut header = [0u8; HEADER_LEN];
    file.read_exact(&mut header)
        .map_err(|_| StoreError::NotALog)?;

    if &header[..MAGIC.len()] != MAGIC {
        return Err(StoreError::NotALog);
    }
    if header[HEADER_LEN - 1] != FORMAT_VERSION {
        return Err(StoreError::UnsupportedVersion(header[HEADER_LEN - 1]));
    }
    Ok(())
}

/// Walk the frames, returning the record count and the length of the last
/// complete record. Nothing is decrypted here.
///
/// The distinction that matters is between a write interrupted by a crash and a
/// file that has been edited. An interrupted write leaves a *prefix* of a frame
/// this code wrote, so its length field is either incomplete or valid. A length
/// field that is complete and impossible cannot have come from here, and is
/// refused rather than quietly treated as a torn tail: doing the latter would
/// let anyone drop the last record by changing four bytes.
fn scan(file: &mut File) -> Result<(usize, u64), StoreError> {
    file.seek(SeekFrom::Start(HEADER_LEN as u64))?;
    let mut reader = BufReader::new(file);

    let mut count = 0usize;
    let mut good_len = HEADER_LEN as u64;

    loop {
        let mut length_bytes = [0u8; 4];
        // A clean end, or too few bytes to be a length field: an interrupted
        // write, which the caller truncates away.
        if read_fully(&mut reader, &mut length_bytes)? < length_bytes.len() {
            return Ok((count, good_len));
        }

        let length = u32::from_be_bytes(length_bytes) as usize;
        if length == 0 {
            return Err(StoreError::Corrupt {
                at: good_len,
                why: "a record frame claims to be empty",
            });
        }
        if length > MAX_RECORD_LEN {
            return Err(StoreError::Corrupt {
                at: good_len,
                why: "a record frame claims a length this build never writes",
            });
        }

        let mut body = vec![0u8; length];
        if read_fully(&mut reader, &mut body)? != length {
            // The length was plausible but the body is short: the ordinary
            // interrupted write.
            return Ok((count, good_len));
        }

        count += 1;
        good_len += 4 + length as u64;
    }
}

/// Read as much as is there, returning how many bytes arrived. Unlike
/// `read_exact` this distinguishes "nothing left" from "some but not all",
/// which is what tells a clean end from an interrupted write.
fn read_fully<R: Read>(reader: &mut R, buffer: &mut [u8]) -> Result<usize, StoreError> {
    let mut filled = 0usize;
    while filled < buffer.len() {
        match reader.read(&mut buffer[filled..]) {
            Ok(0) => break,
            Ok(read) => filled += read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(StoreError::Io(error)),
        }
    }
    Ok(filled)
}

/// Read the file again, handing each complete record to `visit`.
fn for_each_record<F>(path: &Path, mut visit: F) -> Result<(), StoreError>
where
    F: FnMut(usize, u8, &[u8]) -> Result<(), StoreError>,
{
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);

    let mut header = [0u8; HEADER_LEN];
    reader
        .read_exact(&mut header)
        .map_err(|_| StoreError::NotALog)?;

    let mut sequence = 0usize;
    let mut offset = HEADER_LEN as u64;

    loop {
        // The same rule as `scan`: an impossible frame means the file was
        // edited, and is refused. Being lenient here while `scan` is strict
        // would mean a file that opens cleanly and then silently replays only
        // part of itself.
        let mut length_bytes = [0u8; 4];
        if read_fully(&mut reader, &mut length_bytes)? < length_bytes.len() {
            return Ok(());
        }

        let length = u32::from_be_bytes(length_bytes) as usize;
        if length == 0 || length > MAX_RECORD_LEN {
            return Err(StoreError::Corrupt {
                at: offset,
                why: "a record frame claims an impossible length",
            });
        }

        let mut body = vec![0u8; length];
        if read_fully(&mut reader, &mut body)? != length {
            return Ok(());
        }

        visit(sequence, body[0], &body[1..])?;
        sequence += 1;
        offset += 4 + length as u64;
    }
}

/// Associated data naming the file format and the record's position.
fn record_context(sequence: usize) -> Aad {
    Aad::new("localsecrets.log.v1", &[&sequence.to_string()])
}

fn seal(key: &DataKey, sequence: usize, payload: &[u8]) -> Result<Vec<u8>, StoreError> {
    let envelope = key
        .seal(payload, &record_context(sequence))
        .map_err(|_| StoreError::Crypto)?;

    let mut out = Vec::with_capacity(envelope.nonce.len() + envelope.ciphertext.len());
    out.extend_from_slice(&envelope.nonce);
    out.extend_from_slice(&envelope.ciphertext);
    Ok(out)
}

fn open(key: &DataKey, sequence: usize, payload: &[u8]) -> Result<Vec<u8>, StoreError> {
    if payload.len() < NONCE_LEN {
        return Err(StoreError::Unreadable { sequence });
    }
    let (nonce, ciphertext) = payload.split_at(NONCE_LEN);

    let envelope = Envelope {
        nonce: nonce.to_vec(),
        ciphertext: ciphertext.to_vec(),
    };

    key.open(&envelope, &record_context(sequence))
        .map_err(|_| StoreError::Unreadable { sequence })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use ls_core::crypto::aead::DataKey;

    /// A log in a temporary directory that cleans itself up.
    struct Scratch {
        directory: PathBuf,
    }

    impl Scratch {
        fn new(label: &str) -> Self {
            let unique = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or_default();
            let directory = std::env::temp_dir().join(format!("ls-log-unit-{label}-{unique}"));
            std::fs::create_dir_all(&directory).expect("temporary directory");
            Self { directory }
        }

        fn path(&self) -> PathBuf {
            self.directory.join("store.log")
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.directory);
        }
    }

    fn key() -> DataKey {
        DataKey::from_bytes(&[3u8; 32]).expect("32 bytes")
    }

    /// Swap in a handle that cannot be written to, which is the only way to
    /// produce a real write failure without a full disk.
    fn make_writes_fail(log: &mut Log, path: &Path) {
        log.file = File::open(path).expect("read-only handle");
    }

    #[test]
    fn a_failed_append_is_reported() {
        let scratch = Scratch::new("failed-append");
        let mut log = Log::open(&scratch.path()).expect("open");
        log.append(&key(), b"before").expect("first append");

        make_writes_fail(&mut log, &scratch.path());

        assert!(
            matches!(log.append(&key(), b"after"), Err(StoreError::Io(_))),
            "a write to a read-only handle should fail"
        );
    }

    #[test]
    fn nothing_more_may_be_written_after_a_failed_append() {
        // Every record is sealed against its position. Carrying on after a
        // partial write could reuse a sequence number, and then the log would
        // not replay at all.
        let scratch = Scratch::new("poisoned");
        let mut log = Log::open(&scratch.path()).expect("open");
        log.append(&key(), b"before").expect("first append");

        make_writes_fail(&mut log, &scratch.path());
        let _ = log.append(&key(), b"fails");

        assert!(matches!(
            log.append(&key(), b"and so does this"),
            Err(StoreError::Broken)
        ));
        assert!(matches!(
            log.append_plain(b"and this"),
            Err(StoreError::Broken)
        ));
    }

    #[test]
    fn a_record_refused_for_its_size_does_not_poison_the_log() {
        // Refusing before writing anything leaves the log perfectly usable, and
        // treating that as damage would be a denial of service.
        let scratch = Scratch::new("oversized-ok");
        let mut log = Log::open(&scratch.path()).expect("open");

        let huge = vec![b'x'; MAX_RECORD_LEN + 1];
        assert!(matches!(
            log.append(&key(), &huge),
            Err(StoreError::RecordTooLarge { .. })
        ));

        log.append(&key(), b"still fine")
            .expect("append after refusal");
        assert_eq!(log.len(), 1);
    }

    #[test]
    fn reopening_clears_the_broken_state() {
        let scratch = Scratch::new("reopen-clears");
        let mut log = Log::open(&scratch.path()).expect("open");
        log.append(&key(), b"before").expect("first append");
        make_writes_fail(&mut log, &scratch.path());
        let _ = log.append(&key(), b"fails");
        drop(log);

        let mut reopened = Log::open(&scratch.path()).expect("reopen");
        reopened
            .append(&key(), b"after")
            .expect("append after reopen");

        assert_eq!(
            reopened.read_all(&key()).expect("read"),
            vec![b"before".to_vec(), b"after".to_vec()]
        );
    }
}
