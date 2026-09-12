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
            });
        }

        check_header(&mut file)?;
        let (count, good_len) = scan(&mut file)?;

        if file.metadata()?.len() != good_len {
            // A crash during an append. Everything before the partial record is
            // intact, so keep that and drop the tail.
            file.set_len(good_len)?;
            file.sync_data()?;
        }
        file.seek(SeekFrom::End(0))?;

        Ok(Self {
            path: path.to_path_buf(),
            file,
            count,
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
        Ok(())
    }

    fn write_record(&mut self, kind: u8, payload: &[u8]) -> Result<(), StoreError> {
        let length = payload.len() + 1;
        if length > MAX_RECORD_LEN {
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

        self.file.write_all(&framed)?;
        self.file.sync_data()?;
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
    file.read_exact(&mut header).map_err(|_| StoreError::NotALog)?;

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
fn scan(file: &mut File) -> Result<(usize, u64), StoreError> {
    file.seek(SeekFrom::Start(HEADER_LEN as u64))?;
    let mut reader = BufReader::new(file);

    let mut count = 0usize;
    let mut good_len = HEADER_LEN as u64;
    let mut length_bytes = [0u8; 4];

    loop {
        match reader.read_exact(&mut length_bytes) {
            Ok(()) => {}
            Err(_) => return Ok((count, good_len)),
        }
        let length = u32::from_be_bytes(length_bytes) as usize;
        if length == 0 || length > MAX_RECORD_LEN {
            // Not a frame this build would have written: treat it as the torn
            // tail rather than trying to interpret it.
            return Ok((count, good_len));
        }

        let mut body = vec![0u8; length];
        if reader.read_exact(&mut body).is_err() {
            return Ok((count, good_len));
        }

        count += 1;
        good_len += 4 + length as u64;
    }
}

/// Read the file again, handing each complete record to `visit`.
fn for_each_record<F>(path: &Path, mut visit: F) -> Result<(), StoreError>
where
    F: FnMut(usize, u8, &[u8]) -> Result<(), StoreError>,
{
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);

    let mut header = [0u8; HEADER_LEN];
    reader.read_exact(&mut header).map_err(|_| StoreError::NotALog)?;

    let mut sequence = 0usize;
    let mut length_bytes = [0u8; 4];

    loop {
        if reader.read_exact(&mut length_bytes).is_err() {
            return Ok(());
        }
        let length = u32::from_be_bytes(length_bytes) as usize;
        if length == 0 || length > MAX_RECORD_LEN {
            return Ok(());
        }

        let mut body = vec![0u8; length];
        if reader.read_exact(&mut body).is_err() {
            return Ok(());
        }

        visit(sequence, body[0], &body[1..])?;
        sequence += 1;
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
