//! Exact offline source lease for local npm artifact decisions. Does not use cached()
//! or its polling interval, fetch data, publish cache state, or accept a caller
//! supplied DB/sequence/report. All selected AND fallback slots are bound.
use super::*;
use crate::util::dirfd::{file_generation, FileGeneration};
use crate::util::{open_read_no_follow_capped, OpenRegularError};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_TOTAL_BYTES: u64 = 128 * 1024 * 1024;
pub(crate) const MAX_PUBLICATION_AGE_SECONDS: u64 = 7 * 24 * 3600;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SourceRefusal {
    Unavailable,
    Changed,
    Invalid,
    UnsupportedHashCoverage,
    Stale,
    Rollback,
    ResourceLimit,
}
struct Pin {
    path: PathBuf,
    file: Option<File>,
    generation: Option<FileGeneration>,
    sha256: Option<String>,
}
/// Never serialized. Handles remain live through the bound local operation.
pub(crate) struct MaterializationThreatSource {
    slots: Vec<Pin>,
    context: Vec<Option<PathBuf>>,
    db: ThreatDb,
    commitment: String,
    #[cfg(test)]
    fixture: bool,
}
impl MaterializationThreatSource {
    pub(crate) fn capture() -> Result<Self, SourceRefusal> {
        let context = context();
        if context.len() != 4 || context.iter().any(Option::is_none) {
            return Err(SourceRefusal::Unavailable);
        }
        let mut slots = Vec::new();
        let mut parsed = Vec::new();
        let mut total = 0u64;
        for path in context.iter().flatten() {
            let (pin, bytes) = Pin::capture(path)?;
            total = total
                .checked_add(pin.generation.as_ref().map_or(0, |g| g.size))
                .ok_or(SourceRefusal::ResourceLimit)?;
            if total > MAX_TOTAL_BYTES {
                return Err(SourceRefusal::ResourceLimit);
            }
            parsed.push(bytes.and_then(|bytes| ThreatDb::from_bytes(bytes, 0).ok()));
            slots.push(pin);
        }
        let mut primary = if parsed[0]
            .as_ref()
            .is_some_and(|db| db.verify_signature().is_ok())
        {
            parsed[0].take()
        } else if parsed[1]
            .as_ref()
            .is_some_and(|db| db.verify_signature().is_ok())
        {
            parsed[1].take()
        } else {
            None
        }
        .ok_or(SourceRefusal::Invalid)?;
        if primary.build_sequence == 0 {
            return Err(SourceRefusal::Invalid);
        }
        if primary.format_version < 2 || primary.v2.is_none() {
            return Err(SourceRefusal::UnsupportedHashCoverage);
        }
        // Preserve local supplemental authority semantics, but never silently
        // omit a present corrupt overlay from an installation decision.
        let overlay = parsed[2].take().or_else(|| parsed[3].take());
        if overlay.is_none() && (slots[2].file.is_some() || slots[3].file.is_some()) {
            return Err(SourceRefusal::Invalid);
        }
        primary.supplemental = overlay.map(Box::new);
        let commitment = hex::encode(Sha256::digest(
            serde_json::to_vec(&slots.iter().map(Pin::private_binding).collect::<Vec<_>>())
                .map_err(|_| SourceRefusal::Invalid)?,
        ));
        let result = Self {
            slots,
            context,
            db: primary,
            commitment,
            #[cfg(test)]
            fixture: false,
        };
        result.revalidate(true)?;
        Ok(result)
    }
    pub(crate) fn revalidate(&self, full: bool) -> Result<(), SourceRefusal> {
        #[cfg(test)]
        if self.fixture {
            return Ok(());
        }
        if context() != self.context {
            return Err(SourceRefusal::Changed);
        }
        for slot in &self.slots {
            slot.revalidate(full)?;
        }
        fresh(&self.db, unix_now())?;
        if let Some(overlay) = &self.db.supplemental {
            fresh(overlay, unix_now())?;
        }
        // An already accepted higher generation in this process is a veto, not
        // a reason to substitute cached bytes for the captured source handles.
        if let Some(cache) = CACHE.get() {
            let accepted = cache.state.read().map_err(|_| SourceRefusal::Unavailable)?;
            if accepted
                .as_ref()
                .is_some_and(|entry| entry.db.build_sequence > self.db.build_sequence)
            {
                return Err(SourceRefusal::Rollback);
            }
        }
        if context() != self.context {
            return Err(SourceRefusal::Changed);
        }
        Ok(())
    }
    pub(crate) fn db(&self) -> &ThreatDb {
        &self.db
    }
    /// Private commitment only. Never expose hashes of a local supplemental
    /// feed through a public summary or use its serialized form as a lease.
    pub(crate) fn private_commitment(&self) -> &str {
        &self.commitment
    }
    pub(crate) fn publication(&self) -> (u64, u64) {
        (self.db.build_sequence, self.db.build_timestamp)
    }
    #[cfg(test)]
    pub(crate) fn fixture_blocking_artifact(sha256: [u8; 32]) -> Self {
        let mut writer = ThreatDbWriter::new(1, 1);
        writer.add_artifact_sha256(
            sha256,
            ThreatSource::OssfMalicious,
            Confidence::Confirmed,
            false,
            None,
        );
        let key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let data = writer.build_format(ThreatDbFormat::V2, &key).unwrap();
        Self {
            slots: Vec::new(),
            context: Vec::new(),
            commitment: hex::encode(Sha256::digest(&data)),
            db: ThreatDb::from_bytes(data, 0).unwrap(),
            fixture: true,
        }
    }
    #[cfg(test)]
    pub(crate) fn fixture_empty() -> Self {
        Self::fixture_empty_at(1)
    }
    #[cfg(test)]
    pub(crate) fn fixture_empty_at(sequence: u64) -> Self {
        // Unit-only data constructor, never used by native qualification or a
        // product build. Signature admission has separate negative tests.
        let mut writer = ThreatDbWriter::new(1, sequence);
        let key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let data = writer.build_format(ThreatDbFormat::V2, &key).unwrap();
        let commitment = hex::encode(Sha256::digest(&data));
        Self {
            slots: Vec::new(),
            context: Vec::new(),
            db: ThreatDb::from_bytes(data, 0).unwrap(),
            commitment,
            fixture: true,
        }
    }
}
fn fresh(db: &ThreatDb, now: u64) -> Result<(), SourceRefusal> {
    let age = now
        .checked_sub(db.build_timestamp)
        .ok_or(SourceRefusal::Stale)?;
    if db.build_timestamp == 0 || age > MAX_PUBLICATION_AGE_SECONDS {
        return Err(SourceRefusal::Stale);
    }
    Ok(())
}
fn context() -> Vec<Option<PathBuf>> {
    vec![
        ThreatDb::default_path_v2(),
        ThreatDb::default_path(),
        ThreatDb::supplemental_path_v2(),
        ThreatDb::supplemental_path(),
    ]
}
impl Pin {
    fn private_binding(&self) -> serde_json::Value {
        serde_json::json!({"path":self.path,"sha256":self.sha256,"generation":self.generation.map(|g| {
            serde_json::json!({"identity":g.identity,"size":g.size,"links":g.links,
                "mtime_seconds":g.modified_seconds,"mtime_nanos":g.modified_nanos,
                "ctime_seconds":g.changed_seconds,"ctime_nanos":g.changed_nanos})
        })})
    }
    fn capture(path: &Path) -> Result<(Self, Option<Vec<u8>>), SourceRefusal> {
        if !path.is_absolute() || path.as_os_str().as_encoded_bytes().len() > 4096 {
            return Err(SourceRefusal::Unavailable);
        }
        let file = match open_read_no_follow_capped(path, MAX_FILE_BYTES) {
            Ok(file) => file,
            Err(OpenRegularError::NotFound) => {
                return Ok((
                    Self {
                        path: path.into(),
                        file: None,
                        generation: None,
                        sha256: None,
                    },
                    None,
                ))
            }
            Err(_) => return Err(SourceRefusal::Unavailable),
        };
        trust(&file, path)?;
        let generation = file_generation(&file).map_err(|_| SourceRefusal::Unavailable)?;
        let mut read = file.try_clone().map_err(|_| SourceRefusal::Unavailable)?;
        read.seek(SeekFrom::Start(0))
            .map_err(|_| SourceRefusal::Unavailable)?;
        let mut bytes = Vec::new();
        read.take(MAX_FILE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| SourceRefusal::Unavailable)?;
        if bytes.len() as u64 != generation.size || bytes.len() as u64 > MAX_FILE_BYTES {
            return Err(SourceRefusal::ResourceLimit);
        }
        if file_generation(&file).map_err(|_| SourceRefusal::Changed)? != generation {
            return Err(SourceRefusal::Changed);
        }
        let sha256 = hex::encode(Sha256::digest(&bytes));
        let pin = Self {
            path: path.into(),
            file: Some(file),
            generation: Some(generation),
            sha256: Some(sha256),
        };
        pin.revalidate(false)?;
        Ok((pin, Some(bytes)))
    }
    fn revalidate(&self, full: bool) -> Result<(), SourceRefusal> {
        let visible = match open_read_no_follow_capped(&self.path, MAX_FILE_BYTES) {
            Ok(file) => Some(file),
            Err(OpenRegularError::NotFound) => None,
            Err(_) => return Err(SourceRefusal::Changed),
        };
        match (&self.file, visible) {
            (None, None) => Ok(()),
            (Some(held), Some(visible)) => {
                trust(held, &self.path).map_err(|_| SourceRefusal::Changed)?;
                let generation = self.generation.ok_or(SourceRefusal::Changed)?;
                if file_generation(held).map_err(|_| SourceRefusal::Changed)? != generation
                    || file_generation(&visible).map_err(|_| SourceRefusal::Changed)? != generation
                {
                    return Err(SourceRefusal::Changed);
                }
                if full {
                    let mut reader = held.try_clone().map_err(|_| SourceRefusal::Changed)?;
                    reader
                        .seek(SeekFrom::Start(0))
                        .map_err(|_| SourceRefusal::Changed)?;
                    let mut hasher = Sha256::new();
                    let mut size = 0u64;
                    let mut buf = [0u8; 64 * 1024];
                    let mut reader = reader.take(generation.size + 1);
                    loop {
                        let n = reader.read(&mut buf).map_err(|_| SourceRefusal::Changed)?;
                        if n == 0 {
                            break;
                        }
                        size += n as u64;
                        hasher.update(&buf[..n]);
                    }
                    if size != generation.size
                        || Some(hex::encode(hasher.finalize())) != self.sha256
                    {
                        return Err(SourceRefusal::Changed);
                    }
                    if file_generation(held).map_err(|_| SourceRefusal::Changed)? != generation {
                        return Err(SourceRefusal::Changed);
                    }
                }
                Ok(())
            }
            _ => Err(SourceRefusal::Changed),
        }
    }
}
fn trust(file: &File, path: &Path) -> Result<(), SourceRefusal> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let uid = unsafe { libc::geteuid() };
        let m = file.metadata().map_err(|_| SourceRefusal::Unavailable)?;
        if !m.is_file()
            || m.nlink() != 1
            || (m.uid() != uid && m.uid() != 0)
            || m.mode() & 0o022 != 0
        {
            return Err(SourceRefusal::Unavailable);
        }
        // The final file is no-follow; bind/check the current ancestor closure
        // as well. Root-owned sticky temporary ancestors are acceptable only
        // above the owned non-writable file parent, never as that parent itself.
        let parent = path
            .parent()
            .ok_or(SourceRefusal::Unavailable)?
            .canonicalize()
            .map_err(|_| SourceRefusal::Unavailable)?;
        for (index, ancestor) in parent.ancestors().enumerate() {
            let m = std::fs::symlink_metadata(ancestor).map_err(|_| SourceRefusal::Unavailable)?;
            if !m.is_dir() || (m.uid() != uid && m.uid() != 0) {
                return Err(SourceRefusal::Unavailable);
            }
            if m.mode() & 0o022 != 0 && !(index > 0 && m.uid() == 0 && m.mode() & 0o1000 != 0) {
                return Err(SourceRefusal::Unavailable);
            }
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = (file, path);
        Err(SourceRefusal::Unavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    #[test]
    fn absent_slot_appearance_and_retained_same_length_change_are_detected() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("source.dat");
        let (absent, _) = Pin::capture(&path).unwrap();
        absent.revalidate(true).unwrap();
        std::fs::write(&path, b"one").unwrap();
        assert_eq!(absent.revalidate(false), Err(SourceRefusal::Changed));
        let (present, bytes) = Pin::capture(&path).unwrap();
        assert_eq!(bytes.unwrap(), b"one");
        std::fs::write(&path, b"two").unwrap();
        assert_eq!(present.revalidate(true), Err(SourceRefusal::Changed));
    }
    #[cfg(unix)]
    #[test]
    fn replacement_with_same_bytes_never_reuses_dropped_path_identity() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("source.dat");
        std::fs::write(&path, b"same").unwrap();
        let (pin, _) = Pin::capture(&path).unwrap();
        let other = root.path().join("other");
        std::fs::write(&other, b"same").unwrap();
        std::fs::rename(other, path).unwrap();
        assert_eq!(pin.revalidate(false), Err(SourceRefusal::Changed));
    }
    #[test]
    fn future_and_expired_publication_proxy_never_become_fresh() {
        let mut source = MaterializationThreatSource::fixture_empty();
        let now = unix_now();
        source.db.build_timestamp = now + 1;
        assert_eq!(fresh(&source.db, now), Err(SourceRefusal::Stale));
        source.db.build_timestamp = now - MAX_PUBLICATION_AGE_SECONDS - 1;
        assert_eq!(fresh(&source.db, now), Err(SourceRefusal::Stale));
        source.db.build_timestamp = now - MAX_PUBLICATION_AGE_SECONDS;
        assert!(fresh(&source.db, now).is_ok());
    }
    #[test]
    fn caller_signed_fixture_does_not_pass_embedded_primary_signature() {
        let source = MaterializationThreatSource::fixture_empty();
        assert!(source.db.verify_signature().is_err());
    }
}
