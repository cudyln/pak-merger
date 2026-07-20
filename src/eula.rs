use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const EULA_VERSION: &str = "1.0.0";
pub const EULA_KO: &str = include_str!("../assets/EULA.ko.md");
pub const EULA_EN: &str = include_str!("../assets/EULA.en.md");
pub const EULA_JA: &str = include_str!("../assets/EULA.ja.md");
pub const PRODUCT_NAME: &str = "Pak Merger";

const SETTINGS_DIRECTORY: &str = "PakMerger";
const LEGACY_SETTINGS_DIRECTORY: &str = "Pak Merger";
const CONSENT_FILE_NAME: &str = "eula-consent-v1.json";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EulaLocale {
    Korean,
    English,
    Japanese,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct EulaConfirmations {
    pub non_commercial_use: bool,
    pub original_eula_and_law: bool,
    pub end_user_responsibility: bool,
}

impl EulaConfirmations {
    pub fn all_confirmed(&self) -> bool {
        self.non_commercial_use && self.original_eula_and_law && self.end_user_responsibility
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EulaConsentRecord {
    pub eula_version: String,
    pub eula_text_sha256: String,
    pub accepted_at_unix_seconds: u64,
    pub accepted_locale: EulaLocale,
    pub tool_version: String,
    pub confirmations: EulaConfirmations,
}

pub fn combined_text_sha256() -> String {
    let mut digest = Sha256::new();
    digest.update(EULA_KO.as_bytes());
    digest.update([0]);
    digest.update(EULA_EN.as_bytes());
    digest.update([0]);
    digest.update(EULA_JA.as_bytes());
    hex::encode(digest.finalize())
}

pub fn consent_path() -> io::Result<PathBuf> {
    Ok(consent_path_under(
        local_app_data_root()?,
        SETTINGS_DIRECTORY,
    ))
}

pub fn stored_consent_path() -> io::Result<PathBuf> {
    let current = consent_path()?;
    if current.exists() {
        return Ok(current);
    }
    let legacy = legacy_consent_path()?;
    if legacy.exists() {
        return Ok(legacy);
    }
    Ok(current)
}

fn local_app_data_root() -> io::Result<PathBuf> {
    std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "LOCALAPPDATA is unavailable; EULA acceptance cannot be stored",
            )
        })
}

fn legacy_consent_path() -> io::Result<PathBuf> {
    Ok(consent_path_under(
        local_app_data_root()?,
        LEGACY_SETTINGS_DIRECTORY,
    ))
}

fn consent_path_under(root: impl AsRef<Path>, directory: &str) -> PathBuf {
    root.as_ref().join(directory).join(CONSENT_FILE_NAME)
}

fn read_consent(path: &Path) -> io::Result<Option<EulaConsentRecord>> {
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

pub fn load_consent() -> io::Result<Option<EulaConsentRecord>> {
    if let Some(record) = read_consent(&consent_path()?)? {
        return Ok(Some(record));
    }
    read_consent(&legacy_consent_path()?)
}

pub fn is_valid_record(record: &EulaConsentRecord) -> bool {
    record.eula_version == EULA_VERSION
        && record.eula_text_sha256 == combined_text_sha256()
        && record.confirmations.all_confirmed()
}

pub fn has_valid_consent() -> bool {
    load_consent()
        .ok()
        .flatten()
        .is_some_and(|record| is_valid_record(&record))
}

pub fn accept(
    locale: EulaLocale,
    confirmations: EulaConfirmations,
) -> io::Result<EulaConsentRecord> {
    if !confirmations.all_confirmed() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "all EULA confirmations are required",
        ));
    }
    let record = EulaConsentRecord {
        eula_version: EULA_VERSION.to_owned(),
        eula_text_sha256: combined_text_sha256(),
        accepted_at_unix_seconds: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_secs(),
        accepted_locale: locale,
        tool_version: env!("CARGO_PKG_VERSION").to_owned(),
        confirmations,
    };
    let path = consent_path()?;
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid consent path"))?;
    fs::create_dir_all(parent)?;
    let temporary = parent.join(format!("{CONSENT_FILE_NAME}.partial"));
    let mut writer = fs::File::create(&temporary)?;
    serde_json::to_writer_pretty(&mut writer, &record)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    writer.write_all(b"\n")?;
    writer.sync_all()?;
    if path.exists() {
        fs::remove_file(&path)?;
    }
    fs::rename(temporary, path)?;

    // Migrate the record from the old directory name when possible.
    if let Ok(legacy) = legacy_consent_path() {
        let _ = fs::remove_file(&legacy);
        if let Some(parent) = legacy.parent() {
            let _ = fs::remove_dir(parent);
        }
    }
    Ok(record)
}

pub fn revoke() -> io::Result<()> {
    for path in [consent_path()?, legacy_consent_path()?] {
        match fs::remove_file(&path) {
            Ok(()) => {
                if let Some(parent) = path.parent() {
                    let _ = fs::remove_dir(parent);
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_three_confirmations_are_required() {
        let mut confirmations = EulaConfirmations::default();
        assert!(!confirmations.all_confirmed());
        confirmations.non_commercial_use = true;
        confirmations.original_eula_and_law = true;
        assert!(!confirmations.all_confirmed());
        confirmations.end_user_responsibility = true;
        assert!(confirmations.all_confirmed());
    }

    #[test]
    fn changed_text_hash_invalidates_record() {
        let record = EulaConsentRecord {
            eula_version: EULA_VERSION.to_owned(),
            eula_text_sha256: "wrong".to_owned(),
            accepted_at_unix_seconds: 0,
            accepted_locale: EulaLocale::English,
            tool_version: "test".to_owned(),
            confirmations: EulaConfirmations {
                non_commercial_use: true,
                original_eula_and_law: true,
                end_user_responsibility: true,
            },
        };
        assert!(!is_valid_record(&record));
    }

    #[test]
    fn consent_is_saved_under_a_space_free_directory_name() {
        let path = consent_path_under("C:/LocalAppData", SETTINGS_DIRECTORY);
        assert_eq!(
            path,
            PathBuf::from("C:/LocalAppData/PakMerger/eula-consent-v1.json")
        );
        assert!(!SETTINGS_DIRECTORY.contains(' '));
    }
}
