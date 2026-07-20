//! Loader for declarative game profiles.

use super::{
    AssetProfile, AssetProfileRule, AtomicGroupRule, GameProfile, PathMatchKind, PathMatcher,
    ProfileFormat, ProfileOrigin, ProfilePrecision, ProfileValidationError, validate_game_profile,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use thiserror::Error;

pub const EXTERNAL_PROFILE_SCHEMA_VERSION: u32 = 1;
pub const MAX_EXTERNAL_PROFILE_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Error)]
pub enum ProfileLoadError {
    #[error("game profile must be a .json file: {0}")]
    InvalidExtension(PathBuf),
    #[error("game profile is not a regular file: {0}")]
    NotAFile(PathBuf),
    #[error("failed to read game profile {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("game profile is larger than the {MAX_EXTERNAL_PROFILE_BYTES}-byte safety limit: {0}")]
    TooLarge(PathBuf),
    #[error("invalid game profile JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error(
        "unsupported game profile schema version {found}; expected {EXTERNAL_PROFILE_SCHEMA_VERSION}"
    )]
    UnsupportedSchema { found: u32 },
    #[error(transparent)]
    Validation(#[from] ProfileValidationError),
}

/// Reads one profile from a regular JSON file.
pub fn load_external_profile_file(path: &Path) -> Result<GameProfile, ProfileLoadError> {
    let is_json = path
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("json"));
    if !is_json {
        return Err(ProfileLoadError::InvalidExtension(path.to_owned()));
    }

    // Check both the path and opened handle so a swapped link is still rejected.
    let path_metadata = std::fs::symlink_metadata(path).map_err(|source| ProfileLoadError::Io {
        path: path.to_owned(),
        source,
    })?;
    if path_metadata.file_type().is_symlink() || !path_metadata.file_type().is_file() {
        return Err(ProfileLoadError::NotAFile(path.to_owned()));
    }

    let file = File::open(path).map_err(|source| ProfileLoadError::Io {
        path: path.to_owned(),
        source,
    })?;
    let metadata = file.metadata().map_err(|source| ProfileLoadError::Io {
        path: path.to_owned(),
        source,
    })?;
    if !metadata.is_file() {
        return Err(ProfileLoadError::NotAFile(path.to_owned()));
    }
    if metadata.len() > MAX_EXTERNAL_PROFILE_BYTES {
        return Err(ProfileLoadError::TooLarge(path.to_owned()));
    }

    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_EXTERNAL_PROFILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| ProfileLoadError::Io {
            path: path.to_owned(),
            source,
        })?;
    if bytes.len() as u64 > MAX_EXTERNAL_PROFILE_BYTES {
        return Err(ProfileLoadError::TooLarge(path.to_owned()));
    }
    let mut profile = parse_external_profile_json(&bytes)?;
    if let ProfileOrigin::External {
        source_path,
        sha256: _,
    } = &mut profile.origin
    {
        *source_path = path.to_owned();
    }
    Ok(profile)
}

/// Parses a schema-v1 profile. Unknown fields are rejected.
pub fn parse_external_profile_json(bytes: &[u8]) -> Result<GameProfile, ProfileLoadError> {
    if bytes.len() as u64 > MAX_EXTERNAL_PROFILE_BYTES {
        return Err(ProfileLoadError::TooLarge(PathBuf::from("<memory>")));
    }
    let document: ExternalProfileDocument = serde_json::from_slice(bytes)?;
    if document.schema_version != EXTERNAL_PROFILE_SCHEMA_VERSION {
        return Err(ProfileLoadError::UnsupportedSchema {
            found: document.schema_version,
        });
    }

    let sha256 = hex::encode(Sha256::digest(bytes));
    let profile = GameProfile {
        id: document.id,
        display_name: document.display_name,
        format: document.format,
        origin: ProfileOrigin::External {
            source_path: PathBuf::new(),
            sha256,
        },
        detection_matchers: document
            .detection
            .path_matchers
            .into_iter()
            .map(ExternalPathMatcher::into_matcher)
            .collect::<Result<Vec<_>, _>>()?,
        minimum_detection_matches: document.detection.minimum_matches,
        root_scope_matchers: Vec::new(),
        assets: document
            .assets
            .into_iter()
            .map(ExternalAssetProfile::into_rule)
            .collect::<Result<Vec<_>, _>>()?,
    };
    validate_game_profile(&profile)?;
    Ok(profile)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ExternalProfileDocument {
    schema_version: u32,
    id: String,
    display_name: String,
    format: ProfileFormat,
    detection: ExternalDetection,
    assets: Vec<ExternalAssetProfile>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ExternalDetection {
    minimum_matches: usize,
    path_matchers: Vec<ExternalPathMatcher>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ExternalAssetProfile {
    id: String,
    path_matchers: Vec<ExternalPathMatcher>,
    #[serde(default)]
    priority: u16,
    #[serde(default)]
    field_groups: Vec<ExternalAtomicGroup>,
}

impl ExternalAssetProfile {
    fn into_rule(self) -> Result<AssetProfileRule, ProfileValidationError> {
        Ok(AssetProfileRule {
            matchers: self
                .path_matchers
                .into_iter()
                .map(ExternalPathMatcher::into_matcher)
                .collect::<Result<Vec<_>, _>>()?,
            priority: self.priority,
            profile: AssetProfile {
                id: self.id,
                precision: ProfilePrecision::Declared,
                groups: self
                    .field_groups
                    .into_iter()
                    .map(ExternalAtomicGroup::into_rule)
                    .collect(),
            },
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ExternalPathMatcher {
    kind: PathMatchKind,
    value: String,
}

impl ExternalPathMatcher {
    fn into_matcher(self) -> Result<PathMatcher, ProfileValidationError> {
        PathMatcher::try_new(self.kind, &self.value)
    }
}

#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ExternalGroupMode {
    #[default]
    WholeFields,
    ParallelArrayItems,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ExternalAtomicGroup {
    id: String,
    fields: Vec<String>,
    #[serde(default)]
    mode: ExternalGroupMode,
}

impl ExternalAtomicGroup {
    fn into_rule(self) -> AtomicGroupRule {
        AtomicGroupRule {
            id: self.id,
            fields: self.fields,
            force_compound: true,
            index_coupled: matches!(self.mode, ExternalGroupMode::ParallelArrayItems),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binary_asset::parse_messagepack;
    use crate::profiles::{
        AssetProfileSelectionKind, ProfileDetectionStatus, ProfileRegistry,
        atomic_units_for_row_with_registry,
    };
    use std::io::Write as _;

    const VALID: &str = include_str!("../../profiles/example-game.profile.json");

    fn fixstr(value: &str) -> Vec<u8> {
        let mut out = vec![0xa0 | value.len() as u8];
        out.extend_from_slice(value.as_bytes());
        out
    }

    fn map(fields: &[(&str, Vec<u8>)]) -> Vec<u8> {
        let mut out = vec![0x80 | fields.len() as u8];
        for (name, value) in fields {
            out.extend(fixstr(name));
            out.extend(value);
        }
        out
    }

    #[test]
    fn valid_external_profile_registers_and_drives_parallel_groups() {
        let profile = parse_external_profile_json(VALID.as_bytes()).unwrap();
        assert_eq!(profile.id, "example_game");
        assert_eq!(
            profile.assets[0].profile.precision,
            ProfilePrecision::Declared
        );
        assert_eq!(profile.assets[0].priority, 0);

        let mut registry = ProfileRegistry::empty();
        registry.register(profile).unwrap();
        let detection = registry.detect_inventory(["/ExampleGame/Content/Database/Skills.uasset"]);
        assert_eq!(detection.status, ProfileDetectionStatus::Selected);
        assert_eq!(
            detection.selected_profile_id.as_deref(),
            Some("example_game")
        );
        assert_eq!(
            registry
                .resolve_asset(
                    "/ExampleGame/Content/Database/Skills.uasset",
                    Some("example_game"),
                )
                .selection,
            AssetProfileSelectionKind::Explicit
        );

        let row_raw = map(&[
            ("m_id", vec![1]),
            ("m_Types", vec![0x92, 1, 2]),
            ("m_Values", vec![0x92, 3, 4]),
        ]);
        let row = parse_messagepack(&row_raw).unwrap();
        let units = atomic_units_for_row_with_registry(
            &registry,
            Some("example_game"),
            "/ExampleGame/Content/Database/Skills",
            &row,
        )
        .unwrap();
        assert!(units.iter().any(|unit| {
            unit.id == "group:damage_slots[1]"
                && unit.array_index == Some(1)
                && unit.expected_array_len == Some(2)
        }));
    }

    #[test]
    fn file_loader_accepts_only_a_bounded_regular_json_file() {
        let mut file = tempfile::Builder::new().suffix(".json").tempfile().unwrap();
        file.write_all(VALID.as_bytes()).unwrap();
        file.flush().unwrap();
        let profile = load_external_profile_file(file.path()).unwrap();
        match profile.origin {
            ProfileOrigin::External {
                source_path,
                sha256,
            } => {
                assert_eq!(source_path, file.path());
                assert_eq!(sha256.len(), 64);
            }
            ProfileOrigin::BuiltIn => panic!("loaded profile must retain external origin"),
        }

        let directory = tempfile::tempdir().unwrap();
        let fake_json_directory = directory.path().join("profile.json");
        std::fs::create_dir(&fake_json_directory).unwrap();
        assert!(matches!(
            load_external_profile_file(&fake_json_directory),
            Err(ProfileLoadError::NotAFile(_))
        ));
    }

    #[test]
    fn unknown_fields_leave_no_slot_for_keys_values_code_or_includes() {
        for forbidden in [
            "aesKey",
            "originalValue",
            "replacementBlob",
            "include",
            "script",
        ] {
            let json = VALID.replacen(
                "\"displayName\": \"Example Game\",",
                &format!("\"displayName\": \"Example Game\", \"{forbidden}\": \"not-allowed\","),
                1,
            );
            assert!(matches!(
                parse_external_profile_json(json.as_bytes()),
                Err(ProfileLoadError::Json(_))
            ));
        }
    }

    #[test]
    fn rejects_file_paths_traversal_wildcards_and_unsupported_schema() {
        for path in [
            r"C:\\Games\\table.uasset",
            "../table.uasset",
            "/game/../secret",
            "/game/**/*.uasset",
            "file:///game/table",
        ] {
            let json = VALID.replacen("/examplegame/content/database/skills", path, 1);
            assert!(matches!(
                parse_external_profile_json(json.as_bytes()),
                Err(ProfileLoadError::Validation(_))
            ));
        }

        let version = VALID.replacen("\"schemaVersion\": 1", "\"schemaVersion\": 2", 1);
        assert!(matches!(
            parse_external_profile_json(version.as_bytes()),
            Err(ProfileLoadError::UnsupportedSchema { found: 2 })
        ));
    }

    #[test]
    fn rejects_overlapping_or_identity_fields_before_runtime() {
        let mut overlapping: serde_json::Value = serde_json::from_str(VALID).unwrap();
        overlapping["assets"][0]["fieldGroups"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({ "id": "other", "fields": ["m_Types"] }));
        let overlapping = serde_json::to_vec(&overlapping).unwrap();
        assert!(matches!(
            parse_external_profile_json(&overlapping),
            Err(ProfileLoadError::Validation(_))
        ));

        let identity = VALID.replacen("\"m_Types\"", "\"m_id\"", 1);
        assert!(matches!(
            parse_external_profile_json(identity.as_bytes()),
            Err(ProfileLoadError::Validation(_))
        ));
    }

    #[test]
    fn accepts_optional_bounded_asset_priority() {
        let mut document: serde_json::Value = serde_json::from_str(VALID).unwrap();
        document["assets"][0]["priority"] = serde_json::json!(25);
        let profile = parse_external_profile_json(&serde_json::to_vec(&document).unwrap()).unwrap();
        assert_eq!(profile.assets[0].priority, 25);

        document["assets"][0]["priority"] =
            serde_json::json!(crate::profiles::MAX_ASSET_RULE_PRIORITY + 1);
        assert!(matches!(
            parse_external_profile_json(&serde_json::to_vec(&document).unwrap()),
            Err(ProfileLoadError::Validation(_))
        ));
    }

    #[test]
    fn enforces_document_size_before_parsing() {
        let bytes = vec![b' '; MAX_EXTERNAL_PROFILE_BYTES as usize + 1];
        assert!(matches!(
            parse_external_profile_json(&bytes),
            Err(ProfileLoadError::TooLarge(_))
        ));
    }
}
