//! Game-specific field groups and the generic fallback profile.

mod external;
mod generic;
mod octopath_traveler_0;

pub use external::{
    EXTERNAL_PROFILE_SCHEMA_VERSION, MAX_EXTERNAL_PROFILE_BYTES, ProfileLoadError,
    load_external_profile_file, parse_external_profile_json,
};

use crate::binary_asset::{BinaryAssetError, MsgpackNode, Result};
use crate::types::AtomicGroup;
pub use crate::types::ProfileDetectionStatus;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::PathBuf;
use std::sync::{Arc, LazyLock};
use thiserror::Error;

const MAX_GAME_PROFILES: usize = 64;
const MAX_DETECTION_MATCHERS: usize = 32;
const MAX_ROOT_SCOPE_MATCHERS: usize = 8;
const MAX_ASSET_RULES: usize = 512;
const MAX_MATCHERS_PER_ASSET: usize = 8;
const MAX_GROUPS_PER_ASSET: usize = 128;
const MAX_FIELDS_PER_GROUP: usize = 64;
const MAX_VIRTUAL_PATH_PATTERN_BYTES: usize = 512;
pub const MAX_ASSET_RULE_PRIORITY: u16 = 1_000;
pub const MAX_ATOMIC_UNIT_LAYOUT_CACHE_ENTRIES: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfilePrecision {
    /// Reviewed rules shipped with Pak Merger.
    Audited,
    /// Conservative default rules scoped to an explicitly selected game profile.
    GameDefault,
    /// Rules supplied by an external declarative profile.
    Declared,
    /// Conservative fallback: scalars are separate and compound values are whole fields.
    Generic,
}

/// Database format handled by a profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileFormat {
    /// A BinaryAsset MessagePack payload with `m_DataList` rows keyed by `m_id`.
    #[serde(rename = "messagepack_m_data_list_v1")]
    MessagePackMDataListV1,
}

impl ProfileFormat {
    pub const fn id(self) -> &'static str {
        match self {
            Self::MessagePackMDataListV1 => "messagepack_m_data_list_v1",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AtomicGroupRule {
    pub id: String,
    pub fields: Vec<String>,
    pub force_compound: bool,
    /// Select the same index from every listed parallel array when their lengths agree.
    pub index_coupled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssetProfile {
    pub id: String,
    pub precision: ProfilePrecision,
    pub groups: Vec<AtomicGroupRule>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathMatchKind {
    Exact,
    Prefix,
    Suffix,
    Contains,
}

/// Matcher over normalized Unreal asset paths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathMatcher {
    pub kind: PathMatchKind,
    pub value: String,
}

impl PathMatcher {
    pub fn try_new(
        kind: PathMatchKind,
        value: &str,
    ) -> std::result::Result<Self, ProfileValidationError> {
        validate_virtual_path_pattern(kind, value)?;
        Ok(Self {
            kind,
            value: normalize_asset_path(value),
        })
    }

    pub(crate) fn builtin(kind: PathMatchKind, value: &str) -> Self {
        Self::try_new(kind, value).expect("built-in profile path matcher must be valid")
    }

    fn matches_normalized(&self, asset_path: &str) -> bool {
        match self.kind {
            PathMatchKind::Exact => asset_path == self.value,
            PathMatchKind::Prefix => asset_path.starts_with(&self.value),
            PathMatchKind::Suffix => asset_path.ends_with(&self.value),
            PathMatchKind::Contains => asset_path.contains(&self.value),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssetProfileRule {
    /// Every matcher must match. Multiple matchers allow safe combinations
    /// such as "inside GameText" plus "ends with GameTextNPC" without regex.
    pub matchers: Vec<PathMatcher>,
    /// Higher-priority rules win when broad and precise matchers overlap.
    /// Equal highest priorities remain ambiguous and fail closed.
    pub priority: u16,
    pub profile: AssetProfile,
}

impl AssetProfileRule {
    fn matches_normalized(&self, asset_path: &str) -> bool {
        self.matchers
            .iter()
            .all(|matcher| matcher.matches_normalized(asset_path))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileOrigin {
    BuiltIn,
    External {
        source_path: PathBuf,
        sha256: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GameProfile {
    pub id: String,
    pub display_name: String,
    pub format: ProfileFormat,
    pub origin: ProfileOrigin,
    pub detection_matchers: Vec<PathMatcher>,
    pub minimum_detection_matches: usize,
    /// Optional game-root matchers for rooted/rebased asset paths. Relative
    /// paths whose common `Content` root was removed do not require a match.
    pub root_scope_matchers: Vec<PathMatcher>,
    pub assets: Vec<AssetProfileRule>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileOriginKind {
    BuiltIn,
    External,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileSummary {
    pub id: String,
    pub display_name: String,
    pub format: ProfileFormat,
    pub origin: ProfileOriginKind,
    pub asset_rule_count: usize,
    pub detection_signature_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileDetectionCandidate {
    pub id: String,
    pub display_name: String,
    pub matched_signatures: usize,
    pub required_signatures: usize,
    pub qualifies: bool,
}

/// Result suitable for a GUI/CLI inventory display. An ambiguous result never
/// silently picks a game profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileDetection {
    pub status: ProfileDetectionStatus,
    pub selected_profile_id: Option<String>,
    pub candidates: Vec<ProfileDetectionCandidate>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssetProfileSelectionKind {
    Explicit,
    AutoUniqueMatch,
    GenericNoMatch,
    GenericAmbiguous,
    GenericUnknownRequestedProfile,
}

#[derive(Debug, Clone, Copy)]
pub struct ResolvedAssetProfile<'a> {
    pub game_profile: Option<&'a GameProfile>,
    pub profile: &'a AssetProfile,
    pub selection: AssetProfileSelectionKind,
}

/// Reusable field order and field-selection units for one exact row layout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AtomicUnitLayout {
    pub field_order: Arc<[String]>,
    pub units: Arc<[AtomicGroup]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RowFieldLayout {
    name: String,
    scalar: bool,
    array_len: Option<usize>,
}

#[derive(Debug)]
struct CachedAtomicUnitLayout {
    structure: Box<[RowFieldLayout]>,
    layout: Arc<AtomicUnitLayout>,
}

/// Resolves an asset profile once and reuses atomic-unit plans for repeated row layouts.
pub struct AtomicUnitPlanner<'a> {
    normalized_asset_path: String,
    profile: &'a AssetProfile,
    selection: AssetProfileSelectionKind,
    layouts_by_hash: HashMap<u64, Vec<CachedAtomicUnitLayout>>,
    cached_layout_count: usize,
}

impl<'a> AtomicUnitPlanner<'a> {
    pub fn new(
        registry: &'a ProfileRegistry,
        requested_game_profile: Option<&str>,
        asset_path: &str,
    ) -> Self {
        let normalized_asset_path = normalize_asset_path(asset_path);
        let resolved = registry
            .resolve_asset_normalized(normalized_asset_path.as_str(), requested_game_profile);
        Self {
            normalized_asset_path,
            profile: resolved.profile,
            selection: resolved.selection,
            layouts_by_hash: HashMap::new(),
            cached_layout_count: 0,
        }
    }

    pub fn normalized_asset_path(&self) -> &str {
        &self.normalized_asset_path
    }

    pub fn profile(&self) -> &'a AssetProfile {
        self.profile
    }

    pub fn selection(&self) -> AssetProfileSelectionKind {
        self.selection
    }

    pub fn cached_layout_count(&self) -> usize {
        self.cached_layout_count
    }

    pub fn layout_for_row(&mut self, row: &MsgpackNode) -> Result<Arc<AtomicUnitLayout>> {
        let fields = row.map_fields()?;
        let structure_hash = hash_row_field_layout(fields.as_slice());
        self.layout_for_fields(fields.as_slice(), structure_hash)
    }

    /// Checks field order before building groups. A row with a different shape
    /// will be selected whole, so its indexed-array layout is not cached.
    pub fn layout_for_row_matching_field_order(
        &mut self,
        row: &MsgpackNode,
        expected_field_order: &[String],
    ) -> Result<Option<Arc<AtomicUnitLayout>>> {
        let fields = row.map_fields()?;
        let matches = fields.len() == expected_field_order.len()
            && fields
                .iter()
                .zip(expected_field_order)
                .all(|((name, _), expected)| *name == expected);
        if !matches {
            return Ok(None);
        }
        let structure_hash = hash_row_field_layout(fields.as_slice());
        self.layout_for_fields(fields.as_slice(), structure_hash)
            .map(Some)
    }

    fn layout_for_fields(
        &mut self,
        fields: &[(&str, &MsgpackNode)],
        structure_hash: u64,
    ) -> Result<Arc<AtomicUnitLayout>> {
        if let Some(cached) = self
            .layouts_by_hash
            .get(&structure_hash)
            .and_then(|bucket| {
                bucket
                    .iter()
                    .find(|cached| row_field_layout_matches(&cached.structure, fields))
            })
        {
            return Ok(Arc::clone(&cached.layout));
        }

        let layout = Arc::new(AtomicUnitLayout {
            field_order: fields
                .iter()
                .map(|(name, _)| (*name).to_owned())
                .collect::<Vec<_>>()
                .into(),
            units: atomic_units_for_fields(self.profile, fields)?.into(),
        });

        if self.cached_layout_count < MAX_ATOMIC_UNIT_LAYOUT_CACHE_ENTRIES {
            let structure = fields
                .iter()
                .map(|(name, node)| RowFieldLayout {
                    name: (*name).to_owned(),
                    scalar: node.is_scalar(),
                    array_len: node.as_array().map(<[_]>::len),
                })
                .collect::<Vec<_>>()
                .into_boxed_slice();
            self.layouts_by_hash
                .entry(structure_hash)
                .or_default()
                .push(CachedAtomicUnitLayout {
                    structure,
                    layout: Arc::clone(&layout),
                });
            self.cached_layout_count += 1;
        }

        Ok(layout)
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ProfileValidationError {
    #[error("invalid profile: {0}")]
    Invalid(String),
}

#[derive(Debug, Error)]
pub enum ProfileRegistryError {
    #[error(transparent)]
    Validation(#[from] ProfileValidationError),
    #[error("profile id is already registered: {0}")]
    DuplicateProfileId(String),
    #[error("at most {MAX_GAME_PROFILES} game profiles may be registered")]
    TooManyProfiles,
}

#[derive(Debug, Clone)]
pub struct ProfileRegistry {
    games: Vec<GameProfile>,
    generic: AssetProfile,
}

impl Default for ProfileRegistry {
    fn default() -> Self {
        Self::with_builtins()
    }
}

impl ProfileRegistry {
    pub fn empty() -> Self {
        Self {
            games: Vec::new(),
            generic: generic::asset_profile(),
        }
    }

    pub fn with_builtins() -> Self {
        let mut registry = Self::empty();
        registry
            .register(octopath_traveler_0::game_profile())
            .expect("built-in OT0 profile must be valid");
        registry
    }

    pub fn register(
        &mut self,
        profile: GameProfile,
    ) -> std::result::Result<(), ProfileRegistryError> {
        if self.games.len() >= MAX_GAME_PROFILES {
            return Err(ProfileRegistryError::TooManyProfiles);
        }
        validate_game_profile(&profile)?;
        if self.games.iter().any(|existing| existing.id == profile.id) {
            return Err(ProfileRegistryError::DuplicateProfileId(profile.id));
        }
        self.games.push(profile);
        Ok(())
    }

    pub fn profiles(&self) -> &[GameProfile] {
        &self.games
    }

    pub fn summaries(&self) -> Vec<ProfileSummary> {
        self.games
            .iter()
            .map(|profile| ProfileSummary {
                id: profile.id.clone(),
                display_name: profile.display_name.clone(),
                format: profile.format,
                origin: match profile.origin {
                    ProfileOrigin::BuiltIn => ProfileOriginKind::BuiltIn,
                    ProfileOrigin::External { .. } => ProfileOriginKind::External,
                },
                asset_rule_count: profile.assets.len(),
                detection_signature_count: profile.detection_matchers.len(),
            })
            .collect()
    }

    /// Detects a game profile from an inventory of virtual asset paths.
    /// Selection is deliberately conservative: exactly one profile must meet
    /// its own signature threshold, otherwise the caller gets the generic mode.
    pub fn detect_inventory<'a, I>(&self, asset_paths: I) -> ProfileDetection
    where
        I: IntoIterator<Item = &'a str>,
    {
        let paths: BTreeSet<String> = asset_paths.into_iter().map(normalize_asset_path).collect();
        let mut candidates = Vec::with_capacity(self.games.len());
        let mut qualifying = Vec::new();

        for game in &self.games {
            let matched = game
                .detection_matchers
                .iter()
                .filter(|matcher| paths.iter().any(|path| matcher.matches_normalized(path)))
                .count();
            let qualifies = matched >= game.minimum_detection_matches;
            if qualifies {
                qualifying.push(game.id.clone());
            }
            candidates.push(ProfileDetectionCandidate {
                id: game.id.clone(),
                display_name: game.display_name.clone(),
                matched_signatures: matched,
                required_signatures: game.minimum_detection_matches,
                qualifies,
            });
        }

        let (status, selected_profile_id) = match qualifying.as_slice() {
            [only] => (ProfileDetectionStatus::Selected, Some(only.clone())),
            [] => (ProfileDetectionStatus::GenericNoMatch, None),
            _ => (ProfileDetectionStatus::GenericAmbiguous, None),
        };
        ProfileDetection {
            status,
            selected_profile_id,
            candidates,
        }
    }

    /// Resolves one asset under a profile already pinned from the complete Pak
    /// inventory. Without an explicit pinned id, this always returns the
    /// conservative generic profile; an asset suffix alone is not sufficient
    /// evidence that it belongs to a particular game.
    pub fn resolve_asset<'a>(
        &'a self,
        asset_path: &str,
        requested_game_profile: Option<&str>,
    ) -> ResolvedAssetProfile<'a> {
        let path = normalize_asset_path(asset_path);
        self.resolve_asset_normalized(path.as_str(), requested_game_profile)
    }

    fn resolve_asset_normalized<'a>(
        &'a self,
        normalized_asset_path: &str,
        requested_game_profile: Option<&str>,
    ) -> ResolvedAssetProfile<'a> {
        if let Some(requested) = requested_game_profile {
            let Some(game) = self.games.iter().find(|game| game.id == requested) else {
                return self
                    .generic_resolution(AssetProfileSelectionKind::GenericUnknownRequestedProfile);
            };
            let has_explicit_content_root = normalized_asset_path
                .split('/')
                .any(|segment| segment == "content");
            if has_explicit_content_root
                && !game.root_scope_matchers.is_empty()
                && !game
                    .root_scope_matchers
                    .iter()
                    .any(|matcher| matcher.matches_normalized(normalized_asset_path))
            {
                return self.generic_resolution(AssetProfileSelectionKind::GenericNoMatch);
            }
            let mut highest = None;
            let mut highest_is_ambiguous = false;
            for rule in game
                .assets
                .iter()
                .filter(|rule| rule.matches_normalized(normalized_asset_path))
            {
                match highest {
                    None => highest = Some(rule),
                    Some(current) if rule.priority > current.priority => {
                        highest = Some(rule);
                        highest_is_ambiguous = false;
                    }
                    Some(current) if rule.priority == current.priority => {
                        highest_is_ambiguous = true;
                    }
                    Some(_) => {}
                }
            }
            return match (highest, highest_is_ambiguous) {
                (Some(rule), false) => ResolvedAssetProfile {
                    game_profile: Some(game),
                    profile: &rule.profile,
                    selection: AssetProfileSelectionKind::Explicit,
                },
                (Some(_), true) => {
                    self.generic_resolution(AssetProfileSelectionKind::GenericAmbiguous)
                }
                (None, _) => self.generic_resolution(AssetProfileSelectionKind::GenericNoMatch),
            };
        }

        self.generic_resolution(AssetProfileSelectionKind::GenericNoMatch)
    }

    fn generic_resolution(&self, selection: AssetProfileSelectionKind) -> ResolvedAssetProfile<'_> {
        ResolvedAssetProfile {
            game_profile: None,
            profile: &self.generic,
            selection,
        }
    }
}

static DEFAULT_REGISTRY: LazyLock<ProfileRegistry> = LazyLock::new(ProfileRegistry::with_builtins);

pub fn default_registry() -> &'static ProfileRegistry {
    &DEFAULT_REGISTRY
}

/// Compatibility API for callers that have no inventory-level profile pin.
/// It deliberately uses the generic profile.
pub fn profile_for_asset(asset_path: &str) -> &'static AssetProfile {
    default_registry().resolve_asset(asset_path, None).profile
}

pub fn is_audited_asset(asset_path: &str) -> bool {
    profile_for_asset(asset_path).precision == ProfilePrecision::Audited
}

/// Compatibility API for callers that have no inventory-level profile pin.
/// It deliberately uses generic atomic units.
pub fn atomic_units_for_row(asset_path: &str, row: &MsgpackNode) -> Result<Vec<AtomicGroup>> {
    atomic_units_for_row_with_registry(default_registry(), None, asset_path, row)
}

/// Builds lossless field-selection units using an explicit registry/profile.
/// If the requested profile is unavailable or does not uniquely match the
/// asset, the conservative generic rules are used.
pub fn atomic_units_for_row_with_registry(
    registry: &ProfileRegistry,
    requested_game_profile: Option<&str>,
    asset_path: &str,
    row: &MsgpackNode,
) -> Result<Vec<AtomicGroup>> {
    let resolved = registry.resolve_asset(asset_path, requested_game_profile);
    atomic_units_for_profile(resolved.profile, row)
}

fn atomic_units_for_profile(profile: &AssetProfile, row: &MsgpackNode) -> Result<Vec<AtomicGroup>> {
    let fields = row.map_fields()?;
    atomic_units_for_fields(profile, fields.as_slice())
}

fn atomic_units_for_fields(
    profile: &AssetProfile,
    fields: &[(&str, &MsgpackNode)],
) -> Result<Vec<AtomicGroup>> {
    let field_names: BTreeSet<&str> = fields.iter().map(|(name, _)| *name).collect();
    let mut consumed = BTreeSet::new();
    let mut units = Vec::new();

    for rule in &profile.groups {
        let present: Vec<String> = rule
            .fields
            .iter()
            .map(String::as_str)
            .filter(|name| field_names.contains(name))
            .map(str::to_owned)
            .collect();
        if present.is_empty() {
            continue;
        }
        for field in &present {
            if field == "m_id" || !consumed.insert(field.clone()) {
                return Err(BinaryAssetError::OverlappingFieldSelection(field.clone()));
            }
        }
        let has_compound_value = present.iter().any(|name| {
            fields
                .iter()
                .find(|(field, _)| *field == name.as_str())
                .is_some_and(|(_, node)| !node.is_scalar())
        });
        let parallel_len = rule
            .index_coupled
            .then(|| {
                present
                    .iter()
                    .map(|name| {
                        fields
                            .iter()
                            .find(|(field, _)| *field == name.as_str())
                            .and_then(|(_, node)| node.as_array())
                            .map(|items| items.len())
                    })
                    .collect::<Option<Vec<_>>>()
            })
            .flatten()
            .and_then(|lengths| {
                lengths
                    .first()
                    .copied()
                    .filter(|first| *first > 0 && lengths.iter().all(|len| len == first))
            });
        if let Some(array_len) = parallel_len {
            for array_index in 0..array_len {
                units.push(AtomicGroup {
                    id: format!("group:{}[{array_index}]", rule.id),
                    fields: present.clone(),
                    compound: true,
                    array_index: Some(array_index),
                    expected_array_len: Some(array_len),
                });
            }
        } else {
            units.push(AtomicGroup {
                id: format!("group:{}", rule.id),
                fields: present,
                compound: rule.force_compound || has_compound_value,
                array_index: None,
                expected_array_len: None,
            });
        }
    }

    for (name, node) in fields.iter().copied() {
        if name == "m_id" || consumed.contains(name) {
            continue;
        }
        units.push(AtomicGroup {
            id: format!("field:{name}"),
            fields: vec![name.to_owned()],
            compound: !node.is_scalar(),
            array_index: None,
            expected_array_len: None,
        });
    }
    Ok(units)
}

fn hash_row_field_layout(fields: &[(&str, &MsgpackNode)]) -> u64 {
    const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

    fn update(hash: &mut u64, bytes: &[u8]) {
        for byte in bytes {
            *hash ^= u64::from(*byte);
            *hash = hash.wrapping_mul(FNV_PRIME);
        }
    }

    let mut hash = FNV_OFFSET_BASIS;
    update(&mut hash, &(fields.len() as u64).to_le_bytes());
    for (name, node) in fields {
        update(&mut hash, &(name.len() as u64).to_le_bytes());
        update(&mut hash, name.as_bytes());
        update(&mut hash, &[u8::from(node.is_scalar())]);
        match node.as_array() {
            Some(items) => {
                update(&mut hash, &[1]);
                update(&mut hash, &(items.len() as u64).to_le_bytes());
            }
            None => update(&mut hash, &[0]),
        }
    }
    hash
}

fn row_field_layout_matches(cached: &[RowFieldLayout], fields: &[(&str, &MsgpackNode)]) -> bool {
    cached.len() == fields.len()
        && cached.iter().zip(fields).all(|(cached, (name, node))| {
            cached.name == *name
                && cached.scalar == node.is_scalar()
                && cached.array_len == node.as_array().map(<[_]>::len)
        })
}

pub fn normalize_asset_path(asset_path: &str) -> String {
    let mut path = asset_path.replace('\\', "/").to_ascii_lowercase();
    while path.contains("//") {
        path = path.replace("//", "/");
    }
    for suffix in [".uasset", ".uexp", ".ubulk", ".uptnl"] {
        if path.ends_with(suffix) {
            path.truncate(path.len() - suffix.len());
            break;
        }
    }
    if !path.starts_with('/') {
        path.insert(0, '/');
    }
    path
}

fn validate_game_profile(profile: &GameProfile) -> std::result::Result<(), ProfileValidationError> {
    validate_profile_id(&profile.id, "game profile id")?;
    validate_display_name(&profile.display_name)?;
    if profile.detection_matchers.is_empty()
        || profile.detection_matchers.len() > MAX_DETECTION_MATCHERS
    {
        return invalid(format!(
            "{} detection matchers must contain 1..={MAX_DETECTION_MATCHERS} items",
            profile.id
        ));
    }
    if profile.minimum_detection_matches == 0
        || profile.minimum_detection_matches > profile.detection_matchers.len()
    {
        return invalid(format!(
            "{} minimum detection matches is outside its matcher count",
            profile.id
        ));
    }
    if profile.assets.is_empty() || profile.assets.len() > MAX_ASSET_RULES {
        return invalid(format!(
            "{} asset rules must contain 1..={MAX_ASSET_RULES} items",
            profile.id
        ));
    }

    let mut matcher_keys = BTreeSet::new();
    let mut detection_matchers = BTreeSet::new();
    for matcher in &profile.detection_matchers {
        validate_virtual_path_pattern(matcher.kind, &matcher.value)?;
        if !detection_matchers.insert((matcher.kind, matcher.value.clone())) {
            return invalid(format!(
                "{} contains a duplicate detection path matcher",
                profile.id
            ));
        }
    }
    if profile.root_scope_matchers.len() > MAX_ROOT_SCOPE_MATCHERS {
        return invalid(format!(
            "{} root scope matchers must contain at most {MAX_ROOT_SCOPE_MATCHERS} items",
            profile.id
        ));
    }
    let mut root_scope_matchers = BTreeSet::new();
    for matcher in &profile.root_scope_matchers {
        validate_virtual_path_pattern(matcher.kind, &matcher.value)?;
        if !root_scope_matchers.insert((matcher.kind, matcher.value.clone())) {
            return invalid(format!(
                "{} contains a duplicate root scope matcher",
                profile.id
            ));
        }
    }
    for asset in &profile.assets {
        if asset.priority > MAX_ASSET_RULE_PRIORITY {
            return invalid(format!(
                "{}.{} priority {} is outside the supported 0..={MAX_ASSET_RULE_PRIORITY} range",
                profile.id, asset.profile.id, asset.priority
            ));
        }
        if asset.matchers.is_empty() || asset.matchers.len() > MAX_MATCHERS_PER_ASSET {
            return invalid(format!(
                "{}.{} matchers must contain 1..={MAX_MATCHERS_PER_ASSET} items",
                profile.id, asset.profile.id
            ));
        }
        let mut local_matchers = BTreeSet::new();
        for matcher in &asset.matchers {
            validate_virtual_path_pattern(matcher.kind, &matcher.value)?;
            if !local_matchers.insert((matcher.kind, matcher.value.clone())) {
                return invalid(format!(
                    "{}.{} contains a duplicate path matcher",
                    profile.id, asset.profile.id
                ));
            }
        }
        if !matcher_keys.insert(local_matchers) {
            return invalid(format!(
                "{} contains a duplicate asset path matcher",
                profile.id
            ));
        }
        validate_profile_id(&asset.profile.id, "asset profile id")?;
        if asset.profile.groups.len() > MAX_GROUPS_PER_ASSET {
            return invalid(format!(
                "{}.{} has more than {MAX_GROUPS_PER_ASSET} field groups",
                profile.id, asset.profile.id
            ));
        }
        let mut group_ids = BTreeSet::new();
        let mut grouped_fields = BTreeMap::new();
        for group in &asset.profile.groups {
            validate_profile_id(&group.id, "field group id")?;
            if !group_ids.insert(group.id.clone()) {
                return invalid(format!(
                    "{}.{} contains duplicate field group id {}",
                    profile.id, asset.profile.id, group.id
                ));
            }
            if group.fields.is_empty() || group.fields.len() > MAX_FIELDS_PER_GROUP {
                return invalid(format!(
                    "{}.{}.{} fields must contain 1..={MAX_FIELDS_PER_GROUP} items",
                    profile.id, asset.profile.id, group.id
                ));
            }
            let mut local_fields = BTreeSet::new();
            for field in &group.fields {
                validate_field_name(field)?;
                if field == "m_id" {
                    return invalid(format!(
                        "{}.{}.{} may not include the row id field m_id",
                        profile.id, asset.profile.id, group.id
                    ));
                }
                if !local_fields.insert(field.clone()) {
                    return invalid(format!(
                        "{}.{}.{} contains duplicate field {field}",
                        profile.id, asset.profile.id, group.id
                    ));
                }
                if let Some(previous) = grouped_fields.insert(field.clone(), group.id.clone()) {
                    return invalid(format!(
                        "{}.{} field {field} overlaps groups {previous} and {}",
                        profile.id, asset.profile.id, group.id
                    ));
                }
            }
        }
    }
    Ok(())
}

fn validate_profile_id(
    value: &str,
    label: &str,
) -> std::result::Result<(), ProfileValidationError> {
    if value.is_empty() || value.len() > 64 {
        return invalid(format!("{label} length must be 1..=64 bytes"));
    }
    if !value.bytes().enumerate().all(|(index, byte)| {
        byte.is_ascii_lowercase()
            || byte.is_ascii_digit()
            || (index > 0 && matches!(byte, b'_' | b'-' | b'.'))
    }) || value.as_bytes()[0].is_ascii_digit()
    {
        return invalid(format!(
            "{label} must start with a lowercase letter and use lowercase ASCII letters, digits, '.', '-' or '_'"
        ));
    }
    Ok(())
}

fn validate_field_name(value: &str) -> std::result::Result<(), ProfileValidationError> {
    if value.is_empty() || value.len() > 96 {
        return invalid("field names must contain 1..=96 bytes".to_owned());
    }
    if !value.bytes().enumerate().all(|(index, byte)| {
        byte.is_ascii_alphabetic() || byte == b'_' || (index > 0 && byte.is_ascii_digit())
    }) {
        return invalid(format!("invalid declarative field name: {value}"));
    }
    Ok(())
}

fn validate_display_name(value: &str) -> std::result::Result<(), ProfileValidationError> {
    if value.trim() != value || value.is_empty() || value.chars().count() > 96 {
        return invalid(
            "display name must contain 1..=96 characters without outer whitespace".to_owned(),
        );
    }
    if value.chars().any(char::is_control) {
        return invalid("display name may not contain control characters".to_owned());
    }
    Ok(())
}

fn validate_virtual_path_pattern(
    kind: PathMatchKind,
    value: &str,
) -> std::result::Result<(), ProfileValidationError> {
    if value.len() < 4 || value.len() > MAX_VIRTUAL_PATH_PATTERN_BYTES {
        return invalid(format!(
            "virtual path patterns must contain 4..={MAX_VIRTUAL_PATH_PATTERN_BYTES} bytes"
        ));
    }
    if !value.starts_with('/') || value.starts_with("//") || value.contains("//") {
        return invalid(
            "virtual path patterns must start with one '/' and may not contain empty segments"
                .to_owned(),
        );
    }
    if value.contains('\\')
        || value.contains(':')
        || value.contains("%2e")
        || value.contains("%2E")
        || value.chars().any(char::is_control)
        || value
            .chars()
            .any(|ch| matches!(ch, '*' | '?' | '[' | ']' | '{' | '}'))
    {
        return invalid("virtual path patterns may not contain file references, escapes, controls, or wildcard syntax".to_owned());
    }
    if value
        .split('/')
        .any(|segment| matches!(segment, "." | ".."))
    {
        return invalid("virtual path patterns may not traverse directories".to_owned());
    }
    let minimum_segments = if kind == PathMatchKind::Suffix { 1 } else { 2 };
    if value
        .split('/')
        .filter(|segment| !segment.is_empty())
        .count()
        < minimum_segments
    {
        return invalid(format!(
            "this virtual path matcher must identify at least {minimum_segments} path segment(s)"
        ));
    }
    Ok(())
}

fn invalid<T>(message: String) -> std::result::Result<T, ProfileValidationError> {
    Err(ProfileValidationError::Invalid(message))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binary_asset::parse_messagepack;

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
    fn asset_suffix_without_inventory_pin_stays_generic() {
        let registry = ProfileRegistry::with_builtins();
        let unpinned = registry.resolve_asset(
            r"Octopath_Traveler0\Content\Local\DataBase\Skill\SkillAvailID.uexp",
            None,
        );
        assert_eq!(unpinned.profile.precision, ProfilePrecision::Generic);

        let pinned = registry.resolve_asset(
            r"Octopath_Traveler0\Content\Local\DataBase\Skill\SkillAvailID.uexp",
            Some("octopath_traveler_0"),
        );
        assert_eq!(pinned.profile.id, "skill_avail_id");
        assert_eq!(pinned.profile.precision, ProfilePrecision::Audited);
        assert!(!pinned.profile.groups.is_empty());
    }

    #[test]
    fn known_ot0_rule_beats_the_database_default() {
        let registry = ProfileRegistry::with_builtins();
        let resolved = registry.resolve_asset(
            "/Octopath_Traveler0/Content/Local/DataBase/Skill/SkillID.uasset",
            Some("octopath_traveler_0"),
        );

        assert_eq!(resolved.selection, AssetProfileSelectionKind::Explicit);
        assert_eq!(resolved.profile.id, "skill_id");
        assert_eq!(resolved.profile.precision, ProfilePrecision::Audited);
    }

    #[test]
    fn unknown_ot0_database_asset_uses_the_safe_game_default() {
        let registry = ProfileRegistry::with_builtins();
        let asset_path =
            "/Octopath_Traveler0/Content/Local/DataBase/Unknown/UnreviewedTable.uasset";
        let detection = registry.detect_inventory([asset_path]);
        assert_eq!(detection.status, ProfileDetectionStatus::Selected);
        let selected_profile = detection.selected_profile_id.as_deref();
        let resolved = registry.resolve_asset(asset_path, selected_profile);

        assert_eq!(resolved.selection, AssetProfileSelectionKind::Explicit);
        assert_eq!(resolved.profile.id, "database_default");
        assert_eq!(resolved.profile.precision, ProfilePrecision::GameDefault);
        assert!(resolved.profile.groups.is_empty());

        let row = parse_messagepack(&map(&[
            ("m_id", vec![1]),
            ("m_scalar", vec![2]),
            ("m_array", vec![0x91, 3]),
        ]))
        .unwrap();
        let units =
            atomic_units_for_row_with_registry(&registry, selected_profile, asset_path, &row)
                .unwrap();
        assert!(
            units
                .iter()
                .any(|unit| unit.id == "field:m_scalar" && !unit.compound)
        );
        assert!(
            units
                .iter()
                .any(|unit| unit.id == "field:m_array" && unit.compound)
        );
    }

    #[test]
    fn selected_ot0_profile_does_not_claim_assets_outside_local_database() {
        let registry = ProfileRegistry::with_builtins();
        let resolved = registry.resolve_asset(
            "/Octopath_Traveler0/Content/UI/UnreviewedWidget.uasset",
            Some("octopath_traveler_0"),
        );

        assert_eq!(
            resolved.selection,
            AssetProfileSelectionKind::GenericNoMatch
        );
        assert_eq!(resolved.profile.precision, ProfilePrecision::Generic);
        assert!(resolved.game_profile.is_none());
    }

    #[test]
    fn pinned_ot0_profile_does_not_claim_another_games_rooted_database_path() {
        let registry = ProfileRegistry::with_builtins();
        let detection = registry.detect_inventory([
            "/Octopath_Traveler0/Content/Local/DataBase/Enemy/EnemyID.uasset",
            "/OtherGame/Content/Local/DataBase/Skill/SkillID.uasset",
        ]);
        assert_eq!(detection.status, ProfileDetectionStatus::Selected);
        assert_eq!(
            detection.selected_profile_id.as_deref(),
            Some("octopath_traveler_0")
        );
        let resolved = registry.resolve_asset(
            "/OtherGame/Content/Local/DataBase/Skill/SkillID.uasset",
            detection.selected_profile_id.as_deref(),
        );

        assert_eq!(
            resolved.selection,
            AssetProfileSelectionKind::GenericNoMatch
        );
        assert_eq!(resolved.profile.precision, ProfilePrecision::Generic);
        assert!(resolved.game_profile.is_none());
    }

    #[test]
    fn external_inventory_detection_does_not_scope_each_asset_path() {
        let mut document: serde_json::Value =
            serde_json::from_str(include_str!("../../profiles/example-game.profile.json")).unwrap();
        document["detection"]["pathMatchers"][0] = serde_json::json!({
            "kind": "exact",
            "value": "/examplegame/content/versionasset"
        });
        let profile = parse_external_profile_json(&serde_json::to_vec(&document).unwrap()).unwrap();
        let mut registry = ProfileRegistry::empty();
        registry.register(profile).unwrap();
        let detection = registry.detect_inventory([
            "/ExampleGame/Content/VersionAsset.uasset",
            "/ExampleGame/Content/Database/Skills.uasset",
        ]);
        assert_eq!(detection.status, ProfileDetectionStatus::Selected);

        let resolved = registry.resolve_asset(
            "/ExampleGame/Content/Database/Skills.uasset",
            detection.selected_profile_id.as_deref(),
        );
        assert_eq!(resolved.selection, AssetProfileSelectionKind::Explicit);
        assert_eq!(resolved.profile.id, "skills");
        assert_eq!(resolved.profile.precision, ProfilePrecision::Declared);
    }

    #[test]
    fn root_scope_matchers_are_bounded_and_must_be_unique() {
        let mut duplicate = octopath_traveler_0::game_profile();
        duplicate.id = "duplicate_root_scope".to_owned();
        duplicate.display_name = "Duplicate Root Scope".to_owned();
        duplicate
            .root_scope_matchers
            .push(duplicate.root_scope_matchers[0].clone());
        let mut registry = ProfileRegistry::empty();
        assert!(matches!(
            registry.register(duplicate),
            Err(ProfileRegistryError::Validation(_))
        ));

        let mut excessive = octopath_traveler_0::game_profile();
        excessive.id = "excessive_root_scope".to_owned();
        excessive.display_name = "Excessive Root Scope".to_owned();
        excessive.root_scope_matchers = (0..=MAX_ROOT_SCOPE_MATCHERS)
            .map(|index| {
                PathMatcher::builtin(PathMatchKind::Contains, &format!("/scope{index}/content/"))
            })
            .collect();
        assert!(matches!(
            registry.register(excessive),
            Err(ProfileRegistryError::Validation(_))
        ));
    }

    #[test]
    fn pinned_ot0_profile_accepts_its_rooted_path_and_content_relative_paths() {
        let registry = ProfileRegistry::with_builtins();
        for asset_path in [
            "/Octopath_Traveler0/Content/Local/DataBase/Skill/SkillID.uasset",
            "/Local/DataBase/Skill/SkillID.uasset",
        ] {
            let resolved = registry.resolve_asset(asset_path, Some("octopath_traveler_0"));
            assert_eq!(resolved.selection, AssetProfileSelectionKind::Explicit);
            assert_eq!(resolved.profile.id, "skill_id");
            assert_eq!(resolved.profile.precision, ProfilePrecision::Audited);
        }

        let relative_default = registry.resolve_asset(
            "/Local/DataBase/Unknown/UnreviewedTable.uasset",
            Some("octopath_traveler_0"),
        );
        assert_eq!(
            relative_default.selection,
            AssetProfileSelectionKind::Explicit
        );
        assert_eq!(relative_default.profile.id, "database_default");
        assert_eq!(
            relative_default.profile.precision,
            ProfilePrecision::GameDefault
        );
    }

    #[test]
    fn equal_highest_priority_matches_remain_ambiguous() {
        let mut game = octopath_traveler_0::game_profile();
        game.id = "priority_overlap_test".to_owned();
        game.display_name = "Priority Overlap Test".to_owned();
        for (id, matchers) in [
            (
                "overlap_contains",
                vec![PathMatcher::builtin(
                    PathMatchKind::Contains,
                    "/local/database/unknown/",
                )],
            ),
            (
                "overlap_suffix",
                vec![PathMatcher::builtin(
                    PathMatchKind::Suffix,
                    "/unknown/unreviewedtable",
                )],
            ),
        ] {
            game.assets.push(AssetProfileRule {
                matchers,
                priority: 500,
                profile: AssetProfile {
                    id: id.to_owned(),
                    precision: ProfilePrecision::Audited,
                    groups: Vec::new(),
                },
            });
        }

        let mut registry = ProfileRegistry::empty();
        registry.register(game).unwrap();
        let resolved = registry.resolve_asset(
            "/Octopath_Traveler0/Content/Local/DataBase/Unknown/UnreviewedTable",
            Some("priority_overlap_test"),
        );
        assert_eq!(
            resolved.selection,
            AssetProfileSelectionKind::GenericAmbiguous
        );
        assert_eq!(resolved.profile.precision, ProfilePrecision::Generic);
    }

    #[test]
    fn atomic_unit_planner_reuses_an_exact_layout_without_changing_units() {
        let registry = ProfileRegistry::with_builtins();
        let asset_path = "/Octopath_Traveler0/Content/Local/DataBase/Skill/SkillID";
        let first = parse_messagepack(&map(&[
            ("m_id", vec![1]),
            ("m_Avails", vec![0x92, 2, 3]),
            ("m_Effectives", vec![0x92, 4, 5]),
            ("m_Enabled", vec![0xc3]),
        ]))
        .unwrap();
        let second = parse_messagepack(&map(&[
            ("m_id", vec![9]),
            ("m_Avails", vec![0x92, 6, 7]),
            ("m_Effectives", vec![0x92, 8, 9]),
            ("m_Enabled", vec![0xc2]),
        ]))
        .unwrap();
        let expected = atomic_units_for_row_with_registry(
            &registry,
            Some("octopath_traveler_0"),
            asset_path,
            &first,
        )
        .unwrap();

        let mut planner = AtomicUnitPlanner::new(
            &registry,
            Some("octopath_traveler_0"),
            &format!("{asset_path}.uasset"),
        );
        let first_layout = planner.layout_for_row(&first).unwrap();
        let second_layout = planner.layout_for_row(&second).unwrap();

        assert!(Arc::ptr_eq(&first_layout, &second_layout));
        assert_eq!(planner.cached_layout_count(), 1);
        assert_eq!(first_layout.units.as_ref(), expected.as_slice());
        assert_eq!(
            first_layout.field_order.as_ref(),
            ["m_id", "m_Avails", "m_Effectives", "m_Enabled"]
        );
        assert_eq!(planner.profile().id, "skill_id");
        assert_eq!(planner.selection(), AssetProfileSelectionKind::Explicit);
        assert_eq!(
            planner.normalized_asset_path(),
            asset_path.to_ascii_lowercase()
        );
    }

    #[test]
    fn atomic_unit_planner_misses_on_value_kind_or_array_length_changes() {
        let registry = ProfileRegistry::empty();
        let mut planner = AtomicUnitPlanner::new(&registry, None, "/Game/Database/Table");
        let scalar = parse_messagepack(&map(&[("m_id", vec![1]), ("m_Value", vec![2])])).unwrap();
        let array_one =
            parse_messagepack(&map(&[("m_id", vec![1]), ("m_Value", vec![0x91, 2])])).unwrap();
        let array_two =
            parse_messagepack(&map(&[("m_id", vec![1]), ("m_Value", vec![0x92, 2, 3])])).unwrap();

        let scalar_layout = planner.layout_for_row(&scalar).unwrap();
        let array_one_layout = planner.layout_for_row(&array_one).unwrap();
        let array_two_layout = planner.layout_for_row(&array_two).unwrap();

        assert!(!Arc::ptr_eq(&scalar_layout, &array_one_layout));
        assert!(!Arc::ptr_eq(&array_one_layout, &array_two_layout));
        assert_eq!(planner.cached_layout_count(), 3);
    }

    #[test]
    fn atomic_unit_planner_does_not_cache_a_mismatched_field_order() {
        let registry = ProfileRegistry::empty();
        let mut planner = AtomicUnitPlanner::new(&registry, None, "/Game/Database/Table");
        let carrier = parse_messagepack(&map(&[("m_id", vec![1]), ("m_Value", vec![2])])).unwrap();
        let donor =
            parse_messagepack(&map(&[("m_id", vec![1]), ("m_Other", vec![0x92, 2, 3])])).unwrap();
        let carrier_layout = planner.layout_for_row(&carrier).unwrap();

        let donor_layout = planner
            .layout_for_row_matching_field_order(&donor, &carrier_layout.field_order)
            .unwrap();

        assert!(donor_layout.is_none());
        assert_eq!(planner.cached_layout_count(), 1);
    }

    #[test]
    fn atomic_unit_planner_checks_exact_structure_after_a_hash_collision() {
        let registry = ProfileRegistry::empty();
        let mut planner = AtomicUnitPlanner::new(&registry, None, "/Game/Database/Table");
        let first = parse_messagepack(&map(&[("m_id", vec![1]), ("m_First", vec![2])])).unwrap();
        let second = parse_messagepack(&map(&[("m_id", vec![1]), ("m_Second", vec![2])])).unwrap();
        let first_fields = first.map_fields().unwrap();
        let second_fields = second.map_fields().unwrap();

        let first_layout = planner
            .layout_for_fields(first_fields.as_slice(), 7)
            .unwrap();
        let second_layout = planner
            .layout_for_fields(second_fields.as_slice(), 7)
            .unwrap();
        let first_hit = planner
            .layout_for_fields(first_fields.as_slice(), 7)
            .unwrap();

        assert!(!Arc::ptr_eq(&first_layout, &second_layout));
        assert!(Arc::ptr_eq(&first_layout, &first_hit));
        assert_eq!(planner.cached_layout_count(), 2);
    }

    #[test]
    fn atomic_unit_planner_stops_caching_after_256_layouts_without_rejecting_rows() {
        let registry = ProfileRegistry::empty();
        let mut planner = AtomicUnitPlanner::new(&registry, None, "/Game/Database/Table");
        for index in 0..MAX_ATOMIC_UNIT_LAYOUT_CACHE_ENTRIES {
            let field = format!("m_f{index:03}");
            let row =
                parse_messagepack(&map(&[("m_id", vec![1]), (field.as_str(), vec![2])])).unwrap();
            planner.layout_for_row(&row).unwrap();
        }
        assert_eq!(
            planner.cached_layout_count(),
            MAX_ATOMIC_UNIT_LAYOUT_CACHE_ENTRIES
        );

        let overflow =
            parse_messagepack(&map(&[("m_id", vec![1]), ("m_overflow", vec![2])])).unwrap();
        let first = planner.layout_for_row(&overflow).unwrap();
        let second = planner.layout_for_row(&overflow).unwrap();
        assert!(!Arc::ptr_eq(&first, &second));
        assert_eq!(
            planner.cached_layout_count(),
            MAX_ATOMIC_UNIT_LAYOUT_CACHE_ENTRIES
        );
    }

    #[test]
    fn couples_parallel_condition_arrays() {
        let row_raw = map(&[
            ("m_id", vec![1]),
            ("m_Conditions", vec![0x91, 1]),
            ("m_Params", vec![0x91, 2]),
            ("m_AilmentTypes", vec![0x91, 3]),
            ("m_PrioritySkill", vec![0xc3]),
        ]);
        let row = parse_messagepack(&row_raw).unwrap();
        let registry = ProfileRegistry::with_builtins();
        let units = atomic_units_for_row_with_registry(
            &registry,
            Some("octopath_traveler_0"),
            "/Octopath_Traveler0/Content/Local/DataBase/AIBattle/TacticalActionList",
            &row,
        )
        .unwrap();
        let condition = units
            .iter()
            .find(|unit| unit.id == "group:condition_parameters[0]")
            .unwrap();
        assert_eq!(
            condition.fields,
            ["m_Conditions", "m_Params", "m_AilmentTypes"]
        );
        assert!(condition.compound);
        assert_eq!(condition.array_index, Some(0));
        assert_eq!(condition.expected_array_len, Some(1));
        assert!(
            units
                .iter()
                .any(|unit| unit.id == "field:m_PrioritySkill" && !unit.compound)
        );
    }

    #[test]
    fn generic_profile_keeps_scalar_independent_and_array_atomic() {
        let row_raw = map(&[
            ("m_id", vec![1]),
            ("m_scalar", vec![0xc3]),
            ("m_array", vec![0x92, 1, 2]),
        ]);
        let row = parse_messagepack(&row_raw).unwrap();
        let units = atomic_units_for_row("/Local/DataBase/Unknown/SomeTable", &row).unwrap();
        assert_eq!(
            profile_for_asset("unknown").precision,
            ProfilePrecision::Generic
        );
        assert!(
            units
                .iter()
                .any(|unit| unit.id == "field:m_scalar" && !unit.compound)
        );
        assert!(
            units
                .iter()
                .any(|unit| unit.id == "field:m_array" && unit.compound)
        );
        assert!(
            !units
                .iter()
                .any(|unit| unit.fields.len() == 1 && unit.fields[0] == "m_id")
        );
    }

    #[test]
    fn return_fields_are_one_event_atomic_unit() {
        let row_raw = map(&[
            ("m_id", vec![1]),
            ("m_ReturnMapID", vec![2]),
            ("m_ReturnPathActorName", fixstr("Gate")),
            ("m_ReturnPos", vec![0x92, 0, 0]),
            ("m_ReturnDir", vec![3]),
        ]);
        let row = parse_messagepack(&row_raw).unwrap();
        let registry = ProfileRegistry::with_builtins();
        let units = atomic_units_for_row_with_registry(
            &registry,
            Some("octopath_traveler_0"),
            "/Octopath_Traveler0/Content/Local/DataBase/Event/EventList.uasset",
            &row,
        )
        .unwrap();
        let return_unit = units
            .iter()
            .find(|unit| unit.id == "group:return_transition")
            .unwrap();
        assert_eq!(return_unit.fields.len(), 4);
        assert!(return_unit.compound);
        assert_eq!(return_unit.array_index, None);
    }

    #[test]
    fn inventory_detection_never_guesses_when_profiles_are_ambiguous() {
        let ot0 = octopath_traveler_0::game_profile();
        let mut duplicate = ot0.clone();
        duplicate.id = "another_game".to_owned();
        duplicate.display_name = "Another Game".to_owned();
        let mut registry = ProfileRegistry::empty();
        registry.register(ot0).unwrap();
        registry.register(duplicate).unwrap();

        let detection = registry
            .detect_inventory(["/Octopath_Traveler0/Content/Local/DataBase/Skill/SkillID.uasset"]);
        assert_eq!(detection.status, ProfileDetectionStatus::GenericAmbiguous);
        assert_eq!(detection.selected_profile_id, None);
        assert_eq!(
            registry
                .resolve_asset(
                    "/Octopath_Traveler0/Content/Local/DataBase/Skill/SkillID",
                    None,
                )
                .selection,
            AssetProfileSelectionKind::GenericNoMatch
        );
    }

    #[test]
    fn ot0_inventory_selects_ot0_but_other_game_skill_suffix_stays_generic() {
        let registry = ProfileRegistry::with_builtins();
        let ot0 = registry.detect_inventory([
            "../../../Octopath_Traveler0/Content/Local/DataBase/Skill/SkillID.uasset",
            "../../../Octopath_Traveler0/Content/UI/SomeWidget.uasset",
        ]);
        assert_eq!(ot0.status, ProfileDetectionStatus::Selected);
        assert_eq!(
            ot0.selected_profile_id.as_deref(),
            Some("octopath_traveler_0")
        );

        let other = registry.detect_inventory([
            "../../../OtherGame/Content/Local/DataBase/Skill/SkillID.uasset",
            "../../../OtherGame/Content/UI/SomeWidget.uasset",
        ]);
        assert_eq!(other.status, ProfileDetectionStatus::GenericNoMatch);
        assert_eq!(other.selected_profile_id, None);
        let units = atomic_units_for_row_with_registry(
            &registry,
            other.selected_profile_id.as_deref(),
            "/Local/DataBase/Skill/SkillID",
            &parse_messagepack(&map(&[
                ("m_id", vec![1]),
                ("m_Avails", vec![0x91, 2]),
                ("m_Effectives", vec![0x91, 3]),
            ]))
            .unwrap(),
        )
        .unwrap();
        assert!(!units.iter().any(|unit| unit.id.starts_with("group:")));
    }

    #[test]
    fn explicit_profile_selection_is_available_for_gui_and_cli() {
        let registry = ProfileRegistry::with_builtins();
        let resolved = registry.resolve_asset(
            "/Octopath_Traveler0/Content/Local/DataBase/Enemy/EnemyGroups",
            Some("octopath_traveler_0"),
        );
        assert_eq!(resolved.selection, AssetProfileSelectionKind::Explicit);
        assert_eq!(resolved.profile.id, "enemy_groups");
        assert_eq!(resolved.game_profile.unwrap().id, "octopath_traveler_0");
    }
}
