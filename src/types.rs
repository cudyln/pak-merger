use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Internal progress scale for one database item.
pub const ANALYSIS_PROGRESS_STEPS_PER_ITEM: usize = 1_000_000;

pub const MAX_SUPPORTED_PAKS: usize = 64;
pub const MAX_SUPPORTED_TOTAL_BYTES: u64 = 128 * 1024 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PakInput {
    pub path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InputDescriptor {
    pub id: String,
    pub path: PathBuf,
    pub display_name: String,
    pub sha256: String,
    pub size: u64,
    pub pak_version: Option<u32>,
    pub mount_point: Option<String>,
    pub entry_count: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct RowKey {
    pub asset_path: String,
    pub m_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AtomicGroup {
    pub id: String,
    pub fields: Vec<String>,
    pub compound: bool,
    /// Selects one matching index from each parallel array when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub array_index: Option<usize>,
    /// Array length recorded during analysis. Selected inputs must match it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_array_len: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PackageGroup {
    pub virtual_base_path: String,
    pub entries: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ConflictKind {
    FieldValue,
    AtomicGroup,
    RowIdCollision,
    /// Distinct NpcSet rows may refer to the same in-game location.
    PotentialPlacementCollision,
    OpaquePackage,
    StructureMismatch,
    EncodingDrift,
    ReferenceBreak,
    UnsupportedAsset,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Provenance {
    pub input_id: String,
    pub input_path: PathBuf,
    pub entry_path: Option<String>,
    pub raw_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Variant {
    pub id: String,
    pub label: String,
    pub input_id: String,
    pub raw_sha256: String,
    pub semantic_sha256: String,
    pub preview: String,
    pub marker: String,
    pub provenance: Provenance,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Conflict {
    pub id: String,
    pub kind: ConflictKind,
    pub asset_path: String,
    pub row_id: Option<String>,
    pub group_id: Option<String>,
    pub message: String,
    pub variants: Vec<Variant>,
    pub blocking: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AssetActionKind {
    Copy,
    Deduplicate,
    MergeDatabase,
    SelectOpaque,
    Unsupported,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AssetPlan {
    pub virtual_path: String,
    pub package_entries: Vec<String>,
    pub action: AssetActionKind,
    pub donor_input_ids: Vec<String>,
    pub conflict_ids: Vec<String>,
    pub warnings: Vec<String>,
    /// Equal values with different MessagePack encodings; only a sample is listed.
    #[serde(default)]
    pub encoding_drift_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AnalysisRequest {
    pub pak_paths: Vec<PathBuf>,
    pub carrier_path: PathBuf,
}

/// Records how the analysis chose its game profile.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProfileDetectionStatus {
    Selected,
    GenericNoMatch,
    GenericAmbiguous,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MergePlan {
    pub schema_version: u32,
    pub plan_id: String,
    pub request: AnalysisRequest,
    pub inputs: Vec<InputDescriptor>,
    pub carrier_input_id: String,
    pub assets: Vec<AssetPlan>,
    pub conflicts: Vec<Conflict>,
    pub warnings: Vec<String>,
    /// Selected game profile. `None` means general rules were used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_profile_id: Option<String>,
    /// Profile detection result recorded with the plan.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_detection_status: Option<ProfileDetectionStatus>,
    #[serde(default)]
    pub encoding_drift_count: u64,
    pub full_reencode_forbidden: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResolutionSet {
    pub plan_id: String,
    #[serde(default)]
    pub choices: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResolvedPlan {
    pub plan: MergePlan,
    pub resolutions: ResolutionSet,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OutputCompression {
    #[default]
    None,
    Oodle,
}

impl OutputCompression {
    pub const fn report_name(self) -> &'static str {
        match self {
            Self::None => "None",
            Self::Oodle => "Oodle",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct WriteOptions {
    #[serde(default)]
    pub compression: OutputCompression,
    #[serde(default = "default_multithreaded")]
    pub multithreaded: bool,
    /// Replace an existing output after the new Pak passes verification.
    #[serde(default)]
    pub overwrite_existing: bool,
}

const fn default_multithreaded() -> bool {
    true
}

impl Default for WriteOptions {
    fn default() -> Self {
        Self {
            compression: OutputCompression::None,
            multithreaded: true,
            overwrite_existing: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MergeProgressStage {
    CheckingInputs,
    ComparingChanges,
    PreparingFiles,
    IndexingDatabase,
    BuildingDatabase,
    WritingPak,
    VerifyingPak,
    CheckingReferences,
    Finalizing,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergeProgress {
    pub stage: MergeProgressStage,
    pub completed: u64,
    pub total: u64,
    pub current_item: Option<String>,
}

impl MergePlan {
    pub fn unresolved_conflict_ids(&self, resolutions: &ResolutionSet) -> Vec<String> {
        self.conflicts
            .iter()
            .filter(|conflict| conflict.blocking && !resolutions.choices.contains_key(&conflict.id))
            .map(|conflict| conflict.id.clone())
            .collect()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MergeReport {
    pub schema_version: u32,
    pub tool_version: String,
    pub plan_id: String,
    pub carrier_input_id: String,
    pub inputs: Vec<InputDescriptor>,
    pub output_path: PathBuf,
    pub output_sha256: String,
    pub output_size: u64,
    pub output_entry_count: usize,
    pub output_pak_version: u32,
    pub output_mount_point: String,
    pub output_compression: String,
    pub output_encrypted: bool,
    pub output_signed: bool,
    pub final_inventory: Vec<FinalEntryInventory>,
    pub actions: Vec<AssetPlan>,
    pub conflicts: Vec<Conflict>,
    pub resolved_conflicts: Vec<ResolvedConflictRecord>,
    pub resolutions: ResolutionSet,
    pub warnings: Vec<String>,
    pub raw_preserved_nodes: u64,
    pub raw_replaced_nodes: u64,
    pub raw_preservation_audits: Vec<RawPreservationAssetAudit>,
    pub encoding_drift_count: u64,
    pub reference_validation_warnings: Vec<String>,
    pub full_reencode_forbidden: bool,
    pub verification_passed: bool,
}

/// Verification summary for one rebuilt database.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RawPreservationAssetAudit {
    pub asset_path: String,
    pub pak_entry_path: String,
    pub entry_sha256: String,
    pub ledger_sha256: String,
    pub verified_row_count: u64,
    pub verified_atomic_unit_count: u64,
    pub preserved_node_count: u64,
    pub replaced_node_count: u64,
    pub passed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FinalEntryInventory {
    pub path: String,
    pub size: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResolvedConflictRecord {
    pub conflict_id: String,
    pub selected_variant: Option<Variant>,
    pub automatic: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerificationResult {
    pub valid: bool,
    pub pak_sha256: String,
    pub entry_count: usize,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}
