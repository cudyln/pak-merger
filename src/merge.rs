#[cfg(test)]
use crate::binary_asset::BinaryAsset;
use crate::binary_asset::{
    self, AtomicDonorSelection, IndexedBinaryAsset, IndexedRow, IntegerValue, MsgpackKind, NodeRef,
    RowId,
};
use crate::control::CancellationToken;
use crate::pak::{self, PackageComponent, PakArchive};
use crate::profiles;
use crate::resources;
use crate::types::*;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{self, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

const MAX_REFERENCE_BREAK_EXAMPLES: usize = 32;
const MAX_PLAN_CONFLICTS: usize = 50_000;
const MAX_ENCODING_DRIFT_SAMPLES_PER_ASSET: usize = 64;
const DATABASE_PROGRESS_ROW_INTERVAL: usize = 256;
const OUTPUT_COPY_BUFFER_BYTES: usize = 8 * 1024 * 1024;
/// Each comparison unit owns a fixed slice of the public analysis progress
/// range. Detailed database work replaces (rather than adds to) that unit's
/// current slice, so concurrent updates cannot double-count completed work.
const ANALYSIS_PROGRESS_STEPS_PER_UNIT: usize = ANALYSIS_PROGRESS_STEPS_PER_ITEM;
const DATABASE_ANALYSIS_PHASE_COUNT: usize = 2;
const OT0_PROFILE_ID: &str = "octopath_traveler_0";
type DatabaseIndexProgressCallback<'a> = dyn FnMut(u64, u64, &str) + 'a;
type AnalysisUnitProgressCallback<'a> = dyn FnMut(AnalysisUnitProgress) + 'a;

#[cfg(test)]
std::thread_local! {
    static TEST_WHOLE_ROW_VARIANT_BUILD_CALLS: std::cell::Cell<usize> = const {
        std::cell::Cell::new(0)
    };
    static TEST_ATOMIC_VARIANT_BUILD_CALLS: std::cell::Cell<usize> = const {
        std::cell::Cell::new(0)
    };
    static TEST_ATOMIC_VARIANT_ROW_PARSE_CALLS: std::cell::Cell<usize> = const {
        std::cell::Cell::new(0)
    };
}

#[cfg(test)]
static TEST_DATABASE_INDEX_BUILD_COUNTS: std::sync::LazyLock<
    std::sync::Mutex<BTreeMap<String, usize>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(BTreeMap::new()));

#[cfg(test)]
fn record_test_database_index_build(asset_path: &str) {
    let mut counts = TEST_DATABASE_INDEX_BUILD_COUNTS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    *counts.entry(sort_key(asset_path)).or_default() += 1;
}

#[cfg(test)]
fn test_database_index_build_count(asset_path: &str) -> usize {
    TEST_DATABASE_INDEX_BUILD_COUNTS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(&sort_key(asset_path))
        .copied()
        .unwrap_or(0)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AnalysisUnitProgress {
    completed_steps: usize,
    current_item: Option<String>,
}

impl AnalysisUnitProgress {
    fn started(current_item: Option<String>) -> Self {
        Self {
            completed_steps: 0,
            current_item,
        }
    }
}

struct AnalysisProgressTracker {
    unit_steps: Vec<usize>,
    completed_steps: usize,
    total_steps: usize,
}

impl AnalysisProgressTracker {
    fn new(unit_count: usize) -> Result<Self> {
        let total_steps = unit_count
            .checked_mul(ANALYSIS_PROGRESS_STEPS_PER_UNIT)
            .ok_or(MergeError::SizeOverflow("analysis progress"))?;
        Ok(Self {
            unit_steps: vec![0; unit_count],
            completed_steps: 0,
            total_steps,
        })
    }

    fn update(
        &mut self,
        unit_index: usize,
        update: AnalysisUnitProgress,
        progress: &mut dyn FnMut(usize, usize, Option<String>),
    ) {
        let next = update
            .completed_steps
            .min(ANALYSIS_PROGRESS_STEPS_PER_UNIT.saturating_sub(1))
            .max(self.unit_steps[unit_index]);
        self.completed_steps += next - self.unit_steps[unit_index];
        self.unit_steps[unit_index] = next;
        progress(self.completed_steps, self.total_steps, update.current_item);
    }

    fn finish(
        &mut self,
        unit_index: usize,
        current_item: Option<String>,
        progress: &mut dyn FnMut(usize, usize, Option<String>),
    ) {
        let previous = self.unit_steps[unit_index];
        self.completed_steps += ANALYSIS_PROGRESS_STEPS_PER_UNIT - previous;
        self.unit_steps[unit_index] = ANALYSIS_PROGRESS_STEPS_PER_UNIT;
        progress(self.completed_steps, self.total_steps, current_item);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OutputTargetStamp {
    len: u64,
    modified: Option<SystemTime>,
    readonly: bool,
}

#[derive(Debug, Clone, Copy)]
struct KnownReferenceRule {
    source_table: &'static str,
    field: &'static str,
    target_table: &'static str,
}

// Reference checks run only when both complete tables are available.
const KNOWN_REFERENCE_RULES: &[KnownReferenceRule] = &[
    KnownReferenceRule {
        source_table: "EnemyGroups",
        field: "m_EnemyID",
        target_table: "EnemyID",
    },
    KnownReferenceRule {
        source_table: "EnemyID",
        field: "m_TypeID",
        target_table: "EnemyTypeID",
    },
    KnownReferenceRule {
        source_table: "EnemyID",
        field: "m_WeakID",
        target_table: "EnemyWeakLockID",
    },
    KnownReferenceRule {
        source_table: "EnemyID",
        field: "m_ResistAilmentID",
        target_table: "SkillResistAilmentID",
    },
    KnownReferenceRule {
        source_table: "EnemyID",
        field: "m_SkillsID",
        target_table: "SkillID",
    },
    KnownReferenceRule {
        source_table: "SkillID",
        field: "m_BoostSkills",
        target_table: "SkillID",
    },
    KnownReferenceRule {
        source_table: "SkillID",
        field: "m_ReplaceSkill",
        target_table: "SkillID",
    },
    KnownReferenceRule {
        source_table: "SkillID",
        field: "m_ReplaceSkillArray",
        target_table: "SkillID",
    },
    KnownReferenceRule {
        source_table: "SkillID",
        field: "m_WeaponReplaceSkill",
        target_table: "SkillID",
    },
    KnownReferenceRule {
        source_table: "SkillID",
        field: "m_Avails",
        target_table: "SkillAvailID",
    },
    KnownReferenceRule {
        source_table: "SkillID",
        field: "m_BeginEffective",
        target_table: "SkillEffectiveID",
    },
    KnownReferenceRule {
        source_table: "SkillID",
        field: "m_Effectives",
        target_table: "SkillEffectiveID",
    },
    KnownReferenceRule {
        source_table: "SkillID",
        field: "m_EndEffective",
        target_table: "SkillEffectiveID",
    },
    KnownReferenceRule {
        source_table: "SkillAvailID",
        field: "m_DelayedSkill",
        target_table: "SkillID",
    },
    KnownReferenceRule {
        source_table: "SkillAvailID",
        field: "m_ResistAilmentID",
        target_table: "SkillResistAilmentID",
    },
    KnownReferenceRule {
        source_table: "BattleEventList",
        field: "m_EventCommand",
        target_table: "BattleEventCommand",
    },
];

#[derive(Debug, thiserror::Error)]
pub enum MergeError {
    #[error("Pak error: {0}")]
    Pak(#[from] pak::PakError),
    #[error("could not read the game database: {0}")]
    BinaryAsset(#[from] binary_asset::BinaryAssetError),
    #[error("could not read or write a file: {0}")]
    Io(#[from] std::io::Error),
    #[error("could not read or write JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("cannot start this operation: {0}")]
    InvalidRequest(String),
    #[error("an input Pak changed after analysis: {0}")]
    InputChanged(PathBuf),
    #[error("some conflicts still need a choice: {0}")]
    Unresolved(String),
    #[error("a saved choice is not valid: {0}")]
    InvalidResolution(String),
    #[error("not enough memory for {0}")]
    AllocationFailed(&'static str),
    #[error("{0} is too large")]
    SizeOverflow(&'static str),
    #[error("standalone file cannot be merged as a database: {0}")]
    StandaloneDatabase(String),
    #[error("package {package} is missing {component}")]
    MissingPackageComponent {
        package: String,
        component: &'static str,
    },
    #[error("the merge plan is inconsistent: {0}")]
    InvalidPlan(String),
    #[error("analysis found {actual} conflicts; limit is {limit}")]
    TooManyConflicts { actual: usize, limit: usize },
    #[error("the merged database is too large")]
    DatabaseTooLarge,
    #[error("the database file layouts do not match: {0}")]
    DatabaseStructureMismatch(String),
    #[error("the merged output did not pass its final checks: {0}")]
    Verification(String),
    #[error("operation cancelled")]
    Cancelled,
}

pub type Result<T> = std::result::Result<T, MergeError>;

fn check_cancel(cancelled: Option<&CancellationToken>) -> Result<()> {
    if cancelled.is_some_and(CancellationToken::is_cancelled) {
        Err(MergeError::Cancelled)
    } else {
        Ok(())
    }
}

fn database_analysis_phase_progress(
    phase_index: usize,
    completed: u64,
    total: u64,
    current_item: String,
) -> AnalysisUnitProgress {
    debug_assert!(phase_index < DATABASE_ANALYSIS_PHASE_COUNT);
    let phase_start =
        ANALYSIS_PROGRESS_STEPS_PER_UNIT * phase_index / DATABASE_ANALYSIS_PHASE_COUNT;
    let phase_end =
        ANALYSIS_PROGRESS_STEPS_PER_UNIT * (phase_index + 1) / DATABASE_ANALYSIS_PHASE_COUNT;
    let phase_steps = phase_end - phase_start;
    let within_phase = if total == 0 {
        0
    } else {
        ((u128::from(completed.min(total)) * phase_steps as u128) / u128::from(total)) as usize
    };
    AnalysisUnitProgress {
        // Detailed work never marks the unit complete. The worker result is
        // the sole transition to the final step, including for zero-row DBs.
        completed_steps: phase_start
            .saturating_add(within_phase)
            .min(ANALYSIS_PROGRESS_STEPS_PER_UNIT - 1),
        current_item: Some(current_item),
    }
}

fn parse_indexed_binary_asset(
    bytes: pak::PakEntryData,
    cancelled: Option<&CancellationToken>,
) -> Result<IndexedBinaryAsset> {
    let result = match cancelled {
        Some(token) => IndexedBinaryAsset::parse_backed_with_cancel(bytes, token),
        None => IndexedBinaryAsset::parse_backed(bytes),
    };
    match result {
        Err(binary_asset::BinaryAssetError::Cancelled) => Err(MergeError::Cancelled),
        Err(error) => Err(error.into()),
        Ok(asset) => Ok(asset),
    }
}

fn parse_indexed_binary_asset_with_progress(
    bytes: pak::PakEntryData,
    cancelled: Option<&CancellationToken>,
    progress: &mut dyn FnMut(usize, usize),
) -> Result<IndexedBinaryAsset> {
    let no_cancellation = CancellationToken::new();
    let cancellation = cancelled.unwrap_or(&no_cancellation);
    match IndexedBinaryAsset::parse_backed_with_cancel_and_progress(bytes, cancellation, progress) {
        Err(binary_asset::BinaryAssetError::Cancelled) => Err(MergeError::Cancelled),
        Err(error) => Err(error.into()),
        Ok(asset) => Ok(asset),
    }
}

fn indexed_row<'a>(
    asset: &'a IndexedBinaryAsset,
    row_id: RowId,
    cancelled: Option<&CancellationToken>,
) -> Result<Option<IndexedRow<'a>>> {
    let result = match cancelled {
        Some(token) => asset.row_with_cancel(row_id, token),
        None => asset.row(row_id),
    };
    match result {
        Err(binary_asset::BinaryAssetError::Cancelled) => Err(MergeError::Cancelled),
        Err(error) => Err(error.into()),
        Ok(row) => Ok(row),
    }
}

fn indexed_row_at<'a>(
    asset: &'a IndexedBinaryAsset,
    index: usize,
    cancelled: Option<&CancellationToken>,
) -> Result<Option<IndexedRow<'a>>> {
    let result = match cancelled {
        Some(token) => asset.row_at_with_cancel(index, token),
        None => asset.row_at(index),
    };
    match result {
        Err(binary_asset::BinaryAssetError::Cancelled) => Err(MergeError::Cancelled),
        Err(error) => Err(error.into()),
        Ok(row) => Ok(row),
    }
}

struct OpenedPak {
    descriptor: InputDescriptor,
    archive: Arc<PakArchive>,
    source_modified: Option<SystemTime>,
    canonical_mount_point: String,
    canonical_packages: pak::PackageGrouping,
    /// Case-folded canonical output path -> original archive inventory index.
    /// The inventory entry retains the raw archive path used for reads.
    entry_index: BTreeMap<String, usize>,
}

/// An analyzed set of Pak files whose validated archive handles and parsed
/// database source mappings remain available for the later write. The GUI
/// keeps this session alive from file inspection through output creation, so
/// large input archives are never reopened, rehashed, or decompressed twice.
/// Compact row indexes retain only row IDs/ranges plus the existing Pak mmap or
/// decoded temporary-file backing. Output generation borrows those indexes;
/// complete provider trees and copied payload bodies are never kept.
pub struct MergeAnalysisSession {
    plan: Arc<MergePlan>,
    opened: Vec<OpenedPak>,
    /// Analysis-owned compact indexes. `IndexedBinaryAsset` keeps the original
    /// archive slice or decoded cache mapping alive without copying the entry.
    parsed_databases: BTreeMap<String, Vec<ParsedDbProvider>>,
    cached_database_bytes: u64,
}

impl MergeAnalysisSession {
    pub fn plan(&self) -> &MergePlan {
        &self.plan
    }

    /// Shares the immutable analysis plan with the GUI without cloning every
    /// conflict, choice, preview, and provenance string.
    pub fn shared_plan(&self) -> Arc<MergePlan> {
        Arc::clone(&self.plan)
    }

    pub fn cached_database_bytes(&self) -> u64 {
        // Logical bytes referenced by the disk-backed database cache, not
        // resident parsed-tree memory.
        self.cached_database_bytes
    }
}

#[derive(Debug, Clone)]
struct GroupProvider {
    input_index: usize,
    group: pak::PackageGroup,
}

#[derive(Debug, Clone)]
struct LooseProvider {
    input_index: usize,
    path: String,
}

enum AnalysisUnit {
    Package(Vec<GroupProvider>),
    Loose(Vec<LooseProvider>),
}

impl AnalysisUnit {
    fn label(&self) -> Option<String> {
        match self {
            Self::Package(providers) => providers
                .first()
                .map(|provider| provider.group.base_path.clone()),
            Self::Loose(providers) => providers.first().map(|provider| provider.path.clone()),
        }
    }
}

struct AnalysisUnitOutput {
    asset: AssetPlan,
    conflicts: Vec<Conflict>,
    warnings: Vec<String>,
    parsed_database: Option<(String, Vec<ParsedDbProvider>, u64)>,
}

struct ParsedDbProvider {
    input_index: usize,
    group: pak::PackageGroup,
    uasset: pak::PakEntryData,
    uexp_size: usize,
    asset: IndexedBinaryAsset,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum NpcPlacementLogicalKey {
    MapAppear { map_id: i64, appear_label: String },
    Label(String),
}

impl NpcPlacementLogicalKey {
    fn stable_text(&self) -> String {
        match self {
            Self::MapAppear {
                map_id,
                appear_label,
            } => format!("map={map_id};appear={appear_label}"),
            Self::Label(label) => format!("label={label}"),
        }
    }

    fn display_text(&self) -> String {
        match self {
            Self::MapAppear {
                map_id,
                appear_label,
            } => format!("m_MapID={map_id}, m_AppearLabel={appear_label}"),
            Self::Label(label) => format!("fallback m_label={label}"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct NpcPlacementBinding {
    owner_npc: i64,
    talk_id: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct NpcPlacementOccurrence {
    provider_local: usize,
    row_id: RowId,
    binding: NpcPlacementBinding,
}

#[derive(Debug, Clone)]
enum OutputSource {
    Pak { input_index: usize, path: String },
    Temporary(PathBuf),
}

#[derive(Debug, Clone)]
struct OutputEntry {
    path: String,
    source: OutputSource,
}

struct RemoveFileOnDrop(PathBuf);

impl Drop for RemoveFileOnDrop {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

pub fn analyze(request: AnalysisRequest) -> Result<MergePlan> {
    validate_request(&request)?;
    let opened = open_paks(&request)?;
    Ok(analyze_opened(request, &opened, None, true, &mut |_, _, _| {})?.0)
}

/// Analyze archives retained by the fast structural inspection. Compressed
/// entry bodies are decoded lazily and cached when semantic comparison first
/// needs them.
///
/// `archives` must contain exactly one archive for every request path. Keeping
/// the returned session alive also keeps the original read-only file handles
/// alive, which prevents the inputs from changing between analysis and merge.
pub fn analyze_with_archives(
    request: AnalysisRequest,
    archives: Vec<Arc<PakArchive>>,
) -> Result<MergeAnalysisSession> {
    analyze_with_archives_and_cancel(request, archives, &CancellationToken::new())
}

pub fn analyze_with_archives_and_cancel(
    request: AnalysisRequest,
    archives: Vec<Arc<PakArchive>>,
    cancelled: &CancellationToken,
) -> Result<MergeAnalysisSession> {
    analyze_with_archives_progress_and_cancel(request, archives, cancelled, |_, _, _| {})
}

pub fn analyze_with_archives_progress_and_cancel<F>(
    request: AnalysisRequest,
    archives: Vec<Arc<PakArchive>>,
    cancelled: &CancellationToken,
    progress: F,
) -> Result<MergeAnalysisSession>
where
    F: FnMut(usize, usize, Option<String>),
{
    analyze_with_archives_progress_cancel_and_threads(request, archives, cancelled, true, progress)
}

pub fn analyze_with_archives_progress_cancel_and_threads<F>(
    request: AnalysisRequest,
    archives: Vec<Arc<PakArchive>>,
    cancelled: &CancellationToken,
    multithreaded: bool,
    mut progress: F,
) -> Result<MergeAnalysisSession>
where
    F: FnMut(usize, usize, Option<String>),
{
    check_cancel(Some(cancelled))?;
    validate_cached_request(&request, &archives)?;
    let opened = opened_from_archives(&request, archives)?;
    let (plan, parsed_databases, cached_database_bytes) = analyze_opened(
        request,
        &opened,
        Some(cancelled),
        multithreaded,
        &mut progress,
    )?;
    Ok(MergeAnalysisSession {
        plan: Arc::new(plan),
        opened,
        parsed_databases,
        cached_database_bytes,
    })
}

fn analyze_opened(
    request: AnalysisRequest,
    opened: &[OpenedPak],
    cancelled: Option<&CancellationToken>,
    multithreaded: bool,
    progress: &mut dyn FnMut(usize, usize, Option<String>),
) -> Result<(MergePlan, BTreeMap<String, Vec<ParsedDbProvider>>, u64)> {
    let carrier_index = opened
        .iter()
        .position(|input| same_path(&input.descriptor.path, &request.carrier_path))
        .ok_or_else(|| {
            MergeError::InvalidRequest(
                "The base Pak must be one of the selected Pak files.".to_owned(),
            )
        })?;
    let carrier_input_id = opened[carrier_index].descriptor.id.clone();
    let profile_detection = detect_profile_from_opened_inventory(opened);
    let selected_profile_id = profile_detection.selected_profile_id.clone();
    let (package_map, loose_map) = collect_providers(opened);
    let mut assets = Vec::new();
    let mut conflicts = Vec::new();
    let mut parsed_databases = BTreeMap::new();
    let mut cached_database_bytes = 0_u64;
    let mut warnings = opened
        .iter()
        .flat_map(|input| {
            input
                .archive
                .inventory()
                .entries
                .iter()
                .filter(|entry| !entry.payload_sha1_matches)
                .map(|entry| {
                    format!(
                        "{} contains {}, whose integrity value is outdated. Its data structure is valid, so the actual contents will be used and the merged Pak will store the corrected value (stored {}, actual {}).",
                        input.descriptor.display_name,
                        entry.path,
                        entry.stored_payload_sha1,
                        entry.payload_sha1
                    )
                })
        })
        .collect::<Vec<_>>();
    match profile_detection.status {
        ProfileDetectionStatus::Selected
            if selected_profile_id.as_deref() != Some(OT0_PROFILE_ID) =>
        {
            warnings.push(format!(
                "Profile {} has no built-in reference checks.",
                selected_profile_id.as_deref().unwrap_or("unknown")
            ));
        }
        ProfileDetectionStatus::Selected => {}
        ProfileDetectionStatus::GenericNoMatch => {
            warnings.push("No database profile matched; using general field rules.".to_owned())
        }
        ProfileDetectionStatus::GenericAmbiguous => warnings
            .push("Multiple database profiles matched; using general field rules.".to_owned()),
    }

    let units = package_map
        .into_values()
        .map(AnalysisUnit::Package)
        .chain(loose_map.into_values().map(AnalysisUnit::Loose))
        .collect::<Vec<_>>();
    let comparison_total = units.len();
    let comparison_progress_total = comparison_total
        .checked_mul(ANALYSIS_PROGRESS_STEPS_PER_UNIT)
        .ok_or(MergeError::SizeOverflow("analysis progress"))?;
    progress(0, comparison_progress_total, None);
    let outputs = analyze_units(
        &units,
        opened,
        carrier_index,
        selected_profile_id.as_deref(),
        cancelled,
        multithreaded,
        progress,
    )?;
    for mut output in outputs {
        if let Some((key, providers, disk_bytes)) = output.parsed_database.take() {
            cached_database_bytes = cached_database_bytes
                .checked_add(disk_bytes)
                .ok_or(MergeError::SizeOverflow("database cache"))?;
            parsed_databases.insert(key, providers);
        }
        assets.push(output.asset);
        conflicts.append(&mut output.conflicts);
        ensure_conflict_count(&conflicts)?;
        warnings.append(&mut output.warnings);
    }

    let inputs: Vec<_> = opened.iter().map(|item| item.descriptor.clone()).collect();

    assets.sort_by_key(|asset| sort_key(&asset.virtual_path));
    conflicts.sort_by(|left, right| left.id.cmp(&right.id));
    warnings.sort();
    warnings.dedup();

    let encoding_drift_count = assets.iter().map(|asset| asset.encoding_drift_count).sum();
    let profile_status_id = profile_detection_status_id(profile_detection.status);
    let pinned_profile_id = selected_profile_id.as_deref().unwrap_or("generic");
    let plan_id = stable_id(
        "plan",
        inputs
            .iter()
            .map(|input| input.sha256.as_str())
            .chain(std::iter::once(carrier_input_id.as_str()))
            .chain(std::iter::once(profile_status_id))
            .chain(std::iter::once(pinned_profile_id))
            .chain(conflicts.iter().map(|conflict| conflict.id.as_str())),
    );
    let plan = MergePlan {
        schema_version: 1,
        plan_id,
        request,
        inputs,
        carrier_input_id,
        assets,
        conflicts,
        warnings,
        selected_profile_id,
        profile_detection_status: Some(profile_detection.status),
        encoding_drift_count,
        full_reencode_forbidden: true,
    };
    Ok((plan, parsed_databases, cached_database_bytes))
}

pub fn resolve(plan: MergePlan, mut resolutions: ResolutionSet) -> Result<ResolvedPlan> {
    validate_resolutions(&plan, &mut resolutions)?;
    Ok(ResolvedPlan { plan, resolutions })
}

fn validate_resolutions(plan: &MergePlan, resolutions: &mut ResolutionSet) -> Result<()> {
    if resolutions.plan_id.is_empty() {
        resolutions.plan_id = plan.plan_id.clone();
    }
    if resolutions.plan_id != plan.plan_id {
        return Err(MergeError::InvalidResolution(format!(
            "resolution plan_id {} does not match {}",
            resolutions.plan_id, plan.plan_id
        )));
    }
    let conflict_by_id: BTreeMap<_, _> = plan
        .conflicts
        .iter()
        .map(|conflict| (conflict.id.as_str(), conflict))
        .collect();
    for (conflict_id, variant_id) in &resolutions.choices {
        let conflict = conflict_by_id.get(conflict_id.as_str()).ok_or_else(|| {
            MergeError::InvalidResolution(format!("unknown conflict id {conflict_id}"))
        })?;
        if matches!(
            conflict.kind,
            ConflictKind::EncodingDrift | ConflictKind::PotentialPlacementCollision
        ) {
            return Err(MergeError::InvalidResolution(format!(
                "{:?} {} is informational and cannot be selected",
                conflict.kind, conflict.id
            )));
        }
        if !conflict
            .variants
            .iter()
            .any(|variant| variant.id == *variant_id)
        {
            return Err(MergeError::InvalidResolution(format!(
                "choice {variant_id} is not available for conflict {conflict_id}"
            )));
        }
    }
    let unresolved = plan.unresolved_conflict_ids(resolutions);
    if !unresolved.is_empty() {
        return Err(MergeError::Unresolved(unresolved.join(", ")));
    }
    Ok(())
}

pub fn write(resolved: ResolvedPlan, output_path: &Path) -> Result<MergeReport> {
    write_with_options(resolved, output_path, WriteOptions::default())
}

pub fn write_with_options(
    resolved: ResolvedPlan,
    output_path: &Path,
    options: WriteOptions,
) -> Result<MergeReport> {
    write_with_options_and_progress(resolved, output_path, options, |_| {})
}

pub fn write_with_options_and_progress<F>(
    resolved: ResolvedPlan,
    output_path: &Path,
    options: WriteOptions,
    mut progress: F,
) -> Result<MergeReport>
where
    F: FnMut(MergeProgress) + Send,
{
    require_output_path(output_path)?;
    let existing_output = capture_output_target(output_path, options.overwrite_existing)?;

    validate_request(&resolved.plan.request)?;
    let opened = {
        let mut input_progress = |completed: usize, total: usize, path: &Path| {
            progress(MergeProgress {
                stage: MergeProgressStage::CheckingInputs,
                completed: completed as u64,
                total: total as u64,
                current_item: Some(path.display().to_string()),
            });
        };
        open_paks_with_progress(&resolved.plan.request, &mut input_progress)?
    };
    progress(MergeProgress {
        stage: MergeProgressStage::ComparingChanges,
        completed: 0,
        total: 1,
        current_item: None,
    });
    let (current_plan, parsed_databases, _) = analyze_opened(
        resolved.plan.request.clone(),
        &opened,
        None,
        true,
        &mut |_, _, _| {},
    )?;
    progress(MergeProgress {
        stage: MergeProgressStage::ComparingChanges,
        completed: 1,
        total: 1,
        current_item: None,
    });
    if current_plan.plan_id != resolved.plan.plan_id {
        return Err(MergeError::InputChanged(
            resolved.plan.request.carrier_path.clone(),
        ));
    }
    let mut resolutions = resolved.resolutions;
    validate_resolutions(&current_plan, &mut resolutions)?;
    verify_input_identities(&opened, &current_plan.inputs)?;
    write_opened_with_progress(
        &current_plan,
        &resolutions,
        &opened,
        &parsed_databases,
        output_path,
        options,
        existing_output,
        None,
        &mut progress,
    )
}

/// Build from a live analysis session. Unlike the compatibility `write*`
/// APIs, this path does not reopen, rehash, decompress, or reanalyze any input.
/// The session's read-only handles have continuously protected the exact bytes
/// that produced the displayed plan. Output creation borrows the compact row
/// indexes produced by that analysis and leaves them available for retries.
pub fn write_session_with_options_and_progress<F>(
    session: &MergeAnalysisSession,
    resolutions: ResolutionSet,
    output_path: &Path,
    options: WriteOptions,
    progress: F,
) -> Result<MergeReport>
where
    F: FnMut(MergeProgress) + Send,
{
    write_session_with_options_progress_and_cancel(
        session,
        resolutions,
        output_path,
        options,
        &CancellationToken::new(),
        progress,
    )
}

pub fn write_session_with_options_progress_and_cancel<F>(
    session: &MergeAnalysisSession,
    resolutions: ResolutionSet,
    output_path: &Path,
    options: WriteOptions,
    cancelled: &CancellationToken,
    mut progress: F,
) -> Result<MergeReport>
where
    F: FnMut(MergeProgress) + Send,
{
    check_cancel(Some(cancelled))?;
    require_output_path(output_path)?;
    let existing_output = capture_output_target(output_path, options.overwrite_existing)?;
    verify_session_input_stamps(&session.opened)?;
    let mut resolutions = resolutions;
    validate_resolutions(&session.plan, &mut resolutions)?;
    write_opened_with_progress(
        &session.plan,
        &resolutions,
        &session.opened,
        &session.parsed_databases,
        output_path,
        options,
        existing_output,
        Some(cancelled),
        &mut progress,
    )
}

#[allow(clippy::too_many_arguments)]
fn write_opened_with_progress<F>(
    current_plan: &MergePlan,
    resolutions: &ResolutionSet,
    opened: &[OpenedPak],
    parsed_databases: &BTreeMap<String, Vec<ParsedDbProvider>>,
    output_path: &Path,
    options: WriteOptions,
    existing_output: Option<OutputTargetStamp>,
    cancelled: Option<&CancellationToken>,
    progress: &mut F,
) -> Result<MergeReport>
where
    F: FnMut(MergeProgress) + Send,
{
    check_cancel(cancelled)?;
    let carrier_index = opened
        .iter()
        .position(|input| input.descriptor.id == current_plan.carrier_input_id)
        .ok_or_else(|| {
            MergeError::InvalidRequest("The selected base Pak is no longer available.".to_owned())
        })?;
    let (package_map, loose_map) = collect_providers(opened);
    let runtime_temp_root = resources::runtime_temp_directory()?;
    let direct_output_install = install_paths_share_volume(&runtime_temp_root, output_path)?;
    let temp_dir = tempfile::Builder::new()
        .prefix("pak-merger-")
        .tempdir_in(&runtime_temp_root)?;
    let mut output_entries = Vec::new();
    let mut raw_preserved_nodes = 0_u64;
    let mut raw_replaced_nodes = 0_u64;
    let mut pending_raw_preservation_audits = Vec::new();

    let asset_total = current_plan.assets.len();
    for (asset_index, asset) in current_plan.assets.iter().enumerate() {
        check_cancel(cancelled)?;
        progress(MergeProgress {
            stage: MergeProgressStage::PreparingFiles,
            completed: asset_index as u64,
            total: asset_total as u64,
            current_item: Some(asset.virtual_path.clone()),
        });
        if let Some(providers) = package_map.get(&sort_key(&asset.virtual_path)) {
            match asset.action {
                AssetActionKind::Copy | AssetActionKind::Deduplicate => {
                    let donor = donor_for_asset(asset, providers, opened)?;
                    append_package_sources(&mut output_entries, donor, opened)?;
                }
                AssetActionKind::SelectOpaque | AssetActionKind::Unsupported => {
                    let conflict = conflict_for_asset(current_plan, asset)?;
                    let input_id = selected_input_id(conflict, resolutions)?;
                    let donor = provider_by_input_id(providers, opened, input_id)?;
                    append_package_sources(&mut output_entries, donor, opened)?;
                }
                AssetActionKind::MergeDatabase => {
                    let parsed = parsed_databases
                        .get(&sort_key(&asset.virtual_path))
                        .ok_or_else(|| {
                            MergeError::InputChanged(PathBuf::from(&asset.virtual_path))
                        })?;
                    let uasset_path = temp_dir.path().join(format!(
                        "{}-header.bin",
                        stable_id("tmp", [asset.virtual_path.as_str()])
                    ));
                    let uexp_path = temp_dir.path().join(format!(
                        "{}-payload.bin",
                        stable_id("tmp", [asset.virtual_path.as_str()])
                    ));
                    let result = build_merged_database(
                        current_plan,
                        resolutions,
                        opened,
                        parsed,
                        carrier_index,
                        cancelled,
                        &uexp_path,
                        progress,
                    )?;
                    raw_preserved_nodes += result.raw_preserved_nodes;
                    raw_replaced_nodes += result.raw_replaced_nodes;
                    pending_raw_preservation_audits.push(result.raw_audit);
                    fs::write(&uasset_path, result.uasset)?;
                    output_entries.push(OutputEntry {
                        path: result.uasset_entry,
                        source: OutputSource::Temporary(uasset_path),
                    });
                    output_entries.push(OutputEntry {
                        path: result.uexp_entry,
                        source: OutputSource::Temporary(uexp_path),
                    });
                }
            }
        } else if let Some(providers) = loose_map.get(&sort_key(&asset.virtual_path)) {
            let donor = match asset.action {
                AssetActionKind::Copy | AssetActionKind::Deduplicate => &providers[0],
                AssetActionKind::SelectOpaque | AssetActionKind::Unsupported => {
                    let conflict = conflict_for_asset(current_plan, asset)?;
                    let selected = selected_input_id(conflict, resolutions)?;
                    providers
                        .iter()
                        .find(|provider| opened[provider.input_index].descriptor.id == selected)
                        .ok_or_else(|| {
                            MergeError::InvalidResolution(format!(
                                "the selected Pak {selected} does not contain file {}",
                                asset.virtual_path
                            ))
                        })?
                }
                AssetActionKind::MergeDatabase => {
                    return Err(MergeError::StandaloneDatabase(asset.virtual_path.clone()));
                }
            };
            output_entries.push(OutputEntry {
                path: donor.path.clone(),
                source: OutputSource::Pak {
                    input_index: donor.input_index,
                    path: archive_entry_path(&opened[donor.input_index], &donor.path)?.to_owned(),
                },
            });
        } else {
            return Err(MergeError::InputChanged(PathBuf::from(&asset.virtual_path)));
        }
    }
    progress(MergeProgress {
        stage: MergeProgressStage::PreparingFiles,
        completed: asset_total as u64,
        total: asset_total as u64,
        current_item: None,
    });

    output_entries.sort_by_key(|entry| sort_key(&entry.path));
    ensure_unique_output_paths(&output_entries)?;
    let partial_path = temp_dir.path().join("merged-output.pak.partial");
    // Compute progress offsets from already parsed metadata. This avoids a
    // sizing read while letting one very large entry advance the global Pak
    // creation bar from each writer block/chunk callback.
    let mut source_map = BTreeMap::new();
    let mut paths = Vec::with_capacity(output_entries.len());
    let mut disk_estimate_entries = Vec::with_capacity(output_entries.len());
    let mut total_logical_bytes = 0_u64;
    for entry in output_entries {
        let size = match &entry.source {
            OutputSource::Pak { input_index, path } => {
                opened[*input_index].archive.entry_size(path)?
            }
            OutputSource::Temporary(path) => fs::metadata(path)?.len(),
        };
        let offset = total_logical_bytes;
        total_logical_bytes = total_logical_bytes
            .checked_add(size)
            .ok_or_else(|| MergeError::InvalidRequest("output size overflow".to_owned()))?;
        disk_estimate_entries.push((entry.path.clone(), size));
        paths.push(entry.path.clone());
        source_map.insert(sort_key(&entry.path), (entry, offset, size));
    }
    let progress_total_bytes = total_logical_bytes.max(1);
    let mount = opened[carrier_index].canonical_mount_point.clone();
    // Database staging files already occupy the executable's work volume at this
    // point. Check only the remaining bytes needed for the partial Pak and,
    // for compressed output, its one strict decoded verification cache.
    ensure_output_disk_space(
        &partial_path,
        &mount,
        &disk_estimate_entries,
        options.compression,
    )?;
    check_cancel(cancelled)?;
    let no_cancellation = CancellationToken::new();
    let writer_cancellation = cancelled.unwrap_or(&no_cancellation);
    let raw_audit_paths = pending_raw_preservation_audits
        .iter()
        .map(|audit| audit.pak_entry_path.clone())
        .collect::<Vec<_>>();
    let write_result = pak::write_pak_v11_from_mapped_provider_with_source_hashes(
        &partial_path,
        &mount,
        paths,
        options.compression,
        |path| {
            if cancelled.is_some_and(CancellationToken::is_cancelled) {
                return Err(pak::PakError::Io(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "operation cancelled",
                )));
            }
            let (source, _, _) = source_map
                .get(&sort_key(path))
                .ok_or_else(|| pak::PakError::MissingEntry(path.to_owned()))?;
            match &source.source {
                OutputSource::Pak { input_index, path } => opened[*input_index]
                    .archive
                    .map_entry_with_threads_and_cancel(
                        path,
                        pak::MAX_IN_MEMORY_ENTRY_BYTES,
                        options.multithreaded,
                        writer_cancellation,
                    ),
                OutputSource::Temporary(path) => {
                    pak::PakEntryData::map_file(path, pak::MAX_IN_MEMORY_ENTRY_BYTES)
                }
            }
        },
        options.multithreaded,
        writer_cancellation,
        |event| match event {
            pak::PakWriteProgress::Writing {
                completed,
                total,
                current_path,
            } => {
                let completed_bytes = current_path
                    .as_deref()
                    .and_then(|path| source_map.get(&sort_key(path)))
                    .map_or_else(
                        || {
                            if completed == total {
                                total_logical_bytes
                            } else {
                                0
                            }
                        },
                        |(_, offset, _)| *offset,
                    );
                progress(MergeProgress {
                    stage: MergeProgressStage::WritingPak,
                    completed: completed_bytes,
                    total: progress_total_bytes,
                    current_item: current_path,
                });
            }
            pak::PakWriteProgress::WritingBytes {
                completed_bytes,
                total_bytes: _,
                current_path,
            } => {
                let overall_completed = source_map
                    .get(&sort_key(&current_path))
                    .map(|(_, offset, size)| offset.saturating_add(completed_bytes.min(*size)))
                    .unwrap_or(completed_bytes.min(total_logical_bytes));
                progress(MergeProgress {
                    stage: MergeProgressStage::WritingPak,
                    completed: overall_completed,
                    total: progress_total_bytes,
                    current_item: Some(current_path),
                });
            }
            pak::PakWriteProgress::Verifying => progress(MergeProgress {
                stage: MergeProgressStage::VerifyingPak,
                completed: 0,
                total: 1,
                current_item: None,
            }),
            pak::PakWriteProgress::VerificationProgress {
                completed_bytes,
                total_bytes,
                current_path,
            } => progress(MergeProgress {
                stage: MergeProgressStage::VerifyingPak,
                completed: completed_bytes,
                total: total_bytes,
                current_item: current_path,
            }),
        },
        raw_audit_paths,
    );
    let verified_write = match write_result {
        Ok(result) => result,
        Err(_) if cancelled.is_some_and(CancellationToken::is_cancelled) => {
            return Err(MergeError::Cancelled);
        }
        Err(error) => return Err(error.into()),
    };
    let verified_archive = verified_write.archive;
    // The writer uses `create_new` and removes only the file it created on
    // failure. Install our later-stage cleanup guard only after that ownership
    // is proven, so a racing pre-existing path can never be deleted here.
    let _partial_cleanup = RemoveFileOnDrop(partial_path.clone());
    check_cancel(cancelled)?;
    progress(MergeProgress {
        stage: MergeProgressStage::VerifyingPak,
        completed: 1,
        total: 1,
        current_item: None,
    });
    let verified_output = verified_archive.inventory();
    // The strict Pak verification has already computed every final entry hash.
    // Bind the row-by-row preservation records to that inventory instead of
    // reopening and rereading each staged database payload before Pak writing.
    let raw_preservation_audits = finalize_raw_preservation_audits(
        pending_raw_preservation_audits,
        verified_output,
        &verified_write.source_sha256,
    )?;
    let compression_errors = output_compression_errors(verified_output, options.compression);
    if !compression_errors.is_empty() {
        return Err(MergeError::Verification(compression_errors.join("; ")));
    }
    progress(MergeProgress {
        stage: MergeProgressStage::CheckingReferences,
        completed: 0,
        total: 1,
        current_item: None,
    });
    let mut reference_progress = |completed: u64, total: u64, item: Option<String>| {
        progress(MergeProgress {
            stage: MergeProgressStage::CheckingReferences,
            completed,
            total,
            current_item: item,
        });
    };
    let reference_validation_warnings = validate_references_for_pinned_profile(
        current_plan,
        &verified_archive,
        cancelled,
        options.multithreaded,
        &mut reference_progress,
    )?;
    check_cancel(cancelled)?;
    progress(MergeProgress {
        stage: MergeProgressStage::CheckingReferences,
        completed: 1,
        total: 1,
        current_item: None,
    });

    let output_sha256 = verified_output.archive_sha256.clone();
    let output_size = fs::metadata(&partial_path)?.len();
    let encoding_drift_count = current_plan.encoding_drift_count;
    let resolved_conflicts =
        build_report_conflict_records(current_plan, resolutions, &current_plan.carrier_input_id);
    let final_inventory = verified_output
        .entries
        .iter()
        .map(|entry| FinalEntryInventory {
            path: entry.path.clone(),
            size: entry.size,
            sha256: entry.sha256.clone(),
        })
        .collect();
    let report_value = MergeReport {
        schema_version: 4,
        tool_version: env!("CARGO_PKG_VERSION").to_owned(),
        plan_id: current_plan.plan_id.clone(),
        carrier_input_id: current_plan.carrier_input_id.clone(),
        inputs: current_plan.inputs.clone(),
        output_path: output_path.to_path_buf(),
        output_sha256,
        output_size,
        output_entry_count: verified_output.entries.len(),
        output_pak_version: verified_output.footer.version,
        output_mount_point: verified_output.mount_point.clone(),
        output_compression: options.compression.report_name().to_owned(),
        output_encrypted: false,
        output_signed: false,
        final_inventory,
        actions: current_plan.assets.clone(),
        conflicts: current_plan.conflicts.clone(),
        resolved_conflicts,
        resolutions: resolutions.clone(),
        warnings: current_plan.warnings.clone(),
        raw_preserved_nodes,
        raw_replaced_nodes,
        raw_preservation_audits,
        encoding_drift_count,
        reference_validation_warnings,
        full_reencode_forbidden: true,
        verification_passed: true,
    };
    drop(verified_archive);
    progress(MergeProgress {
        stage: MergeProgressStage::Finalizing,
        completed: 0,
        total: if direct_output_install {
            1
        } else {
            output_size.max(1)
        },
        current_item: Some(output_path.display().to_string()),
    });
    check_cancel(cancelled)?;
    install_verified_output(
        &partial_path,
        output_path,
        existing_output.as_ref(),
        direct_output_install,
        output_size,
        &report_value.output_sha256,
        cancelled,
        progress,
    )?;
    // Keep decoded input data across analysis and generation, but release it
    // as soon as a verified output has been installed. Failed or cancelled
    // attempts retain the cache so a retry does not repeat decompression.
    for input in opened {
        input.archive.release_decoded_cache();
    }
    progress(MergeProgress {
        stage: MergeProgressStage::Finalizing,
        completed: if direct_output_install {
            1
        } else {
            output_size.max(1)
        },
        total: if direct_output_install {
            1
        } else {
            output_size.max(1)
        },
        current_item: None,
    });
    Ok(report_value)
}

pub fn verify(path: &Path, expected_report: Option<&MergeReport>) -> Result<VerificationResult> {
    match pak::verify_pak_v11(path, None) {
        Ok(inventory) => {
            let mut errors = Vec::new();
            let mut warnings = Vec::new();
            if let Some(report) = expected_report {
                if inventory.archive_sha256 != report.output_sha256 {
                    errors.push(format!(
                        "Pak SHA-256 mismatch: expected {}, got {}",
                        report.output_sha256, inventory.archive_sha256
                    ));
                }
                if inventory.entries.len() != report.output_entry_count {
                    errors.push(format!(
                        "file count mismatch: expected {}, got {}",
                        report.output_entry_count,
                        inventory.entries.len()
                    ));
                }
                if report.final_inventory.len() != report.output_entry_count {
                    errors.push(format!(
                        "report inventory count mismatch: report declares {} entries but lists {}",
                        report.output_entry_count,
                        report.final_inventory.len()
                    ));
                }
                if inventory.footer.version != report.output_pak_version {
                    errors.push(format!(
                        "Pak version mismatch: expected {}, got {}",
                        report.output_pak_version, inventory.footer.version
                    ));
                }
                if inventory.mount_point != report.output_mount_point {
                    errors.push(format!(
                        "Pak root path mismatch: expected {:?}, got {:?}",
                        report.output_mount_point, inventory.mount_point
                    ));
                }
                let actual_entries: BTreeMap<_, _> = inventory
                    .entries
                    .iter()
                    .map(|entry| (sort_key(&entry.path), entry))
                    .collect();
                let mut reported_paths = BTreeSet::new();
                for entry in &report.final_inventory {
                    if !reported_paths.insert(sort_key(&entry.path)) {
                        errors.push(format!(
                            "report inventory contains a duplicate path: {}",
                            entry.path
                        ));
                        continue;
                    }
                    match actual_entries.get(&sort_key(&entry.path)) {
                        Some(actual)
                            if actual.size == entry.size && actual.sha256 == entry.sha256 => {}
                        Some(actual) => errors.push(format!(
                            "file check failed for {}: expected {} bytes/{}, got {} bytes/{}",
                            entry.path, entry.size, entry.sha256, actual.size, actual.sha256
                        )),
                        None => errors.push(format!(
                            "a file listed in the report is missing: {}",
                            entry.path
                        )),
                    }
                }
                if !report.full_reencode_forbidden {
                    warnings.push("report does not assert fullReencodeForbidden".to_owned());
                }
                let reported_compression = match report.output_compression.as_str() {
                    "None" => Some(OutputCompression::None),
                    "Oodle" => Some(OutputCompression::Oodle),
                    other => {
                        errors.push(format!(
                            "report declares an unsupported output compression method: {other}"
                        ));
                        None
                    }
                };
                if let Some(compression) = reported_compression {
                    errors.extend(output_compression_errors(&inventory, compression));
                }
                if report.output_encrypted || report.output_signed {
                    errors.push(
                        "report attributes do not describe an unencrypted, unsigned output"
                            .to_owned(),
                    );
                }
                let expected_audit_count = report
                    .actions
                    .iter()
                    .filter(|asset| asset.action == AssetActionKind::MergeDatabase)
                    .count();
                if report.raw_preservation_audits.len() != expected_audit_count {
                    errors.push(format!(
                        "unchanged-data check count mismatch: expected {expected_audit_count}, report has {}",
                        report.raw_preservation_audits.len()
                    ));
                }
                errors.extend(raw_audit_inventory_errors(
                    &report.raw_preservation_audits,
                    &inventory,
                ));
            }
            Ok(VerificationResult {
                valid: errors.is_empty(),
                pak_sha256: inventory.archive_sha256,
                entry_count: inventory.entries.len(),
                errors,
                warnings,
            })
        }
        Err(error) => Ok(VerificationResult {
            valid: false,
            pak_sha256: String::new(),
            entry_count: 0,
            errors: vec![error.to_string()],
            warnings: Vec::new(),
        }),
    }
}

fn output_compression_errors(
    inventory: &pak::PakInventory,
    expected: OutputCompression,
) -> Vec<String> {
    let nonempty_entries = inventory.entries.iter().filter(|entry| entry.size != 0);
    match expected {
        OutputCompression::None => {
            let compressed_count = nonempty_entries.filter(|entry| entry.compressed).count();
            if compressed_count == 0 {
                Vec::new()
            } else {
                vec![format!(
                    "output was expected to be uncompressed, but {compressed_count} files are compressed"
                )]
            }
        }
        OutputCompression::Oodle => {
            let mut errors = Vec::new();
            if inventory.footer.compression_slots != ["Oodle"] {
                errors.push(format!(
                    "output does not declare only Oodle compression: {:?}",
                    inventory.footer.compression_slots
                ));
            }
            let uncompressed_count = nonempty_entries.filter(|entry| !entry.compressed).count();
            if uncompressed_count != 0 {
                errors.push(format!(
                    "Oodle output contains {uncompressed_count} non-empty uncompressed files"
                ));
            }
            errors
        }
    }
}

fn raw_audit_inventory_errors(
    audits: &[RawPreservationAssetAudit],
    inventory: &pak::PakInventory,
) -> Vec<String> {
    let entries: BTreeMap<_, _> = inventory
        .entries
        .iter()
        .map(|entry| (sort_key(&entry.path), entry))
        .collect();
    let mut assets = BTreeSet::new();
    let mut audited_entries = BTreeSet::new();
    let mut errors = Vec::new();
    for audit in audits {
        if !assets.insert(sort_key(&audit.asset_path)) {
            errors.push(format!(
                "duplicate unchanged-data check for file group: {}",
                audit.asset_path
            ));
        }
        let entry_key = sort_key(&audit.pak_entry_path);
        if !audited_entries.insert(entry_key.clone()) {
            errors.push(format!(
                "duplicate unchanged-data check for Pak file: {}",
                audit.pak_entry_path
            ));
        }
        if !audit.passed {
            errors.push(format!(
                "unchanged-data check did not pass: {}",
                audit.asset_path
            ));
        }
        for (label, digest) in [
            ("Pak file", audit.entry_sha256.as_str()),
            ("check record", audit.ledger_sha256.as_str()),
        ] {
            if digest.len() != 64
                || !digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                errors.push(format!(
                    "unchanged-data {label} SHA-256 is not valid for {}",
                    audit.asset_path
                ));
            }
        }
        match entries.get(&entry_key) {
            Some(entry) if entry.sha256 == audit.entry_sha256 => {}
            Some(entry) => errors.push(format!(
                "unchanged-data Pak file SHA-256 mismatch for {}: report {}, Pak {}",
                audit.pak_entry_path, audit.entry_sha256, entry.sha256
            )),
            None => errors.push(format!(
                "a Pak file required by the unchanged-data check is missing: {}",
                audit.pak_entry_path
            )),
        }
    }
    errors
}

fn validate_request(request: &AnalysisRequest) -> Result<()> {
    validate_request_shape(request)?;
    let mut total = 0_u64;
    for path in &request.pak_paths {
        total = total
            .checked_add(fs::metadata(path)?.len())
            .ok_or_else(|| MergeError::InvalidRequest("input size overflow".to_owned()))?;
    }
    validate_total_input_size(total)
}

fn validate_request_shape(request: &AnalysisRequest) -> Result<()> {
    if request.pak_paths.is_empty() {
        return Err(MergeError::InvalidRequest(
            "at least one Pak input is required".to_owned(),
        ));
    }
    if request.pak_paths.len() > MAX_SUPPORTED_PAKS {
        return Err(MergeError::InvalidRequest(format!(
            "{} Pak inputs exceed the supported limit of {}",
            request.pak_paths.len(),
            MAX_SUPPORTED_PAKS
        )));
    }
    let mut unique = BTreeSet::new();
    for path in &request.pak_paths {
        if path
            .extension()
            .and_then(|value| value.to_str())
            .map(str::to_ascii_lowercase)
            != Some("pak".to_owned())
        {
            return Err(MergeError::InvalidRequest(format!(
                "Pak input must use .pak: {}",
                path.display()
            )));
        }
        let key = sort_key(&path.to_string_lossy());
        if !unique.insert(key) {
            return Err(MergeError::InvalidRequest(format!(
                "duplicate Pak input: {}",
                path.display()
            )));
        }
    }
    if !request
        .pak_paths
        .iter()
        .any(|path| same_path(path, &request.carrier_path))
    {
        return Err(MergeError::InvalidRequest(
            "The base Pak is not in the selected Pak list.".to_owned(),
        ));
    }
    Ok(())
}

fn validate_total_input_size(total: u64) -> Result<()> {
    if total > MAX_SUPPORTED_TOTAL_BYTES {
        return Err(MergeError::InvalidRequest(format!(
            "input total {total} exceeds the supported limit of {MAX_SUPPORTED_TOTAL_BYTES} bytes"
        )));
    }
    Ok(())
}

fn validate_cached_request(request: &AnalysisRequest, archives: &[Arc<PakArchive>]) -> Result<()> {
    validate_request_shape(request)?;
    if archives.len() != request.pak_paths.len() {
        return Err(MergeError::InvalidRequest(format!(
            "the inspection cache contains {} Pak files, but the request contains {}",
            archives.len(),
            request.pak_paths.len()
        )));
    }
    let total = archives.iter().try_fold(0_u64, |total, archive| {
        total
            .checked_add(archive.inventory().archive_size)
            .ok_or_else(|| MergeError::InvalidRequest("input size overflow".to_owned()))
    })?;
    validate_total_input_size(total)
}

fn open_paks(request: &AnalysisRequest) -> Result<Vec<OpenedPak>> {
    open_paks_with_progress(request, &mut |_, _, _| {})
}

fn open_paks_with_progress(
    request: &AnalysisRequest,
    progress: &mut dyn FnMut(usize, usize, &Path),
) -> Result<Vec<OpenedPak>> {
    let mut opened = Vec::with_capacity(request.pak_paths.len());
    let mut archive_sources = BTreeMap::<String, PathBuf>::new();
    let total = request.pak_paths.len();
    for (index, path) in request.pak_paths.iter().enumerate() {
        progress(index, total, path);
        let archive = Arc::new(PakArchive::open(path)?);
        let inventory = archive.inventory();
        if let Some(first_path) =
            archive_sources.insert(inventory.archive_sha256.clone(), path.clone())
        {
            return Err(MergeError::InvalidRequest(format!(
                "These Pak files are identical. Remove one before analyzing: {} and {} (SHA-256 {})",
                first_path.display(),
                path.display(),
                inventory.archive_sha256
            )));
        }
        let display_name = path
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("Pak")
            .to_owned();
        let descriptor = InputDescriptor {
            id: format!("pak-{}", inventory.archive_sha256),
            path: path.clone(),
            display_name,
            sha256: inventory.archive_sha256.clone(),
            size: inventory.archive_size,
            pak_version: Some(inventory.footer.version),
            mount_point: Some(inventory.mount_point.clone()),
            entry_count: Some(inventory.entries.len()),
        };
        let source_modified = archive.source_modified();
        opened.push(OpenedPak {
            descriptor,
            archive,
            source_modified,
            canonical_mount_point: String::new(),
            canonical_packages: pak::PackageGrouping::default(),
            entry_index: BTreeMap::new(),
        });
        progress(index + 1, total, path);
    }
    canonicalize_mount_points(&mut opened, &request.carrier_path)?;
    Ok(opened)
}

fn opened_from_archives(
    request: &AnalysisRequest,
    archives: Vec<Arc<PakArchive>>,
) -> Result<Vec<OpenedPak>> {
    let mut by_path = BTreeMap::new();
    for archive in archives {
        let key = sort_key(&archive.inventory().source_path.to_string_lossy());
        if by_path.insert(key, archive).is_some() {
            return Err(MergeError::InvalidRequest(
                "the inspection cache contains the same Pak path more than once".to_owned(),
            ));
        }
    }

    let mut opened = Vec::with_capacity(request.pak_paths.len());
    let mut archive_sources = BTreeMap::<String, PathBuf>::new();
    for path in &request.pak_paths {
        let key = sort_key(&path.to_string_lossy());
        let archive = by_path.remove(&key).ok_or_else(|| {
            MergeError::InvalidRequest(format!(
                "the inspected Pak is no longer available in the analysis cache: {}",
                path.display()
            ))
        })?;
        let inventory = archive.inventory();
        if !same_path(&inventory.source_path, path) {
            return Err(MergeError::InvalidRequest(format!(
                "the inspected Pak path does not match the selected file: {}",
                path.display()
            )));
        }
        verify_cached_archive_path(path, &archive)?;
        if let Some(first_path) =
            archive_sources.insert(inventory.archive_sha256.clone(), path.clone())
        {
            return Err(MergeError::InvalidRequest(format!(
                "These Pak files are identical. Remove one before analyzing: {} and {} (SHA-256 {})",
                first_path.display(),
                path.display(),
                inventory.archive_sha256
            )));
        }
        let display_name = path
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("Pak")
            .to_owned();
        let descriptor = InputDescriptor {
            id: format!("pak-{}", inventory.archive_sha256),
            path: path.clone(),
            display_name,
            sha256: inventory.archive_sha256.clone(),
            size: inventory.archive_size,
            pak_version: Some(inventory.footer.version),
            mount_point: Some(inventory.mount_point.clone()),
            entry_count: Some(inventory.entries.len()),
        };
        let source_modified = archive.source_modified();
        opened.push(OpenedPak {
            descriptor,
            archive,
            source_modified,
            canonical_mount_point: String::new(),
            canonical_packages: pak::PackageGrouping::default(),
            entry_index: BTreeMap::new(),
        });
    }
    if !by_path.is_empty() {
        return Err(MergeError::InvalidRequest(
            "the inspection cache contains a Pak that was not selected".to_owned(),
        ));
    }
    canonicalize_mount_points(&mut opened, &request.carrier_path)?;
    Ok(opened)
}

fn verify_session_input_stamps(opened: &[OpenedPak]) -> Result<()> {
    for input in opened {
        verify_cached_archive_path(&input.descriptor.path, &input.archive)?;
        if input.source_modified != input.archive.source_modified() {
            return Err(MergeError::InputChanged(input.descriptor.path.clone()));
        }
    }
    Ok(())
}

fn verify_cached_archive_path(path: &Path, archive: &PakArchive) -> Result<()> {
    if !same_path(archive.path(), path) {
        return Err(MergeError::InputChanged(path.to_path_buf()));
    }
    let metadata = fs::metadata(path).map_err(|_| MergeError::InputChanged(path.to_path_buf()))?;
    if metadata.len() != archive.inventory().archive_size {
        return Err(MergeError::InputChanged(path.to_path_buf()));
    }
    if let (Some(expected), Ok(actual)) = (archive.source_modified(), metadata.modified())
        && actual != expected
    {
        return Err(MergeError::InputChanged(path.to_path_buf()));
    }
    Ok(())
}

fn canonicalize_mount_points(opened: &mut [OpenedPak], carrier_path: &Path) -> Result<()> {
    let Some(_) = opened.first() else {
        return Ok(());
    };

    let mount_components: Vec<Vec<String>> = opened
        .iter()
        .map(|input| safe_mount_components(&input.archive.inventory().mount_point))
        .collect::<Result<_>>()?;
    let mut common_len = mount_components[0].len();
    for components in &mount_components[1..] {
        common_len = (0..common_len.min(components.len()))
            .take_while(|index| {
                mount_components[0][*index].eq_ignore_ascii_case(&components[*index])
            })
            .count();
    }
    if common_len == 0
        || !mount_components[0][..common_len]
            .iter()
            .any(|component| component != "..")
    {
        let mounts = opened
            .iter()
            .map(|input| input.archive.inventory().mount_point.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        return Err(MergeError::InvalidRequest(format!(
            "The Pak files point to different game folders and cannot be merged together. Pak root paths: {mounts}"
        )));
    }

    let carrier_index = opened
        .iter()
        .position(|input| same_path(&input.descriptor.path, carrier_path))
        .ok_or_else(|| {
            MergeError::InvalidRequest("The selected base Pak is no longer available.".to_owned())
        })?;
    let common_mount =
        pak::normalize_mount_point(&mount_components[carrier_index][..common_len].join("/"))?;

    for (input, components) in opened.iter_mut().zip(mount_components) {
        let prefix = components[common_len..].join("/");
        let inventory = input.archive.inventory();
        let mut entry_index = BTreeMap::new();
        let mut canonical_paths = Vec::with_capacity(inventory.entries.len());
        for (index, entry) in inventory.entries.iter().enumerate() {
            let canonical = if prefix.is_empty() {
                entry.path.clone()
            } else {
                pak::normalize_entry_path(&format!("{prefix}/{}", entry.path))?
            };
            let key = sort_key(&canonical);
            if let Some(previous) = entry_index.insert(key, index) {
                let first = &inventory.entries[previous].path;
                return Err(MergeError::InvalidRequest(format!(
                    "Matching the Pak root paths would create the same internal file path twice in {}: {first} and {}",
                    input.descriptor.path.display(),
                    entry.path
                )));
            }
            canonical_paths.push(canonical);
        }
        input.canonical_packages = pak::group_packages(canonical_paths.iter().map(String::as_str))?;
        input.canonical_mount_point = common_mount.clone();
        input.entry_index = entry_index;
    }
    Ok(())
}

fn safe_mount_components(mount_point: &str) -> Result<Vec<String>> {
    let normalized = pak::normalize_mount_point(mount_point)?;
    let mut components = Vec::new();
    let mut saw_named_component = false;
    for component in normalized.trim_end_matches('/').split('/') {
        if component == "." {
            return Err(MergeError::InvalidRequest(format!(
                "The Pak root path contains an unsafe '.' section: {mount_point}"
            )));
        }
        if component == ".." {
            if saw_named_component {
                return Err(MergeError::InvalidRequest(format!(
                    "The Pak root path leaves its game folder through '..': {mount_point}"
                )));
            }
        } else {
            saw_named_component = true;
        }
        components.push(component.to_owned());
    }
    if !saw_named_component {
        return Err(MergeError::InvalidRequest(format!(
            "The Pak root path does not name a game folder: {mount_point}"
        )));
    }
    Ok(components)
}

fn collect_providers(
    opened: &[OpenedPak],
) -> (
    BTreeMap<String, Vec<GroupProvider>>,
    BTreeMap<String, Vec<LooseProvider>>,
) {
    let mut packages: BTreeMap<String, Vec<GroupProvider>> = BTreeMap::new();
    let mut loose: BTreeMap<String, Vec<LooseProvider>> = BTreeMap::new();
    for (input_index, input) in opened.iter().enumerate() {
        for group in &input.canonical_packages.packages {
            packages
                .entry(sort_key(&group.base_path))
                .or_default()
                .push(GroupProvider {
                    input_index,
                    group: group.clone(),
                });
        }
        for path in &input.canonical_packages.loose_entries {
            loose
                .entry(sort_key(path))
                .or_default()
                .push(LooseProvider {
                    input_index,
                    path: path.clone(),
                });
        }
    }
    (packages, loose)
}

/// Detect a game profile only from the complete, canonicalized inventory.
/// The common mount point is joined to every rebased asset path so a familiar
/// table suffix in an unrelated game can never activate game-specific rules.
fn detect_profile_from_opened_inventory(opened: &[OpenedPak]) -> profiles::ProfileDetection {
    let mut inventory = BTreeSet::new();
    for input in opened {
        let mount = input.canonical_mount_point.trim_end_matches('/');
        inventory.insert(mount.to_owned());
        for group in &input.canonical_packages.packages {
            inventory.insert(format!(
                "{mount}/{}",
                group.base_path.trim_start_matches('/')
            ));
        }
        for path in &input.canonical_packages.loose_entries {
            inventory.insert(format!("{mount}/{}", path.trim_start_matches('/')));
        }
    }
    profiles::default_registry().detect_inventory(inventory.iter().map(String::as_str))
}

const fn profile_detection_status_id(status: ProfileDetectionStatus) -> &'static str {
    match status {
        ProfileDetectionStatus::Selected => "selected",
        ProfileDetectionStatus::GenericNoMatch => "generic_no_match",
        ProfileDetectionStatus::GenericAmbiguous => "generic_ambiguous",
    }
}

fn pinned_profile_id(plan: &MergePlan) -> Option<&str> {
    matches!(
        plan.profile_detection_status,
        Some(ProfileDetectionStatus::Selected)
    )
    .then_some(plan.selected_profile_id.as_deref())
    .flatten()
}

fn is_database_candidate(providers: &[GroupProvider]) -> bool {
    providers.iter().all(|provider| {
        provider.group.complete
            && provider.group.components.len() == 2
            && provider
                .group
                .components
                .contains_key(&PackageComponent::Uasset)
            && provider
                .group
                .components
                .contains_key(&PackageComponent::Uexp)
    })
}

fn analyze_units(
    units: &[AnalysisUnit],
    opened: &[OpenedPak],
    carrier_index: usize,
    selected_profile_id: Option<&str>,
    cancelled: Option<&CancellationToken>,
    multithreaded: bool,
    progress: &mut dyn FnMut(usize, usize, Option<String>),
) -> Result<Vec<AnalysisUnitOutput>> {
    let worker_count = crate::resources::worker_threads().min(units.len());
    if !multithreaded || units.len() < 2 || worker_count < 2 {
        let mut outputs = Vec::with_capacity(units.len());
        let mut tracker = AnalysisProgressTracker::new(units.len())?;
        for (index, unit) in units.iter().enumerate() {
            check_cancel(cancelled)?;
            let label = unit.label();
            tracker.update(
                index,
                AnalysisUnitProgress::started(label.clone()),
                progress,
            );
            let result = {
                let mut detailed_progress = |update| tracker.update(index, update, progress);
                analyze_unit(
                    unit,
                    opened,
                    carrier_index,
                    selected_profile_id,
                    cancelled,
                    multithreaded,
                    &mut detailed_progress,
                )
            };
            let output = result?;
            tracker.finish(index, label, progress);
            outputs.push(output);
        }
        return Ok(outputs);
    }

    let (database_indices, independent_indices): (Vec<_>, Vec<_>) =
        (0..units.len()).partition(|&index| unit_requires_database_parse(&units[index]));

    analyze_partitioned_units(
        units.len(),
        worker_count,
        database_indices,
        independent_indices,
        |index, detailed_progress| {
            analyze_unit(
                &units[index],
                opened,
                carrier_index,
                selected_profile_id,
                cancelled,
                multithreaded,
                detailed_progress,
            )
        },
        |index| units[index].label(),
        progress,
    )
}

/// Runs database comparisons on at most two bounded workers while distributing
/// independent comparisons over the remaining workers. When both partitions
/// are non-empty, one worker is always reserved for independent work so large
/// database parsers cannot starve loose files and opaque packages.
enum AnalysisWorkerMessage<T> {
    Progress {
        index: usize,
        update: AnalysisUnitProgress,
    },
    Finished {
        index: usize,
        label: Option<String>,
        result: Result<T>,
    },
}

fn analyze_partitioned_units<T, Analyze, Label>(
    total: usize,
    worker_count: usize,
    database_indices: Vec<usize>,
    independent_indices: Vec<usize>,
    analyze: Analyze,
    label: Label,
    progress: &mut dyn FnMut(usize, usize, Option<String>),
) -> Result<Vec<T>>
where
    T: Send,
    Analyze: Fn(usize, &mut AnalysisUnitProgressCallback<'_>) -> Result<T> + Sync,
    Label: Fn(usize) -> Option<String> + Sync,
{
    debug_assert_eq!(database_indices.len() + independent_indices.len(), total);
    debug_assert!(worker_count >= 2);

    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::scope(|scope| -> Result<Vec<T>> {
        if !database_indices.is_empty() {
            let reserved_for_independent = usize::from(!independent_indices.is_empty());
            let database_worker_count = database_indices
                .len()
                .min(2)
                .min(worker_count.saturating_sub(reserved_for_independent).max(1));
            let mut worker_indices = (0..database_worker_count)
                .map(|_| Vec::new())
                .collect::<Vec<_>>();
            for (position, index) in database_indices.into_iter().enumerate() {
                worker_indices[position % database_worker_count].push(index);
            }

            for indices in worker_indices {
                let sender = sender.clone();
                let analyze = &analyze;
                let label = &label;
                scope.spawn(move || {
                    for index in indices {
                        let item_label = label(index);
                        if sender
                            .send(AnalysisWorkerMessage::Progress {
                                index,
                                update: AnalysisUnitProgress::started(item_label.clone()),
                            })
                            .is_err()
                        {
                            break;
                        }
                        let mut detailed_progress = |update| {
                            let _ = sender.send(AnalysisWorkerMessage::Progress { index, update });
                        };
                        let result = analyze(index, &mut detailed_progress);
                        if sender
                            .send(AnalysisWorkerMessage::Finished {
                                index,
                                label: item_label,
                                result,
                            })
                            .is_err()
                        {
                            break;
                        }
                    }
                });
            }
        }

        if !independent_indices.is_empty() {
            let database_worker_count = if total == independent_indices.len() {
                0
            } else {
                let database_count = total - independent_indices.len();
                database_count
                    .min(2)
                    .min(worker_count.saturating_sub(1).max(1))
            };
            let available_workers = worker_count.saturating_sub(database_worker_count);
            let independent_worker_count = available_workers.max(1).min(independent_indices.len());
            let mut worker_indices = (0..independent_worker_count)
                .map(|_| Vec::new())
                .collect::<Vec<_>>();
            for (position, index) in independent_indices.into_iter().enumerate() {
                worker_indices[position % independent_worker_count].push(index);
            }

            for indices in worker_indices {
                let sender = sender.clone();
                let analyze = &analyze;
                let label = &label;
                scope.spawn(move || {
                    for index in indices {
                        let item_label = label(index);
                        if sender
                            .send(AnalysisWorkerMessage::Progress {
                                index,
                                update: AnalysisUnitProgress::started(item_label.clone()),
                            })
                            .is_err()
                        {
                            break;
                        }
                        let mut detailed_progress = |update| {
                            let _ = sender.send(AnalysisWorkerMessage::Progress { index, update });
                        };
                        let result = analyze(index, &mut detailed_progress);
                        if sender
                            .send(AnalysisWorkerMessage::Finished {
                                index,
                                label: item_label,
                                result,
                            })
                            .is_err()
                        {
                            break;
                        }
                    }
                });
            }
        }
        drop(sender);

        let mut slots = (0..total).map(|_| None).collect::<Vec<_>>();
        let mut tracker = AnalysisProgressTracker::new(total)?;
        let mut finished = 0_usize;
        while finished < total {
            let message = receiver.recv().map_err(|_| {
                MergeError::InvalidRequest(
                    "a parallel comparison worker stopped unexpectedly".to_owned(),
                )
            })?;
            match message {
                AnalysisWorkerMessage::Progress { index, update } => {
                    tracker.update(index, update, progress);
                }
                AnalysisWorkerMessage::Finished {
                    index,
                    label,
                    result,
                } => {
                    let succeeded = result.is_ok();
                    slots[index] = Some(result);
                    if succeeded {
                        tracker.finish(index, label, progress);
                    } else {
                        tracker.update(index, AnalysisUnitProgress::started(label), progress);
                    }
                    finished += 1;
                }
            }
        }
        slots
            .into_iter()
            .map(|slot| slot.expect("every parallel analysis result slot is filled"))
            .collect()
    })
}

fn unit_requires_database_parse(unit: &AnalysisUnit) -> bool {
    matches!(unit, AnalysisUnit::Package(providers) if providers.len() > 1 && is_database_candidate(providers))
}

fn analyze_unit(
    unit: &AnalysisUnit,
    opened: &[OpenedPak],
    carrier_index: usize,
    selected_profile_id: Option<&str>,
    cancelled: Option<&CancellationToken>,
    multithreaded: bool,
    detailed_progress: &mut AnalysisUnitProgressCallback<'_>,
) -> Result<AnalysisUnitOutput> {
    check_cancel(cancelled)?;
    match unit {
        AnalysisUnit::Package(providers) => {
            if providers.len() == 1 {
                return Ok(AnalysisUnitOutput {
                    asset: package_asset_plan(
                        providers,
                        opened,
                        AssetActionKind::Copy,
                        Vec::new(),
                        Vec::new(),
                    ),
                    conflicts: Vec::new(),
                    warnings: Vec::new(),
                    parsed_database: None,
                });
            }
            if providers_semantically_identical(opened, providers, multithreaded, cancelled)? {
                return Ok(AnalysisUnitOutput {
                    asset: package_asset_plan(
                        providers,
                        opened,
                        AssetActionKind::Deduplicate,
                        Vec::new(),
                        Vec::new(),
                    ),
                    conflicts: Vec::new(),
                    warnings: Vec::new(),
                    parsed_database: None,
                });
            }

            let mut warnings = Vec::new();
            if is_database_candidate(providers) {
                match analyze_database_group(
                    opened,
                    providers,
                    carrier_index,
                    selected_profile_id,
                    cancelled,
                    multithreaded,
                    detailed_progress,
                ) {
                    Ok((asset, conflicts, found_warnings, providers, cached_bytes)) => {
                        let key = sort_key(&asset.virtual_path);
                        return Ok(AnalysisUnitOutput {
                            asset,
                            conflicts,
                            warnings: found_warnings,
                            parsed_database: Some((key, providers, cached_bytes)),
                        });
                    }
                    Err(MergeError::DatabaseStructureMismatch(message)) => {
                        warnings.push(format!(
                            "{} cannot be compared row by row because the surrounding data differs. Choose one Pak for the whole file group. Details: {message}",
                            providers[0].group.base_path
                        ));
                        let (asset, conflict) = analyze_package_selection_group(
                            opened,
                            providers,
                            ConflictKind::StructureMismatch,
                            "The data outside the row list differs. Choose one Pak for the whole file group.",
                            multithreaded,
                            cancelled,
                        )?;
                        return Ok(AnalysisUnitOutput {
                            asset,
                            conflicts: vec![conflict],
                            warnings,
                            parsed_database: None,
                        });
                    }
                    Err(MergeError::Cancelled) => return Err(MergeError::Cancelled),
                    Err(error @ MergeError::Pak(_)) | Err(error @ MergeError::Io(_)) => {
                        return Err(error);
                    }
                    Err(error) => warnings.push(format!(
                        "{} could not be compared field by field, so its related files must be chosen from one Pak. Details: {error}",
                        providers[0].group.base_path
                    )),
                }
            }

            let (asset, conflict) =
                analyze_opaque_group(opened, providers, multithreaded, cancelled)?;
            Ok(AnalysisUnitOutput {
                asset,
                conflicts: vec![conflict],
                warnings,
                parsed_database: None,
            })
        }
        AnalysisUnit::Loose(providers) => {
            if providers.len() == 1 {
                return Ok(AnalysisUnitOutput {
                    asset: loose_asset_plan(providers, opened, AssetActionKind::Copy, Vec::new()),
                    conflicts: Vec::new(),
                    warnings: Vec::new(),
                    parsed_database: None,
                });
            }
            if loose_identical(opened, providers, multithreaded, cancelled)? {
                return Ok(AnalysisUnitOutput {
                    asset: loose_asset_plan(
                        providers,
                        opened,
                        AssetActionKind::Deduplicate,
                        Vec::new(),
                    ),
                    conflicts: Vec::new(),
                    warnings: Vec::new(),
                    parsed_database: None,
                });
            }
            let conflict = make_loose_conflict(opened, providers, multithreaded, cancelled)?;
            Ok(AnalysisUnitOutput {
                asset: loose_asset_plan(
                    providers,
                    opened,
                    AssetActionKind::SelectOpaque,
                    vec![conflict.id.clone()],
                ),
                conflicts: vec![conflict],
                warnings: Vec::new(),
                parsed_database: None,
            })
        }
    }
}

type DatabaseAnalysis = (
    AssetPlan,
    Vec<Conflict>,
    Vec<String>,
    Vec<ParsedDbProvider>,
    u64,
);

fn analyze_database_group(
    opened: &[OpenedPak],
    providers: &[GroupProvider],
    global_carrier_index: usize,
    selected_profile_id: Option<&str>,
    cancelled: Option<&CancellationToken>,
    multithreaded: bool,
    detailed_progress: &mut AnalysisUnitProgressCallback<'_>,
) -> Result<DatabaseAnalysis> {
    let parsed = {
        let mut indexing_progress = |completed: u64, total: u64, current_item: &str| {
            detailed_progress(database_analysis_phase_progress(
                0,
                completed,
                total,
                current_item.to_owned(),
            ));
        };
        load_cached_database(
            opened,
            providers,
            multithreaded,
            cancelled,
            Some(&mut indexing_progress),
        )?
    };
    let supporting_files_differ = validate_database_shell_compatibility(&parsed)?;
    let carrier_local = parsed
        .iter()
        .position(|provider| provider.input_index == global_carrier_index)
        .unwrap_or(0);
    let asset_path = parsed[carrier_local].group.base_path.clone();
    let mut unit_planner = profiles::AtomicUnitPlanner::new(
        profiles::default_registry(),
        selected_profile_id,
        &asset_path,
    );
    let mut row_ids = BTreeSet::new();
    for provider in &parsed {
        row_ids.extend(provider.asset.row_ids().iter().copied());
    }
    let mut conflicts = Vec::new();
    let mut warnings = Vec::new();
    let mut encoding_drift_count = 0_u64;
    let mut encoding_drift_samples = 0_usize;
    if supporting_files_differ {
        warnings.push(format!(
            "{asset_path}: the related .uasset file differs between Paks. The merge will keep the base Pak file and update only its structurally verified data-size field. Check this database in game after merging."
        ));
    }

    let row_total = row_ids.len();
    let first_row_id = row_ids.first().copied();
    detailed_progress(database_analysis_phase_progress(
        1,
        0,
        row_total as u64,
        match first_row_id {
            Some(row_id) => format!("{asset_path} · m_id {row_id}"),
            None => asset_path.clone(),
        },
    ));
    for (row_index, row_id) in row_ids.into_iter().enumerate() {
        check_cancel(cancelled)?;
        let carrier_row = indexed_row(&parsed[carrier_local].asset, row_id, cancelled)?;
        if let Some(carrier_row) = carrier_row.as_ref() {
            let carrier_layout = unit_planner.layout_for_row(&carrier_row.node)?;
            struct UnitAnalysis {
                unit: AtomicGroup,
                first_semantic: Option<String>,
                first_raw: Option<String>,
                semantic_differs: bool,
                raw_differs: bool,
            }
            let mut unit_analyses = carrier_layout
                .units
                .iter()
                .cloned()
                .map(|unit| UnitAnalysis {
                    unit,
                    first_semantic: None,
                    first_raw: None,
                    semantic_differs: false,
                    raw_differs: false,
                })
                .collect::<Vec<_>>();
            let mut shape_mismatch = false;
            let mut atomic_layout_mismatch = false;

            for analysis in &mut unit_analyses {
                let hashes =
                    binary_asset::atomic_group_hashes(carrier_row.node_ref(), &analysis.unit)?;
                analysis.first_semantic = Some(hashes.semantic_sha256);
                analysis.first_raw = Some(hashes.raw_sha256);
            }

            // Parse at most the carrier plus one other provider row at once.
            // Variant records keep only hashes/previews, never an AST or raw
            // value copy, so a large String/Binary field cannot multiply by
            // the number of Paks during semantic analysis.
            for (local, provider) in parsed.iter().enumerate() {
                check_cancel(cancelled)?;
                if local == carrier_local {
                    continue;
                }
                let Some(row) = indexed_row(&provider.asset, row_id, cancelled)? else {
                    continue;
                };
                let Some(donor_layout) = unit_planner
                    .layout_for_row_matching_field_order(&row.node, &carrier_layout.field_order)?
                else {
                    shape_mismatch = true;
                    continue;
                };
                let layout_matches = donor_layout.units == carrier_layout.units;
                atomic_layout_mismatch |= !layout_matches;
                if !layout_matches {
                    continue;
                }
                for analysis in &mut unit_analyses {
                    let hashes = binary_asset::atomic_group_hashes(row.node_ref(), &analysis.unit)?;
                    analysis.semantic_differs |= analysis
                        .first_semantic
                        .as_deref()
                        .is_some_and(|first| first != hashes.semantic_sha256);
                    analysis.raw_differs |= analysis
                        .first_raw
                        .as_deref()
                        .is_some_and(|first| first != hashes.raw_sha256);
                }
            }
            if shape_mismatch || atomic_layout_mismatch {
                let whole_variants = make_whole_row_variants(
                    opened,
                    &parsed,
                    carrier_local,
                    &asset_path,
                    row_id,
                    cancelled,
                )?;
                let message = if shape_mismatch {
                    "This row has a different field layout. Choose one Pak for the whole row."
                } else {
                    "Linked fields or lists have different layouts. Choose one Pak for the whole row."
                };
                conflicts.push(make_conflict(
                    ConflictKind::StructureMismatch,
                    &asset_path,
                    Some(row_id),
                    Some("__whole_row__"),
                    message,
                    whole_variants,
                    true,
                ));
                ensure_conflict_count(&conflicts)?;
                let completed_rows = row_index + 1;
                if should_report_database_progress(completed_rows, row_total) {
                    detailed_progress(database_analysis_phase_progress(
                        1,
                        completed_rows as u64,
                        row_total as u64,
                        format!("{asset_path} · m_id {row_id}"),
                    ));
                }
                continue;
            }

            struct PendingAtomicConflict {
                unit: AtomicGroup,
                kind: ConflictKind,
                message: &'static str,
                blocking: bool,
            }
            let mut pending = Vec::new();
            for analysis in unit_analyses {
                if analysis.semantic_differs {
                    let kind = if analysis.unit.compound || analysis.unit.fields.len() > 1 {
                        ConflictKind::AtomicGroup
                    } else {
                        ConflictKind::FieldValue
                    };
                    pending.push(PendingAtomicConflict {
                        unit: analysis.unit,
                        kind,
                        message: "The saved values differ. Choose which Pak to use.",
                        blocking: true,
                    });
                } else if analysis.raw_differs {
                    encoding_drift_count = encoding_drift_count.saturating_add(1);
                    if encoding_drift_samples < MAX_ENCODING_DRIFT_SAMPLES_PER_ASSET {
                        pending.push(PendingAtomicConflict {
                            unit: analysis.unit,
                            kind: ConflictKind::EncodingDrift,
                            message: "The value is the same, but its storage format differs. The base Pak format will be kept.",
                            blocking: false,
                        });
                        encoding_drift_samples += 1;
                    }
                }
            }
            if !pending.is_empty() {
                let pending_units = pending.iter().map(|item| &item.unit).collect::<Vec<_>>();
                let variants_by_unit = make_atomic_variant_sets(
                    opened,
                    &parsed,
                    carrier_local,
                    row_id,
                    &pending_units,
                    cancelled,
                )?;
                for (pending, variants) in pending.into_iter().zip(variants_by_unit) {
                    conflicts.push(make_conflict(
                        pending.kind,
                        &asset_path,
                        Some(row_id),
                        Some(&pending.unit.id),
                        pending.message,
                        variants,
                        pending.blocking,
                    ));
                    ensure_conflict_count(&conflicts)?;
                }
            }
        } else {
            let mut first_semantic = None;
            let mut semantic_differs = false;
            for provider in &parsed {
                check_cancel(cancelled)?;
                let Some(row) = indexed_row(&provider.asset, row_id, cancelled)? else {
                    continue;
                };
                let semantic = row.node.semantic_sha256();
                if let Some(first) = first_semantic.as_deref() {
                    semantic_differs |= first != semantic;
                } else {
                    first_semantic = Some(semantic);
                }
            }
            if semantic_differs {
                let mut variants = Vec::new();
                variants
                    .try_reserve_exact(parsed.len())
                    .map_err(|_| MergeError::AllocationFailed("row choices"))?;
                for provider in &parsed {
                    check_cancel(cancelled)?;
                    let Some(row) = indexed_row(&provider.asset, row_id, cancelled)? else {
                        continue;
                    };
                    variants.push(make_row_variant(
                        opened,
                        provider,
                        &asset_path,
                        row_id,
                        "$row",
                        row.node_ref(),
                    )?);
                }
                conflicts.push(make_conflict(
                    ConflictKind::RowIdCollision,
                    &asset_path,
                    Some(row_id),
                    Some("$row"),
                    "This row is not in the base Pak and differs between the other Paks. Choose one Pak for the whole row.",
                    variants,
                    true,
                ));
                ensure_conflict_count(&conflicts)?;
            }
        }
        let completed_rows = row_index + 1;
        if should_report_database_progress(completed_rows, row_total) {
            detailed_progress(database_analysis_phase_progress(
                1,
                completed_rows as u64,
                row_total as u64,
                format!("{asset_path} · m_id {row_id}"),
            ));
        }
    }

    let (mut placement_conflicts, mut placement_warnings) =
        analyze_potential_npc_placement_collisions(opened, &parsed, &asset_path, cancelled)?;
    conflicts.append(&mut placement_conflicts);
    warnings.append(&mut placement_warnings);
    ensure_conflict_count(&conflicts)?;

    if encoding_drift_count != 0 {
        warnings.push(format!(
            "Encoding drift retained for {encoding_drift_count} item(s) in {asset_path}; the base Pak storage format will be kept. {encoding_drift_samples} example(s) are available in the comparison details."
        ));
    }

    let conflict_ids = conflicts
        .iter()
        .filter(|conflict| conflict.blocking)
        .map(|conflict| conflict.id.clone())
        .collect();
    let mut asset_plan = package_asset_plan(
        providers,
        opened,
        AssetActionKind::MergeDatabase,
        conflict_ids,
        warnings.clone(),
    );
    asset_plan.encoding_drift_count = encoding_drift_count;
    let cached_bytes = database_provider_bytes(opened, providers)?;
    Ok((asset_plan, conflicts, warnings, parsed, cached_bytes))
}

fn analyze_potential_npc_placement_collisions(
    opened: &[OpenedPak],
    parsed: &[ParsedDbProvider],
    asset_path: &str,
    cancelled: Option<&CancellationToken>,
) -> Result<(Vec<Conflict>, Vec<String>)> {
    if !is_npc_set_list_asset(asset_path) {
        return Ok((Vec::new(), Vec::new()));
    }

    let mut placements = BTreeMap::<NpcPlacementLogicalKey, Vec<NpcPlacementOccurrence>>::new();
    for (provider_local, provider) in parsed.iter().enumerate() {
        for &row_id in provider.asset.row_ids() {
            let row = indexed_row(&provider.asset, row_id, cancelled)?
                .expect("indexed row ID remains available");
            let Some(binding) = npc_placement_binding(&row.node)? else {
                continue;
            };
            let Some(key) = npc_placement_logical_key(&row.node)? else {
                continue;
            };
            placements
                .entry(key)
                .or_default()
                .push(NpcPlacementOccurrence {
                    provider_local,
                    row_id,
                    binding,
                });
        }
    }

    let mut conflicts = Vec::new();
    let mut warnings = Vec::new();
    for (key, mut occurrences) in placements {
        occurrences.sort_unstable();
        let row_ids: BTreeSet<_> = occurrences
            .iter()
            .map(|occurrence| occurrence.row_id)
            .collect();
        let bindings: BTreeSet<_> = occurrences
            .iter()
            .map(|occurrence| occurrence.binding)
            .collect();
        if row_ids.len() < 2 || bindings.len() < 2 {
            continue;
        }

        // A logical-key duplicate already shared identically by every input is
        // not a cross-provider disagreement. Require at least two providers to
        // claim the key and compare their exact row/binding patterns.
        let mut patterns = BTreeMap::<usize, BTreeSet<(RowId, NpcPlacementBinding)>>::new();
        for occurrence in &occurrences {
            patterns
                .entry(occurrence.provider_local)
                .or_default()
                .insert((occurrence.row_id, occurrence.binding));
        }
        if patterns.len() < 2 {
            continue;
        }
        let distinct_patterns: BTreeSet<Vec<_>> = patterns
            .values()
            .map(|pattern| pattern.iter().copied().collect())
            .collect();
        if distinct_patterns.len() < 2 {
            continue;
        }

        let key_text = key.stable_text();
        let key_display = key.display_text();
        let group_id = format!("npc_placement:{key_text}");
        let mut variants = Vec::with_capacity(occurrences.len());
        for occurrence in &occurrences {
            let provider = &parsed[occurrence.provider_local];
            let input = &opened[provider.input_index].descriptor;
            let row = indexed_row(&provider.asset, occurrence.row_id, cancelled)?
                .ok_or_else(|| MergeError::InputChanged(input.path.clone()))?;
            let raw_sha256 = row.node_ref().raw_sha256();
            let semantic_sha256 = row.node_ref().semantic_sha256();
            let row_text = occurrence.row_id.to_string();
            let owner_text = occurrence.binding.owner_npc.to_string();
            let talk_text = occurrence.binding.talk_id.to_string();
            variants.push(Variant {
                id: stable_id(
                    "variant",
                    [
                        asset_path,
                        key_text.as_str(),
                        row_text.as_str(),
                        input.id.as_str(),
                        owner_text.as_str(),
                        talk_text.as_str(),
                        raw_sha256.as_str(),
                    ],
                ),
                label: input.display_name.clone(),
                input_id: input.id.clone(),
                raw_sha256: raw_sha256.clone(),
                semantic_sha256,
                preview: format!(
                    "row {}, {key_display}, m_OwnerNPC={}, m_TalkID={}",
                    occurrence.row_id, occurrence.binding.owner_npc, occurrence.binding.talk_id
                ),
                marker: format!("row-map:0x{:02X}", row.node.marker),
                provenance: Provenance {
                    input_id: input.id.clone(),
                    input_path: input.path.clone(),
                    entry_path: provider
                        .group
                        .components
                        .get(&PackageComponent::Uexp)
                        .cloned(),
                    raw_sha256,
                },
            });
        }

        let row_list = row_ids
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        let message = format!(
            "NpcSet location {key_display} may contain overlapping NPC or dialogue settings (rows: {row_list}). The rows will still be combined, but only one may appear in game. Check this location after merging."
        );
        conflicts.push(make_conflict(
            ConflictKind::PotentialPlacementCollision,
            asset_path,
            None,
            Some(&group_id),
            &message,
            variants,
            false,
        ));
        warnings.push(message);
    }
    Ok((conflicts, warnings))
}

fn is_npc_set_list_asset(asset_path: &str) -> bool {
    let path = sort_key(asset_path);
    path.contains("local/database/npc/")
        && path
            .rsplit('/')
            .next()
            .is_some_and(|name| name.starts_with("npcsetlist"))
}

fn npc_placement_logical_key(
    row: &binary_asset::MsgpackNode,
) -> Result<Option<NpcPlacementLogicalKey>> {
    let map_id = npc_integer_field(row, "m_MapID")?;
    let appear_label = npc_string_field(row, "m_AppearLabel")?;
    if let (Some(map_id), Some(appear_label)) = (map_id.filter(|value| *value > 0), appear_label) {
        return Ok(Some(NpcPlacementLogicalKey::MapAppear {
            map_id,
            appear_label,
        }));
    }
    Ok(npc_string_field(row, "m_label")?.map(NpcPlacementLogicalKey::Label))
}

fn npc_placement_binding(row: &binary_asset::MsgpackNode) -> Result<Option<NpcPlacementBinding>> {
    let Some(owner_npc) = npc_integer_field(row, "m_OwnerNPC")?.filter(|value| *value > 0) else {
        return Ok(None);
    };
    let Some(talk_id) = npc_integer_field(row, "m_TalkID")?.filter(|value| *value > 0) else {
        return Ok(None);
    };
    Ok(Some(NpcPlacementBinding { owner_npc, talk_id }))
}

fn npc_integer_field(row: &binary_asset::MsgpackNode, field: &str) -> Result<Option<i64>> {
    Ok(row
        .map_get(field)?
        .and_then(binary_asset::MsgpackNode::integer_value)
        .and_then(IntegerValue::as_i64))
}

fn npc_string_field(row: &binary_asset::MsgpackNode, field: &str) -> Result<Option<String>> {
    Ok(row
        .map_get(field)?
        .and_then(binary_asset::MsgpackNode::string_value)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_ascii_lowercase))
}

/// Validates every byte that can reach the merged BinaryAsset output.
///
/// A differing supporting `.uasset` is not itself a merge blocker. Every file
/// must independently prove that it contains one structurally identified
/// `BinaryAsset` export paired with the parsed `.uexp`. Output retains the base
/// Pak's file and updates only that export's structurally located SerialSize.
/// The boolean return records that the other supporting-file bytes differ and
/// must be surfaced as an analysis warning.
fn validate_database_shell_compatibility(parsed: &[ParsedDbProvider]) -> Result<bool> {
    let shell_digests: BTreeSet<_> = parsed
        .iter()
        .map(|provider| database_shell_digest(&provider.asset))
        .collect::<Result<_>>()?;
    if shell_digests.len() != 1 {
        return Err(MergeError::DatabaseStructureMismatch(
            "BinaryAsset prefix/root-outside-m_DataList/footer/package-tag fingerprints differ"
                .to_owned(),
        ));
    }

    let descriptors: Vec<_> = parsed
        .iter()
        .map(|provider| {
            parse_uasset_shell(
                provider.uasset.as_ref(),
                provider.uexp_size,
                Some(&provider.group.base_path),
            )
        })
        .collect::<Result<_>>()?;
    let package_identities: BTreeSet<_> = descriptors
        .iter()
        .map(|descriptor| {
            (
                sort_key(&descriptor.package_path),
                descriptor.object_name.to_ascii_lowercase(),
            )
        })
        .collect();
    if package_identities.len() != 1 {
        return Err(MergeError::DatabaseStructureMismatch(
            "the .uasset files identify different BinaryAsset packages or objects".to_owned(),
        ));
    }

    let raw_uasset_digests: BTreeSet<_> = parsed
        .iter()
        .map(|provider| binary_asset::sha256_hex(provider.uasset.as_ref()))
        .collect();
    Ok(raw_uasset_digests.len() != 1)
}

fn database_shell_digest(asset: &IndexedBinaryAsset) -> Result<String> {
    let list_range = asset.data_list_range();
    let mut prefix = asset.prefix;
    prefix[6..10].fill(0);
    let mut digest = Sha256::new();
    digest.update(b"PAK-MERGER-BINARY-ASSET-SHELL-V1");
    update_framed(&mut digest, &prefix);
    update_framed(&mut digest, &asset.payload()[..list_range.start]);
    update_framed(&mut digest, &asset.payload()[list_range.end..]);
    update_framed(&mut digest, &asset.footer);
    update_framed(&mut digest, &asset.package_tag);
    Ok(hex::encode(digest.finalize()))
}

#[derive(Debug)]
struct UassetShellDescriptor {
    package_path: String,
    object_name: String,
    serial_size_offset: usize,
    _bulk_data_start_offset: usize,
}

fn parse_uasset_shell(
    uasset: &[u8],
    uexp_size: usize,
    expected_asset_path: Option<&str>,
) -> Result<UassetShellDescriptor> {
    const PACKAGE_MAGIC: [u8; binary_asset::PACKAGE_TAG_SIZE] = [0xC1, 0x83, 0x2A, 0x9E];
    const TOTAL_HEADER_SIZE_OFFSET: usize = 0x1C;
    const FOLDER_NAME_OFFSET: usize = 0x20;
    const PACKAGE_FLAGS: u32 = 0x8000_2200;
    // OT0's cooked imports include the 4-byte package-name extension after
    // the traditional 28-byte FObjectImport body.
    const IMPORT_ENTRY_SIZE: usize = 32;
    const MAX_NAME_COUNT: usize = 100_000;
    const MAX_IMPORT_COUNT: usize = 100_000;

    if uasset.get(..binary_asset::PACKAGE_TAG_SIZE) != Some(PACKAGE_MAGIC.as_slice()) {
        return Err(MergeError::DatabaseStructureMismatch(
            ".uasset does not carry the expected C1 83 2A 9E package tag".to_owned(),
        ));
    }
    if read_i32_le_at(uasset, 4) != Some(-8) {
        return Err(MergeError::DatabaseStructureMismatch(
            ".uasset LegacyVersion is not the expected value -8".to_owned(),
        ));
    }
    if uasset.get(8..TOTAL_HEADER_SIZE_OFFSET) != Some(&[0; 20]) {
        return Err(MergeError::DatabaseStructureMismatch(
            ".uasset version fields do not match the supported unversioned OT0 package layout"
                .to_owned(),
        ));
    }
    if read_u32_le_at(uasset, TOTAL_HEADER_SIZE_OFFSET) != u32::try_from(uasset.len()).ok() {
        return Err(MergeError::DatabaseStructureMismatch(
            ".uasset TotalHeaderSize does not equal its exact byte length".to_owned(),
        ));
    }

    let (package_path, folder_end) =
        parse_unreal_fstring(uasset, FOLDER_NAME_OFFSET, "package path")?;
    if package_path.is_empty() || !package_path.starts_with("/Game/") {
        return Err(MergeError::DatabaseStructureMismatch(
            ".uasset package path is not a /Game/... path".to_owned(),
        ));
    }
    let field_offset = |relative: usize| {
        folder_end.checked_add(relative).ok_or_else(|| {
            MergeError::DatabaseStructureMismatch(".uasset summary offset overflow".to_owned())
        })
    };
    if read_u32_le_at(uasset, field_offset(0)?) != Some(PACKAGE_FLAGS) {
        return Err(MergeError::DatabaseStructureMismatch(
            ".uasset package flags do not match the supported OT0 BinaryAsset layout".to_owned(),
        ));
    }

    let name_count = checked_u32_usize(
        read_u32_le_at(uasset, field_offset(4)?),
        ".uasset name count",
        MAX_NAME_COUNT,
    )?;
    let name_offset = checked_u32_usize(
        read_u32_le_at(uasset, field_offset(8)?),
        ".uasset name-table offset",
        uasset.len(),
    )?;
    let export_count = read_u32_le_at(uasset, field_offset(0x1C)?).ok_or_else(|| {
        MergeError::DatabaseStructureMismatch(".uasset export count is out of range".to_owned())
    })?;
    if export_count != 1 {
        return Err(MergeError::DatabaseStructureMismatch(format!(
            ".uasset has {export_count} exports; detailed database merging requires exactly one"
        )));
    }
    let export_offset = checked_u32_usize(
        read_u32_le_at(uasset, field_offset(0x20)?),
        ".uasset export-table offset",
        uasset.len(),
    )?;
    let import_count = checked_u32_usize(
        read_u32_le_at(uasset, field_offset(0x24)?),
        ".uasset import count",
        MAX_IMPORT_COUNT,
    )?;
    let import_offset = checked_u32_usize(
        read_u32_le_at(uasset, field_offset(0x28)?),
        ".uasset import-table offset",
        uasset.len(),
    )?;
    let bulk_data_start_offset = field_offset(0x8C)?;
    read_u64_le_at(uasset, bulk_data_start_offset).ok_or_else(|| {
        MergeError::DatabaseStructureMismatch(
            ".uasset BulkDataStartOffset is outside the package summary".to_owned(),
        )
    })?;

    let names = parse_uasset_names(uasset, name_offset, name_count)?;
    let import_bytes = import_count.checked_mul(IMPORT_ENTRY_SIZE).ok_or_else(|| {
        MergeError::DatabaseStructureMismatch(".uasset import-table size overflow".to_owned())
    })?;
    let import_end = import_offset.checked_add(import_bytes).ok_or_else(|| {
        MergeError::DatabaseStructureMismatch(".uasset import-table range overflow".to_owned())
    })?;
    if import_end > uasset.len() {
        return Err(MergeError::DatabaseStructureMismatch(
            ".uasset import table extends beyond the header".to_owned(),
        ));
    }

    let export_end = export_offset.checked_add(0x2C).ok_or_else(|| {
        MergeError::DatabaseStructureMismatch(".uasset export range overflow".to_owned())
    })?;
    if export_end > uasset.len() {
        return Err(MergeError::DatabaseStructureMismatch(
            ".uasset export table extends beyond the header".to_owned(),
        ));
    }
    let class_index = read_i32_le_at(uasset, export_offset).ok_or_else(|| {
        MergeError::DatabaseStructureMismatch(
            ".uasset export class index is out of range".to_owned(),
        )
    })?;
    let import_index = class_index
        .checked_neg()
        .and_then(|value| value.checked_sub(1))
        .and_then(|value| usize::try_from(value).ok())
        .filter(|index| *index < import_count)
        .ok_or_else(|| {
            MergeError::DatabaseStructureMismatch(
                ".uasset export class does not resolve to an import".to_owned(),
            )
        })?;
    let class_import_offset = import_offset
        .checked_add(import_index.checked_mul(IMPORT_ENTRY_SIZE).ok_or_else(|| {
            MergeError::DatabaseStructureMismatch(".uasset class import offset overflow".to_owned())
        })?)
        .ok_or_else(|| {
            MergeError::DatabaseStructureMismatch(".uasset class import offset overflow".to_owned())
        })?;
    let class_name = uasset_fname(
        uasset,
        class_import_offset + 20,
        &names,
        "export class name",
    )?;
    if !class_name.eq_ignore_ascii_case("BinaryAsset") {
        return Err(MergeError::DatabaseStructureMismatch(format!(
            ".uasset export class is {class_name}, not BinaryAsset"
        )));
    }
    let object_name = uasset_fname(uasset, export_offset + 0x10, &names, "export object name")?;

    let expected_object_name = package_path.rsplit('/').next().unwrap_or_default();
    if !object_name.eq_ignore_ascii_case(expected_object_name) {
        return Err(MergeError::DatabaseStructureMismatch(format!(
            ".uasset export object {object_name} does not match package {expected_object_name}"
        )));
    }
    if let Some(expected) = expected_asset_path {
        let internal = package_path.strip_prefix("/Game/").unwrap_or(&package_path);
        let expected = sort_key(expected);
        let expected = expected
            .strip_prefix("octopath_traveler0/content/")
            .unwrap_or(&expected);
        if sort_key(internal) != expected {
            return Err(MergeError::DatabaseStructureMismatch(format!(
                ".uasset package path {package_path} does not match Pak path {expected}"
            )));
        }
    }

    let serial_size_offset = export_offset + 0x1C;
    let serial_offset_offset = export_offset + 0x24;
    let expected_serial_size = uexp_size
        .checked_sub(binary_asset::PACKAGE_TAG_SIZE)
        .ok_or_else(|| {
            MergeError::DatabaseStructureMismatch(
                ".uexp is shorter than its package tag".to_owned(),
            )
        })?;
    let expected_serial_size = u64::try_from(expected_serial_size).map_err(|_| {
        MergeError::DatabaseStructureMismatch(".uexp size does not fit in u64".to_owned())
    })?;
    if read_u64_le_at(uasset, serial_size_offset) != Some(expected_serial_size) {
        return Err(MergeError::DatabaseStructureMismatch(format!(
            ".uasset export SerialSize does not match the paired .uexp ({expected_serial_size} bytes)"
        )));
    }
    if read_u64_le_at(uasset, serial_offset_offset) != u64::try_from(uasset.len()).ok() {
        return Err(MergeError::DatabaseStructureMismatch(format!(
            ".uasset export SerialOffset at {serial_offset_offset:#x} does not equal the .uasset length"
        )));
    }

    Ok(UassetShellDescriptor {
        package_path,
        object_name,
        serial_size_offset,
        _bulk_data_start_offset: bulk_data_start_offset,
    })
}

fn parse_unreal_fstring(bytes: &[u8], offset: usize, field: &str) -> Result<(String, usize)> {
    let length = read_i32_le_at(bytes, offset).ok_or_else(|| {
        MergeError::DatabaseStructureMismatch(format!("{field} FString length is out of range"))
    })?;
    if length == 0 {
        return Err(MergeError::DatabaseStructureMismatch(format!(
            "{field} FString is empty"
        )));
    }
    let body_offset = offset.checked_add(4).ok_or_else(|| {
        MergeError::DatabaseStructureMismatch(format!("{field} FString offset overflow"))
    })?;
    if length > 0 {
        let byte_len = usize::try_from(length).map_err(|_| {
            MergeError::DatabaseStructureMismatch(format!("{field} FString is too large"))
        })?;
        let end = body_offset.checked_add(byte_len).ok_or_else(|| {
            MergeError::DatabaseStructureMismatch(format!("{field} FString range overflow"))
        })?;
        let body = bytes.get(body_offset..end).ok_or_else(|| {
            MergeError::DatabaseStructureMismatch(format!("{field} FString is truncated"))
        })?;
        if body.last() != Some(&0) {
            return Err(MergeError::DatabaseStructureMismatch(format!(
                "{field} FString is not NUL-terminated"
            )));
        }
        let value = std::str::from_utf8(&body[..body.len() - 1]).map_err(|_| {
            MergeError::DatabaseStructureMismatch(format!("{field} FString is not valid UTF-8"))
        })?;
        Ok((value.to_owned(), end))
    } else {
        let units = length
            .checked_neg()
            .and_then(|value| usize::try_from(value).ok())
            .ok_or_else(|| {
                MergeError::DatabaseStructureMismatch(format!(
                    "{field} UTF-16 FString is too large"
                ))
            })?;
        let byte_len = units.checked_mul(2).ok_or_else(|| {
            MergeError::DatabaseStructureMismatch(format!("{field} UTF-16 FString size overflow"))
        })?;
        let end = body_offset.checked_add(byte_len).ok_or_else(|| {
            MergeError::DatabaseStructureMismatch(format!("{field} UTF-16 FString range overflow"))
        })?;
        let body = bytes.get(body_offset..end).ok_or_else(|| {
            MergeError::DatabaseStructureMismatch(format!("{field} UTF-16 FString is truncated"))
        })?;
        let mut decoded_units = body
            .chunks_exact(2)
            .map(|unit| u16::from_le_bytes([unit[0], unit[1]]))
            .collect::<Vec<_>>();
        if decoded_units.last() != Some(&0) {
            return Err(MergeError::DatabaseStructureMismatch(format!(
                "{field} UTF-16 FString is not NUL-terminated"
            )));
        }
        decoded_units.pop();
        let value = char::decode_utf16(decoded_units)
            .collect::<std::result::Result<String, _>>()
            .map_err(|_| {
                MergeError::DatabaseStructureMismatch(format!(
                    "{field} FString contains invalid UTF-16"
                ))
            })?;
        Ok((value, end))
    }
}

fn parse_uasset_names(bytes: &[u8], offset: usize, count: usize) -> Result<Vec<String>> {
    let mut names = Vec::new();
    names.try_reserve_exact(count).map_err(|_| {
        MergeError::DatabaseStructureMismatch(".uasset name-table allocation failed".to_owned())
    })?;
    let mut cursor = offset;
    for index in 0..count {
        let (name, end) = parse_unreal_fstring(bytes, cursor, &format!("name-table item {index}"))?;
        cursor = end.checked_add(4).ok_or_else(|| {
            MergeError::DatabaseStructureMismatch(".uasset name-table range overflow".to_owned())
        })?;
        if cursor > bytes.len() {
            return Err(MergeError::DatabaseStructureMismatch(
                ".uasset name-table hash is truncated".to_owned(),
            ));
        }
        names.push(name);
    }
    Ok(names)
}

fn uasset_fname(bytes: &[u8], offset: usize, names: &[String], field: &str) -> Result<String> {
    let name_index = checked_u32_usize(read_u32_le_at(bytes, offset), field, names.len())?;
    if read_u32_le_at(bytes, offset + 4) != Some(0) {
        return Err(MergeError::DatabaseStructureMismatch(format!(
            "{field} has a nonzero FName instance number"
        )));
    }
    names.get(name_index).cloned().ok_or_else(|| {
        MergeError::DatabaseStructureMismatch(format!("{field} index is outside the name table"))
    })
}

fn checked_u32_usize(value: Option<u32>, field: &str, upper_bound: usize) -> Result<usize> {
    let value = value
        .and_then(|value| usize::try_from(value).ok())
        .ok_or_else(|| MergeError::DatabaseStructureMismatch(format!("{field} is out of range")))?;
    if value > upper_bound {
        return Err(MergeError::DatabaseStructureMismatch(format!(
            "{field} exceeds the supported bound {upper_bound}"
        )));
    }
    Ok(value)
}

fn read_u32_le_at(bytes: &[u8], offset: usize) -> Option<u32> {
    bytes
        .get(offset..offset.checked_add(4)?)?
        .try_into()
        .ok()
        .map(u32::from_le_bytes)
}

fn read_i32_le_at(bytes: &[u8], offset: usize) -> Option<i32> {
    read_u32_le_at(bytes, offset).map(|value| i32::from_le_bytes(value.to_le_bytes()))
}

fn read_u64_le_at(bytes: &[u8], offset: usize) -> Option<u64> {
    bytes
        .get(offset..offset.checked_add(8)?)?
        .try_into()
        .ok()
        .map(u64::from_le_bytes)
}

fn make_atomic_variant(
    opened: &[OpenedPak],
    provider: &ParsedDbProvider,
    row: NodeRef<'_>,
    row_id: RowId,
    unit: &AtomicGroup,
    raw_sha256: String,
    semantic_sha256: String,
) -> Result<Variant> {
    #[cfg(test)]
    TEST_ATOMIC_VARIANT_BUILD_CALLS.with(|calls| calls.set(calls.get() + 1));

    let input = &opened[provider.input_index].descriptor;
    let marker = unit
        .fields
        .iter()
        .filter_map(|field| binary_asset::atomic_group_value(row, unit, field).ok())
        .map(|node| format!("{}:0x{:02X}", node.node.type_name(), node.node.marker))
        .collect::<Vec<_>>()
        .join(", ");
    let preview = unit
        .fields
        .iter()
        .filter_map(|field| {
            binary_asset::atomic_group_value(row, unit, field)
                .ok()
                .map(|node| {
                    let label = unit
                        .array_index
                        .map(|index| format!("{field}[{index}]"))
                        .unwrap_or_else(|| field.clone());
                    format!("{label}={}", preview_node(node.node))
                })
        })
        .collect::<Vec<_>>()
        .join("; ");
    let id = stable_id(
        "variant",
        [
            provider.group.base_path.as_str(),
            &row_id.to_string(),
            unit.id.as_str(),
            input.id.as_str(),
            raw_sha256.as_str(),
        ],
    );
    Ok(Variant {
        id,
        label: input.display_name.clone(),
        input_id: input.id.clone(),
        raw_sha256: raw_sha256.clone(),
        semantic_sha256,
        preview,
        marker,
        provenance: Provenance {
            input_id: input.id.clone(),
            input_path: input.path.clone(),
            entry_path: provider
                .group
                .components
                .get(&PackageComponent::Uexp)
                .cloned(),
            raw_sha256,
        },
    })
}

/// Builds GUI/CLI choices only after a semantic conflict or a sampled storage
/// drift has been confirmed. Provider order matches the legacy eager path:
/// the base Pak first, followed by every other provider in input order.
fn make_atomic_variant_sets(
    opened: &[OpenedPak],
    parsed: &[ParsedDbProvider],
    carrier_local: usize,
    row_id: RowId,
    units: &[&AtomicGroup],
    cancelled: Option<&CancellationToken>,
) -> Result<Vec<Vec<Variant>>> {
    check_cancel(cancelled)?;
    let mut variants_by_unit = Vec::new();
    variants_by_unit
        .try_reserve_exact(units.len())
        .map_err(|_| MergeError::AllocationFailed("field choices"))?;
    for _ in units {
        let mut variants = Vec::new();
        variants
            .try_reserve_exact(parsed.len())
            .map_err(|_| MergeError::AllocationFailed("field choices"))?;
        variants_by_unit.push(variants);
    }

    let mut append = |provider: &ParsedDbProvider| -> Result<()> {
        check_cancel(cancelled)?;
        let Some(row) = indexed_row(&provider.asset, row_id, cancelled)? else {
            return Ok(());
        };
        #[cfg(test)]
        TEST_ATOMIC_VARIANT_ROW_PARSE_CALLS.with(|calls| calls.set(calls.get() + 1));
        for (unit, variants) in units.iter().zip(&mut variants_by_unit) {
            let hashes = binary_asset::atomic_group_hashes(row.node_ref(), unit)?;
            variants.push(make_atomic_variant(
                opened,
                provider,
                row.node_ref(),
                row_id,
                unit,
                hashes.raw_sha256,
                hashes.semantic_sha256,
            )?);
        }
        Ok(())
    };

    append(&parsed[carrier_local])?;
    for (local, provider) in parsed.iter().enumerate() {
        if local != carrier_local {
            append(provider)?;
        }
    }
    Ok(variants_by_unit)
}

/// Materializes whole-row choices only after a structural mismatch has made
/// them necessary. Provider order deliberately matches the legacy eager path:
/// the base Pak first, followed by every other provider in input order.
fn make_whole_row_variants(
    opened: &[OpenedPak],
    parsed: &[ParsedDbProvider],
    carrier_local: usize,
    asset_path: &str,
    row_id: RowId,
    cancelled: Option<&CancellationToken>,
) -> Result<Vec<Variant>> {
    #[cfg(test)]
    TEST_WHOLE_ROW_VARIANT_BUILD_CALLS.with(|calls| calls.set(calls.get() + 1));

    check_cancel(cancelled)?;
    let mut variants = Vec::new();
    variants
        .try_reserve_exact(parsed.len())
        .map_err(|_| MergeError::AllocationFailed("whole-row choices"))?;

    let carrier = &parsed[carrier_local];
    let carrier_row = indexed_row(&carrier.asset, row_id, cancelled)?
        .ok_or_else(|| MergeError::InputChanged(PathBuf::from(asset_path)))?;
    variants.push(make_row_variant(
        opened,
        carrier,
        asset_path,
        row_id,
        "__whole_row__",
        carrier_row.node_ref(),
    )?);

    for (local, provider) in parsed.iter().enumerate() {
        check_cancel(cancelled)?;
        if local == carrier_local {
            continue;
        }
        let Some(row) = indexed_row(&provider.asset, row_id, cancelled)? else {
            continue;
        };
        variants.push(make_row_variant(
            opened,
            provider,
            asset_path,
            row_id,
            "__whole_row__",
            row.node_ref(),
        )?);
    }
    Ok(variants)
}

fn make_row_variant(
    opened: &[OpenedPak],
    provider: &ParsedDbProvider,
    asset_path: &str,
    row_id: RowId,
    group_id: &str,
    row: NodeRef<'_>,
) -> Result<Variant> {
    let input = &opened[provider.input_index].descriptor;
    let raw_sha256 = row.raw_sha256();
    let semantic_sha256 = row.semantic_sha256();
    Ok(Variant {
        id: stable_id(
            "variant",
            [
                asset_path,
                &row_id.to_string(),
                group_id,
                &input.id,
                &raw_sha256,
            ],
        ),
        label: input.display_name.clone(),
        input_id: input.id.clone(),
        raw_sha256: raw_sha256.clone(),
        semantic_sha256,
        preview: format!("row {row_id}, {} fields", row.node.map_fields()?.len()),
        marker: format!("row-map:0x{:02X}", row.node.marker),
        provenance: Provenance {
            input_id: input.id.clone(),
            input_path: input.path.clone(),
            entry_path: provider
                .group
                .components
                .get(&PackageComponent::Uexp)
                .cloned(),
            raw_sha256,
        },
    })
}

#[allow(clippy::too_many_arguments)]
fn make_conflict(
    kind: ConflictKind,
    asset_path: &str,
    row_id: Option<RowId>,
    group_id: Option<&str>,
    message: &str,
    mut variants: Vec<Variant>,
    blocking: bool,
) -> Conflict {
    variants.sort_by(|left, right| {
        left.input_id
            .cmp(&right.input_id)
            .then_with(|| left.id.cmp(&right.id))
    });
    let row_text = row_id.map(|id| id.to_string()).unwrap_or_default();
    let id = stable_id(
        "conflict",
        std::iter::once(asset_path)
            .chain(std::iter::once(row_text.as_str()))
            .chain(std::iter::once(group_id.unwrap_or_default()))
            .chain(variants.iter().map(|variant| variant.id.as_str())),
    );
    Conflict {
        id,
        kind,
        asset_path: asset_path.to_owned(),
        row_id: row_id.map(|id| id.to_string()),
        group_id: group_id.map(str::to_owned),
        message: message.to_owned(),
        variants,
        blocking,
    }
}

fn analyze_opaque_group(
    opened: &[OpenedPak],
    providers: &[GroupProvider],
    multithreaded: bool,
    cancelled: Option<&CancellationToken>,
) -> Result<(AssetPlan, Conflict)> {
    analyze_package_selection_group(
        opened,
        providers,
        ConflictKind::OpaquePackage,
        "This file group cannot be compared field by field. Choose one Pak for the whole group.",
        multithreaded,
        cancelled,
    )
}

fn analyze_package_selection_group(
    opened: &[OpenedPak],
    providers: &[GroupProvider],
    kind: ConflictKind,
    message: &str,
    multithreaded: bool,
    cancelled: Option<&CancellationToken>,
) -> Result<(AssetPlan, Conflict)> {
    let base_path = providers[0].group.base_path.clone();
    let mut variants = Vec::new();
    for provider in providers {
        let input = &opened[provider.input_index].descriptor;
        let digest = group_digest(
            &opened[provider.input_index],
            &provider.group,
            multithreaded,
            cancelled,
        )?;
        variants.push(Variant {
            id: stable_id(
                "variant",
                [base_path.as_str(), input.id.as_str(), digest.as_str()],
            ),
            label: input.display_name.clone(),
            input_id: input.id.clone(),
            raw_sha256: digest.clone(),
            semantic_sha256: digest.clone(),
            preview: format!("{} related files", provider.group.components.len()),
            marker: "whole-file-group".to_owned(),
            provenance: Provenance {
                input_id: input.id.clone(),
                input_path: input.path.clone(),
                entry_path: Some(base_path.clone()),
                raw_sha256: digest,
            },
        });
    }
    let conflict = make_conflict(kind, &base_path, None, None, message, variants, true);
    let asset = package_asset_plan(
        providers,
        opened,
        AssetActionKind::SelectOpaque,
        vec![conflict.id.clone()],
        Vec::new(),
    );
    Ok((asset, conflict))
}

fn make_loose_conflict(
    opened: &[OpenedPak],
    providers: &[LooseProvider],
    multithreaded: bool,
    cancelled: Option<&CancellationToken>,
) -> Result<Conflict> {
    let path = providers[0].path.clone();
    let mut variants = Vec::new();
    for provider in providers {
        let input = &opened[provider.input_index];
        let entry = inventory_entry(input, &provider.path)?;
        let logical_sha256 =
            canonical_logical_sha256(input, &provider.path, multithreaded, cancelled)?;
        variants.push(Variant {
            id: stable_id(
                "variant",
                [
                    path.as_str(),
                    input.descriptor.id.as_str(),
                    logical_sha256.as_str(),
                ],
            ),
            label: input.descriptor.display_name.clone(),
            input_id: input.descriptor.id.clone(),
            raw_sha256: logical_sha256.clone(),
            semantic_sha256: logical_sha256.clone(),
            preview: format!("{} bytes", entry.size),
            marker: "whole-file".to_owned(),
            provenance: Provenance {
                input_id: input.descriptor.id.clone(),
                input_path: input.descriptor.path.clone(),
                entry_path: Some(path.clone()),
                raw_sha256: logical_sha256,
            },
        });
    }
    Ok(make_conflict(
        ConflictKind::OpaquePackage,
        &path,
        None,
        None,
        "The same file has different contents. Choose which Pak to use.",
        variants,
        true,
    ))
}

fn package_asset_plan(
    providers: &[GroupProvider],
    opened: &[OpenedPak],
    action: AssetActionKind,
    conflict_ids: Vec<String>,
    warnings: Vec<String>,
) -> AssetPlan {
    let mut entries = BTreeSet::new();
    let mut donors = Vec::new();
    for provider in providers {
        entries.extend(provider.group.components.values().cloned());
        donors.push(opened[provider.input_index].descriptor.id.clone());
    }
    donors.sort();
    donors.dedup();
    AssetPlan {
        virtual_path: providers[0].group.base_path.clone(),
        package_entries: entries.into_iter().collect(),
        action,
        donor_input_ids: donors,
        conflict_ids,
        warnings,
        encoding_drift_count: 0,
    }
}

fn loose_asset_plan(
    providers: &[LooseProvider],
    opened: &[OpenedPak],
    action: AssetActionKind,
    conflict_ids: Vec<String>,
) -> AssetPlan {
    let mut donors: Vec<_> = providers
        .iter()
        .map(|provider| opened[provider.input_index].descriptor.id.clone())
        .collect();
    donors.sort();
    donors.dedup();
    AssetPlan {
        virtual_path: providers[0].path.clone(),
        package_entries: vec![providers[0].path.clone()],
        action,
        donor_input_ids: donors,
        conflict_ids,
        warnings: Vec::new(),
        encoding_drift_count: 0,
    }
}

fn providers_semantically_identical(
    opened: &[OpenedPak],
    providers: &[GroupProvider],
    multithreaded: bool,
    cancelled: Option<&CancellationToken>,
) -> Result<bool> {
    let Some(first) = providers.first() else {
        return Ok(true);
    };
    let first_digest = group_digest(
        &opened[first.input_index],
        &first.group,
        multithreaded,
        cancelled,
    )?;
    for provider in &providers[1..] {
        if group_digest(
            &opened[provider.input_index],
            &provider.group,
            multithreaded,
            cancelled,
        )? != first_digest
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn loose_identical(
    opened: &[OpenedPak],
    providers: &[LooseProvider],
    multithreaded: bool,
    cancelled: Option<&CancellationToken>,
) -> Result<bool> {
    let Some(first) = providers.first() else {
        return Ok(true);
    };
    let first_hash = canonical_logical_sha256(
        &opened[first.input_index],
        &first.path,
        multithreaded,
        cancelled,
    )?;
    for provider in &providers[1..] {
        if canonical_logical_sha256(
            &opened[provider.input_index],
            &provider.path,
            multithreaded,
            cancelled,
        )? != first_hash
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn group_digest(
    opened: &OpenedPak,
    group: &pak::PackageGroup,
    multithreaded: bool,
    cancelled: Option<&CancellationToken>,
) -> Result<String> {
    let mut digest = Sha256::new();
    digest.update(b"PAK-MERGER-PACKAGE-GROUP-V1");
    for (component, path) in &group.components {
        let logical_sha256 = canonical_logical_sha256(opened, path, multithreaded, cancelled)?;
        digest.update([*component as u8]);
        update_framed(&mut digest, path.as_bytes());
        update_framed(&mut digest, logical_sha256.as_bytes());
    }
    Ok(hex::encode(digest.finalize()))
}

fn inventory_entry<'a>(opened: &'a OpenedPak, path: &str) -> Result<&'a pak::PakEntryInventory> {
    let index = opened
        .entry_index
        .get(&sort_key(path))
        .ok_or_else(|| MergeError::InputChanged(PathBuf::from(path)))?;
    opened
        .archive
        .inventory()
        .entries
        .get(*index)
        .ok_or_else(|| MergeError::InputChanged(PathBuf::from(path)))
}

fn archive_entry_path<'a>(opened: &'a OpenedPak, canonical_path: &str) -> Result<&'a str> {
    Ok(&inventory_entry(opened, canonical_path)?.path)
}

fn canonical_logical_sha256(
    opened: &OpenedPak,
    canonical_path: &str,
    multithreaded: bool,
    cancelled: Option<&CancellationToken>,
) -> Result<String> {
    let archive_path = archive_entry_path(opened, canonical_path)?;
    let no_cancellation = CancellationToken::new();
    let cancellation = cancelled.unwrap_or(&no_cancellation);
    Ok(opened.archive.logical_sha256_with_threads_and_cancel(
        archive_path,
        multithreaded,
        cancellation,
    )?)
}

fn map_canonical_entry(
    opened: &OpenedPak,
    canonical_path: &str,
    multithreaded: bool,
    cancelled: Option<&CancellationToken>,
) -> Result<pak::PakEntryData> {
    let archive_path = archive_entry_path(opened, canonical_path)?;
    let no_cancellation = CancellationToken::new();
    let cancellation = cancelled.unwrap_or(&no_cancellation);
    Ok(opened.archive.map_entry_with_threads_and_cancel(
        archive_path,
        usize::MAX as u64,
        multithreaded,
        cancellation,
    )?)
}

fn missing_package_component(group: &pak::PackageGroup, component: PackageComponent) -> MergeError {
    MergeError::MissingPackageComponent {
        package: group.base_path.clone(),
        component: component.extension(),
    }
}

/// Builds the compact row indexes retained by an analysis session. Uncompressed
/// entries remain zero-copy views of the source Pak; compressed entries reuse
/// `PakArchive`'s one-time decoded cache (large entries are temporary-file
/// mappings). No provider-wide MessagePack tree or copied entry body is kept;
/// individual rows are parsed only when compared or merged.
fn load_cached_database(
    opened: &[OpenedPak],
    providers: &[GroupProvider],
    multithreaded: bool,
    cancelled: Option<&CancellationToken>,
    mut indexing_progress: Option<&mut DatabaseIndexProgressCallback<'_>>,
) -> Result<Vec<ParsedDbProvider>> {
    let mut parsed = Vec::new();
    parsed
        .try_reserve_exact(providers.len())
        .map_err(|_| MergeError::AllocationFailed("database input metadata"))?;
    let total_index_bytes = providers.iter().try_fold(0_u64, |total, provider| {
        let uexp_entry = provider
            .group
            .components
            .get(&PackageComponent::Uexp)
            .ok_or_else(|| missing_package_component(&provider.group, PackageComponent::Uexp))?;
        total
            .checked_add(inventory_entry(&opened[provider.input_index], uexp_entry)?.size)
            .ok_or(MergeError::SizeOverflow("database index"))
    })?;
    let mut completed_index_bytes = 0_u64;
    if let Some(report) = indexing_progress.as_mut() {
        let first_item = providers
            .first()
            .map(|provider| provider.group.base_path.as_str())
            .unwrap_or("database");
        report(0, total_index_bytes, first_item);
    }
    for provider in providers {
        check_cancel(cancelled)?;
        let uasset_entry = provider
            .group
            .components
            .get(&PackageComponent::Uasset)
            .ok_or_else(|| missing_package_component(&provider.group, PackageComponent::Uasset))?;
        let uexp_entry = provider
            .group
            .components
            .get(&PackageComponent::Uexp)
            .ok_or_else(|| missing_package_component(&provider.group, PackageComponent::Uexp))?;
        let uexp = map_canonical_entry(
            &opened[provider.input_index],
            uexp_entry,
            multithreaded,
            cancelled,
        )?;
        let uasset_mapping = map_canonical_entry(
            &opened[provider.input_index],
            uasset_entry,
            multithreaded,
            cancelled,
        )?;
        // The compact index takes ownership of the immutable Pak/cache mapping.
        // Its one validation parse is dropped before the next provider is
        // loaded, so neither payload copies nor provider-wide ASTs accumulate.
        let uexp_size = uexp.as_ref().len();
        #[cfg(test)]
        record_test_database_index_build(&provider.group.base_path);
        let asset = if let Some(report) = indexing_progress.as_mut() {
            let provider_start = completed_index_bytes;
            let current_item = provider.group.base_path.as_str();
            let mut provider_progress = |completed: usize, _total: usize| {
                report(
                    provider_start.saturating_add(completed as u64),
                    total_index_bytes,
                    current_item,
                );
            };
            parse_indexed_binary_asset_with_progress(uexp, cancelled, &mut provider_progress)?
        } else {
            parse_indexed_binary_asset(uexp, cancelled)?
        };
        completed_index_bytes = completed_index_bytes.saturating_add(uexp_size as u64);
        if let Some(report) = indexing_progress.as_mut() {
            report(
                completed_index_bytes,
                total_index_bytes,
                provider.group.base_path.as_str(),
            );
        }
        parsed.push(ParsedDbProvider {
            input_index: provider.input_index,
            group: provider.group.clone(),
            uasset: uasset_mapping,
            uexp_size,
            asset,
        });
    }
    Ok(parsed)
}

fn database_provider_bytes(opened: &[OpenedPak], providers: &[GroupProvider]) -> Result<u64> {
    providers.iter().try_fold(0_u64, |total, provider| {
        provider
            .group
            .components
            .values()
            .try_fold(total, |subtotal, path| {
                subtotal
                    .checked_add(inventory_entry(&opened[provider.input_index], path)?.size)
                    .ok_or(MergeError::SizeOverflow("database cache"))
            })
    })
}

fn preview_node(node: &binary_asset::MsgpackNode) -> String {
    let text = match &node.kind {
        MsgpackKind::Nil => "null".to_owned(),
        MsgpackKind::Boolean(value) => value.to_string(),
        MsgpackKind::Integer(IntegerValue::Signed(value)) => value.to_string(),
        MsgpackKind::Integer(IntegerValue::Unsigned(value)) => value.to_string(),
        MsgpackKind::Float(value) => value.to_string(),
        MsgpackKind::String(value) => format!("\"{value}\""),
        MsgpackKind::Binary(value) => format!("binary[{}]", value.len()),
        MsgpackKind::Array(value) => format!("array[{}]", value.len()),
        MsgpackKind::Map(value) => format!("map[{}]", value.len()),
        MsgpackKind::Extension { type_tag, data } => {
            format!("extension(type={type_tag}, {} bytes)", data.len())
        }
    };
    if text.chars().count() > 160 {
        format!("{}…", text.chars().take(159).collect::<String>())
    } else {
        text
    }
}

struct BuiltDatabase {
    uasset_entry: String,
    uexp_entry: String,
    uasset: Vec<u8>,
    raw_preserved_nodes: u64,
    raw_replaced_nodes: u64,
    raw_audit: PendingRawPreservationAudit,
}

struct PendingRawPreservationAudit {
    asset_path: String,
    pak_entry_path: String,
    expected_entry_size: u64,
    audit: RawAuditAccumulator,
}

struct RawAuditAccumulator {
    ledger: Sha256,
    verified_rows: u64,
    verified_units: u64,
    preserved_nodes: u64,
    replaced_nodes: u64,
}

fn write_database_bytes(
    writer: &mut impl Write,
    bytes: &[u8],
    cancelled: Option<&CancellationToken>,
) -> Result<()> {
    for chunk in bytes.chunks(8 * 1024 * 1024) {
        check_cancel(cancelled)?;
        writer.write_all(chunk)?;
    }
    Ok(())
}

fn load_selected_indexed_rows<'a>(
    parsed: &'a [ParsedDbProvider],
    row_id: RowId,
    selected: &BTreeSet<usize>,
    cancelled: Option<&CancellationToken>,
) -> Result<Vec<Option<IndexedRow<'a>>>> {
    let mut rows = Vec::new();
    rows.try_reserve_exact(parsed.len())
        .map_err(|_| MergeError::AllocationFailed("current database row metadata"))?;
    for (local, provider) in parsed.iter().enumerate() {
        rows.push(if selected.contains(&local) {
            indexed_row(&provider.asset, row_id, cancelled)?
        } else {
            None
        });
    }
    Ok(rows)
}

fn should_report_database_progress(completed_rows: usize, total_rows: usize) -> bool {
    completed_rows != 0
        && (completed_rows == total_rows
            || completed_rows.is_multiple_of(DATABASE_PROGRESS_ROW_INTERVAL))
}

fn report_database_build_progress(
    progress: &mut dyn FnMut(MergeProgress),
    asset_path: &str,
    completed_rows: usize,
    total_rows: usize,
    row_id: Option<RowId>,
) {
    let current_item = match row_id {
        Some(row_id) => format!("{asset_path} · m_id {row_id}"),
        None => asset_path.to_owned(),
    };
    progress(MergeProgress {
        stage: MergeProgressStage::BuildingDatabase,
        completed: completed_rows as u64,
        total: total_rows as u64,
        current_item: Some(current_item),
    });
}

#[allow(clippy::too_many_arguments)]
fn build_merged_database(
    plan: &MergePlan,
    resolutions: &ResolutionSet,
    opened: &[OpenedPak],
    parsed: &[ParsedDbProvider],
    global_carrier_index: usize,
    cancelled: Option<&CancellationToken>,
    uexp_path: &Path,
    progress: &mut dyn FnMut(MergeProgress),
) -> Result<BuiltDatabase> {
    let carrier_local = parsed
        .iter()
        .position(|provider| provider.input_index == global_carrier_index)
        .unwrap_or(0);
    let carrier_provider = &parsed[carrier_local];
    let carrier_asset = &carrier_provider.asset;
    let asset_path = &carrier_provider.group.base_path;
    let mut unit_planner = profiles::AtomicUnitPlanner::new(
        profiles::default_registry(),
        pinned_profile_id(plan),
        asset_path,
    );
    let conflict_index = build_asset_conflict_index(plan, asset_path);
    let mut raw_preserved = 0_u64;
    let mut raw_replaced = 0_u64;

    let mut appended_ids = BTreeSet::new();
    for provider in parsed {
        for &row_id in provider.asset.row_ids() {
            if !carrier_asset.contains_row(row_id) {
                appended_ids.insert(row_id);
            }
        }
    }
    let output_row_count = carrier_asset
        .row_count()
        .checked_add(appended_ids.len())
        .ok_or(MergeError::DatabaseTooLarge)?;
    let first_row_id = carrier_asset
        .row_ids()
        .first()
        .copied()
        .or_else(|| appended_ids.first().copied());
    report_database_build_progress(progress, asset_path, 0, output_row_count, first_row_id);
    let list_range = carrier_asset.data_list_range();
    let list_header = carrier_asset.data_list_header_for_len(output_row_count)?;
    let mut audit = RawAuditAccumulator {
        ledger: Sha256::new(),
        verified_rows: 0,
        verified_units: 0,
        preserved_nodes: 0,
        replaced_nodes: 0,
    };
    audit
        .ledger
        .update(b"PAK-MERGER-RAW-PRESERVATION-ASSET-LEDGER-V1");
    update_framed(&mut audit.ledger, sort_key(asset_path).as_bytes());

    let uexp_entry = carrier_provider
        .group
        .components
        .get(&PackageComponent::Uexp)
        .expect("database carrier has uexp")
        .clone();
    update_framed(&mut audit.ledger, sort_key(&uexp_entry).as_bytes());

    let output_file = File::create(uexp_path)?;
    let mut writer = BufWriter::with_capacity(4 * 1024 * 1024, output_file);
    // The payload length is patched after all rows and carrier suffix bytes
    // have been streamed. No rebuilt payload or list of row bodies is kept in
    // memory.
    write_database_bytes(&mut writer, &carrier_asset.prefix, cancelled)?;
    write_database_bytes(
        &mut writer,
        &carrier_asset.payload()[..list_range.start],
        cancelled,
    )?;
    write_database_bytes(&mut writer, &list_header, cancelled)?;

    for row_index in 0..carrier_asset.row_count() {
        check_cancel(cancelled)?;
        let row_id = carrier_asset.row_ids()[row_index];
        enum RowChoice {
            Whole(usize),
            Atomic(Vec<AtomicDonorSelection>),
        }
        let carrier_row_for_plan = indexed_row(carrier_asset, row_id, cancelled)?
            .expect("validated row position remains available");
        let choice = if let Some(conflict) =
            indexed_conflict(&conflict_index, row_id, "__whole_row__")
        {
            let input_id = selected_input_id(conflict, resolutions)?;
            let donor_local = parsed
                .iter()
                .position(|provider| opened[provider.input_index].descriptor.id == input_id)
                .ok_or_else(|| {
                    MergeError::InvalidResolution(format!(
                        "selected whole-row input {input_id} is unavailable"
                    ))
                })?;
            raw_replaced += 1;
            RowChoice::Whole(donor_local)
        } else {
            let layout = unit_planner.layout_for_row(&carrier_row_for_plan.node)?;
            let mut selections = Vec::new();
            let mut selected_whole_fields = BTreeSet::new();
            let mut selected_indexed_fields: BTreeMap<String, (usize, BTreeSet<usize>)> =
                BTreeMap::new();
            for unit in layout.units.iter() {
                if let Some(conflict) = indexed_conflict(&conflict_index, row_id, &unit.id) {
                    if !conflict.blocking && conflict.kind == ConflictKind::EncodingDrift {
                        continue;
                    }
                    let input_id = selected_input_id(conflict, resolutions)?;
                    if let Some(index) = unit.array_index {
                        let expected_len = unit.expected_array_len.ok_or_else(|| {
                            MergeError::DatabaseStructureMismatch(format!(
                                "indexed unit {} has no audited array length",
                                unit.id
                            ))
                        })?;
                        for field in &unit.fields {
                            let (known_len, indices) = selected_indexed_fields
                                .entry(field.clone())
                                .or_insert_with(|| (expected_len, BTreeSet::new()));
                            if *known_len != expected_len || !indices.insert(index) {
                                return Err(MergeError::DatabaseStructureMismatch(format!(
                                    "overlapping or inconsistent indexed selection {} {field}[{index}]",
                                    unit.id
                                )));
                            }
                        }
                    } else {
                        selected_whole_fields.extend(unit.fields.iter().cloned());
                    }
                    let donor_local = parsed
                        .iter()
                        .position(|provider| opened[provider.input_index].descriptor.id == input_id)
                        .ok_or_else(|| {
                            MergeError::InvalidResolution(format!(
                                "the selected Pak {input_id} is not available for this field"
                            ))
                        })?;
                    selections.push(AtomicDonorSelection {
                        fields: unit.fields.clone(),
                        donor_input: donor_local,
                        array_index: unit.array_index,
                        expected_array_len: unit.expected_array_len,
                    });
                }
            }
            if selected_whole_fields.is_empty() && selected_indexed_fields.is_empty() {
                // The complete row subtree is an exact carrier copy.
                raw_preserved += 1;
            } else {
                // Whole fields and indexed array elements are exact raw donor
                // nodes. Untouched top-level values and unselected array
                // elements remain exact carrier nodes.
                let field_count = carrier_row_for_plan.node.map_fields()?.len() as u64;
                let touched_fields = selected_whole_fields
                    .len()
                    .saturating_add(selected_indexed_fields.len())
                    as u64;
                raw_preserved += field_count.saturating_sub(touched_fields);
                raw_replaced += selected_whole_fields.len() as u64;
                for (expected_len, indices) in selected_indexed_fields.values() {
                    raw_preserved += expected_len.saturating_sub(indices.len()) as u64;
                    raw_replaced += indices.len() as u64;
                }
            }
            RowChoice::Atomic(selections)
        };

        let mut selected_rows = BTreeSet::from([carrier_local]);
        match &choice {
            RowChoice::Whole(donor_local) => {
                selected_rows.insert(*donor_local);
            }
            RowChoice::Atomic(selections) => {
                selected_rows.extend(selections.iter().map(|selection| selection.donor_input));
            }
        }
        let mut source_rows = std::iter::repeat_with(|| None)
            .take(parsed.len())
            .collect::<Vec<Option<IndexedRow<'_>>>>();
        source_rows[carrier_local] = Some(carrier_row_for_plan);
        for &local in &selected_rows {
            if local != carrier_local {
                source_rows[local] = indexed_row(&parsed[local].asset, row_id, cancelled)?;
            }
        }
        let carrier_row = source_rows[carrier_local]
            .as_ref()
            .expect("validated row position remains available");
        let row_bytes = match &choice {
            RowChoice::Whole(donor_local) => {
                let donor_row = source_rows[*donor_local].as_ref().ok_or_else(|| {
                    MergeError::InvalidPlan(format!(
                        "selected Pak no longer contains m_id {}",
                        carrier_row.id
                    ))
                })?;
                std::borrow::Cow::Borrowed(donor_row.node_ref().raw())
            }
            RowChoice::Atomic(selections) if selections.is_empty() => {
                std::borrow::Cow::Borrowed(carrier_row.node_ref().raw())
            }
            RowChoice::Atomic(selections) => {
                let row_refs: Vec<_> = source_rows
                    .iter()
                    .map(|row| row.as_ref().map(IndexedRow::node_ref))
                    .collect();
                std::borrow::Cow::Owned(binary_asset::merge_row_atomic_node_refs(
                    carrier_row.node_ref(),
                    &row_refs,
                    selections,
                )?)
            }
        };
        record_streamed_row(
            row_bytes.as_ref(),
            carrier_row.id,
            asset_path,
            &conflict_index,
            resolutions,
            opened,
            parsed,
            &source_rows,
            carrier_local,
            &mut unit_planner,
            &mut audit,
        )?;
        write_database_bytes(&mut writer, row_bytes.as_ref(), cancelled)?;
        let completed_rows = row_index + 1;
        if should_report_database_progress(completed_rows, output_row_count) {
            report_database_build_progress(
                progress,
                asset_path,
                completed_rows,
                output_row_count,
                Some(row_id),
            );
        }
    }

    let carrier_row_count = carrier_asset.row_count();
    for (appended_index, row_id) in appended_ids.into_iter().enumerate() {
        check_cancel(cancelled)?;
        let selected_input =
            if let Some(conflict) = indexed_conflict(&conflict_index, row_id, "$row") {
                Some(selected_input_id(conflict, resolutions)?.to_owned())
            } else {
                None
            };
        let donor_local = if let Some(input_id) = selected_input {
            parsed
                .iter()
                .position(|provider| opened[provider.input_index].descriptor.id == input_id)
                .ok_or_else(|| {
                    MergeError::InvalidResolution(format!(
                        "the selected Pak {input_id} is not available for this added row"
                    ))
                })?
        } else {
            parsed
                .iter()
                .position(|provider| provider.asset.contains_row(row_id))
                .ok_or_else(|| {
                    MergeError::InvalidPlan(format!("no input contains appended row m_id {row_id}"))
                })?
        };
        let source_rows =
            load_selected_indexed_rows(parsed, row_id, &BTreeSet::from([donor_local]), cancelled)?;
        let row = source_rows[donor_local].as_ref().ok_or_else(|| {
            MergeError::InvalidPlan(format!(
                "selected input no longer contains appended row m_id {row_id}"
            ))
        })?;
        let row_bytes = row.node_ref().raw();
        record_streamed_row(
            row_bytes,
            row_id,
            asset_path,
            &conflict_index,
            resolutions,
            opened,
            parsed,
            &source_rows,
            carrier_local,
            &mut unit_planner,
            &mut audit,
        )?;
        write_database_bytes(&mut writer, row_bytes, cancelled)?;
        raw_replaced += 1;
        let completed_rows = carrier_row_count + appended_index + 1;
        if should_report_database_progress(completed_rows, output_row_count) {
            report_database_build_progress(
                progress,
                asset_path,
                completed_rows,
                output_row_count,
                Some(row_id),
            );
        }
    }

    write_database_bytes(
        &mut writer,
        &carrier_asset.payload()[list_range.end..],
        cancelled,
    )?;
    let payload_end = writer.stream_position()?;
    let payload_len = payload_end
        .checked_sub(binary_asset::PREFIX_SIZE as u64)
        .ok_or_else(|| MergeError::Verification("merged payload length underflow".to_owned()))?;
    let payload_len_u32 = u32::try_from(payload_len).map_err(|_| MergeError::DatabaseTooLarge)?;
    writer.write_all(&carrier_asset.footer)?;
    writer.write_all(&carrier_asset.package_tag)?;
    writer.seek(SeekFrom::Start(6))?;
    writer.write_all(&payload_len_u32.to_le_bytes())?;
    writer.flush()?;
    drop(writer);

    let merged_uexp_size_u64 = fs::metadata(uexp_path)?.len();
    if audit.verified_rows != output_row_count as u64 {
        return Err(MergeError::Verification(format!(
            "stored row count mismatch for {asset_path}: expected {output_row_count}, built {}",
            audit.verified_rows
        )));
    }
    let merged_uexp_size =
        usize::try_from(merged_uexp_size_u64).map_err(|_| MergeError::DatabaseTooLarge)?;
    let uasset_entry = carrier_provider
        .group
        .components
        .get(&PackageComponent::Uasset)
        .expect("database carrier has uasset")
        .clone();
    let patched_uasset = patch_serial_size(
        carrier_provider.uasset.as_ref(),
        carrier_provider.uexp_size,
        merged_uexp_size,
    )?;
    let raw_audit = PendingRawPreservationAudit {
        asset_path: asset_path.clone(),
        pak_entry_path: uexp_entry.clone(),
        expected_entry_size: merged_uexp_size_u64,
        audit,
    };
    Ok(BuiltDatabase {
        uasset_entry,
        uexp_entry,
        uasset: patched_uasset,
        raw_preserved_nodes: raw_preserved,
        raw_replaced_nodes: raw_replaced,
        raw_audit,
    })
}

#[allow(clippy::too_many_arguments)]
fn record_streamed_row(
    row_bytes: &[u8],
    expected_id: RowId,
    asset_path: &str,
    conflict_index: &AssetConflictIndex<'_>,
    resolutions: &ResolutionSet,
    opened: &[OpenedPak],
    parsed: &[ParsedDbProvider],
    source_rows: &[Option<IndexedRow<'_>>],
    carrier_local: usize,
    unit_planner: &mut profiles::AtomicUnitPlanner<'_>,
    audit: &mut RawAuditAccumulator,
) -> Result<()> {
    let output_node = binary_asset::parse_messagepack(row_bytes)?;
    let output_id = raw_audit_row_id(&output_node)?;
    if output_id != expected_id {
        return Err(MergeError::Verification(format!(
            "stored row ID mismatch for {asset_path}: expected {expected_id}, built {output_id}"
        )));
    }
    let carrier_input_id = &opened[parsed[carrier_local].input_index].descriptor.id;
    let row_sha256: [u8; 32] = Sha256::digest(row_bytes).into();
    let row_sha256_hex = hex::encode(row_sha256);
    update_framed(&mut audit.ledger, b"row");
    update_framed(&mut audit.ledger, expected_id.to_string().as_bytes());
    update_framed(&mut audit.ledger, row_sha256_hex.as_bytes());
    audit.verified_rows += 1;

    let Some(carrier_row) = source_rows[carrier_local].as_ref() else {
        audit.replaced_nodes += 1;
        update_framed(&mut audit.ledger, b"appended-row");
        return Ok(());
    };
    if let Some(whole_conflict) = indexed_conflict(conflict_index, expected_id, "__whole_row__") {
        let selected = selected_input_id(whole_conflict, resolutions)?;
        if selected == carrier_input_id {
            audit.preserved_nodes += 1;
            update_framed(&mut audit.ledger, b"whole-row-carrier");
        } else {
            audit.replaced_nodes += 1;
            update_framed(&mut audit.ledger, b"whole-row-donor");
        }
        return Ok(());
    }

    let layout = unit_planner.layout_for_row(&carrier_row.node)?;
    if layout.units.is_empty() {
        audit.preserved_nodes += 1;
        update_framed(&mut audit.ledger, b"whole-row-no-profile-units");
        return Ok(());
    }
    let output_row = NodeRef {
        node: &output_node,
        source: row_bytes,
    };
    for unit in layout.units.iter() {
        let (expected_unit_hash, replaced) = expected_atomic_audit_digest(
            asset_path,
            expected_id,
            unit,
            conflict_index,
            resolutions,
            opened,
            parsed,
            source_rows,
            carrier_local,
        )?;
        let actual_unit_hash = raw_atomic_audit_digest_from_row(output_row, unit)?;
        if expected_unit_hash != actual_unit_hash {
            return Err(MergeError::Verification(format!(
                "linked-value storage mismatch for {asset_path} m_id={expected_id} {}: expected {expected_unit_hash}, built {actual_unit_hash}",
                unit.id
            )));
        }
        update_framed(&mut audit.ledger, b"atomic-unit");
        update_framed(&mut audit.ledger, expected_id.to_string().as_bytes());
        update_framed(&mut audit.ledger, unit.id.as_bytes());
        update_framed(&mut audit.ledger, expected_unit_hash.as_bytes());
        if replaced {
            audit.replaced_nodes += 1;
            update_framed(&mut audit.ledger, b"donor");
        } else {
            audit.preserved_nodes += 1;
            update_framed(&mut audit.ledger, b"carrier");
        }
        audit.verified_units += 1;
    }
    Ok(())
}

fn finalize_raw_preservation_audits(
    pending: Vec<PendingRawPreservationAudit>,
    inventory: &pak::PakInventory,
    writer_source_sha256: &BTreeMap<String, String>,
) -> Result<Vec<RawPreservationAssetAudit>> {
    let entries: BTreeMap<_, _> = inventory
        .entries
        .iter()
        .map(|entry| (sort_key(&entry.path), entry))
        .collect();
    let mut seen_assets = BTreeSet::new();
    let mut seen_entries = BTreeSet::new();
    let mut finalized = Vec::new();
    finalized
        .try_reserve_exact(pending.len())
        .map_err(|_| MergeError::AllocationFailed("unchanged-data checks"))?;

    for pending in pending {
        if !seen_assets.insert(sort_key(&pending.asset_path)) {
            return Err(MergeError::Verification(format!(
                "duplicate unchanged-data check for file group: {}",
                pending.asset_path
            )));
        }
        let entry_key = sort_key(&pending.pak_entry_path);
        if !seen_entries.insert(entry_key.clone()) {
            return Err(MergeError::Verification(format!(
                "duplicate unchanged-data check for Pak file: {}",
                pending.pak_entry_path
            )));
        }
        let entry = entries.get(&entry_key).ok_or_else(|| {
            MergeError::Verification(format!(
                "a Pak file required by the unchanged-data check is missing: {}",
                pending.pak_entry_path
            ))
        })?;
        if entry.size != pending.expected_entry_size {
            return Err(MergeError::Verification(format!(
                "unchanged-data Pak file size mismatch for {}: staged {}, Pak {}",
                pending.pak_entry_path, pending.expected_entry_size, entry.size
            )));
        }

        let source_sha256 = writer_source_sha256
            .get(&pending.pak_entry_path)
            .ok_or_else(|| {
                MergeError::Verification(format!(
                    "the Pak writer did not record the source bytes for {}",
                    pending.pak_entry_path
                ))
            })?;
        if source_sha256 != &entry.sha256 {
            return Err(MergeError::Verification(format!(
                "unchanged-data source hash mismatch for {}: writer {}, Pak {}",
                pending.pak_entry_path, source_sha256, entry.sha256
            )));
        }
        let entry_sha256 = entry.sha256.clone();
        let mut audit = pending.audit;
        update_framed(&mut audit.ledger, b"entry-sha256");
        update_framed(&mut audit.ledger, entry_sha256.as_bytes());
        update_framed(&mut audit.ledger, &audit.verified_rows.to_be_bytes());
        update_framed(&mut audit.ledger, &audit.verified_units.to_be_bytes());
        update_framed(&mut audit.ledger, &audit.preserved_nodes.to_be_bytes());
        update_framed(&mut audit.ledger, &audit.replaced_nodes.to_be_bytes());
        finalized.push(RawPreservationAssetAudit {
            asset_path: pending.asset_path,
            pak_entry_path: pending.pak_entry_path,
            entry_sha256,
            ledger_sha256: hex::encode(audit.ledger.finalize()),
            verified_row_count: audit.verified_rows,
            verified_atomic_unit_count: audit.verified_units,
            preserved_node_count: audit.preserved_nodes,
            replaced_node_count: audit.replaced_nodes,
            passed: true,
        });
    }
    Ok(finalized)
}

fn raw_audit_row_id(node: &binary_asset::MsgpackNode) -> Result<RowId> {
    binary_asset::logical_row_id(node).map_err(|error| {
        MergeError::Verification(format!(
            "a row has an invalid logical m_id while checking stored data: {error}"
        ))
    })
}

#[allow(clippy::too_many_arguments)]
fn expected_atomic_audit_digest(
    asset_path: &str,
    row_id: RowId,
    unit: &AtomicGroup,
    conflicts: &AssetConflictIndex<'_>,
    resolutions: &ResolutionSet,
    opened: &[OpenedPak],
    parsed: &[ParsedDbProvider],
    source_rows: &[Option<IndexedRow<'_>>],
    carrier_local: usize,
) -> Result<(String, bool)> {
    let carrier_row = source_rows[carrier_local]
        .as_ref()
        .ok_or_else(|| MergeError::Verification(format!("base Pak row {row_id} disappeared")))?;
    let Some(conflict) = indexed_conflict(conflicts, row_id, &unit.id) else {
        return Ok((
            raw_atomic_audit_digest_from_row(carrier_row.node_ref(), unit)?,
            false,
        ));
    };
    if conflict.kind == ConflictKind::EncodingDrift {
        return Ok((
            raw_atomic_audit_digest_from_row(carrier_row.node_ref(), unit)?,
            false,
        ));
    }

    let selected = selected_input_id(conflict, resolutions)?;
    let carrier_input_id = &opened[parsed[carrier_local].input_index].descriptor.id;
    if selected == carrier_input_id {
        return Ok((
            raw_atomic_audit_digest_from_row(carrier_row.node_ref(), unit)?,
            false,
        ));
    }
    let donor_local = parsed
        .iter()
        .position(|provider| opened[provider.input_index].descriptor.id == selected)
        .ok_or_else(|| {
            MergeError::Verification(format!(
                "selected Pak {selected} is unavailable while checking stored data for {asset_path}"
            ))
        })?;
    let donor_row = source_rows[donor_local].as_ref().ok_or_else(|| {
        MergeError::Verification(format!(
            "selected Pak {selected} has no row {row_id} while checking stored data for {asset_path}"
        ))
    })?;
    Ok((
        raw_atomic_audit_digest_from_row(donor_row.node_ref(), unit)?,
        true,
    ))
}

fn raw_atomic_audit_digest_from_row(row: NodeRef<'_>, unit: &AtomicGroup) -> Result<String> {
    raw_atomic_audit_digest(unit, |field| {
        Ok(binary_asset::atomic_group_value(row, unit, field)?.raw())
    })
}

fn raw_atomic_audit_digest<'a>(
    unit: &AtomicGroup,
    mut raw_for: impl FnMut(&str) -> Result<&'a [u8]>,
) -> Result<String> {
    let mut digest = Sha256::new();
    digest.update(b"PAK-MERGER-RAW-PRESERVATION-ATOMIC-UNIT-V1");
    update_framed(&mut digest, unit.id.as_bytes());
    match unit.array_index {
        Some(index) => {
            digest.update([1]);
            digest.update((index as u64).to_be_bytes());
            let expected_len = unit.expected_array_len.ok_or_else(|| {
                MergeError::Verification(format!(
                    "indexed stored-data check {} has no expected length",
                    unit.id
                ))
            })?;
            digest.update((expected_len as u64).to_be_bytes());
        }
        None => digest.update([0]),
    }
    for field in &unit.fields {
        update_framed(&mut digest, field.as_bytes());
        update_framed(&mut digest, raw_for(field)?);
    }
    Ok(hex::encode(digest.finalize()))
}

fn patch_serial_size(uasset: &[u8], old_uexp_size: usize, new_uexp_size: usize) -> Result<Vec<u8>> {
    let descriptor = parse_uasset_shell(uasset, old_uexp_size, None).map_err(|error| {
        MergeError::Verification(format!(
            "the base Pak .uasset is not structurally valid: {error}"
        ))
    })?;
    let new_serial = new_uexp_size
        .checked_sub(binary_asset::PACKAGE_TAG_SIZE)
        .ok_or_else(|| {
            MergeError::Verification("merged .uexp is shorter than its package tag".to_owned())
        })?;
    let new_serial = u64::try_from(new_serial)
        .map_err(|_| MergeError::Verification("merged .uexp is too large".to_owned()))?;
    let mut output = uasset.to_vec();
    let serial_range = descriptor.serial_size_offset..descriptor.serial_size_offset + 8;
    output[serial_range].copy_from_slice(&new_serial.to_le_bytes());
    parse_uasset_shell(&output, new_uexp_size, None).map_err(|error| {
        MergeError::Verification(format!(
            "the updated .uasset no longer matches the merged .uexp: {error}"
        ))
    })?;
    Ok(output)
}

type AssetConflictIndex<'a> = BTreeMap<RowId, BTreeMap<&'a str, &'a Conflict>>;

fn build_asset_conflict_index<'a>(plan: &'a MergePlan, asset_path: &str) -> AssetConflictIndex<'a> {
    let mut index = BTreeMap::new();
    for conflict in &plan.conflicts {
        if !conflict.asset_path.eq_ignore_ascii_case(asset_path) {
            continue;
        }
        let (Some(row_id), Some(group_id)) = (&conflict.row_id, &conflict.group_id) else {
            continue;
        };
        let Ok(row_id) = row_id.parse::<RowId>() else {
            continue;
        };
        index
            .entry(row_id)
            .or_insert_with(BTreeMap::new)
            .insert(group_id.as_str(), conflict);
    }
    index
}

fn indexed_conflict<'a>(
    index: &'a AssetConflictIndex<'a>,
    row_id: RowId,
    group_id: &str,
) -> Option<&'a Conflict> {
    index
        .get(&row_id)
        .and_then(|groups| groups.get(group_id).copied())
}

fn conflict_for_asset<'a>(plan: &'a MergePlan, asset: &AssetPlan) -> Result<&'a Conflict> {
    let id = asset.conflict_ids.first().ok_or_else(|| {
        MergeError::InvalidPlan(format!(
            "{} requires a choice but has no conflict record",
            asset.virtual_path
        ))
    })?;
    plan.conflicts
        .iter()
        .find(|conflict| conflict.id == *id)
        .ok_or_else(|| MergeError::InvalidResolution(format!("missing conflict {id}")))
}

fn selected_input_id<'a>(
    conflict: &'a Conflict,
    resolutions: &'a ResolutionSet,
) -> Result<&'a str> {
    let selected = resolutions
        .choices
        .get(&conflict.id)
        .ok_or_else(|| MergeError::Unresolved(format!("missing choice for {}", conflict.id)))?;
    conflict
        .variants
        .iter()
        .find(|variant| variant.id == *selected)
        .map(|variant| variant.input_id.as_str())
        .ok_or_else(|| {
            MergeError::InvalidResolution(format!(
                "the selected choice {selected} is missing from {}",
                conflict.id
            ))
        })
}

fn donor_for_asset<'a>(
    asset: &AssetPlan,
    providers: &'a [GroupProvider],
    opened: &[OpenedPak],
) -> Result<&'a GroupProvider> {
    let preferred = asset.donor_input_ids.iter().find_map(|id| {
        providers
            .iter()
            .find(|provider| opened[provider.input_index].descriptor.id == *id)
    });
    preferred.or_else(|| providers.first()).ok_or_else(|| {
        MergeError::InvalidPlan(format!("{} has no input provider", asset.virtual_path))
    })
}

fn provider_by_input_id<'a>(
    providers: &'a [GroupProvider],
    opened: &[OpenedPak],
    input_id: &str,
) -> Result<&'a GroupProvider> {
    providers
        .iter()
        .find(|provider| opened[provider.input_index].descriptor.id == input_id)
        .ok_or_else(|| {
            MergeError::InvalidResolution(format!("input {input_id} has no selected package"))
        })
}

fn append_package_sources(
    output: &mut Vec<OutputEntry>,
    donor: &GroupProvider,
    opened: &[OpenedPak],
) -> Result<()> {
    for path in donor.group.components.values() {
        output.push(OutputEntry {
            path: path.clone(),
            source: OutputSource::Pak {
                input_index: donor.input_index,
                path: archive_entry_path(&opened[donor.input_index], path)?.to_owned(),
            },
        });
    }
    Ok(())
}

fn ensure_unique_output_paths(entries: &[OutputEntry]) -> Result<()> {
    let mut seen = BTreeSet::new();
    for entry in entries {
        if !seen.insert(sort_key(&entry.path)) {
            return Err(MergeError::Verification(format!(
                "duplicate output path: {}",
                entry.path
            )));
        }
    }
    Ok(())
}

fn ensure_conflict_count(conflicts: &[Conflict]) -> Result<()> {
    if conflicts.len() > MAX_PLAN_CONFLICTS {
        return Err(MergeError::TooManyConflicts {
            actual: conflicts.len(),
            limit: MAX_PLAN_CONFLICTS,
        });
    }
    Ok(())
}

fn verify_input_identities(opened: &[OpenedPak], descriptors: &[InputDescriptor]) -> Result<()> {
    for input in opened {
        let descriptor = descriptors
            .iter()
            .find(|descriptor| descriptor.id == input.descriptor.id)
            .ok_or_else(|| MergeError::InputChanged(input.descriptor.path.clone()))?;
        if descriptor.sha256 != input.archive.inventory().archive_sha256 {
            return Err(MergeError::InputChanged(input.descriptor.path.clone()));
        }
    }
    Ok(())
}

fn validate_references_for_pinned_profile(
    plan: &MergePlan,
    archive: &PakArchive,
    cancelled: Option<&CancellationToken>,
    multithreaded: bool,
    progress: &mut dyn FnMut(u64, u64, Option<String>),
) -> Result<Vec<String>> {
    if pinned_profile_id(plan) == Some(OT0_PROFILE_ID) {
        return validate_known_references_in_archive(archive, cancelled, multithreaded, progress);
    }
    progress(1, 1, None);
    Ok(vec![
        "Reference checks require the OCTOPATH TRAVELER 0 profile.".to_owned(),
    ])
}

#[cfg(test)]
fn validate_known_references(path: &Path) -> Result<Vec<String>> {
    let archive = PakArchive::open(path)?;
    validate_known_references_in_archive(&archive, None, true, &mut |_, _, _| {})
}

fn validate_known_references_in_archive(
    archive: &PakArchive,
    cancelled: Option<&CancellationToken>,
    multithreaded: bool,
    progress: &mut dyn FnMut(u64, u64, Option<String>),
) -> Result<Vec<String>> {
    let mut table_groups = BTreeMap::<&'static str, pak::PackageGroup>::new();
    for group in &archive.inventory().packages.packages {
        let Some(table) = known_reference_table(&group.base_path) else {
            continue;
        };
        if let Some(previous) = table_groups.insert(table, group.clone()) {
            return Err(MergeError::Verification(format!(
                "Reference checking cannot continue because table {table} appears in two places: {} and {}",
                previous.base_path, group.base_path
            )));
        }
    }

    let mut warnings = Vec::new();
    #[derive(Debug, Clone, Copy)]
    struct PendingReference {
        rule_index: usize,
        source_row: RowId,
        target_id: u64,
    }

    // Keep only compact IDs and references. Each complete BinaryAsset tree is
    // dropped before the next table is parsed, so final verification cannot
    // recreate the old all-databases-in-memory peak.
    let mut row_ids = BTreeMap::<&'static str, Vec<RowId>>::new();
    let mut pending_references = Vec::<PendingReference>::new();
    let logical_table_bytes = table_groups.values().try_fold(0_u64, |total, group| {
        let uexp = group
            .components
            .get(&PackageComponent::Uexp)
            .ok_or_else(|| missing_package_component(group, PackageComponent::Uexp))?;
        total
            .checked_add(archive.entry_size(uexp)?)
            .ok_or_else(|| MergeError::Verification("reference check size overflow".to_owned()))
    })?;
    // Use one fixed denominator for the complete operation: one share for
    // indexing, one for row parsing, and one for comparing collected links.
    // The final link count is not known until rows have been parsed, so its
    // fixed byte-weighted share prevents a 100% -> lower percentage jump.
    let table_work_bytes = logical_table_bytes
        .checked_mul(2)
        .ok_or_else(|| MergeError::Verification("reference check size overflow".to_owned()))?;
    let total_work_bytes = logical_table_bytes
        .checked_mul(3)
        .ok_or_else(|| MergeError::Verification("reference check size overflow".to_owned()))?
        .max(1);
    let mut completed_work_bytes = 0_u64;
    progress(0, total_work_bytes, None);
    for (&table, group) in &table_groups {
        check_cancel(cancelled)?;
        let uexp = group
            .components
            .get(&PackageComponent::Uexp)
            .ok_or_else(|| missing_package_component(group, PackageComponent::Uexp))?;
        let table_bytes = archive.entry_size(uexp)?;
        let table_start = completed_work_bytes;
        let table_label = format!("{} · {table}", group.base_path);
        let mut index_progress = |completed: usize, _total: usize| {
            progress(
                table_start.saturating_add((completed as u64).min(table_bytes)),
                total_work_bytes,
                Some(table_label.clone()),
            );
        };
        match read_reference_table(
            archive,
            group,
            cancelled,
            multithreaded,
            &mut index_progress,
        ) {
            Ok(asset) => {
                completed_work_bytes = table_start.saturating_add(table_bytes);
                let mut ids = Vec::new();
                ids.try_reserve_exact(asset.row_count()).map_err(|_| {
                    MergeError::Verification(format!(
                        "not enough memory for the compact row-ID list of table {table}"
                    ))
                })?;
                for row_index in 0..asset.row_count() {
                    check_cancel(cancelled)?;
                    let row = indexed_row_at(&asset, row_index, cancelled)?
                        .expect("indexed reference row remains available");
                    ids.push(row.id);
                    for (rule_index, rule) in KNOWN_REFERENCE_RULES.iter().enumerate() {
                        if rule.source_table != table {
                            continue;
                        }
                        let Some(node) = row.node.map_get(rule.field)? else {
                            continue;
                        };
                        visit_positive_integer_leaves(node, &mut |target_id| {
                            pending_references.try_reserve(1).map_err(|_| {
                                MergeError::Verification(
                                    "not enough memory for the reference list".to_owned(),
                                )
                            })?;
                            pending_references.push(PendingReference {
                                rule_index,
                                source_row: row.id,
                                target_id,
                            });
                            Ok(())
                        })?;
                    }
                    if (row_index + 1).is_multiple_of(DATABASE_PROGRESS_ROW_INTERVAL)
                        || row_index + 1 == asset.row_count()
                    {
                        let row_fraction = if asset.row_count() == 0 {
                            table_bytes
                        } else {
                            table_bytes.saturating_mul((row_index + 1) as u64)
                                / asset.row_count() as u64
                        };
                        progress(
                            completed_work_bytes.saturating_add(row_fraction),
                            total_work_bytes,
                            Some(table_label.clone()),
                        );
                    }
                }
                ids.sort_unstable();
                ids.dedup();
                row_ids.insert(table, ids);
                completed_work_bytes = table_start.saturating_add(table_bytes.saturating_mul(2));
                progress(completed_work_bytes, total_work_bytes, Some(table_label));
            }
            Err(MergeError::Cancelled) => return Err(MergeError::Cancelled),
            Err(reason) => {
                completed_work_bytes = table_start.saturating_add(table_bytes.saturating_mul(2));
                progress(completed_work_bytes, total_work_bytes, Some(table_label));
                warnings.push(format!(
                    "References in table {table} could not be checked because the table could not be read: {reason}"
                ));
            }
        }
    }
    let mut checked_rules = 0_usize;
    let mut checked_rows = 0_usize;
    let mut missing_count = 0_u64;
    let mut missing_examples = BTreeSet::new();
    let mut active_rule_indices = BTreeSet::new();

    let source_tables: BTreeSet<_> = KNOWN_REFERENCE_RULES
        .iter()
        .map(|rule| rule.source_table)
        .collect();
    for source_table in source_tables {
        check_cancel(cancelled)?;
        if !table_groups.contains_key(source_table) {
            continue;
        }
        if !row_ids.contains_key(source_table) {
            continue;
        }

        let mut source_has_active_rule = false;
        for (rule_index, rule) in KNOWN_REFERENCE_RULES
            .iter()
            .enumerate()
            .filter(|(_, rule)| rule.source_table == source_table)
        {
            if row_ids.contains_key(rule.target_table) {
                active_rule_indices.insert(rule_index);
                checked_rules = checked_rules.saturating_add(1);
                source_has_active_rule = true;
            } else {
                let reason = if table_groups.contains_key(rule.target_table) {
                    "is present but could not be read"
                } else {
                    "is not present in the merged mod Pak"
                };
                warnings.push(format!(
                    "References from {}.{} to {} were not checked because the target table {reason}.",
                    rule.source_table, rule.field, rule.target_table
                ));
            }
        }
        if source_has_active_rule {
            checked_rows = checked_rows.saturating_add(
                row_ids
                    .get(source_table)
                    .expect("a readable source table has compact row IDs")
                    .len(),
            );
        }
    }

    let reference_count = u64::try_from(pending_references.len())
        .map_err(|_| MergeError::Verification("reference check count overflow".to_owned()))?;
    progress(table_work_bytes, total_work_bytes, None);
    for (reference_index, pending) in pending_references.into_iter().enumerate() {
        check_cancel(cancelled)?;
        if !active_rule_indices.contains(&pending.rule_index) {
        } else {
            let rule = &KNOWN_REFERENCE_RULES[pending.rule_index];
            let targets = row_ids
                .get(rule.target_table)
                .expect("active reference rule has compact target IDs");
            let present = i64::try_from(pending.target_id)
                .ok()
                .is_some_and(|id| targets.binary_search(&id).is_ok());
            if !present {
                missing_count = missing_count.saturating_add(1);
                if missing_examples.len() < MAX_REFERENCE_BREAK_EXAMPLES {
                    missing_examples.insert(format!(
                        "{}.{} row {} -> {} id {}",
                        rule.source_table,
                        rule.field,
                        pending.source_row,
                        rule.target_table,
                        pending.target_id
                    ));
                }
            }
        }
        let completed_references = reference_index as u64 + 1;
        if completed_references.is_multiple_of(4096) || completed_references == reference_count {
            let reference_progress = logical_table_bytes
                .saturating_mul(completed_references)
                .checked_div(reference_count)
                .unwrap_or(logical_table_bytes);
            progress(
                table_work_bytes.saturating_add(reference_progress),
                total_work_bytes,
                None,
            );
        }
    }

    progress(total_work_bytes, total_work_bytes, None);

    if missing_count != 0 {
        let examples = missing_examples.into_iter().collect::<Vec<_>>().join("; ");
        return Err(MergeError::Verification(format!(
            "{missing_count} reference(s) point to rows missing from the merged Pak. Examples: {examples}"
        )));
    }

    warnings.push(format!(
        "Reference checks: {checked_rules} rule(s), {checked_rows} row(s)."
    ));
    warnings.push("Other game-specific links may still need in-game testing.".to_owned());
    warnings.sort();
    warnings.dedup();
    Ok(warnings)
}

fn known_reference_table(base_path: &str) -> Option<&'static str> {
    let path = sort_key(base_path);
    const TABLES: &[(&str, &str)] = &[
        ("/local/database/enemy/enemygroups", "EnemyGroups"),
        ("/local/database/enemy/enemyid", "EnemyID"),
        ("/local/database/enemy/enemytypeid", "EnemyTypeID"),
        ("/local/database/enemy/enemyweaklockid", "EnemyWeakLockID"),
        ("/local/database/skill/skillid", "SkillID"),
        ("/local/database/skill/skillavailid", "SkillAvailID"),
        ("/local/database/skill/skilleffectiveid", "SkillEffectiveID"),
        (
            "/local/database/skill/skillresistailmentid",
            "SkillResistAilmentID",
        ),
        ("/local/database/battle/battleeventlist", "BattleEventList"),
        (
            "/local/database/battle/battleeventcommand",
            "BattleEventCommand",
        ),
    ];
    TABLES
        .iter()
        .find_map(|(suffix, table)| path.ends_with(suffix).then_some(*table))
}

fn read_reference_table(
    archive: &PakArchive,
    group: &pak::PackageGroup,
    cancelled: Option<&CancellationToken>,
    multithreaded: bool,
    progress: &mut dyn FnMut(usize, usize),
) -> Result<IndexedBinaryAsset> {
    if !group.complete {
        return Err(missing_package_component(group, PackageComponent::Uasset));
    }
    let uexp = group
        .components
        .get(&PackageComponent::Uexp)
        .ok_or_else(|| missing_package_component(group, PackageComponent::Uexp))?;
    let no_cancellation = CancellationToken::new();
    let cancellation = cancelled.unwrap_or(&no_cancellation);
    let bytes = archive.map_entry_with_threads_and_cancel(
        uexp,
        usize::MAX as u64,
        multithreaded,
        cancellation,
    )?;
    parse_indexed_binary_asset_with_progress(bytes, cancelled, progress)
}

fn visit_positive_integer_leaves(
    node: &binary_asset::MsgpackNode,
    visitor: &mut impl FnMut(u64) -> Result<()>,
) -> Result<()> {
    match &node.kind {
        MsgpackKind::Integer(IntegerValue::Signed(value)) if *value > 0 => {
            visitor(*value as u64)?;
        }
        MsgpackKind::Integer(IntegerValue::Unsigned(value)) if *value > 0 => visitor(*value)?,
        MsgpackKind::Array(items) => {
            for item in items {
                visit_positive_integer_leaves(item, visitor)?;
            }
        }
        MsgpackKind::Map(entries) => {
            for entry in entries {
                // Reference-bearing fields are defined in terms of values;
                // integer map keys are structural and are never interpreted as
                // foreign keys.
                visit_positive_integer_leaves(&entry.value, visitor)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn require_output_path(path: &Path) -> Result<()> {
    if path
        .extension()
        .and_then(|value| value.to_str())
        .map(str::to_ascii_lowercase)
        != Some("pak".to_owned())
    {
        return Err(MergeError::InvalidRequest(
            "output must use the .pak extension".to_owned(),
        ));
    }
    if path
        .file_name()
        .and_then(|value| value.to_str())
        .is_some_and(|name| !name.to_ascii_lowercase().ends_with("_p.pak"))
    {
        return Err(MergeError::InvalidRequest(
            "output file name must end with _P.pak".to_owned(),
        ));
    }
    Ok(())
}

fn capture_output_target(
    path: &Path,
    overwrite_existing: bool,
) -> Result<Option<OutputTargetStamp>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !overwrite_existing {
                return Err(MergeError::InvalidRequest(format!(
                    "output already exists: {}",
                    path.display()
                )));
            }
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(MergeError::InvalidRequest(format!(
                    "the existing output is not a regular file and cannot be replaced: {}",
                    path.display()
                )));
            }
            Ok(Some(OutputTargetStamp {
                len: metadata.len(),
                modified: metadata.modified().ok(),
                readonly: metadata.permissions().readonly(),
            }))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn ensure_output_target_unchanged(path: &Path, expected: Option<&OutputTargetStamp>) -> Result<()> {
    let current = match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(MergeError::InvalidRequest(format!(
                    "the output path changed while the Pak was being built: {}",
                    path.display()
                )));
            }
            Some(OutputTargetStamp {
                len: metadata.len(),
                modified: metadata.modified().ok(),
                readonly: metadata.permissions().readonly(),
            })
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    if current.as_ref() != expected {
        return Err(MergeError::InvalidRequest(format!(
            "the output path changed while the Pak was being built; no file was replaced: {}",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(windows)]
fn install_paths_share_volume(work_directory: &Path, output: &Path) -> Result<bool> {
    let output_parent = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let output_parent = fs::canonicalize(output_parent).map_err(|error| {
        MergeError::InvalidRequest(format!(
            "the output folder could not be opened: {} ({error})",
            output_parent.display()
        ))
    })?;
    let work_volume = fs::canonicalize(work_directory)
        .ok()
        .and_then(|path| windows_volume_identity(&path).ok());
    let output_volume = windows_volume_identity(&output_parent).ok();
    Ok(known_volume_identities_match(work_volume, output_volume))
}

#[cfg(any(windows, test))]
fn known_volume_identities_match(left: Option<String>, right: Option<String>) -> bool {
    matches!((left, right), (Some(left), Some(right)) if left == right)
}

#[cfg(not(windows))]
fn install_paths_share_volume(_work_directory: &Path, output: &Path) -> Result<bool> {
    // The supported release target is Windows x64. Other platforms still use
    // the direct rename path and report the native cross-device error.
    let output_parent = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::canonicalize(output_parent).map_err(|error| {
        MergeError::InvalidRequest(format!(
            "the output folder could not be opened: {} ({error})",
            output_parent.display()
        ))
    })?;
    Ok(true)
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn windows_volume_identity(path: &Path) -> io::Result<String> {
    use windows_sys::Win32::Storage::FileSystem::{
        GetVolumeNameForVolumeMountPointW, GetVolumePathNameW,
    };

    let path = wide_path(path)?;
    let mut mount_point = vec![0_u16; 32_768];
    let mount_point_succeeded = unsafe {
        GetVolumePathNameW(
            path.as_ptr(),
            mount_point.as_mut_ptr(),
            mount_point.len() as u32,
        )
    };
    if mount_point_succeeded == 0 {
        return Err(io::Error::last_os_error());
    }

    let mut volume_name = vec![0_u16; 512];
    let volume_name_succeeded = unsafe {
        GetVolumeNameForVolumeMountPointW(
            mount_point.as_ptr(),
            volume_name.as_mut_ptr(),
            volume_name.len() as u32,
        )
    };
    if volume_name_succeeded == 0 {
        return Err(io::Error::last_os_error());
    }
    let end = volume_name
        .iter()
        .position(|value| *value == 0)
        .unwrap_or(volume_name.len());
    Ok(String::from_utf16_lossy(&volume_name[..end]).to_ascii_lowercase())
}

#[cfg(windows)]
fn wide_path(path: &Path) -> io::Result<Vec<u16>> {
    use std::os::windows::ffi::OsStrExt;

    let mut encoded: Vec<u16> = path.as_os_str().encode_wide().collect();
    if encoded.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "file path contains a NUL character",
        ));
    }
    encoded.push(0);
    Ok(encoded)
}

#[allow(clippy::too_many_arguments)]
fn install_verified_output<F>(
    partial: &Path,
    output: &Path,
    expected_output: Option<&OutputTargetStamp>,
    direct_install: bool,
    expected_size: u64,
    expected_sha256: &str,
    cancelled: Option<&CancellationToken>,
    progress: &mut F,
) -> Result<()>
where
    F: FnMut(MergeProgress) + Send,
{
    ensure_output_target_unchanged(output, expected_output)?;
    if direct_install {
        check_cancel(cancelled)?;
        return rename_verified_output(partial, output, expected_output.is_some())
            .map_err(Into::into);
    }

    copy_verified_output_to_sidecar(
        partial,
        output,
        expected_output,
        expected_size,
        expected_sha256,
        cancelled,
        progress,
    )
}

#[allow(clippy::too_many_arguments)]
fn copy_verified_output_to_sidecar<F>(
    partial: &Path,
    output: &Path,
    expected_output: Option<&OutputTargetStamp>,
    expected_size: u64,
    expected_sha256: &str,
    cancelled: Option<&CancellationToken>,
    progress: &mut F,
) -> Result<()>
where
    F: FnMut(MergeProgress) + Send,
{
    let output_parent = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    ensure_destination_copy_space(output_parent, expected_size)?;
    check_cancel(cancelled)?;

    // tempfile opens the sidecar with create-new semantics and removes only
    // that owned path if copying, verification, cancellation, or install fails.
    let mut sidecar = tempfile::Builder::new()
        .prefix(".pak-merger-install-")
        .suffix(".partial")
        .tempfile_in(output_parent)?;
    let mut reader = File::open(partial)?;
    let mut buffer = vec![0_u8; OUTPUT_COPY_BUFFER_BYTES];
    let mut digest = Sha256::new();
    let mut copied = 0_u64;
    let progress_total = expected_size.max(1);

    loop {
        check_cancel(cancelled)?;
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        sidecar.write_all(&buffer[..read])?;
        digest.update(&buffer[..read]);
        copied = copied
            .checked_add(read as u64)
            .ok_or(MergeError::SizeOverflow("copied output"))?;
        progress(MergeProgress {
            stage: MergeProgressStage::Finalizing,
            completed: copied.min(progress_total),
            total: progress_total,
            current_item: Some(output.display().to_string()),
        });
    }
    sidecar.as_file_mut().sync_all()?;

    if copied != expected_size {
        return Err(MergeError::Verification(format!(
            "the copied Pak size changed: expected {expected_size} bytes, copied {copied} bytes"
        )));
    }
    let copied_sha256 = hex::encode(digest.finalize());
    if copied_sha256 != expected_sha256 {
        return Err(MergeError::Verification(format!(
            "the copied Pak SHA-256 does not match: expected {expected_sha256}, got {copied_sha256}"
        )));
    }

    check_cancel(cancelled)?;
    ensure_output_target_unchanged(output, expected_output)?;
    let sidecar_path = sidecar.into_temp_path();
    rename_verified_output(sidecar_path.as_ref(), output, expected_output.is_some())?;
    Ok(())
}

fn ensure_destination_copy_space(directory: &Path, expected_size: u64) -> Result<()> {
    let allocation_unit = fs2::allocation_granularity(directory)?.max(1);
    let required = round_up_estimate(expected_size, allocation_unit)?;
    let available = fs2::available_space(directory)?;
    if available < required {
        return Err(MergeError::InvalidRequest(format!(
            "there is not enough free space in the save folder: {available} bytes available, {required} bytes required"
        )));
    }
    Ok(())
}

/// Atomically renames an already verified file on the destination volume.
/// New outputs never replace a file that appears after the last target check.
#[cfg(windows)]
#[allow(unsafe_code)]
fn rename_verified_output(partial: &Path, output: &Path, replace_existing: bool) -> io::Result<()> {
    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };

    let partial = wide_path(partial)?;
    let output = wide_path(output)?;
    let flags = MOVEFILE_WRITE_THROUGH
        | if replace_existing {
            MOVEFILE_REPLACE_EXISTING
        } else {
            0
        };
    let succeeded = unsafe { MoveFileExW(partial.as_ptr(), output.as_ptr(), flags) };
    if succeeded == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(windows))]
fn rename_verified_output(
    partial: &Path,
    output: &Path,
    _replace_existing: bool,
) -> io::Result<()> {
    fs::rename(partial, output)
}

fn ensure_output_disk_space(
    output: &Path,
    mount_point: &str,
    entries: &[(String, u64)],
    compression: OutputCompression,
) -> Result<()> {
    let parent = output
        .parent()
        .ok_or_else(|| MergeError::InvalidRequest("output has no parent".to_owned()))?;
    let allocation_unit = fs2::allocation_granularity(parent)?.max(1);
    let required =
        estimated_output_additional_bytes(mount_point, entries, compression, allocation_unit)?;
    let available = fs2::available_space(parent)?;
    if available < required {
        return Err(MergeError::InvalidRequest(format!(
            "there is not enough free space in the temporary work folder after preparing merged files: {available} bytes available, {required} additional bytes required"
        )));
    }
    Ok(())
}

#[cfg(test)]
fn checked_logical_entry_bytes(sizes: impl IntoIterator<Item = u64>) -> Result<u64> {
    sizes.into_iter().try_fold(0_u64, |total, size| {
        total
            .checked_add(size)
            .ok_or_else(disk_space_estimate_overflow)
    })
}

const V11_COMPRESSED_ENTRY_HEADER_BASE_BYTES: u64 = pak::ENTRY_HEADER_SIZE_NONE_V11 + 4;
const V11_COMPRESSION_BLOCK_RANGE_BYTES: u64 = 16;
const V11_ENCODED_ENTRY_NONE_MAX_BYTES: u64 = 20;
const V11_ENCODED_ENTRY_COMPRESSED_BASE_MAX_BYTES: u64 = 28;
const V11_ENCODED_BLOCK_SIZE_BYTES: u64 = 4;
const V11_PRIMARY_INDEX_FIXED_BYTES: u64 = 100;
const V11_PATH_HASH_INDEX_FIXED_BYTES: u64 = 8;
const V11_PATH_HASH_RECORD_BYTES: u64 = 12;
const V11_FULL_DIRECTORY_INDEX_FIXED_BYTES: u64 = 4;
const V11_FULL_DIRECTORY_FILE_COUNT_BYTES: u64 = 4;
const V11_FULL_DIRECTORY_FILE_OFFSET_BYTES: u64 = 4;
const V11_MAX_ENCODED_COMPRESSION_BLOCKS: u64 = 0xffff;

fn disk_space_estimate_overflow() -> MergeError {
    MergeError::InvalidRequest("disk-space estimate overflow".to_owned())
}

fn checked_estimate_add(left: u64, right: u64) -> Result<u64> {
    left.checked_add(right)
        .ok_or_else(disk_space_estimate_overflow)
}

fn checked_estimate_mul(left: u64, right: u64) -> Result<u64> {
    left.checked_mul(right)
        .ok_or_else(disk_space_estimate_overflow)
}

fn estimated_output_additional_bytes(
    mount_point: &str,
    entries: &[(String, u64)],
    compression: OutputCompression,
    allocation_unit: u64,
) -> Result<u64> {
    let oodle_bounds = if compression == OutputCompression::Oodle {
        pak::oodle_output_block_bounds(&required_oodle_block_sizes(entries)?)?
    } else {
        BTreeMap::new()
    };
    estimated_output_additional_bytes_with_bounds_and_allocation(
        mount_point,
        entries,
        compression,
        &oodle_bounds,
        allocation_unit,
        allocation_unit,
    )
}

fn required_oodle_block_sizes(entries: &[(String, u64)]) -> Result<BTreeSet<u64>> {
    let mut sizes = BTreeSet::new();
    for (_, logical_size) in entries {
        if *logical_size == 0 {
            continue;
        }
        let (block_size, block_count) = pak::oodle_output_block_layout(*logical_size)?;
        debug_assert!(block_count <= V11_MAX_ENCODED_COMPRESSION_BLOCKS);
        if *logical_size >= block_size {
            sizes.insert(block_size);
        }
        let remainder = logical_size % block_size;
        if remainder != 0 {
            sizes.insert(remainder);
        }
    }
    Ok(sizes)
}

#[cfg(test)]
fn estimated_output_additional_bytes_with_bounds(
    mount_point: &str,
    entries: &[(String, u64)],
    compression: OutputCompression,
    oodle_bounds: &BTreeMap<u64, u64>,
) -> Result<u64> {
    estimated_output_additional_bytes_with_bounds_and_allocation(
        mount_point,
        entries,
        compression,
        oodle_bounds,
        1,
        0,
    )
}

fn round_up_estimate(value: u64, unit: u64) -> Result<u64> {
    if unit == 0 {
        return Err(disk_space_estimate_overflow());
    }
    let remainder = value % unit;
    if remainder == 0 {
        Ok(value)
    } else {
        checked_estimate_add(value, unit - remainder)
    }
}

fn estimated_output_additional_bytes_with_bounds_and_allocation(
    mount_point: &str,
    entries: &[(String, u64)],
    compression: OutputCompression,
    oodle_bounds: &BTreeMap<u64, u64>,
    allocation_unit: u64,
    temporary_file_metadata_bytes: u64,
) -> Result<u64> {
    let mut data_bytes = 0_u64;
    let mut encoded_index_bytes = 0_u64;
    for (_, logical_size) in entries {
        let (payload_bytes, entry_header_bytes, encoded_entry_bytes) = match compression {
            OutputCompression::None => (
                *logical_size,
                pak::ENTRY_HEADER_SIZE_NONE_V11,
                V11_ENCODED_ENTRY_NONE_MAX_BYTES,
            ),
            OutputCompression::Oodle if *logical_size == 0 => (
                0,
                pak::ENTRY_HEADER_SIZE_NONE_V11,
                V11_ENCODED_ENTRY_NONE_MAX_BYTES,
            ),
            OutputCompression::Oodle => {
                let (block_size, block_count) = pak::oodle_output_block_layout(*logical_size)?;
                debug_assert!(block_count <= V11_MAX_ENCODED_COMPRESSION_BLOCKS);
                let full_block_count = logical_size / block_size;
                let full_block_bytes = if full_block_count == 0 {
                    0
                } else {
                    let bound = *oodle_bounds.get(&block_size).ok_or_else(|| {
                        MergeError::InvalidRequest(format!(
                            "missing Oodle size estimate for a {block_size}-byte full block"
                        ))
                    })?;
                    checked_estimate_mul(full_block_count, bound)?
                };
                let remainder = logical_size % block_size;
                let remainder_bytes = if remainder == 0 {
                    0
                } else {
                    *oodle_bounds.get(&remainder).ok_or_else(|| {
                        MergeError::InvalidRequest(format!(
                            "missing Oodle size estimate for a {remainder}-byte block"
                        ))
                    })?
                };
                let payload_bytes = checked_estimate_add(full_block_bytes, remainder_bytes)?;
                let entry_header_bytes = checked_estimate_add(
                    V11_COMPRESSED_ENTRY_HEADER_BASE_BYTES,
                    checked_estimate_mul(block_count, V11_COMPRESSION_BLOCK_RANGE_BYTES)?,
                )?;
                let encoded_entry_bytes = checked_estimate_add(
                    V11_ENCODED_ENTRY_COMPRESSED_BASE_MAX_BYTES,
                    checked_estimate_mul(block_count, V11_ENCODED_BLOCK_SIZE_BYTES)?,
                )?;
                (payload_bytes, entry_header_bytes, encoded_entry_bytes)
            }
        };
        data_bytes = checked_estimate_add(
            data_bytes,
            checked_estimate_add(entry_header_bytes, payload_bytes)?,
        )?;
        encoded_index_bytes = checked_estimate_add(encoded_index_bytes, encoded_entry_bytes)?;
    }

    let primary_index_bytes = checked_estimate_add(
        checked_estimate_add(
            pak_string_serialized_size(mount_point)?,
            V11_PRIMARY_INDEX_FIXED_BYTES,
        )?,
        encoded_index_bytes,
    )?;
    let entry_count = u64::try_from(entries.len()).map_err(|_| disk_space_estimate_overflow())?;
    let path_hash_index_bytes = checked_estimate_add(
        V11_PATH_HASH_INDEX_FIXED_BYTES,
        checked_estimate_mul(entry_count, V11_PATH_HASH_RECORD_BYTES)?,
    )?;
    let full_directory_index_bytes = full_directory_index_serialized_size(entries)?;
    let pak_upper_bound = [
        data_bytes,
        primary_index_bytes,
        path_hash_index_bytes,
        full_directory_index_bytes,
        pak::PAK_V11_FOOTER_SIZE,
    ]
    .into_iter()
    .try_fold(0_u64, checked_estimate_add)?;
    let pak_upper_bound = round_up_estimate(pak_upper_bound, allocation_unit)?;

    // Strict verification retains a decoded copy only for compressed entries.
    // Staged database files are deliberately absent here: they already occupy
    // this volume and are reflected in `available_space` at the call site.
    match compression {
        OutputCompression::None => Ok(pak_upper_bound),
        OutputCompression::Oodle => {
            let verification_temp_bytes =
                entries.iter().try_fold(0_u64, |total, (_, logical_size)| {
                    if *logical_size == 0 {
                        return Ok(total);
                    }
                    let allocated = round_up_estimate(*logical_size, allocation_unit)?;
                    let with_metadata =
                        checked_estimate_add(allocated, temporary_file_metadata_bytes)?;
                    checked_estimate_add(total, with_metadata)
                })?;
            checked_estimate_add(pak_upper_bound, verification_temp_bytes)
        }
    }
}

fn pak_string_serialized_size(value: &str) -> Result<u64> {
    let payload_bytes = if value.is_empty() || value.is_ascii() {
        let len = u64::try_from(value.len()).map_err(|_| disk_space_estimate_overflow())?;
        checked_estimate_add(len, 1)?
    } else {
        let units = u64::try_from(value.encode_utf16().count())
            .map_err(|_| disk_space_estimate_overflow())?;
        checked_estimate_mul(checked_estimate_add(units, 1)?, 2)?
    };
    checked_estimate_add(4, payload_bytes)
}

fn split_output_path_child(path: &str) -> Option<(&str, &str)> {
    if path == "/" || path.is_empty() {
        None
    } else {
        let path = path.strip_suffix('/').unwrap_or(path);
        match path.rfind('/').map(|index| index + 1) {
            Some(index) => Some(path.split_at(index)),
            None => Some(("/", path)),
        }
    }
}

fn full_directory_index_serialized_size(entries: &[(String, u64)]) -> Result<u64> {
    let mut directories: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for (path, _) in entries {
        let mut current = path.as_str();
        while let Some((parent, _)) = split_output_path_child(current) {
            current = parent;
            directories.entry(parent).or_default();
        }
        let (directory, filename) = split_output_path_child(path).ok_or_else(|| {
            MergeError::InvalidRequest(format!("invalid output path for Pak index: {path:?}"))
        })?;
        directories.entry(directory).or_default().insert(filename);
    }

    let mut size = V11_FULL_DIRECTORY_INDEX_FIXED_BYTES;
    for (directory, files) in directories {
        size = checked_estimate_add(size, pak_string_serialized_size(directory)?)?;
        size = checked_estimate_add(size, V11_FULL_DIRECTORY_FILE_COUNT_BYTES)?;
        for filename in files {
            size = checked_estimate_add(size, pak_string_serialized_size(filename)?)?;
            size = checked_estimate_add(size, V11_FULL_DIRECTORY_FILE_OFFSET_BYTES)?;
        }
    }
    Ok(size)
}

fn build_report_conflict_records(
    plan: &MergePlan,
    resolutions: &ResolutionSet,
    carrier_input_id: &str,
) -> Vec<ResolvedConflictRecord> {
    plan.conflicts
        .iter()
        .map(|conflict| {
            let explicit = resolutions.choices.get(&conflict.id);
            let automatic_id = if explicit.is_none()
                && !conflict.blocking
                && conflict.kind == ConflictKind::EncodingDrift
            {
                conflict
                    .variants
                    .iter()
                    .find(|variant| variant.input_id == carrier_input_id)
                    .or_else(|| conflict.variants.first())
                    .map(|variant| variant.id.as_str())
            } else {
                None
            };
            let selected_id = explicit.map(String::as_str).or(automatic_id);
            ResolvedConflictRecord {
                conflict_id: conflict.id.clone(),
                selected_variant: selected_id.and_then(|id| {
                    conflict
                        .variants
                        .iter()
                        .find(|variant| variant.id == id)
                        .cloned()
                }),
                automatic: explicit.is_none() && selected_id.is_some(),
            }
        })
        .collect()
}

fn stable_id<'a>(prefix: &str, parts: impl IntoIterator<Item = &'a str>) -> String {
    let mut digest = Sha256::new();
    digest.update(b"PAK-MERGER-STABLE-ID-V1");
    update_framed(&mut digest, prefix.as_bytes());
    for part in parts {
        update_framed(&mut digest, part.as_bytes());
    }
    format!("{prefix}-{}", hex::encode(digest.finalize()))
}

fn update_framed(digest: &mut Sha256, bytes: &[u8]) {
    digest.update((bytes.len() as u64).to_be_bytes());
    digest.update(bytes);
}

fn sort_key(value: &str) -> String {
    value.replace('\\', "/").to_ascii_lowercase()
}

fn same_path(left: &Path, right: &Path) -> bool {
    left.to_string_lossy()
        .eq_ignore_ascii_case(&right.to_string_lossy())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_errors_keep_resource_package_and_plan_failures_distinct() {
        assert_eq!(
            MergeError::AllocationFailed("field choices").to_string(),
            "not enough memory for field choices"
        );
        assert_eq!(
            MergeError::SizeOverflow("database index").to_string(),
            "database index is too large"
        );
        assert_eq!(
            MergeError::InvalidPlan("an input row is missing".to_owned()).to_string(),
            "the merge plan is inconsistent: an input row is missing"
        );

        let group = pak::PackageGroup {
            base_path: "Game/Data/Table".to_owned(),
            components: BTreeMap::new(),
            complete: false,
        };
        assert!(matches!(
            missing_package_component(&group, PackageComponent::Uexp),
            MergeError::MissingPackageComponent {
                package,
                component: ".uexp"
            } if package == "Game/Data/Table"
        ));
    }

    #[cfg(windows)]
    #[test]
    fn install_volume_detection_recognizes_the_work_volume() {
        let root = tempfile::tempdir().unwrap();
        let output = root.path().join("Result_P.pak");

        assert!(install_paths_share_volume(root.path(), &output).unwrap());
        assert_eq!(
            windows_volume_identity(root.path()).unwrap(),
            windows_volume_identity(output.parent().unwrap()).unwrap()
        );
    }

    #[test]
    fn unknown_or_different_volume_identity_uses_the_sidecar_path() {
        assert!(known_volume_identities_match(
            Some("volume-a".to_owned()),
            Some("volume-a".to_owned())
        ));
        assert!(!known_volume_identities_match(
            Some("volume-a".to_owned()),
            Some("volume-b".to_owned())
        ));
        assert!(!known_volume_identities_match(
            None,
            Some("volume-a".to_owned())
        ));
        assert!(!known_volume_identities_match(None, None));
    }

    #[test]
    fn sidecar_install_copies_checks_and_atomically_publishes_the_output() {
        let work = tempfile::tempdir().unwrap();
        let destination = tempfile::tempdir().unwrap();
        let partial = work.path().join("verified.pak.partial");
        let output = destination.path().join("Result_P.pak");
        let payload = (0..(1024 * 1024 + 37))
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        fs::write(&partial, &payload).unwrap();
        let expected_sha256 = hex::encode(Sha256::digest(&payload));
        let mut progress_events = Vec::new();

        install_verified_output(
            &partial,
            &output,
            None,
            false,
            payload.len() as u64,
            &expected_sha256,
            None,
            &mut |event| progress_events.push(event),
        )
        .unwrap();

        assert_eq!(fs::read(&output).unwrap(), payload);
        assert!(partial.exists());
        assert!(progress_events.iter().any(|event| {
            event.stage == MergeProgressStage::Finalizing
                && event.completed == payload.len() as u64
                && event.total == payload.len() as u64
        }));
        assert!(!destination.path().read_dir().unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".pak-merger-install-")
        }));
    }

    #[test]
    fn cancelled_sidecar_install_preserves_the_old_output_and_cleans_up() {
        let work = tempfile::tempdir().unwrap();
        let destination = tempfile::tempdir().unwrap();
        let partial = work.path().join("verified.pak.partial");
        let output = destination.path().join("Result_P.pak");
        let payload = vec![0x5a; 1024 * 1024];
        fs::write(&partial, &payload).unwrap();
        fs::write(&output, b"keep this output").unwrap();
        let expected_output = capture_output_target(&output, true).unwrap().unwrap();
        let expected_sha256 = hex::encode(Sha256::digest(&payload));
        let cancelled = CancellationToken::new();
        let cancel_from_progress = cancelled.clone();

        let error = copy_verified_output_to_sidecar(
            &partial,
            &output,
            Some(&expected_output),
            payload.len() as u64,
            &expected_sha256,
            Some(&cancelled),
            &mut |event| {
                if event.completed > 0 {
                    cancel_from_progress.cancel();
                }
            },
        )
        .unwrap_err();

        assert!(matches!(error, MergeError::Cancelled));
        assert_eq!(fs::read(&output).unwrap(), b"keep this output");
        assert!(!destination.path().read_dir().unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".pak-merger-install-")
        }));
    }

    #[test]
    fn sidecar_install_rechecks_the_output_after_copying() {
        let work = tempfile::tempdir().unwrap();
        let destination = tempfile::tempdir().unwrap();
        let partial = work.path().join("verified.pak.partial");
        let output = destination.path().join("Result_P.pak");
        let payload = vec![0xa5; 512 * 1024];
        fs::write(&partial, &payload).unwrap();
        fs::write(&output, b"original").unwrap();
        let expected_output = capture_output_target(&output, true).unwrap().unwrap();
        let expected_sha256 = hex::encode(Sha256::digest(&payload));
        let mut changed = false;

        let error = copy_verified_output_to_sidecar(
            &partial,
            &output,
            Some(&expected_output),
            payload.len() as u64,
            &expected_sha256,
            None,
            &mut |event| {
                if event.completed > 0 && !changed {
                    fs::write(&output, vec![0x11; 4096]).unwrap();
                    changed = true;
                }
            },
        )
        .unwrap_err();

        assert!(error.to_string().contains("output path changed"));
        assert_eq!(fs::read(&output).unwrap(), vec![0x11; 4096]);
        assert!(!destination.path().read_dir().unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".pak-merger-install-")
        }));
    }

    #[test]
    fn database_build_progress_is_throttled_and_always_reports_completion() {
        assert!(!should_report_database_progress(0, 513));
        assert!(!should_report_database_progress(1, 513));
        assert!(!should_report_database_progress(255, 513));
        assert!(should_report_database_progress(256, 513));
        assert!(!should_report_database_progress(257, 513));
        assert!(should_report_database_progress(512, 513));
        assert!(should_report_database_progress(513, 513));
    }

    #[test]
    fn output_space_estimate_uses_only_the_selected_output_and_has_no_fixed_headroom() {
        let logical_bytes = 4_336_986_270_u64;
        let entries = vec![("Local/DataBase/Large.uexp".to_owned(), logical_bytes)];
        let uncompressed = estimated_output_additional_bytes_with_bounds(
            "../../../Game/Content/",
            &entries,
            OutputCompression::None,
            &BTreeMap::new(),
        )
        .unwrap();

        assert!(uncompressed > logical_bytes);
        assert!(uncompressed < logical_bytes + 64 * 1024);
        // Three input Paks may each contain this same complete database. The
        // preflight is based on the one selected output entry, not 3x input.
        assert!(uncompressed < logical_bytes * 2);
    }

    #[test]
    fn oodle_output_space_estimate_covers_codec_bound_and_strict_decode_once() {
        let logical_bytes = 4_336_986_270_u64;
        let entries = vec![("Local/DataBase/Large.uexp".to_owned(), logical_bytes)];
        let raw_sizes = required_oodle_block_sizes(&entries).unwrap();
        let bounds = raw_sizes
            .into_iter()
            .map(|size| (size, size + 256))
            .collect::<BTreeMap<_, _>>();
        let oodle = estimated_output_additional_bytes_with_bounds(
            "../../../Game/Content/",
            &entries,
            OutputCompression::Oodle,
            &bounds,
        )
        .unwrap();

        assert!(oodle > logical_bytes * 2);
        assert!(oodle < logical_bytes * 2 + 64 * 1024 * 1024);
    }

    #[test]
    fn oodle_output_space_estimate_includes_real_temp_file_allocation_rounding() {
        let entries = vec![
            ("A.bin".to_owned(), 1_u64),
            ("B.bin".to_owned(), 4_097_u64),
            ("Empty.bin".to_owned(), 0_u64),
        ];
        let bounds = required_oodle_block_sizes(&entries)
            .unwrap()
            .into_iter()
            .map(|size| (size, size + 64))
            .collect::<BTreeMap<_, _>>();
        let byte_exact = estimated_output_additional_bytes_with_bounds_and_allocation(
            "../../../Game/Content/",
            &entries,
            OutputCompression::Oodle,
            &bounds,
            1,
            0,
        )
        .unwrap();
        let clustered = estimated_output_additional_bytes_with_bounds_and_allocation(
            "../../../Game/Content/",
            &entries,
            OutputCompression::Oodle,
            &bounds,
            4_096,
            4_096,
        )
        .unwrap();

        // Two non-empty decoded temporary files need 4 KiB metadata each;
        // their data allocations round from 1→4 KiB and 4097→8 KiB. The Pak
        // file itself is also rounded to its final allocation unit.
        assert!(clustered >= byte_exact + 4_096 * 4);
    }

    #[test]
    fn output_space_estimate_derives_index_overhead_from_final_paths() {
        let short = vec![("A.bin".to_owned(), 1_u64)];
        let deep = vec![(
            "Local/DataBase/GameText/Localize/KO-KR/SystemText/A.bin".to_owned(),
            1_u64,
        )];
        let short_bytes = estimated_output_additional_bytes_with_bounds(
            "../../../Game/Content/",
            &short,
            OutputCompression::None,
            &BTreeMap::new(),
        )
        .unwrap();
        let deep_bytes = estimated_output_additional_bytes_with_bounds(
            "../../../Game/Content/Local/DataBase/",
            &deep,
            OutputCompression::None,
            &BTreeMap::new(),
        )
        .unwrap();

        assert!(deep_bytes > short_bytes);
    }

    #[test]
    fn output_space_estimate_rejects_sum_envelope_and_layout_overflow() {
        assert!(matches!(
            checked_logical_entry_bytes([u64::MAX, 1]),
            Err(MergeError::InvalidRequest(message))
                if message == "disk-space estimate overflow"
        ));
        let impossible = vec![("Huge.bin".to_owned(), u64::MAX)];
        assert!(matches!(
            estimated_output_additional_bytes_with_bounds(
                "../../../Game/Content/",
                &impossible,
                OutputCompression::None,
                &BTreeMap::new(),
            ),
            Err(MergeError::InvalidRequest(message))
                if message == "disk-space estimate overflow"
        ));
        let twenty_gib = vec![("Huge.bin".to_owned(), 20_u64 * 1024 * 1024 * 1024)];
        let sizes = required_oodle_block_sizes(&twenty_gib).unwrap();
        let (block_size, block_count) = pak::oodle_output_block_layout(twenty_gib[0].1).unwrap();
        assert!(block_size > u64::from(repak::COMPRESSION_BLOCK_SIZE));
        assert!(block_count <= V11_MAX_ENCODED_COMPRESSION_BLOCKS);
        assert!(sizes.contains(&block_size));
        let bounds = sizes
            .into_iter()
            .map(|size| (size, size + 256))
            .collect::<BTreeMap<_, _>>();
        let estimate = estimated_output_additional_bytes_with_bounds(
            "../../../Game/Content/",
            &twenty_gib,
            OutputCompression::Oodle,
            &bounds,
        )
        .unwrap();
        assert!(estimate > twenty_gib[0].1 * 2);

        let unrepresentable = vec![("Huge.bin".to_owned(), u64::MAX)];
        assert!(matches!(
            required_oodle_block_sizes(&unrepresentable),
            Err(MergeError::Pak(pak::PakError::Repak(message)))
                if message.contains("larger than u32")
        ));
    }

    #[test]
    fn partitioned_analysis_does_not_starve_independent_work_behind_databases() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::{Condvar, Mutex};
        use std::time::Duration;

        let independent_started = (Mutex::new(false), Condvar::new());
        let active_databases = AtomicUsize::new(0);
        let maximum_active_databases = AtomicUsize::new(0);
        let mut progress_events = Vec::new();

        let results = analyze_partitioned_units(
            4,
            4,
            vec![0, 1],
            vec![2, 3],
            |index, _detailed_progress| {
                if index < 2 {
                    let active = active_databases.fetch_add(1, Ordering::SeqCst) + 1;
                    maximum_active_databases.fetch_max(active, Ordering::SeqCst);
                    if index == 0 {
                        let (ready, ready_changed) = &independent_started;
                        let ready = ready.lock().expect("independent-work signal is available");
                        let (ready, timeout) = ready_changed
                            .wait_timeout_while(ready, Duration::from_secs(2), |ready| !*ready)
                            .expect("independent-work signal remains available");
                        if timeout.timed_out() || !*ready {
                            active_databases.fetch_sub(1, Ordering::SeqCst);
                            return Err(MergeError::InvalidRequest(
                                "independent work was starved behind database parsing".to_owned(),
                            ));
                        }
                    }
                    active_databases.fetch_sub(1, Ordering::SeqCst);
                } else {
                    let (ready, ready_changed) = &independent_started;
                    *ready.lock().expect("independent-work signal is available") = true;
                    ready_changed.notify_all();
                }
                Ok(index)
            },
            |index| Some(format!("unit-{index}")),
            &mut |completed, total, label| {
                progress_events.push((completed, total, label));
            },
        )
        .unwrap();

        assert_eq!(results, vec![0, 1, 2, 3]);
        assert_eq!(maximum_active_databases.load(Ordering::SeqCst), 2);
        assert!(
            progress_events
                .windows(2)
                .all(|pair| pair[0].0 <= pair[1].0)
        );
        assert!(
            progress_events
                .iter()
                .all(|(_, total, _)| *total == 4 * ANALYSIS_PROGRESS_STEPS_PER_UNIT)
        );
        assert_eq!(
            progress_events.last().map(|event| event.0),
            Some(4 * ANALYSIS_PROGRESS_STEPS_PER_UNIT)
        );
        assert!(progress_events.iter().all(|(_, _, label)| label.is_some()));
    }

    #[test]
    fn partitioned_analysis_caps_database_workers_at_two() {
        use std::collections::HashSet;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::{Barrier, Mutex};

        let first_pair_started = Barrier::new(2);
        let database_threads = Mutex::new(HashSet::new());
        let active_databases = AtomicUsize::new(0);
        let maximum_active_databases = AtomicUsize::new(0);

        let results = analyze_partitioned_units(
            8,
            8,
            vec![0, 1, 2, 3, 4, 5],
            vec![6, 7],
            |index, _detailed_progress| {
                if index < 6 {
                    database_threads
                        .lock()
                        .expect("database thread set is available")
                        .insert(std::thread::current().id());
                    let active = active_databases.fetch_add(1, Ordering::SeqCst) + 1;
                    maximum_active_databases.fetch_max(active, Ordering::SeqCst);
                    if index < 2 {
                        first_pair_started.wait();
                    }
                    active_databases.fetch_sub(1, Ordering::SeqCst);
                }
                Ok(index)
            },
            |index| Some(format!("unit-{index}")),
            &mut |_, _, _| {},
        )
        .unwrap();

        assert_eq!(results, (0..8).collect::<Vec<_>>());
        assert_eq!(
            database_threads
                .lock()
                .expect("database thread set is available")
                .len(),
            2
        );
        assert_eq!(maximum_active_databases.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn partitioned_analysis_keeps_error_selection_in_original_unit_order() {
        let mut completed = Vec::new();
        let error = analyze_partitioned_units(
            4,
            4,
            vec![0, 3],
            vec![1, 2],
            |index, _detailed_progress| match index {
                1 => Err(MergeError::InvalidRequest("unit one failed".to_owned())),
                3 => Err(MergeError::InvalidRequest("unit three failed".to_owned())),
                _ => Ok(index),
            },
            |index| Some(format!("unit-{index}")),
            &mut |count, total, _| completed.push((count, total)),
        )
        .unwrap_err();

        assert!(error.to_string().contains("unit one failed"));
        assert!(completed.windows(2).all(|pair| pair[0].0 <= pair[1].0));
        assert!(completed.iter().all(|(count, total)| count < total));
    }

    #[test]
    fn partitioned_analysis_propagates_cancellation_from_independent_work() {
        use std::sync::{Condvar, Mutex};

        let cancellation = CancellationToken::new();
        let cancellation_issued = (Mutex::new(false), Condvar::new());
        let mut completed = Vec::new();
        let error = analyze_partitioned_units(
            4,
            4,
            vec![0, 1],
            vec![2, 3],
            |index, _detailed_progress| {
                if index == 0 {
                    let (issued, issued_changed) = &cancellation_issued;
                    let mut issued = issued.lock().expect("cancellation signal is available");
                    while !*issued {
                        issued = issued_changed
                            .wait(issued)
                            .expect("cancellation signal remains available");
                    }
                } else if index == 2 {
                    cancellation.cancel();
                    let (issued, issued_changed) = &cancellation_issued;
                    *issued.lock().expect("cancellation signal is available") = true;
                    issued_changed.notify_all();
                }
                check_cancel(Some(&cancellation))?;
                Ok(index)
            },
            |index| Some(format!("unit-{index}")),
            &mut |count, total, _| completed.push((count, total)),
        )
        .unwrap_err();

        assert!(matches!(error, MergeError::Cancelled));
        assert!(completed.windows(2).all(|pair| pair[0].0 <= pair[1].0));
        assert!(completed.iter().all(|(count, total)| count < total));
    }

    fn fixstr(value: &str) -> Vec<u8> {
        let mut output = vec![0xa0 | value.len() as u8];
        output.extend_from_slice(value.as_bytes());
        output
    }

    fn test_row(id: u8, x: u8, y: u8) -> Vec<u8> {
        test_row_raw(id, &[x], &[y])
    }

    fn test_row_raw(id: u8, x: &[u8], y: &[u8]) -> Vec<u8> {
        let mut output = vec![0x83];
        output.extend(fixstr("m_id"));
        output.push(id);
        output.extend(fixstr("x"));
        output.extend_from_slice(x);
        output.extend(fixstr("y"));
        output.extend_from_slice(y);
        output
    }

    fn many_encoding_drift_fields_row(field_count: usize, use_float64: bool) -> Vec<u8> {
        let map_count = field_count + 1;
        let mut row = vec![0xDE];
        row.extend_from_slice(&(map_count as u16).to_be_bytes());
        row.extend(fixstr("m_id"));
        row.push(1);
        for index in 0..field_count {
            row.extend(fixstr(&format!("f{index:03}")));
            if use_float64 {
                row.push(0xCB);
                row.extend_from_slice(&1.0_f64.to_bits().to_be_bytes());
            } else {
                row.push(1);
            }
        }
        row
    }

    fn test_asset(row: Vec<u8>) -> Vec<u8> {
        test_asset_rows(vec![row])
    }

    fn test_asset_rows(rows: Vec<Vec<u8>>) -> Vec<u8> {
        assert!(rows.len() <= 15);
        let mut payload = vec![0x81];
        payload.extend(fixstr("m_DataList"));
        payload.push(0x90 | rows.len() as u8);
        for row in rows {
            payload.extend(row);
        }
        let mut prefix = [0x11; binary_asset::PREFIX_SIZE];
        prefix[6..10].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        let mut output = prefix.to_vec();
        output.extend(payload);
        output.extend([0xFA, 0xFB, 0xFC, 0xFD]);
        output.extend([0xC1, 0x83, 0x2A, 0x9E]);
        output
    }

    fn id_only_row(id: u8) -> Vec<u8> {
        let mut row = vec![0x81];
        row.extend(fixstr("m_id"));
        row.push(id);
        row
    }

    fn enemy_group_row(id: u8, enemy_id: u8) -> Vec<u8> {
        let mut row = vec![0x82];
        row.extend(fixstr("m_id"));
        row.push(id);
        row.extend(fixstr("m_EnemyID"));
        row.extend([0x91, enemy_id]);
        row
    }

    fn npc_placement_row(
        id: u8,
        map_id: u8,
        appear_label: &str,
        label: &str,
        owner_npc: u8,
        talk_id: u8,
    ) -> Vec<u8> {
        let mut row = vec![0x87];
        for (field, value) in [
            ("m_id", vec![id]),
            ("m_MapID", vec![map_id]),
            ("m_AppearLabel", fixstr(appear_label)),
            ("m_label", fixstr(label)),
            ("m_OwnerNPC", vec![owner_npc]),
            ("m_TalkID", vec![talk_id]),
        ] {
            row.extend(fixstr(field));
            row.extend(value);
        }
        // A harmless extra scalar keeps the synthetic row representative of a
        // wider NpcSet map without changing the placement detector inputs.
        row.extend(fixstr("m_IconType"));
        row.push(0);
        row
    }

    fn append_uasset_name(output: &mut Vec<u8>, value: &str) {
        output.extend_from_slice(&((value.len() + 1) as i32).to_le_bytes());
        output.extend_from_slice(value.as_bytes());
        output.push(0);
        output.extend_from_slice(&[0; 4]);
    }

    fn uasset_with_metadata(
        base: &str,
        uexp_size: usize,
        package_guid_byte: u8,
        bulk_data_start_offset: Option<u64>,
        trailing_padding: usize,
    ) -> Vec<u8> {
        let serial_size = (uexp_size - binary_asset::PACKAGE_TAG_SIZE) as u64;
        let logical_base = base
            .trim_start_matches('/')
            .strip_prefix("Octopath_Traveler0/Content/")
            .unwrap_or_else(|| base.trim_start_matches('/'));
        let package_path = format!("/Game/{logical_base}");
        let object_name = logical_base.rsplit('/').next().unwrap();
        let folder_len = package_path.len() + 1;
        let folder_end = 0x24 + folder_len;
        let bulk_offset = folder_end + 0x8C;
        let name_offset = (bulk_offset + 8 + 3) & !3;
        let names = [
            package_path.as_str(),
            "/Script/CoreUObject",
            "/Script/Kingship",
            "BinaryAsset",
            "Class",
            "Default__BinaryAsset",
            object_name,
            "Package",
        ];

        let mut uasset = vec![0; name_offset];
        for name in names {
            append_uasset_name(&mut uasset, name);
        }
        while uasset.len() % 4 != 0 {
            uasset.push(0);
        }
        let import_offset = uasset.len();
        uasset.resize(import_offset + 3 * 32, 0);
        // ClassIndex -2 resolves to import 1, whose ObjectName is BinaryAsset.
        uasset[import_offset + 32 + 20..import_offset + 32 + 24]
            .copy_from_slice(&3_u32.to_le_bytes());
        while uasset.len() % 4 != 0 {
            uasset.push(0);
        }
        let export_offset = uasset.len();
        uasset.resize(export_offset + 112 + trailing_padding, 0);
        let header_size = uasset.len();

        uasset[..binary_asset::PACKAGE_TAG_SIZE].copy_from_slice(&[0xC1, 0x83, 0x2A, 0x9E]);
        uasset[4..8].copy_from_slice(&(-8_i32).to_le_bytes());
        uasset[0x1C..0x20].copy_from_slice(&(header_size as u32).to_le_bytes());
        uasset[0x20..0x24].copy_from_slice(&(folder_len as i32).to_le_bytes());
        uasset[0x24..0x24 + package_path.len()].copy_from_slice(package_path.as_bytes());
        uasset[0x24 + package_path.len()] = 0;
        uasset[folder_end..folder_end + 4].copy_from_slice(&0x8000_2200_u32.to_le_bytes());
        uasset[folder_end + 4..folder_end + 8].copy_from_slice(&(names.len() as u32).to_le_bytes());
        uasset[folder_end + 8..folder_end + 12]
            .copy_from_slice(&(name_offset as u32).to_le_bytes());
        uasset[folder_end + 0x1C..folder_end + 0x20].copy_from_slice(&1_u32.to_le_bytes());
        uasset[folder_end + 0x20..folder_end + 0x24]
            .copy_from_slice(&(export_offset as u32).to_le_bytes());
        uasset[folder_end + 0x24..folder_end + 0x28].copy_from_slice(&3_u32.to_le_bytes());
        uasset[folder_end + 0x28..folder_end + 0x2C]
            .copy_from_slice(&(import_offset as u32).to_le_bytes());
        uasset[folder_end + 0x40..folder_end + 0x50].fill(package_guid_byte);
        let bulk_value = bulk_data_start_offset.unwrap_or_else(|| header_size as u64 + serial_size);
        uasset[bulk_offset..bulk_offset + 8].copy_from_slice(&bulk_value.to_le_bytes());

        uasset[export_offset..export_offset + 4].copy_from_slice(&(-2_i32).to_le_bytes());
        uasset[export_offset + 0x10..export_offset + 0x14].copy_from_slice(&6_u32.to_le_bytes());
        uasset[export_offset + 0x1C..export_offset + 0x24]
            .copy_from_slice(&serial_size.to_le_bytes());
        uasset[export_offset + 0x24..export_offset + 0x2C]
            .copy_from_slice(&(header_size as u64).to_le_bytes());
        uasset
    }

    fn uasset_with_serial_size(base: &str, uexp_size: usize) -> Vec<u8> {
        uasset_with_metadata(base, uexp_size, 0x11, None, 0)
    }

    fn audited_en_us_gametextskill_uasset(
        uexp_size: usize,
        package_guid_byte: u8,
        bulk_data_start_offset: u64,
    ) -> Vec<u8> {
        uasset_with_metadata(
            "Local/DataBase/GameText/Localize/EN-US/SystemText/GameTextSkill",
            uexp_size,
            package_guid_byte,
            Some(bulk_data_start_offset),
            0,
        )
    }

    fn analyze_en_us_gametextskill_header_mutation(
        directory: &Path,
        stem: &str,
        mutate_donor: impl FnOnce(&mut [u8]),
    ) -> MergePlan {
        let pak_a = directory.join(format!("{stem}A_P.pak"));
        let pak_b = directory.join(format!("{stem}B_P.pak"));
        let base = "Local/DataBase/GameText/Localize/EN-US/SystemText/GameTextSkill";
        let uasset_path = format!("{base}.uasset");
        let uexp_path = format!("{base}.uexp");
        let carrier_uexp = test_asset(test_row(1, 10, 20));
        let donor_uexp = test_asset(test_row(1, 11, 20));
        let header_size = uasset_with_serial_size(base, carrier_uexp.len()).len();
        let carrier_uasset = audited_en_us_gametextskill_uasset(
            carrier_uexp.len(),
            0x11,
            (header_size + carrier_uexp.len() - binary_asset::PACKAGE_TAG_SIZE) as u64,
        );
        let mut donor_uasset = carrier_uasset.clone();
        mutate_donor(&mut donor_uasset);
        pak::write_pak_v11(
            &pak_a,
            "../../../Example/Content/",
            [
                pak::PakWriteEntry::new(&uasset_path, carrier_uasset),
                pak::PakWriteEntry::new(&uexp_path, carrier_uexp),
            ],
        )
        .unwrap();
        pak::write_pak_v11(
            &pak_b,
            "../../../Example/Content/",
            [
                pak::PakWriteEntry::new(&uasset_path, donor_uasset),
                pak::PakWriteEntry::new(&uexp_path, donor_uexp),
            ],
        )
        .unwrap();
        analyze(AnalysisRequest {
            pak_paths: vec![pak_a.clone(), pak_b],
            carrier_path: pak_a,
        })
        .unwrap()
    }

    fn write_npc_set_test_pak(path: &Path, rows: Vec<Vec<u8>>) {
        let base = "Local/DataBase/Npc/NpcSetList_Test_A1";
        let uexp = test_asset_rows(rows);
        pak::write_pak_v11(
            path,
            "../../../Example/Content/",
            [
                pak::PakWriteEntry::new(
                    format!("{base}.uasset"),
                    uasset_with_serial_size(base, uexp.len()),
                ),
                pak::PakWriteEntry::new(format!("{base}.uexp"), uexp),
            ],
        )
        .unwrap();
    }

    fn write_versioned_test_pak(
        path: &Path,
        version: repak::Version,
        mount_point: &str,
        entries: impl IntoIterator<Item = (String, Vec<u8>)>,
    ) {
        let path_hash_seed = ((version.version_major() as u32) >= 10).then_some(0_u64);
        let mut writer = repak::PakBuilder::new().writer(
            std::io::Cursor::new(Vec::new()),
            version,
            mount_point.to_owned(),
            path_hash_seed,
        );
        for (entry_path, bytes) in entries {
            writer
                .write_file(&entry_path, false, &bytes)
                .expect("write synthetic Pak entry");
        }
        let bytes = writer
            .write_index()
            .expect("write synthetic Pak index")
            .into_inner();
        fs::write(path, bytes).unwrap();
    }

    fn analyze_test_paks_with_threads(
        pak_paths: Vec<PathBuf>,
        carrier_path: PathBuf,
        multithreaded: bool,
    ) -> MergeAnalysisSession {
        let archives = pak_paths
            .iter()
            .map(|path| PakArchive::open(path).map(Arc::new))
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();
        analyze_with_archives_progress_cancel_and_threads(
            AnalysisRequest {
                pak_paths,
                carrier_path,
            },
            archives,
            &CancellationToken::new(),
            multithreaded,
            |_, _, _| {},
        )
        .unwrap()
    }

    fn write_compressed_test_pak(
        path: &Path,
        compression: repak::Compression,
        entries: impl IntoIterator<Item = (String, Vec<u8>)>,
    ) {
        let mut writer = repak::PakBuilder::new().compression([compression]).writer(
            std::io::Cursor::new(Vec::new()),
            repak::Version::V11,
            "../../../Example/Content/".to_owned(),
            Some(0),
        );
        for (entry_path, bytes) in entries {
            writer
                .write_file(&entry_path, true, &bytes)
                .expect("write compressed synthetic Pak entry");
        }
        let bytes = writer
            .write_index()
            .expect("write compressed synthetic Pak index")
            .into_inner();
        fs::write(path, bytes).unwrap();
    }

    fn analyze_npc_set_test_rows(
        directory: &Path,
        stem: &str,
        rows_a: Vec<Vec<u8>>,
        rows_b: Vec<Vec<u8>>,
    ) -> (PathBuf, PathBuf, MergePlan) {
        let pak_a = directory.join(format!("{stem}A_P.pak"));
        let pak_b = directory.join(format!("{stem}B_P.pak"));
        write_npc_set_test_pak(&pak_a, rows_a);
        write_npc_set_test_pak(&pak_b, rows_b);
        let plan = analyze(AnalysisRequest {
            pak_paths: vec![pak_a.clone(), pak_b.clone()],
            carrier_path: pak_a.clone(),
        })
        .unwrap();
        (pak_a, pak_b, plan)
    }

    fn parallel_condition_row(id: u8, conditions: &[u8], params: &[u8]) -> Vec<u8> {
        assert!(conditions.len() <= 15);
        assert!(params.len() <= 15);
        let mut row = vec![0x83];
        row.extend(fixstr("m_id"));
        row.push(id);
        row.extend(fixstr("m_Conditions"));
        row.push(0x90 | conditions.len() as u8);
        row.extend_from_slice(conditions);
        row.extend(fixstr("m_Params"));
        row.push(0x90 | params.len() as u8);
        row.extend_from_slice(params);
        row
    }

    fn test_asset_with_shell_value(row: Vec<u8>, shell_value: u8) -> Vec<u8> {
        let mut payload = vec![0x82];
        payload.extend(fixstr("m_DataList"));
        payload.push(0x91);
        payload.extend(row);
        payload.extend(fixstr("m_ShellValue"));
        payload.push(shell_value);
        let mut prefix = [0x11; binary_asset::PREFIX_SIZE];
        prefix[6..10].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        let mut output = prefix.to_vec();
        output.extend(payload);
        output.extend([0xFA, 0xFB, 0xFC, 0xFD]);
        output.extend([0xC1, 0x83, 0x2A, 0x9E]);
        output
    }

    #[test]
    fn serial_size_patch_uses_only_the_structural_export_slot() {
        let old_size = 100_usize;
        let new_size = 120_usize;
        let old_serial = (old_size - binary_asset::PACKAGE_TAG_SIZE) as u64;
        let base = "Local/DataBase/Test/SerialPatch";
        let mut uasset = uasset_with_metadata(base, old_size, 0x11, None, 16);
        let unrelated_offset = uasset.len() - 8;
        uasset[unrelated_offset..].copy_from_slice(&old_serial.to_le_bytes());
        let descriptor = parse_uasset_shell(&uasset, old_size, Some(base)).unwrap();
        let patched = patch_serial_size(&uasset, old_size, new_size).unwrap();
        assert_eq!(
            &patched[descriptor.serial_size_offset..descriptor.serial_size_offset + 8],
            &((new_size - binary_asset::PACKAGE_TAG_SIZE) as u64).to_le_bytes()
        );
        assert_eq!(&patched[unrelated_offset..], &old_serial.to_le_bytes());
        for index in 0..uasset.len() {
            if !(descriptor.serial_size_offset..descriptor.serial_size_offset + 8).contains(&index)
            {
                assert_eq!(
                    patched[index], uasset[index],
                    "unexpected change at {index:#x}"
                );
            }
        }
    }

    #[test]
    fn serial_size_patch_preserves_bulk_boundary_and_validates_even_without_size_change() {
        let old_uexp_size = 100usize;
        let new_uexp_size = 140usize;
        let old_serial = (old_uexp_size - binary_asset::PACKAGE_TAG_SIZE) as u64;
        let base = "Local/DataBase/Test/BulkBoundary";
        let first = uasset_with_serial_size(base, old_uexp_size);
        let header_size = first.len() as u64;
        let uasset =
            uasset_with_metadata(base, old_uexp_size, 0x11, Some(header_size + old_serial), 0);
        let descriptor = parse_uasset_shell(&uasset, old_uexp_size, Some(base)).unwrap();
        let original_bulk = uasset
            [descriptor._bulk_data_start_offset..descriptor._bulk_data_start_offset + 8]
            .to_vec();

        let patched = patch_serial_size(&uasset, old_uexp_size, new_uexp_size).unwrap();
        assert_eq!(
            &patched[descriptor._bulk_data_start_offset..descriptor._bulk_data_start_offset + 8],
            original_bulk
        );

        let mut malformed = uasset.clone();
        malformed[0] ^= 0x7F;
        assert!(patch_serial_size(&malformed, old_uexp_size, old_uexp_size).is_err());
    }

    #[test]
    fn pak_only_analysis_never_requires_game_version_acknowledgement() {
        let temp = tempfile::tempdir().unwrap();
        let first = temp.path().join("PlainA_P.pak");
        let second = temp.path().join("PlainB_P.pak");
        pak::write_pak_v11(
            &first,
            "../../../Example/Content/",
            [pak::PakWriteEntry::new("Loose/A.bin", b"a".to_vec())],
        )
        .unwrap();
        pak::write_pak_v11(
            &second,
            "../../../Example/Content/",
            [pak::PakWriteEntry::new("Loose/B.bin", b"b".to_vec())],
        )
        .unwrap();

        let plan = analyze(AnalysisRequest {
            pak_paths: vec![first.clone(), second],
            carrier_path: first,
        })
        .unwrap();
        resolve(
            plan.clone(),
            ResolutionSet {
                plan_id: plan.plan_id,
                ..ResolutionSet::default()
            },
        )
        .unwrap();
    }

    #[test]
    fn complete_inventory_profile_is_pinned_serialized_and_deterministic() {
        let temp = tempfile::tempdir().unwrap();
        let first = temp.path().join("Ot0ProfileA_P.pak");
        let second = temp.path().join("Ot0ProfileB_P.pak");
        let mount = "../../../Octopath_Traveler0/Content/";
        pak::write_pak_v11(
            &first,
            mount,
            [pak::PakWriteEntry::new(
                "Local/DataBase/Skill/SkillID.uasset",
                b"header".to_vec(),
            )],
        )
        .unwrap();
        pak::write_pak_v11(
            &second,
            mount,
            [pak::PakWriteEntry::new("Loose/Second.bin", b"b".to_vec())],
        )
        .unwrap();
        let request = AnalysisRequest {
            pak_paths: vec![first.clone(), second],
            carrier_path: first,
        };
        let plan = analyze(request.clone()).unwrap();
        assert_eq!(plan.selected_profile_id.as_deref(), Some(OT0_PROFILE_ID));
        assert_eq!(
            plan.profile_detection_status,
            Some(ProfileDetectionStatus::Selected)
        );

        let serialized = serde_json::to_vec(&plan).unwrap();
        let restored: MergePlan = serde_json::from_slice(&serialized).unwrap();
        assert_eq!(restored, plan);
        let repeated = analyze(request).unwrap();
        assert_eq!(repeated.plan_id, plan.plan_id);
        assert_eq!(repeated.selected_profile_id, plan.selected_profile_id);

        let mut legacy_json = serde_json::to_value(&plan).unwrap();
        let object = legacy_json.as_object_mut().unwrap();
        object.remove("selected_profile_id");
        object.remove("profile_detection_status");
        let legacy: MergePlan = serde_json::from_value(legacy_json).unwrap();
        assert_eq!(legacy.selected_profile_id, None);
        assert_eq!(legacy.profile_detection_status, None);
    }

    #[test]
    fn other_game_with_ot0_table_suffix_uses_generic_profile_and_skips_ot0_links() {
        let temp = tempfile::tempdir().unwrap();
        let first = temp.path().join("OtherProfileA_P.pak");
        let second = temp.path().join("OtherProfileB_P.pak");
        let mount = "../../../OtherGame/Content/";
        pak::write_pak_v11(
            &first,
            mount,
            [pak::PakWriteEntry::new(
                "Local/DataBase/Skill/SkillID.uasset",
                b"header".to_vec(),
            )],
        )
        .unwrap();
        pak::write_pak_v11(
            &second,
            mount,
            [pak::PakWriteEntry::new("Loose/Second.bin", b"b".to_vec())],
        )
        .unwrap();
        let plan = analyze(AnalysisRequest {
            pak_paths: vec![first.clone(), second],
            carrier_path: first.clone(),
        })
        .unwrap();
        assert_eq!(plan.selected_profile_id, None);
        assert_eq!(
            plan.profile_detection_status,
            Some(ProfileDetectionStatus::GenericNoMatch)
        );
        assert!(
            plan.warnings
                .iter()
                .any(|warning| warning.contains("using general field rules"))
        );

        let archive = PakArchive::open(&first).unwrap();
        let reference_warnings =
            validate_references_for_pinned_profile(&plan, &archive, None, true, &mut |_, _, _| {})
                .unwrap();
        assert_eq!(reference_warnings.len(), 1);
        assert!(reference_warnings[0].contains("require the OCTOPATH TRAVELER 0 profile"));
    }

    #[test]
    fn mixed_nested_mounts_rebase_paths_and_preserve_raw_source_mapping() {
        let temp = tempfile::tempdir().unwrap();
        let root_pak = temp.path().join("Root_P.pak");
        let nested_pak = temp.path().join("NestedV3_P.pak");
        let root_mount = "../../../Example/Content/";
        let nested_mount = concat!(
            "../../../Example/Content/Local/DataBase/GameText/Localize/",
            "KO-KR/SystemText/"
        );
        let nested_base = "Local/DataBase/GameText/Localize/KO-KR/SystemText/GameTextSkill";

        write_versioned_test_pak(
            &root_pak,
            repak::Version::V11,
            root_mount,
            [("Loose/Root.bin".to_owned(), b"root".to_vec())],
        );
        write_versioned_test_pak(
            &nested_pak,
            repak::Version::V3,
            nested_mount,
            [
                ("GameTextSkill.uasset".to_owned(), b"nested-header".to_vec()),
                ("GameTextSkill.uexp".to_owned(), b"nested-payload".to_vec()),
            ],
        );

        let plan = analyze(AnalysisRequest {
            pak_paths: vec![root_pak.clone(), nested_pak.clone()],
            carrier_path: root_pak,
        })
        .unwrap();
        assert!(plan.conflicts.is_empty());
        assert!(plan.inputs.iter().any(|input| {
            input.path == nested_pak
                && input.pak_version == Some(3)
                && input.mount_point.as_deref() == Some(nested_mount)
        }));
        let nested_asset = plan
            .assets
            .iter()
            .find(|asset| asset.virtual_path == nested_base)
            .expect("rebased nested package");
        assert_eq!(nested_asset.action, AssetActionKind::Copy);

        let output = temp.path().join("MixedMerged_P.pak");
        let report = write(
            resolve(
                plan.clone(),
                ResolutionSet {
                    plan_id: plan.plan_id,
                    ..ResolutionSet::default()
                },
            )
            .unwrap(),
            &output,
        )
        .unwrap();
        assert_eq!(report.output_pak_version, 11);
        assert_eq!(report.output_mount_point, root_mount);

        let archive = PakArchive::open(&output).unwrap();
        assert_eq!(archive.inventory().mount_point, root_mount);
        assert_eq!(archive.read_entry("Loose/Root.bin").unwrap(), b"root");
        assert_eq!(
            archive
                .read_entry(&format!("{nested_base}.uasset"))
                .unwrap(),
            b"nested-header"
        );
        assert_eq!(
            archive.read_entry(&format!("{nested_base}.uexp")).unwrap(),
            b"nested-payload"
        );
    }

    #[test]
    fn unrelated_mounts_with_only_traversal_in_common_are_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let first = temp.path().join("First_P.pak");
        let second = temp.path().join("Second_P.pak");
        write_versioned_test_pak(
            &first,
            repak::Version::V11,
            "../../../FirstGame/Content/",
            [("Loose/First.bin".to_owned(), b"first".to_vec())],
        );
        write_versioned_test_pak(
            &second,
            repak::Version::V3,
            "../../../SecondGame/Content/",
            [("Loose/Second.bin".to_owned(), b"second".to_vec())],
        );

        let error = analyze(AnalysisRequest {
            pak_paths: vec![first.clone(), second],
            carrier_path: first,
        })
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("point to different game folders"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn mount_that_escapes_after_named_component_is_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let first = temp.path().join("First_P.pak");
        let escaping = temp.path().join("Escaping_P.pak");
        write_versioned_test_pak(
            &first,
            repak::Version::V11,
            "../../../Example/Content/",
            [("Loose/First.bin".to_owned(), b"first".to_vec())],
        );
        write_versioned_test_pak(
            &escaping,
            repak::Version::V3,
            "../../../Example/Content/../Other/",
            [("Loose/Second.bin".to_owned(), b"second".to_vec())],
        );

        let error = analyze(AnalysisRequest {
            pak_paths: vec![first.clone(), escaping],
            carrier_path: first,
        })
        .unwrap_err();
        assert!(
            error.to_string().contains("leaves its game folder"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn unresolved_conflicts_block_resolution() {
        let conflict = make_conflict(
            ConflictKind::FieldValue,
            "Local/DataBase/Test",
            Some(1),
            Some("field:x"),
            "test",
            vec![Variant {
                id: "v1".to_owned(),
                label: "A".to_owned(),
                input_id: "a".to_owned(),
                raw_sha256: "00".to_owned(),
                semantic_sha256: "00".to_owned(),
                preview: "1".to_owned(),
                marker: "integer".to_owned(),
                provenance: Provenance {
                    input_id: "a".to_owned(),
                    input_path: PathBuf::from("a.pak"),
                    entry_path: None,
                    raw_sha256: "00".to_owned(),
                },
            }],
            true,
        );
        let plan = MergePlan {
            schema_version: 1,
            plan_id: "p".to_owned(),
            request: AnalysisRequest {
                pak_paths: vec![PathBuf::from("a.pak")],
                carrier_path: PathBuf::from("a.pak"),
            },
            inputs: vec![],
            carrier_input_id: "a".to_owned(),
            assets: vec![],
            conflicts: vec![conflict],
            warnings: vec![],
            selected_profile_id: None,
            profile_detection_status: None,
            encoding_drift_count: 0,
            full_reencode_forbidden: true,
        };
        let resolutions = ResolutionSet {
            plan_id: "p".to_owned(),
            ..ResolutionSet::default()
        };
        assert!(resolve(plan, resolutions).is_err());
    }

    #[test]
    fn encoding_drift_rejects_explicit_choice_and_writes_fixed_carrier_raw() {
        let temp = tempfile::tempdir().unwrap();
        let pak_a = temp.path().join("DriftA_P.pak");
        let pak_b = temp.path().join("DriftB_P.pak");
        let base = "Local/DataBase/Test/EncodingDrift";
        let uasset = format!("{base}.uasset");
        let uexp = format!("{base}.uexp");
        let mount = "../../../Example/Content/";
        for (path, x) in [(&pak_a, [0xcc, 1]), (&pak_b, [0xd0, 1])] {
            let uexp_bytes = test_asset(test_row_raw(1, &x, &[2]));
            pak::write_pak_v11(
                path,
                mount,
                [
                    pak::PakWriteEntry::new(
                        &uasset,
                        uasset_with_serial_size(base, uexp_bytes.len()),
                    ),
                    pak::PakWriteEntry::new(&uexp, uexp_bytes),
                ],
            )
            .unwrap();
        }
        let plan = analyze(AnalysisRequest {
            pak_paths: vec![pak_a.clone(), pak_b],
            carrier_path: pak_a.clone(),
        })
        .unwrap();
        let drift = plan
            .conflicts
            .iter()
            .find(|conflict| conflict.kind == ConflictKind::EncodingDrift)
            .unwrap();
        assert!(!drift.blocking);

        let mut explicit = ResolutionSet {
            plan_id: plan.plan_id.clone(),
            ..ResolutionSet::default()
        };
        explicit
            .choices
            .insert(drift.id.clone(), drift.variants[0].id.clone());
        assert!(resolve(plan.clone(), explicit).is_err());

        let output = temp.path().join("DriftMerged_P.pak");
        let report = write(
            resolve(
                plan.clone(),
                ResolutionSet {
                    plan_id: plan.plan_id.clone(),
                    ..ResolutionSet::default()
                },
            )
            .unwrap(),
            &output,
        )
        .unwrap();
        assert!(!report.resolutions.choices.contains_key(&drift.id));
        let record = report
            .resolved_conflicts
            .iter()
            .find(|record| record.conflict_id == drift.id)
            .unwrap();
        assert!(record.automatic);
        assert_eq!(
            record
                .selected_variant
                .as_ref()
                .map(|variant| &variant.input_id),
            Some(&plan.carrier_input_id)
        );

        let archive = PakArchive::open(&output).unwrap();
        let merged_bytes = archive.read_entry(&uexp).unwrap();
        let merged = BinaryAsset::parse(&merged_bytes).unwrap();
        let row = merged.row(1).unwrap().unwrap();
        assert_eq!(
            row.node.map_get("x").unwrap().unwrap().raw(row.source),
            [0xcc, 1]
        );
    }

    #[test]
    fn encoding_drift_is_counted_exactly_but_only_bounded_examples_are_kept() {
        let temp = tempfile::tempdir().unwrap();
        let pak_a = temp.path().join("ManyDriftA_P.pak");
        let pak_b = temp.path().join("ManyDriftB_P.pak");
        let base = "Local/DataBase/Test/ManyEncodingDrifts";
        let uasset = format!("{base}.uasset");
        let uexp = format!("{base}.uexp");
        for (path, use_float64) in [(&pak_a, false), (&pak_b, true)] {
            let uexp_bytes = test_asset(many_encoding_drift_fields_row(70, use_float64));
            pak::write_pak_v11(
                path,
                "../../../Example/Content/",
                [
                    pak::PakWriteEntry::new(
                        &uasset,
                        uasset_with_serial_size(base, uexp_bytes.len()),
                    ),
                    pak::PakWriteEntry::new(&uexp, uexp_bytes),
                ],
            )
            .unwrap();
        }

        let plan = analyze(AnalysisRequest {
            pak_paths: vec![pak_a.clone(), pak_b],
            carrier_path: pak_a,
        })
        .unwrap();
        assert_eq!(plan.encoding_drift_count, 70);
        assert_eq!(
            plan.conflicts
                .iter()
                .filter(|conflict| conflict.kind == ConflictKind::EncodingDrift)
                .count(),
            MAX_ENCODING_DRIFT_SAMPLES_PER_ASSET
        );
        assert!(!plan.conflicts.iter().any(|conflict| conflict.blocking));
        assert!(plan.warnings.iter().any(|warning| {
            warning.contains("Encoding drift retained for 70 item(s)")
                && warning.contains("64 example(s)")
        }));
    }

    #[test]
    fn encoding_drift_report_falls_back_to_first_variant_without_carrier() {
        let first = Variant {
            id: "variant-a".to_owned(),
            label: "A".to_owned(),
            input_id: "input-a".to_owned(),
            raw_sha256: "11".repeat(32),
            semantic_sha256: "22".repeat(32),
            preview: "1".to_owned(),
            marker: "positive-fixint".to_owned(),
            provenance: Provenance {
                input_id: "input-a".to_owned(),
                input_path: PathBuf::from("a.pak"),
                entry_path: Some("Local/DataBase/Test.uexp".to_owned()),
                raw_sha256: "11".repeat(32),
            },
        };
        let second = Variant {
            id: "variant-b".to_owned(),
            label: "B".to_owned(),
            input_id: "input-b".to_owned(),
            raw_sha256: "33".repeat(32),
            semantic_sha256: "22".repeat(32),
            preview: "1".to_owned(),
            marker: "uint8".to_owned(),
            provenance: Provenance {
                input_id: "input-b".to_owned(),
                input_path: PathBuf::from("b.pak"),
                entry_path: Some("Local/DataBase/Test.uexp".to_owned()),
                raw_sha256: "33".repeat(32),
            },
        };
        let conflict = make_conflict(
            ConflictKind::EncodingDrift,
            "Local/DataBase/Test",
            Some(1),
            Some("field:x"),
            "same value with different raw encoding",
            vec![first, second],
            false,
        );
        let conflict_id = conflict.id.clone();
        let plan = MergePlan {
            schema_version: 1,
            plan_id: "plan".to_owned(),
            request: AnalysisRequest {
                pak_paths: vec![PathBuf::from("a.pak")],
                carrier_path: PathBuf::from("missing-carrier.pak"),
            },
            inputs: Vec::new(),
            carrier_input_id: "missing-carrier".to_owned(),
            assets: Vec::new(),
            conflicts: vec![conflict],
            warnings: Vec::new(),
            selected_profile_id: None,
            profile_detection_status: None,
            encoding_drift_count: 0,
            full_reencode_forbidden: true,
        };
        let records =
            build_report_conflict_records(&plan, &ResolutionSet::default(), "missing-carrier");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].conflict_id, conflict_id);
        assert!(records[0].automatic);
        assert_eq!(
            records[0]
                .selected_variant
                .as_ref()
                .map(|variant| variant.id.as_str()),
            Some("variant-a")
        );
    }

    #[test]
    fn byte_identical_paks_at_different_paths_are_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let first = temp.path().join("SameA_P.pak");
        let second = temp.path().join("SameB_P.pak");
        pak::write_pak_v11(
            &first,
            "../../../Example/Content/",
            [pak::PakWriteEntry::new("Loose/Test.bin", b"same".to_vec())],
        )
        .unwrap();
        fs::copy(&first, &second).unwrap();
        let error = analyze(AnalysisRequest {
            pak_paths: vec![first.clone(), second.clone()],
            carrier_path: first,
        })
        .unwrap_err();
        assert!(error.to_string().contains("Pak files are identical"));
        assert!(error.to_string().contains(&second.display().to_string()));
    }

    #[test]
    fn matching_database_row_layout_batches_only_conflicting_variants() {
        let temp = tempfile::tempdir().unwrap();
        let pak_a = temp.path().join("LazyRowsA_P.pak");
        let pak_b = temp.path().join("LazyRowsB_P.pak");
        let base = "Local/DataBase/Test/LazyRows";
        let uasset = format!("{base}.uasset");
        let uexp = format!("{base}.uexp");
        for (path, x, y) in [(&pak_a, 10_u8, 20_u8), (&pak_b, 11_u8, 21_u8)] {
            let bytes = test_asset(test_row(1, x, y));
            pak::write_pak_v11(
                path,
                "../../../Example/Content/",
                [
                    pak::PakWriteEntry::new(&uasset, uasset_with_serial_size(base, bytes.len())),
                    pak::PakWriteEntry::new(&uexp, bytes),
                ],
            )
            .unwrap();
        }

        TEST_WHOLE_ROW_VARIANT_BUILD_CALLS.with(|calls| calls.set(0));
        TEST_ATOMIC_VARIANT_BUILD_CALLS.with(|calls| calls.set(0));
        TEST_ATOMIC_VARIANT_ROW_PARSE_CALLS.with(|calls| calls.set(0));
        let session = analyze_test_paks_with_threads(vec![pak_a.clone(), pak_b], pak_a, false);

        for field in ["field:x", "field:y"] {
            assert!(session.plan().conflicts.iter().any(|conflict| {
                conflict.kind == ConflictKind::FieldValue
                    && conflict.group_id.as_deref() == Some(field)
            }));
        }
        TEST_WHOLE_ROW_VARIANT_BUILD_CALLS.with(|calls| assert_eq!(calls.get(), 0));
        // Only choices for the changed x/y fields are materialized. Matching
        // m_id is compared by hash without an unused preview/provenance record.
        TEST_ATOMIC_VARIANT_BUILD_CALLS.with(|calls| assert_eq!(calls.get(), 4));
        // Both conflicting fields are materialized in one row parse per Pak,
        // rather than one full MessagePack row parse per field and Pak.
        TEST_ATOMIC_VARIANT_ROW_PARSE_CALLS.with(|calls| assert_eq!(calls.get(), 2));
    }

    #[test]
    fn structural_mismatch_builds_whole_row_variants_lazily_in_legacy_order() {
        let temp = tempfile::tempdir().unwrap();
        let pak_a = temp.path().join("LazyMismatchA_P.pak");
        let pak_b = temp.path().join("LazyMismatchB_P.pak");
        let pak_c = temp.path().join("LazyMismatchC_P.pak");
        let base = "Local/DataBase/Test/LazyMismatch";
        let uasset = format!("{base}.uasset");
        let uexp = format!("{base}.uexp");
        for (path, row) in [
            (&pak_a, test_row(1, 10, 20)),
            (&pak_b, id_only_row(1)),
            (&pak_c, test_row(1, 11, 21)),
        ] {
            let bytes = test_asset(row);
            pak::write_pak_v11(
                path,
                "../../../Example/Content/",
                [
                    pak::PakWriteEntry::new(&uasset, uasset_with_serial_size(base, bytes.len())),
                    pak::PakWriteEntry::new(&uexp, bytes),
                ],
            )
            .unwrap();
        }

        TEST_WHOLE_ROW_VARIANT_BUILD_CALLS.with(|calls| calls.set(0));
        let session =
            analyze_test_paks_with_threads(vec![pak_a.clone(), pak_b, pak_c], pak_a, false);
        let conflict = session
            .plan()
            .conflicts
            .iter()
            .find(|conflict| {
                conflict.kind == ConflictKind::StructureMismatch
                    && conflict.group_id.as_deref() == Some("__whole_row__")
            })
            .unwrap();

        TEST_WHOLE_ROW_VARIANT_BUILD_CALLS.with(|calls| assert_eq!(calls.get(), 1));
        let actual_ids = conflict
            .variants
            .iter()
            .map(|variant| variant.input_id.clone())
            .collect::<Vec<_>>();
        let mut expected_ids = session
            .plan()
            .inputs
            .iter()
            .map(|input| input.id.clone())
            .collect::<Vec<_>>();
        expected_ids.sort();
        assert_eq!(actual_ids, expected_ids);
        assert_eq!(conflict.variants.len(), 3);
        assert!(conflict.variants.iter().all(|variant| {
            variant.provenance.entry_path.as_deref() == Some(uexp.as_str())
                && variant.preview.starts_with("row 1, ")
                && variant.marker.starts_with("row-map:0x")
        }));
    }

    #[test]
    fn database_shell_mismatch_requires_whole_package_selection() {
        let temp = tempfile::tempdir().unwrap();
        let pak_a = temp.path().join("ShellA_P.pak");
        let pak_b = temp.path().join("ShellB_P.pak");
        let base = "Local/DataBase/Test/Shell";
        let uasset = format!("{base}.uasset");
        let uexp = format!("{base}.uexp");
        for (path, shell_value) in [(&pak_a, 1_u8), (&pak_b, 2_u8)] {
            let uexp_bytes = test_asset_with_shell_value(test_row(1, 10, 20), shell_value);
            pak::write_pak_v11(
                path,
                "../../../Example/Content/",
                [
                    pak::PakWriteEntry::new(
                        &uasset,
                        uasset_with_serial_size(base, uexp_bytes.len()),
                    ),
                    pak::PakWriteEntry::new(&uexp, uexp_bytes),
                ],
            )
            .unwrap();
        }

        let plan = analyze(AnalysisRequest {
            pak_paths: vec![pak_a.clone(), pak_b],
            carrier_path: pak_a,
        })
        .unwrap();
        let conflict = plan
            .conflicts
            .iter()
            .find(|conflict| conflict.asset_path == base)
            .unwrap();
        assert_eq!(conflict.kind, ConflictKind::StructureMismatch);
        assert!(conflict.blocking);
        assert_eq!(conflict.row_id, None);
        assert_eq!(
            plan.assets
                .iter()
                .find(|asset| asset.virtual_path == base)
                .unwrap()
                .action,
            AssetActionKind::SelectOpaque
        );
    }

    #[test]
    fn valid_binary_asset_outside_local_database_uses_field_merge() {
        let temp = tempfile::tempdir().unwrap();
        let pak_a = temp.path().join("GenericPathA_P.pak");
        let pak_b = temp.path().join("GenericPathB_P.pak");
        let base = "Custom/GameData/BalanceTable";
        let uasset = format!("{base}.uasset");
        let uexp = format!("{base}.uexp");
        for (path, x) in [(&pak_a, 10_u8), (&pak_b, 11_u8)] {
            let bytes = test_asset(test_row(1, x, 20));
            pak::write_pak_v11(
                path,
                "../../../Example/Content/",
                [
                    pak::PakWriteEntry::new(&uasset, uasset_with_serial_size(base, bytes.len())),
                    pak::PakWriteEntry::new(&uexp, bytes),
                ],
            )
            .unwrap();
        }

        let plan = analyze(AnalysisRequest {
            pak_paths: vec![pak_a.clone(), pak_b],
            carrier_path: pak_a,
        })
        .unwrap();
        let asset = plan
            .assets
            .iter()
            .find(|asset| asset.virtual_path == base)
            .unwrap();
        assert_eq!(asset.action, AssetActionKind::MergeDatabase);
        assert!(plan.conflicts.iter().any(|conflict| {
            conflict.asset_path == base
                && conflict.kind == ConflictKind::FieldValue
                && conflict.group_id.as_deref() == Some("field:x")
        }));
    }

    #[test]
    fn non_binary_package_outside_database_falls_back_to_whole_package_choice() {
        let temp = tempfile::tempdir().unwrap();
        let pak_a = temp.path().join("BlueprintA_P.pak");
        let pak_b = temp.path().join("BlueprintB_P.pak");
        let base = "Blueprints/BP_TestActor";
        for (path, suffix) in [(&pak_a, 1_u8), (&pak_b, 2_u8)] {
            pak::write_pak_v11(
                path,
                "../../../Example/Content/",
                [
                    pak::PakWriteEntry::new(
                        format!("{base}.uasset"),
                        vec![0xC1, 0x83, 0x2A, 0x9E, suffix],
                    ),
                    pak::PakWriteEntry::new(format!("{base}.uexp"), vec![0x42, 0x50, suffix]),
                ],
            )
            .unwrap();
        }

        let plan = analyze(AnalysisRequest {
            pak_paths: vec![pak_a.clone(), pak_b],
            carrier_path: pak_a,
        })
        .unwrap();
        let asset = plan
            .assets
            .iter()
            .find(|asset| asset.virtual_path == base)
            .unwrap();
        assert_eq!(asset.action, AssetActionKind::SelectOpaque);
        assert_eq!(asset.conflict_ids.len(), 1);
        assert!(plan.conflicts.iter().any(|conflict| {
            conflict.asset_path == base && conflict.blocking && conflict.row_id.is_none()
        }));
    }

    #[test]
    fn differing_donor_uasset_header_is_warned_and_carrier_header_is_retained() {
        let temp = tempfile::tempdir().unwrap();
        let pak_a = temp.path().join("HeaderA_P.pak");
        let pak_b = temp.path().join("HeaderB_P.pak");
        let base = "Local/DataBase/GameText/Localize/EN-US/SystemText/GameTextSkill";
        let uasset_path = format!("{base}.uasset");
        let uexp_path = format!("{base}.uexp");
        let carrier_uexp = test_asset(test_row_raw(1, &[10], &[20]));
        let donor_uexp = test_asset(test_row_raw(1, &[0xCC, 11], &[20]));
        let carrier_uexp_size = carrier_uexp.len();
        let donor_uexp_size = donor_uexp.len();
        let carrier_header_size = uasset_with_serial_size(base, carrier_uexp_size).len();
        let donor_header_size = uasset_with_serial_size(base, donor_uexp_size).len();
        let carrier_uasset = audited_en_us_gametextskill_uasset(
            carrier_uexp_size,
            0x11,
            (carrier_header_size + carrier_uexp_size - binary_asset::PACKAGE_TAG_SIZE) as u64,
        );
        let donor_uasset = audited_en_us_gametextskill_uasset(
            donor_uexp_size,
            0xA5,
            (donor_header_size + donor_uexp_size - binary_asset::PACKAGE_TAG_SIZE) as u64,
        );

        pak::write_pak_v11(
            &pak_a,
            "../../../Example/Content/",
            [
                pak::PakWriteEntry::new(&uasset_path, carrier_uasset.clone()),
                pak::PakWriteEntry::new(&uexp_path, carrier_uexp),
            ],
        )
        .unwrap();
        pak::write_pak_v11(
            &pak_b,
            "../../../Example/Content/",
            [
                pak::PakWriteEntry::new(&uasset_path, donor_uasset),
                pak::PakWriteEntry::new(&uexp_path, donor_uexp),
            ],
        )
        .unwrap();

        let plan = analyze(AnalysisRequest {
            pak_paths: vec![pak_a.clone(), pak_b.clone()],
            carrier_path: pak_a,
        })
        .unwrap();
        let asset = plan
            .assets
            .iter()
            .find(|asset| asset.virtual_path == base)
            .unwrap();
        assert_eq!(asset.action, AssetActionKind::MergeDatabase);
        assert!(asset.warnings.iter().any(|warning| {
            warning.contains("related .uasset file differs between Paks")
                && warning.contains("structurally verified data-size field")
        }));
        assert!(
            plan.warnings
                .iter()
                .any(|warning| { warning.contains("related .uasset file differs between Paks") })
        );

        let conflict = plan
            .conflicts
            .iter()
            .find(|conflict| conflict.blocking)
            .unwrap();
        assert_eq!(conflict.group_id.as_deref(), Some("field:x"));
        let donor_input = plan
            .inputs
            .iter()
            .find(|input| input.path == pak_b)
            .unwrap();
        let donor_variant = conflict
            .variants
            .iter()
            .find(|variant| variant.input_id == donor_input.id)
            .unwrap();
        let resolved = resolve(
            plan.clone(),
            ResolutionSet {
                plan_id: plan.plan_id,
                choices: BTreeMap::from([(conflict.id.clone(), donor_variant.id.clone())]),
            },
        )
        .unwrap();
        let output = temp.path().join("HeaderMerged_P.pak");
        let report = write(resolved, &output).unwrap();
        assert!(report.verification_passed);
        let archive = PakArchive::open(output).unwrap();
        let expected_uasset =
            patch_serial_size(&carrier_uasset, carrier_uexp_size, donor_uexp_size).unwrap();
        assert_eq!(archive.read_entry(&uasset_path).unwrap(), expected_uasset);
    }

    #[test]
    fn database_bulk_boundary_difference_allows_field_level_merge() {
        let temp = tempfile::tempdir().unwrap();
        let pak_a = temp.path().join("BulkA_P.pak");
        let pak_b = temp.path().join("BulkB_P.pak");
        let base = "Local/DataBase/Enemy/EnemyGroups";
        let uasset_path = format!("{base}.uasset");
        let uexp_path = format!("{base}.uexp");
        let uexp_a = test_asset(test_row_raw(1, &[10], &[20]));
        let uexp_b = test_asset(test_row_raw(1, &[0xCC, 11], &[20]));
        let header_size = uasset_with_serial_size(base, uexp_a.len()).len() as u64;
        let uasset_a = uasset_with_metadata(
            base,
            uexp_a.len(),
            0x11,
            Some(header_size + (uexp_a.len() - binary_asset::PACKAGE_TAG_SIZE) as u64),
            0,
        );
        let uasset_b = uasset_with_metadata(
            base,
            uexp_b.len(),
            0xA5,
            Some(header_size + (uexp_b.len() - binary_asset::PACKAGE_TAG_SIZE) as u64),
            0,
        );
        pak::write_pak_v11(
            &pak_a,
            "../../../Example/Content/",
            [
                pak::PakWriteEntry::new(&uasset_path, uasset_a),
                pak::PakWriteEntry::new(&uexp_path, uexp_a),
            ],
        )
        .unwrap();
        pak::write_pak_v11(
            &pak_b,
            "../../../Example/Content/",
            [
                pak::PakWriteEntry::new(&uasset_path, uasset_b),
                pak::PakWriteEntry::new(&uexp_path, uexp_b),
            ],
        )
        .unwrap();

        let plan = analyze(AnalysisRequest {
            pak_paths: vec![pak_a.clone(), pak_b],
            carrier_path: pak_a,
        })
        .unwrap();
        let asset = plan
            .assets
            .iter()
            .find(|asset| asset.virtual_path == base)
            .unwrap();
        assert_eq!(asset.action, AssetActionKind::MergeDatabase);
        assert!(
            asset
                .warnings
                .iter()
                .any(|warning| warning.contains(".uasset"))
        );
        assert!(plan.conflicts.iter().any(|conflict| {
            conflict.asset_path == base && conflict.kind == ConflictKind::FieldValue
        }));
    }

    #[test]
    fn malformed_uasset_structure_remains_a_structure_mismatch() {
        let temp = tempfile::tempdir().unwrap();
        let base = "Local/DataBase/GameText/Localize/EN-US/SystemText/GameTextSkill";
        for plan in [
            analyze_en_us_gametextskill_header_mutation(temp.path(), "Magic", |header| {
                header[0] ^= 0x7f;
            }),
            analyze_en_us_gametextskill_header_mutation(temp.path(), "Flags", |header| {
                let folder_len = read_u32_le_at(header, 0x20).unwrap() as usize;
                header[0x24 + folder_len] ^= 0x01;
            }),
        ] {
            let asset = plan
                .assets
                .iter()
                .find(|asset| asset.virtual_path == base)
                .unwrap();
            assert_eq!(asset.action, AssetActionKind::SelectOpaque);
            assert!(plan.conflicts.iter().any(|conflict| {
                conflict.asset_path == base
                    && conflict.kind == ConflictKind::StructureMismatch
                    && conflict.blocking
            }));
        }
    }

    #[test]
    fn known_reference_validation_blocks_only_when_both_tables_are_embedded() {
        let temp = tempfile::tempdir().unwrap();
        let valid = temp.path().join("Valid_P.pak");
        let broken = temp.path().join("Broken_P.pak");
        let group_base = "Octopath_Traveler0/Content/Local/DataBase/Enemy/EnemyGroups";
        let enemy_base = "Octopath_Traveler0/Content/Local/DataBase/Enemy/EnemyID";
        let make_entries = |enemy_reference| {
            let group_uexp = test_asset(enemy_group_row(1, enemy_reference));
            let enemy_uexp = test_asset(id_only_row(7));
            vec![
                pak::PakWriteEntry::new(
                    format!("{group_base}.uasset"),
                    uasset_with_serial_size(group_base, group_uexp.len()),
                ),
                pak::PakWriteEntry::new(format!("{group_base}.uexp"), group_uexp),
                pak::PakWriteEntry::new(
                    format!("{enemy_base}.uasset"),
                    uasset_with_serial_size(enemy_base, enemy_uexp.len()),
                ),
                pak::PakWriteEntry::new(format!("{enemy_base}.uexp"), enemy_uexp),
            ]
        };
        pak::write_pak_v11(&valid, "../../../Example/Content/", make_entries(7)).unwrap();
        pak::write_pak_v11(&broken, "../../../Example/Content/", make_entries(8)).unwrap();

        let warnings = validate_known_references(&valid).unwrap();
        assert!(
            warnings
                .iter()
                .any(|warning| warning.contains("Reference checks: 1 rule(s)"))
        );
        let error = validate_known_references(&broken).unwrap_err();
        assert!(error.to_string().contains("reference(s) point to rows"));
        assert!(error.to_string().contains("EnemyID id 8"));
    }

    #[test]
    fn npc_logical_placement_collision_is_informational_deterministic_and_keeps_union() {
        let temp = tempfile::tempdir().unwrap();
        let row_a = npc_placement_row(10, 7, "SLOT_A", "SharedNpc", 30, 40);
        let row_b = npc_placement_row(20, 7, "slot_a", "SharedNpc", 31, 41);
        let (pak_a, pak_b, plan) = analyze_npc_set_test_rows(
            temp.path(),
            "Collision",
            vec![row_a.clone()],
            vec![row_b.clone()],
        );

        let collision = plan
            .conflicts
            .iter()
            .find(|conflict| conflict.kind == ConflictKind::PotentialPlacementCollision)
            .expect("logical placement warning");
        assert_eq!(
            serde_json::to_string(&collision.kind).unwrap(),
            "\"POTENTIAL_PLACEMENT_COLLISION\""
        );
        assert!(!collision.blocking);
        assert_eq!(collision.row_id, None);
        assert_eq!(
            collision.group_id.as_deref(),
            Some("npc_placement:map=7;appear=slot_a")
        );
        assert_eq!(collision.variants.len(), 2);
        assert!(collision.message.contains("rows will still be combined"));
        assert!(collision.message.contains("only one may appear in game"));
        assert!(collision.variants.iter().any(|variant| {
            variant.provenance.input_path == pak_a
                && variant
                    .provenance
                    .entry_path
                    .as_deref()
                    .is_some_and(|path| path.ends_with("NpcSetList_Test_A1.uexp"))
                && variant.preview.contains("m_OwnerNPC=30")
                && variant.preview.contains("m_TalkID=40")
        }));
        assert!(collision.variants.iter().any(|variant| {
            variant.provenance.input_path == pak_b
                && variant.preview.contains("m_OwnerNPC=31")
                && variant.preview.contains("m_TalkID=41")
        }));
        assert!(plan.warnings.iter().any(|warning| {
            warning.contains("NpcSet location") && warning.contains("only one may appear in game")
        }));
        let asset = plan
            .assets
            .iter()
            .find(|asset| asset.virtual_path.ends_with("NpcSetList_Test_A1"))
            .unwrap();
        assert_eq!(asset.action, AssetActionKind::MergeDatabase);
        assert!(asset.conflict_ids.is_empty());
        assert!(
            asset
                .warnings
                .iter()
                .any(|warning| warning.contains("NpcSet location")
                    && warning.contains("only one may appear in game"))
        );
        assert!(
            plan.unresolved_conflict_ids(&ResolutionSet::default())
                .is_empty()
        );

        let repeated = analyze(plan.request.clone()).unwrap();
        assert_eq!(repeated.plan_id, plan.plan_id);
        assert_eq!(repeated.conflicts, plan.conflicts);
        assert_eq!(repeated.warnings, plan.warnings);

        let mut invalid_choice = ResolutionSet {
            plan_id: plan.plan_id.clone(),
            ..ResolutionSet::default()
        };
        invalid_choice
            .choices
            .insert(collision.id.clone(), collision.variants[0].id.clone());
        assert!(resolve(plan.clone(), invalid_choice).is_err());

        let output = temp.path().join("CollisionMerged_P.pak");
        let report = write(
            resolve(
                plan.clone(),
                ResolutionSet {
                    plan_id: plan.plan_id.clone(),
                    ..ResolutionSet::default()
                },
            )
            .unwrap(),
            &output,
        )
        .unwrap();
        assert!(report.verification_passed);
        assert!(report.conflicts.iter().any(|conflict| {
            conflict.kind == ConflictKind::PotentialPlacementCollision && !conflict.blocking
        }));
        assert!(
            report
                .warnings
                .iter()
                .any(|warning| warning.contains("NpcSet location")
                    && warning.contains("only one may appear in game"))
        );
        let record = report
            .resolved_conflicts
            .iter()
            .find(|record| record.conflict_id == collision.id)
            .unwrap();
        assert!(!record.automatic);
        assert!(record.selected_variant.is_none());

        let archive = PakArchive::open(&output).unwrap();
        let merged_bytes = archive
            .read_entry("Local/DataBase/Npc/NpcSetList_Test_A1.uexp")
            .unwrap();
        let merged = BinaryAsset::parse(&merged_bytes).unwrap();
        assert_eq!(merged.rows().unwrap().len(), 2);
        assert_eq!(merged.row(10).unwrap().unwrap().node_ref().raw(), row_a);
        assert_eq!(merged.row(20).unwrap().unwrap().node_ref().raw(), row_b);
    }

    #[test]
    fn npc_placement_warning_suppresses_equivalent_bindings_and_uses_primary_key() {
        let temp = tempfile::tempdir().unwrap();
        let (_, _, same_binding) = analyze_npc_set_test_rows(
            temp.path(),
            "SameBinding",
            vec![npc_placement_row(10, 7, "SLOT_A", "Shared", 30, 40)],
            vec![npc_placement_row(20, 7, "SLOT_A", "Shared", 30, 40)],
        );
        assert!(
            same_binding
                .conflicts
                .iter()
                .all(|conflict| { conflict.kind != ConflictKind::PotentialPlacementCollision })
        );

        let (_, _, distinct_primary_keys) = analyze_npc_set_test_rows(
            temp.path(),
            "PrimaryWins",
            vec![npc_placement_row(10, 7, "SLOT_A", "Shared", 30, 40)],
            vec![npc_placement_row(20, 7, "SLOT_B", "Shared", 31, 41)],
        );
        assert!(
            distinct_primary_keys
                .conflicts
                .iter()
                .all(|conflict| { conflict.kind != ConflictKind::PotentialPlacementCollision })
        );

        let shared_a = vec![
            npc_placement_row(10, 7, "SLOT_A", "Shared", 30, 40),
            npc_placement_row(20, 7, "SLOT_A", "Shared", 31, 41),
            npc_placement_row(1, 8, "SLOT_Z", "Other", 50, 60),
        ];
        let shared_b = vec![
            npc_placement_row(10, 7, "SLOT_A", "Shared", 30, 40),
            npc_placement_row(20, 7, "SLOT_A", "Shared", 31, 41),
            npc_placement_row(1, 8, "SLOT_Z", "Other", 50, 61),
        ];
        let (_, _, same_provider_pattern) =
            analyze_npc_set_test_rows(temp.path(), "SamePattern", shared_a, shared_b);
        assert!(
            same_provider_pattern
                .conflicts
                .iter()
                .all(|conflict| { conflict.kind != ConflictKind::PotentialPlacementCollision })
        );
    }

    #[test]
    fn npc_placement_warning_falls_back_to_normalized_label() {
        let temp = tempfile::tempdir().unwrap();
        let (_, _, plan) = analyze_npc_set_test_rows(
            temp.path(),
            "Fallback",
            vec![npc_placement_row(10, 0, "", "Shared_Label", 30, 40)],
            vec![npc_placement_row(20, 0, "", " shared_label ", 31, 41)],
        );
        let collision = plan
            .conflicts
            .iter()
            .find(|conflict| conflict.kind == ConflictKind::PotentialPlacementCollision)
            .unwrap();
        assert_eq!(
            collision.group_id.as_deref(),
            Some("npc_placement:label=shared_label")
        );
        assert!(collision.message.contains("fallback m_label=shared_label"));
    }

    #[test]
    fn streamed_audit_is_finalized_from_the_verified_pak_inventory() {
        let temp = tempfile::tempdir().unwrap();
        let output = temp.path().join("Audit_P.pak");
        let entry_path = "Local/DataBase/Test/Audit.uexp";
        let entry_bytes = b"already-streamed-database";
        pak::write_pak_v11(
            &output,
            "../../../Example/Content/",
            [pak::PakWriteEntry::new(entry_path, entry_bytes.to_vec())],
        )
        .unwrap();
        let inventory = pak::inspect_pak(&output).unwrap();
        let verified_entry_sha256 = inventory
            .entries
            .iter()
            .find(|entry| entry.path == entry_path)
            .unwrap()
            .sha256
            .clone();
        let writer_source_sha256 =
            BTreeMap::from([(entry_path.to_owned(), verified_entry_sha256.clone())]);

        let make_pending = |expected_entry_size| {
            let mut ledger = Sha256::new();
            ledger.update(b"row-checks-completed-while-streaming");
            PendingRawPreservationAudit {
                asset_path: "Local/DataBase/Test/Audit".to_owned(),
                pak_entry_path: entry_path.to_owned(),
                expected_entry_size,
                audit: RawAuditAccumulator {
                    ledger,
                    verified_rows: 3,
                    verified_units: 5,
                    preserved_nodes: 7,
                    replaced_nodes: 2,
                },
            }
        };

        let audits = finalize_raw_preservation_audits(
            vec![make_pending(entry_bytes.len() as u64)],
            &inventory,
            &writer_source_sha256,
        )
        .unwrap();
        assert_eq!(audits.len(), 1);
        assert_eq!(audits[0].verified_row_count, 3);
        assert_eq!(audits[0].verified_atomic_unit_count, 5);
        assert_eq!(
            audits[0].entry_sha256,
            inventory
                .entries
                .iter()
                .find(|entry| entry.path == entry_path)
                .unwrap()
                .sha256
        );
        assert!(raw_audit_inventory_errors(&audits, &inventory).is_empty());

        let same_size_wrong_source = BTreeMap::from([(
            entry_path.to_owned(),
            hex::encode(Sha256::digest(vec![0_u8; entry_bytes.len()])),
        )]);
        let error = finalize_raw_preservation_audits(
            vec![make_pending(entry_bytes.len() as u64)],
            &inventory,
            &same_size_wrong_source,
        )
        .unwrap_err();
        assert!(error.to_string().contains("source hash mismatch"));

        let error = finalize_raw_preservation_audits(
            vec![make_pending(entry_bytes.len() as u64 + 1)],
            &inventory,
            &writer_source_sha256,
        )
        .unwrap_err();
        assert!(error.to_string().contains("size mismatch"));
    }

    #[test]
    fn compressed_input_is_decoded_before_writing_uncompressed_merged_output() {
        let temp = tempfile::tempdir().unwrap();
        let compressed_pak = temp.path().join("Compressed_P.pak");
        let plain_pak = temp.path().join("Plain_P.pak");
        let compressed_data = vec![0x5a; 400_000];
        write_compressed_test_pak(
            &compressed_pak,
            repak::Compression::Zstd,
            [("Loose/Compressed.bin".to_owned(), compressed_data.clone())],
        );
        pak::write_pak_v11(
            &plain_pak,
            "../../../Example/Content/",
            [pak::PakWriteEntry::new(
                "Loose/Plain.bin",
                b"plain".to_vec(),
            )],
        )
        .unwrap();

        let plan = analyze(AnalysisRequest {
            pak_paths: vec![compressed_pak.clone(), plain_pak],
            carrier_path: compressed_pak,
        })
        .unwrap();
        assert!(plan.conflicts.iter().all(|conflict| !conflict.blocking));
        let resolved = resolve(
            plan.clone(),
            ResolutionSet {
                plan_id: plan.plan_id,
                ..ResolutionSet::default()
            },
        )
        .unwrap();
        let output = temp.path().join("CompressedMerged_P.pak");
        let report = write(resolved, &output).unwrap();
        assert_eq!(report.output_compression, "None");
        let merged = pak::PakArchive::open(&output).unwrap();
        assert_eq!(
            merged.read_entry("Loose/Compressed.bin").unwrap(),
            compressed_data
        );
        assert_eq!(merged.read_entry("Loose/Plain.bin").unwrap(), b"plain");
    }

    #[test]
    fn output_storage_validation_distinguishes_plain_oodle_and_other_codecs() {
        let temp = tempfile::tempdir().unwrap();
        let plain_path = temp.path().join("Plain.pak");
        pak::write_pak_v11(
            &plain_path,
            "../../../Example/Content/",
            [pak::PakWriteEntry::new("Data/Test.bin", vec![1; 32_000])],
        )
        .unwrap();
        let plain = pak::inspect_pak(&plain_path).unwrap();
        assert!(output_compression_errors(&plain, OutputCompression::None).is_empty());
        assert!(!output_compression_errors(&plain, OutputCompression::Oodle).is_empty());

        let compressed_path = temp.path().join("Zstd.pak");
        write_compressed_test_pak(
            &compressed_path,
            repak::Compression::Zstd,
            [("Data/Test.bin".to_owned(), vec![1; 32_000])],
        );
        let compressed = pak::inspect_pak(&compressed_path).unwrap();
        assert!(!output_compression_errors(&compressed, OutputCompression::None).is_empty());
        let oodle_errors = output_compression_errors(&compressed, OutputCompression::Oodle);
        assert!(
            oodle_errors
                .iter()
                .any(|error| error.contains("does not declare only Oodle"))
        );
    }

    #[test]
    fn live_analysis_session_reuses_compact_indexes_for_cancel_and_completed_retries() {
        let directory = tempfile::tempdir().unwrap();
        let pak_a = directory.path().join("SessionA_P.pak");
        let pak_b = directory.path().join("SessionB_P.pak");
        let output = directory.path().join("SessionMerged_P.pak");
        let retry_output = directory.path().join("SessionRetry_P.pak");
        let failed_output = directory.path().join("SessionFailed_P.pak");
        let cancelled_output = directory.path().join("SessionCancelled_P.pak");
        let base = "Local/DataBase/Test/SessionIndexReuse";
        let uasset_path = format!("{base}.uasset");
        let uexp_path = format!("{base}.uexp");
        let first = test_asset(test_row(1, 10, 20));
        let second = test_asset(test_row(1, 11, 20));
        pak::write_pak_v11(
            &pak_a,
            "../../../Example/Content/",
            [
                pak::PakWriteEntry::new(&uasset_path, uasset_with_serial_size(base, first.len())),
                pak::PakWriteEntry::new(&uexp_path, first),
            ],
        )
        .unwrap();
        pak::write_pak_v11(
            &pak_b,
            "../../../Example/Content/",
            [
                pak::PakWriteEntry::new(&uasset_path, uasset_with_serial_size(base, second.len())),
                pak::PakWriteEntry::new(&uexp_path, second),
            ],
        )
        .unwrap();

        let archives = vec![
            Arc::new(PakArchive::open(&pak_a).unwrap()),
            Arc::new(PakArchive::open(&pak_b).unwrap()),
        ];
        let session = analyze_with_archives(
            AnalysisRequest {
                pak_paths: vec![pak_a.clone(), pak_b],
                carrier_path: pak_a,
            },
            archives,
        )
        .unwrap();
        assert!(session.cached_database_bytes() > 0);
        assert_eq!(session.parsed_databases.len(), 1);
        assert_eq!(session.parsed_databases[&sort_key(base)].len(), 2);
        assert_eq!(
            test_database_index_build_count(base),
            2,
            "analysis must index each provider exactly once"
        );

        let mut resolutions = ResolutionSet {
            plan_id: session.plan().plan_id.clone(),
            ..ResolutionSet::default()
        };
        for conflict in session.plan().conflicts.iter().filter(|item| item.blocking) {
            resolutions
                .choices
                .insert(conflict.id.clone(), conflict.variants[0].id.clone());
        }

        let first_blocking = session
            .plan()
            .conflicts
            .iter()
            .find(|conflict| conflict.blocking)
            .unwrap();
        let mut invalid_resolutions = resolutions.clone();
        invalid_resolutions
            .choices
            .insert(first_blocking.id.clone(), "missing-test-variant".to_owned());
        let error = write_session_with_options_and_progress(
            &session,
            invalid_resolutions,
            &failed_output,
            WriteOptions::default(),
            |_| {},
        )
        .unwrap_err();
        assert!(matches!(error, MergeError::InvalidResolution(_)));
        assert!(!failed_output.exists());
        assert_eq!(test_database_index_build_count(base), 2);

        let token = CancellationToken::new();
        let cancel_signal = token.clone();
        let error = write_session_with_options_progress_and_cancel(
            &session,
            resolutions.clone(),
            &cancelled_output,
            WriteOptions::default(),
            &token,
            |event| {
                if event.stage == MergeProgressStage::BuildingDatabase {
                    cancel_signal.cancel();
                }
            },
        )
        .unwrap_err();
        assert!(matches!(error, MergeError::Cancelled));
        assert!(!cancelled_output.exists());
        assert!(!cancelled_output.with_extension("pak.partial").exists());
        assert_eq!(
            test_database_index_build_count(base),
            2,
            "a cancelled write must leave the session index reusable"
        );

        let mut progress_events = Vec::new();
        let report = write_session_with_options_and_progress(
            &session,
            resolutions,
            &output,
            WriteOptions::default(),
            |event| progress_events.push(event),
        )
        .unwrap();
        assert!(report.verification_passed);
        assert!(output.is_file());
        assert_eq!(test_database_index_build_count(base), 2);
        assert!(
            progress_events
                .iter()
                .all(|event| event.stage != MergeProgressStage::IndexingDatabase)
        );
        let database_progress = progress_events
            .iter()
            .filter(|event| event.stage == MergeProgressStage::BuildingDatabase)
            .collect::<Vec<_>>();
        assert!(!database_progress.is_empty());
        assert!(database_progress.windows(2).all(|events| {
            events[0].total == events[1].total
                && events[0].completed <= events[1].completed
                && events[1].completed <= events[1].total
        }));

        let retry_report = write_session_with_options_and_progress(
            &session,
            report.resolutions,
            &retry_output,
            WriteOptions::default(),
            |_| {},
        )
        .unwrap();
        assert!(retry_report.verification_passed);
        assert!(retry_output.is_file());
        assert_eq!(
            test_database_index_build_count(base),
            2,
            "completed writes must not consume or rebuild the session index"
        );
    }

    #[test]
    fn compatibility_write_indexes_each_provider_once_per_required_analysis() {
        let directory = tempfile::tempdir().unwrap();
        let pak_a = directory.path().join("CompatibilityA_P.pak");
        let pak_b = directory.path().join("CompatibilityB_P.pak");
        let output = directory.path().join("CompatibilityMerged_P.pak");
        let base = "Local/DataBase/Test/CompatibilityIndexReuse";
        let uasset_path = format!("{base}.uasset");
        let uexp_path = format!("{base}.uexp");
        for (path, value) in [(&pak_a, 10_u8), (&pak_b, 11_u8)] {
            let bytes = test_asset(test_row(1, value, 20));
            pak::write_pak_v11(
                path,
                "../../../Example/Content/",
                [
                    pak::PakWriteEntry::new(
                        &uasset_path,
                        uasset_with_serial_size(base, bytes.len()),
                    ),
                    pak::PakWriteEntry::new(&uexp_path, bytes),
                ],
            )
            .unwrap();
        }

        let request = AnalysisRequest {
            pak_paths: vec![pak_a.clone(), pak_b],
            carrier_path: pak_a,
        };
        let plan = analyze(request).unwrap();
        assert_eq!(test_database_index_build_count(base), 2);
        let mut resolutions = ResolutionSet {
            plan_id: plan.plan_id.clone(),
            ..ResolutionSet::default()
        };
        for conflict in plan.conflicts.iter().filter(|item| item.blocking) {
            resolutions
                .choices
                .insert(conflict.id.clone(), conflict.variants[0].id.clone());
        }

        let report = write_with_options(
            resolve(plan, resolutions).unwrap(),
            &output,
            WriteOptions::default(),
        )
        .unwrap();
        assert!(report.verification_passed);
        assert!(output.is_file());
        assert_eq!(
            test_database_index_build_count(base),
            4,
            "the compatibility API reanalyzes once, but its build must not add a third indexing pass"
        );
    }

    #[test]
    fn database_build_progress_counts_base_and_added_rows_together() {
        let directory = tempfile::tempdir().unwrap();
        let pak_a = directory.path().join("ProgressA_P.pak");
        let pak_b = directory.path().join("ProgressB_P.pak");
        let output = directory.path().join("ProgressMerged_P.pak");
        let base = "Local/DataBase/Test/Progress";
        let uasset_path = format!("{base}.uasset");
        let uexp_path = format!("{base}.uexp");
        let first = test_asset(test_row(1, 10, 20));
        let second = test_asset_rows(vec![test_row(1, 10, 20), test_row(2, 30, 40)]);
        for (path, bytes) in [(&pak_a, first), (&pak_b, second)] {
            pak::write_pak_v11(
                path,
                "../../../Example/Content/",
                [
                    pak::PakWriteEntry::new(
                        &uasset_path,
                        uasset_with_serial_size(base, bytes.len()),
                    ),
                    pak::PakWriteEntry::new(&uexp_path, bytes),
                ],
            )
            .unwrap();
        }

        let plan = analyze(AnalysisRequest {
            pak_paths: vec![pak_a.clone(), pak_b],
            carrier_path: pak_a,
        })
        .unwrap();
        let resolved = resolve(
            plan.clone(),
            ResolutionSet {
                plan_id: plan.plan_id,
                ..ResolutionSet::default()
            },
        )
        .unwrap();
        let mut progress_events = Vec::new();
        write_with_options_and_progress(resolved, &output, WriteOptions::default(), |event| {
            progress_events.push(event)
        })
        .unwrap();

        let database_progress = progress_events
            .iter()
            .filter(|event| event.stage == MergeProgressStage::BuildingDatabase)
            .collect::<Vec<_>>();
        assert_eq!(database_progress.len(), 2);
        assert_eq!(
            (database_progress[0].completed, database_progress[0].total),
            (0, 2)
        );
        assert_eq!(
            (database_progress[1].completed, database_progress[1].total),
            (2, 2)
        );
        assert!(
            database_progress[0]
                .current_item
                .as_deref()
                .is_some_and(|item| item.contains(base) && item.contains("m_id 1"))
        );
        assert!(
            database_progress[1]
                .current_item
                .as_deref()
                .is_some_and(|item| item.contains(base) && item.contains("m_id 2"))
        );
    }

    #[test]
    fn end_to_end_pak_only_field_choices_produce_one_verified_pak() {
        let temp = tempfile::tempdir().unwrap();
        let pak_a = temp.path().join("A_P.pak");
        let pak_b = temp.path().join("B_P.pak");
        let base = "Local/DataBase/Test/Test";
        let uasset = format!("{base}.uasset");
        let uexp = format!("{base}.uexp");
        let mount = "../../../Example/Content/";
        let uexp_a = test_asset(test_row(1, 10, 0));
        pak::write_pak_v11(
            &pak_a,
            mount,
            [
                pak::PakWriteEntry::new(&uasset, uasset_with_serial_size(base, uexp_a.len())),
                pak::PakWriteEntry::new(&uexp, uexp_a),
            ],
        )
        .unwrap();
        let uexp_b = test_asset(test_row(1, 0, 20));
        pak::write_pak_v11(
            &pak_b,
            mount,
            [
                pak::PakWriteEntry::new(&uasset, uasset_with_serial_size(base, uexp_b.len())),
                pak::PakWriteEntry::new(&uexp, uexp_b),
            ],
        )
        .unwrap();

        let plan = analyze(AnalysisRequest {
            pak_paths: vec![pak_a.clone(), pak_b.clone()],
            carrier_path: pak_a.clone(),
        })
        .unwrap();
        let input_a = plan
            .inputs
            .iter()
            .find(|input| input.path == pak_a)
            .unwrap()
            .id
            .clone();
        let input_b = plan
            .inputs
            .iter()
            .find(|input| input.path == pak_b)
            .unwrap()
            .id
            .clone();
        let mut resolutions = ResolutionSet {
            plan_id: plan.plan_id.clone(),
            ..ResolutionSet::default()
        };
        for conflict in plan.conflicts.iter().filter(|conflict| conflict.blocking) {
            let donor = match conflict.group_id.as_deref() {
                Some("field:x") => &input_a,
                Some("field:y") => &input_b,
                other => panic!("unexpected blocking conflict: {other:?}"),
            };
            let variant = conflict
                .variants
                .iter()
                .find(|variant| &variant.input_id == donor)
                .unwrap();
            resolutions
                .choices
                .insert(conflict.id.clone(), variant.id.clone());
        }
        let resolved = resolve(plan, resolutions).unwrap();
        let output = temp.path().join("Merged_P.pak");
        let mut progress_events = Vec::new();
        let report = write_with_options_and_progress(
            resolved.clone(),
            &output,
            WriteOptions::default(),
            |event| progress_events.push(event),
        )
        .unwrap();
        assert!(progress_events.iter().any(|event| {
            event.stage == MergeProgressStage::CheckingInputs && event.total == 2
        }));
        assert!(progress_events.iter().any(|event| {
            event.stage == MergeProgressStage::WritingPak && event.current_item.is_some()
        }));
        let database_progress = progress_events
            .iter()
            .filter(|event| event.stage == MergeProgressStage::BuildingDatabase)
            .collect::<Vec<_>>();
        assert_eq!(database_progress.len(), 2);
        assert_eq!(
            (database_progress[0].completed, database_progress[0].total),
            (0, 1)
        );
        assert_eq!(
            (database_progress[1].completed, database_progress[1].total),
            (1, 1)
        );
        assert!(database_progress.iter().all(|event| {
            event
                .current_item
                .as_deref()
                .is_some_and(|item| item.contains(base) && item.contains("m_id 1"))
        }));
        assert_eq!(
            progress_events.last(),
            Some(&MergeProgress {
                stage: MergeProgressStage::Finalizing,
                completed: 1,
                total: 1,
                current_item: None,
            })
        );
        assert!(report.verification_passed);
        assert_eq!(report.raw_preserved_nodes, 1);
        assert_eq!(report.raw_replaced_nodes, 2);
        assert_eq!(report.raw_preservation_audits.len(), 1);
        let audit = &report.raw_preservation_audits[0];
        assert!(audit.passed);
        assert_eq!(audit.verified_row_count, 1);
        assert_eq!(audit.verified_atomic_unit_count, 2);
        assert_eq!(audit.preserved_node_count, 1);
        assert_eq!(audit.replaced_node_count, 1);
        assert_eq!(audit.pak_entry_path, uexp);
        assert_eq!(
            report
                .final_inventory
                .iter()
                .find(|entry| entry.path == uexp)
                .unwrap()
                .sha256,
            audit.entry_sha256
        );
        assert!(output.exists());
        assert!(!temp.path().join("Merged.merge-report.json").exists());
        assert!(verify(&output, Some(&report)).unwrap().valid);
        let mut mismatched_audit_report = report.clone();
        mismatched_audit_report.raw_preservation_audits[0].entry_sha256 = "00".repeat(32);
        let verification = verify(&output, Some(&mismatched_audit_report)).unwrap();
        assert!(!verification.valid);
        assert!(
            verification
                .errors
                .iter()
                .any(|error| error.contains("unchanged-data Pak file SHA-256 mismatch"))
        );

        let repeated_output = temp.path().join("MergedRepeat_P.pak");
        let repeated_report = write(resolved.clone(), &repeated_output).unwrap();
        assert_eq!(report.output_sha256, repeated_report.output_sha256);
        assert_eq!(
            report.raw_preservation_audits,
            repeated_report.raw_preservation_audits
        );

        let overwrite_output = temp.path().join("Overwrite_P.pak");
        fs::write(&overwrite_output, b"keep unless explicitly confirmed").unwrap();
        assert!(write(resolved.clone(), &overwrite_output).is_err());
        assert_eq!(
            fs::read(&overwrite_output).unwrap(),
            b"keep unless explicitly confirmed"
        );
        let overwrite_report = write_with_options(
            resolved.clone(),
            &overwrite_output,
            WriteOptions {
                overwrite_existing: true,
                ..WriteOptions::default()
            },
        )
        .unwrap();
        assert!(
            verify(&overwrite_output, Some(&overwrite_report))
                .unwrap()
                .valid
        );

        let guarded_output = temp.path().join("Guarded_P.pak");
        let guarded_partial = guarded_output.with_extension("pak.partial");
        fs::write(&guarded_partial, b"do not delete").unwrap();
        let guarded_report = write(resolved.clone(), &guarded_output).unwrap();
        assert!(
            verify(&guarded_output, Some(&guarded_report))
                .unwrap()
                .valid
        );
        assert_eq!(fs::read(&guarded_partial).unwrap(), b"do not delete");

        let report_race_output = temp.path().join("ReportRace_P.pak");
        let report_race_partial = temp.path().join("ReportRace.merge-report.json.partial");
        fs::write(&report_race_partial, b"do not delete").unwrap();
        assert!(write(resolved, &report_race_output).is_ok());
        assert_eq!(fs::read(&report_race_partial).unwrap(), b"do not delete");
        assert!(report_race_output.exists());
        assert!(!report_race_output.with_extension("pak.partial").exists());

        let archive = PakArchive::open(&output).unwrap();
        let merged = BinaryAsset::parse(&archive.read_entry(&uexp).unwrap()).unwrap();
        let row = merged.row(1).unwrap().unwrap();
        let expected_a = BinaryAsset::parse(&test_asset(test_row(1, 10, 0))).unwrap();
        let expected_b = BinaryAsset::parse(&test_asset(test_row(1, 0, 20))).unwrap();
        assert_eq!(
            row.node.map_get("x").unwrap().unwrap().raw(row.source),
            expected_a
                .row(1)
                .unwrap()
                .unwrap()
                .node
                .map_get("x")
                .unwrap()
                .unwrap()
                .raw(&expected_a.payload)
        );
        assert_eq!(
            row.node.map_get("y").unwrap().unwrap().raw(row.source),
            expected_b
                .row(1)
                .unwrap()
                .unwrap()
                .node
                .map_get("y")
                .unwrap()
                .unwrap()
                .raw(&expected_b.payload)
        );
        let x = row
            .node
            .map_get("x")
            .unwrap()
            .unwrap()
            .integer_value()
            .unwrap()
            .as_i64()
            .unwrap();
        let y = row
            .node
            .map_get("y")
            .unwrap()
            .unwrap()
            .integer_value()
            .unwrap()
            .as_i64()
            .unwrap();
        assert_eq!((x, y), (10, 20));
    }

    #[test]
    fn disk_streamed_database_union_expands_array_header_and_is_deterministic() {
        let temp = tempfile::tempdir().unwrap();
        let pak_a = temp.path().join("StreamA_P.pak");
        let pak_b = temp.path().join("StreamB_P.pak");
        let base = "Local/DataBase/Test/Streamed";
        let uasset = format!("{base}.uasset");
        let uexp = format!("{base}.uexp");
        let mount = "../../../Example/Content/";
        let rows_a = (1..=15).map(|id| test_row(id, 10, 0)).collect();
        let mut rows_b = vec![test_row(1, 0, 20)];
        rows_b.extend((16..=29).map(|id| test_row(id, 0, 20)));
        let uexp_a = test_asset_rows(rows_a);
        let uexp_b = test_asset_rows(rows_b);
        pak::write_pak_v11(
            &pak_a,
            mount,
            [
                pak::PakWriteEntry::new(&uasset, uasset_with_serial_size(base, uexp_a.len())),
                pak::PakWriteEntry::new(&uexp, uexp_a),
            ],
        )
        .unwrap();
        pak::write_pak_v11(
            &pak_b,
            mount,
            [
                pak::PakWriteEntry::new(&uasset, uasset_with_serial_size(base, uexp_b.len())),
                pak::PakWriteEntry::new(&uexp, uexp_b),
            ],
        )
        .unwrap();

        let plan = analyze(AnalysisRequest {
            pak_paths: vec![pak_a.clone(), pak_b.clone()],
            carrier_path: pak_a.clone(),
        })
        .unwrap();
        let input_a = plan
            .inputs
            .iter()
            .find(|input| input.path == pak_a)
            .unwrap();
        let input_b = plan
            .inputs
            .iter()
            .find(|input| input.path == pak_b)
            .unwrap();
        let mut choices = BTreeMap::new();
        for conflict in plan.conflicts.iter().filter(|conflict| conflict.blocking) {
            let selected_input = match conflict.group_id.as_deref() {
                Some("field:x") => &input_a.id,
                Some("field:y") => &input_b.id,
                other => panic!("unexpected streamed database conflict: {other:?}"),
            };
            let variant = conflict
                .variants
                .iter()
                .find(|variant| &variant.input_id == selected_input)
                .unwrap();
            choices.insert(conflict.id.clone(), variant.id.clone());
        }
        let resolved = resolve(
            plan.clone(),
            ResolutionSet {
                plan_id: plan.plan_id.clone(),
                choices,
            },
        )
        .unwrap();
        let first_output = temp.path().join("StreamMergedA_P.pak");
        let second_output = temp.path().join("StreamMergedB_P.pak");
        let first_report = write(resolved.clone(), &first_output).unwrap();
        let second_report = write(resolved, &second_output).unwrap();
        assert_eq!(first_report.output_sha256, second_report.output_sha256);
        assert_eq!(
            first_report.raw_preservation_audits,
            second_report.raw_preservation_audits
        );

        let archive = PakArchive::open(&first_output).unwrap();
        let merged = BinaryAsset::parse(&archive.read_entry(&uexp).unwrap()).unwrap();
        assert_eq!(merged.row_count(), 29);
        assert_eq!(merged.data_list().unwrap().marker, 0xDC);
        assert_eq!(merged.row_ids(), &(1_i64..=29).collect::<Vec<_>>());
        assert_eq!(
            first_report.raw_preservation_audits[0].verified_row_count,
            29
        );
    }

    #[test]
    fn end_to_end_parallel_array_indices_combine_changes_from_two_paks() {
        let temp = tempfile::tempdir().unwrap();
        let pak_a = temp.path().join("ArrayA_P.pak");
        let pak_b = temp.path().join("ArrayB_P.pak");
        let base = "Octopath_Traveler0/Content/Local/DataBase/AIBattle/TacticalActionList";
        let uasset = format!("{base}.uasset");
        let uexp = format!("{base}.uexp");
        let mount = "../../../Example/Content/";
        for (path, conditions, params) in [(&pak_a, [1, 0], [10, 0]), (&pak_b, [0, 2], [0, 20])] {
            let uexp_bytes = test_asset(parallel_condition_row(1, &conditions, &params));
            pak::write_pak_v11(
                path,
                mount,
                [
                    pak::PakWriteEntry::new(
                        &uasset,
                        uasset_with_serial_size(base, uexp_bytes.len()),
                    ),
                    pak::PakWriteEntry::new(&uexp, uexp_bytes),
                ],
            )
            .unwrap();
        }

        let plan = analyze(AnalysisRequest {
            pak_paths: vec![pak_a.clone(), pak_b.clone()],
            carrier_path: pak_a.clone(),
        })
        .unwrap();
        let input_a = plan
            .inputs
            .iter()
            .find(|input| input.path == pak_a)
            .unwrap()
            .id
            .clone();
        let input_b = plan
            .inputs
            .iter()
            .find(|input| input.path == pak_b)
            .unwrap()
            .id
            .clone();
        let blocking: Vec<_> = plan
            .conflicts
            .iter()
            .filter(|conflict| conflict.blocking)
            .collect();
        assert_eq!(blocking.len(), 2);
        assert!(
            blocking
                .iter()
                .all(|conflict| conflict.kind == ConflictKind::AtomicGroup)
        );
        assert_eq!(
            blocking
                .iter()
                .filter_map(|conflict| conflict.group_id.as_deref())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([
                "group:condition_parameters[0]",
                "group:condition_parameters[1]",
            ])
        );

        let mut resolutions = ResolutionSet {
            plan_id: plan.plan_id.clone(),
            ..ResolutionSet::default()
        };
        for conflict in blocking {
            let donor = match conflict.group_id.as_deref() {
                Some("group:condition_parameters[0]") => &input_a,
                Some("group:condition_parameters[1]") => &input_b,
                other => panic!("unexpected indexed conflict: {other:?}"),
            };
            let variant = conflict
                .variants
                .iter()
                .find(|variant| &variant.input_id == donor)
                .unwrap();
            resolutions
                .choices
                .insert(conflict.id.clone(), variant.id.clone());
        }

        let output = temp.path().join("ArrayMerged_P.pak");
        let report = write(resolve(plan, resolutions).unwrap(), &output).unwrap();
        assert!(report.verification_passed);
        assert_eq!(report.raw_replaced_nodes, 4);
        let audit = report.raw_preservation_audits.first().unwrap();
        assert_eq!(audit.verified_row_count, 1);
        assert_eq!(audit.verified_atomic_unit_count, 2);
        assert_eq!(audit.preserved_node_count, 1);
        assert_eq!(audit.replaced_node_count, 1);
        let archive = PakArchive::open(&output).unwrap();
        let merged = BinaryAsset::parse(&archive.read_entry(&uexp).unwrap()).unwrap();
        let row = merged.row(1).unwrap().unwrap();
        let conditions = row
            .node
            .map_get("m_Conditions")
            .unwrap()
            .unwrap()
            .as_array()
            .unwrap();
        let params = row
            .node
            .map_get("m_Params")
            .unwrap()
            .unwrap()
            .as_array()
            .unwrap();
        let source_a_archive = PakArchive::open(&pak_a).unwrap();
        let source_b_archive = PakArchive::open(&pak_b).unwrap();
        let source_a = BinaryAsset::parse(&source_a_archive.read_entry(&uexp).unwrap()).unwrap();
        let source_b = BinaryAsset::parse(&source_b_archive.read_entry(&uexp).unwrap()).unwrap();
        let source_a_row = source_a.row(1).unwrap().unwrap();
        let source_b_row = source_b.row(1).unwrap().unwrap();
        for field in ["m_Conditions", "m_Params"] {
            let actual = row
                .node
                .map_get(field)
                .unwrap()
                .unwrap()
                .as_array()
                .unwrap();
            let from_a = source_a_row
                .node
                .map_get(field)
                .unwrap()
                .unwrap()
                .as_array()
                .unwrap();
            let from_b = source_b_row
                .node
                .map_get(field)
                .unwrap()
                .unwrap()
                .as_array()
                .unwrap();
            assert_eq!(
                actual[0].raw(row.source),
                from_a[0].raw(source_a_row.source)
            );
            assert_eq!(
                actual[1].raw(row.source),
                from_b[1].raw(source_b_row.source)
            );
        }
        let values = |items: &[binary_asset::MsgpackNode]| {
            items
                .iter()
                .map(|item| item.integer_value().unwrap().as_i64().unwrap())
                .collect::<Vec<_>>()
        };
        assert_eq!(values(conditions), [1, 2]);
        assert_eq!(values(params), [10, 20]);
    }

    #[test]
    fn parallel_array_length_change_fails_closed_as_whole_row_structure_conflict() {
        let temp = tempfile::tempdir().unwrap();
        let pak_a = temp.path().join("ArrayShapeA_P.pak");
        let pak_b = temp.path().join("ArrayShapeB_P.pak");
        let base = "Octopath_Traveler0/Content/Local/DataBase/AIBattle/TacticalActionList";
        let uasset = format!("{base}.uasset");
        let uexp = format!("{base}.uexp");
        for (path, conditions, params) in [
            (&pak_a, vec![1, 0], vec![10, 0]),
            (&pak_b, vec![1, 0, 0], vec![10, 0, 0]),
        ] {
            let uexp_bytes = test_asset(parallel_condition_row(1, &conditions, &params));
            pak::write_pak_v11(
                path,
                "../../../Example/Content/",
                [
                    pak::PakWriteEntry::new(
                        &uasset,
                        uasset_with_serial_size(base, uexp_bytes.len()),
                    ),
                    pak::PakWriteEntry::new(&uexp, uexp_bytes),
                ],
            )
            .unwrap();
        }
        let plan = analyze(AnalysisRequest {
            pak_paths: vec![pak_a.clone(), pak_b],
            carrier_path: pak_a,
        })
        .unwrap();
        let blocking: Vec<_> = plan
            .conflicts
            .iter()
            .filter(|conflict| conflict.blocking)
            .collect();
        assert_eq!(blocking.len(), 1);
        assert_eq!(blocking[0].kind, ConflictKind::StructureMismatch);
        assert_eq!(
            blocking[0].group_id.as_deref(),
            Some("__whole_row__"),
            "analysis warnings: {:?}",
            plan.warnings
        );
        assert_eq!(blocking[0].row_id.as_deref(), Some("1"));
    }

    #[test]
    fn external_pair_analyzes_when_configured() {
        let Some(value) = std::env::var_os("PAK_MERGER_TEST_PAIR") else {
            return;
        };
        let paths: Vec<_> = std::env::split_paths(&value).collect();
        assert_eq!(
            paths.len(),
            2,
            "PAK_MERGER_TEST_PAIR must contain exactly two platform-separated paths"
        );
        let plan = analyze(AnalysisRequest {
            pak_paths: paths.clone(),
            carrier_path: paths[0].clone(),
        })
        .unwrap();
        assert_eq!(plan.inputs.len(), 2);
        assert!(!plan.assets.is_empty());
        assert!(plan.full_reencode_forbidden);
        if let Ok(expected) = std::env::var("PAK_MERGER_EXPECT_STALE_HASH_WARNINGS") {
            let expected: usize = expected.parse().unwrap();
            let actual = plan
                .warnings
                .iter()
                .filter(|warning| warning.contains("whose integrity value is outdated"))
                .count();
            assert_eq!(actual, expected, "analysis warnings: {:?}", plan.warnings);
        }

        if plan
            .unresolved_conflict_ids(&ResolutionSet::default())
            .is_empty()
        {
            let directory = tempfile::tempdir().unwrap();
            let output = directory.path().join("ExternalMerged_P.pak");
            let resolved = resolve(plan, ResolutionSet::default()).unwrap();
            let report = write(resolved, &output).unwrap();
            let verification = verify(&output, Some(&report)).unwrap();
            assert!(
                verification.valid,
                "verification errors: {:?}",
                verification.errors
            );
        }
    }
}
