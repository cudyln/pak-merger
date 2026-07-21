//! Unreal Pak reader and v11 writer.
//!
//! Inputs are unencrypted Pak v0-v11 files using a supported compression
//! method. Output is deterministic, unsigned, and either uncompressed or Oodle.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

#[cfg(test)]
use crate::binary_asset::BinaryAsset;
use crate::binary_asset::{
    MAX_BINARY_ASSET_PAYLOAD_BYTES, PACKAGE_TAG_SIZE, validate_binary_asset_structure_with_cancel,
};
use crate::control::CancellationToken;
use crate::resources;
use crate::types::OutputCompression;
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Unreal's Pak magic, serialized little-endian in the footer.
pub const PAK_MAGIC: u32 = 0x5A6F_12E1;
/// Unreal package tag serialized at the start of `.uasset` files and the end
/// of their BinaryAsset `.uexp` companions.
const UNREAL_PACKAGE_TAG: [u8; PACKAGE_TAG_SIZE] = [0xC1, 0x83, 0x2A, 0x9E];
/// Output version. Input inspection mirrors the pinned repak reader's v0-v11
/// range (including both v8 layouts) while applying stricter validation.
pub const SUPPORTED_PAK_VERSION: u32 = 11;
pub const MIN_PAK_FOOTER_SIZE: u64 = 44;
pub const PAK_V11_FOOTER_SIZE: u64 = 221;
pub const ENTRY_HEADER_SIZE_NONE_V11: u64 = 53;

/// Structural limits for untrusted archive metadata.
pub const MAX_INDEX_BYTES: u64 = 1024 * 1024 * 1024;
pub const MAX_COMBINED_INDEX_BYTES: u64 = 2 * 1024 * 1024 * 1024;
pub const MAX_ENTRY_COUNT: u32 = 2_000_000;
/// Per-entry ceiling imposed by the host address space.
pub const MAX_IN_MEMORY_ENTRY_BYTES: u64 = usize::MAX as u64;
pub const COPY_BUFFER_BYTES: usize = 8 * 1024 * 1024;
/// Small decoded entries stay in RAM; larger entries use temporary mappings.
const DECODED_MEMORY_CACHE_ENTRY_BYTES: u64 = 64 * 1024 * 1024;
pub(crate) const MINIMUM_DECODE_DISK_HEADROOM_BYTES: u64 = 64 * 1024 * 1024;
/// Oodle output is streamed in blocks and has no separate heap limit.
pub const MAX_OODLE_OUTPUT_ENTRY_BYTES: u64 = usize::MAX as u64;
const MAX_STALE_HASH_UASSET_BYTES: u64 = 64 * 1024 * 1024;
/// Structural guard for legacy v3-v9 block tables. Two million standard
/// 126,976-byte blocks cover far more than the supported 128 GiB input set,
/// while still preventing a hostile index from requesting an unbounded
/// metadata allocation. Newer encoded indexes have their own 16-bit format
/// ceiling and large valid entries use a larger declared block size.
const MAX_COMPRESSION_BLOCKS: u32 = 2_000_000;
/// Larger LZ4 and Oodle blocks decode directly into a temporary mapping.
const DIRECT_DECODE_LOGICAL_BLOCK_THRESHOLD: u64 = 8 * 1024 * 1024;
const DIRECT_DECODE_STORED_BLOCK_THRESHOLD: u64 = 16 * 1024 * 1024;

#[derive(Debug, Clone)]
struct DecodeCachePolicy {
    memory_entry_threshold_bytes: u64,
    minimum_disk_headroom_bytes: u64,
    cache_directory: Option<PathBuf>,
    #[cfg(test)]
    cancel_after_disk_reservation: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LogicalValidation {
    Deferred,
    StrictRetain,
    StrictDiscard,
}

impl LogicalValidation {
    fn is_strict(self) -> bool {
        self != Self::Deferred
    }

    fn retains_decoded_entries(self) -> bool {
        self == Self::StrictRetain
    }
}

impl DecodeCachePolicy {
    fn runtime() -> Result<Self> {
        Ok(Self {
            memory_entry_threshold_bytes: DECODED_MEMORY_CACHE_ENTRY_BYTES,
            minimum_disk_headroom_bytes: MINIMUM_DECODE_DISK_HEADROOM_BYTES,
            cache_directory: Some(resources::runtime_temp_directory()?),
            #[cfg(test)]
            cancel_after_disk_reservation: false,
        })
    }
}

#[derive(Debug, Error)]
pub enum PakError {
    #[error("could not read or write the file: {0}")]
    Io(#[from] io::Error),

    #[error("the Pak file structure could not be read: {0}")]
    Repak(String),

    #[error("the file is too small to be a Pak ({actual} bytes; minimum 44)")]
    TooSmall { actual: u64 },

    #[error("the Pak header is missing or invalid ({actual:#010x}; expected {expected:#010x})")]
    InvalidMagic { actual: u32, expected: u32 },

    #[error("Pak version {actual} is not supported; this build can read v0-v11")]
    UnsupportedVersion { actual: u32 },

    #[error("the Pak file list is encrypted and cannot be read")]
    EncryptedIndex,

    #[error("a file inside the Pak is encrypted: {path}")]
    EncryptedEntry { path: String },

    #[error("the Pak file {path} uses unsupported compression {method}")]
    UnsupportedCompression { path: String, method: String },

    #[error("the compressed Pak file {path} could not be decoded: {reason}")]
    DecompressionFailed { path: String, reason: String },

    #[error("Oodle support could not be prepared for {path}: {reason}")]
    OodleUnavailable { path: String, reason: String },

    #[error("invalid Pak root path {mount_point:?}: {reason}")]
    InvalidMountPoint { mount_point: String, reason: String },

    #[error("invalid file path inside the Pak {path:?}: {reason}")]
    InvalidPath { path: String, reason: String },

    #[error("the same internal file path appears twice: {first:?} and {second:?}")]
    DuplicatePath { first: String, second: String },

    #[error("the Pak file-list format is not supported: {0}")]
    UnsupportedLayout(String),

    #[error("the Pak is damaged or contains conflicting records: {0}")]
    Corrupt(String),

    #[error("file integrity check failed for {region}: stored {expected}, actual {actual}")]
    Sha1Mismatch {
        region: String,
        expected: String,
        actual: String,
    },

    #[error("the Pak does not contain this file: {0}")]
    MissingEntry(String),

    #[error("the Pak file {path} is too large for this build ({size} bytes; limit {limit})")]
    EntryTooLarge { path: String, size: u64, limit: u64 },

    #[error("not enough memory to inspect the Pak file {path} ({size} bytes)")]
    EntryAllocationFailed { path: String, size: u64 },

    #[error(
        "not enough temporary disk space to decode {path}: need about {required} bytes, available {available} bytes"
    )]
    InsufficientCacheDisk {
        path: String,
        required: u64,
        available: u64,
    },

    #[error("the output file already exists: {0}")]
    OutputExists(PathBuf),

    #[error("the Pak contains no files")]
    EmptyArchive,

    #[error("the operation was cancelled")]
    Cancelled,
}

pub type Result<T> = std::result::Result<T, PakError>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PakFooterInfo {
    pub version: u32,
    pub encrypted_index: bool,
    pub index_offset: u64,
    pub index_size: u64,
    pub index_sha1: String,
    /// Names declared in the footer. A declared codec is not necessarily used
    /// by an entry; actual use is rejected while parsing encoded entries.
    pub compression_slots: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PakEntryInventory {
    pub path: String,
    /// Logical size after decompression.
    pub size: u64,
    /// Number of payload bytes stored in the archive.
    pub stored_size: u64,
    pub compressed: bool,
    /// For a strict archive inspection this is the logical (decompressed)
    /// SHA-256. A fast input open initially carries the stored-byte SHA-256
    /// for compressed entries until `PakArchive::logical_sha256` is requested.
    pub sha256: String,
    /// Whether `sha256` describes the logical bytes rather than the compressed
    /// bytes stored in the Pak.
    #[serde(default = "default_true")]
    pub sha256_is_logical: bool,
    /// Offset of the versioned entry header, retained for audit output.
    pub header_offset: u64,
    /// SHA-1 of the payload bytes actually read and verified by this tool.
    pub payload_sha1: String,
    /// SHA-1 stored in the local/index entry metadata. This normally equals
    /// `payload_sha1`; a tightly validated legacy BinaryAsset compatibility
    /// exception may retain a stale producer-written value here.
    pub stored_payload_sha1: String,
    /// False only for the audited legacy `.uexp` stale-hash compatibility
    /// profile. All other payload hash mismatches remain fatal.
    pub payload_sha1_matches: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PakInventory {
    pub source_path: PathBuf,
    pub archive_size: u64,
    pub archive_sha256: String,
    pub footer: PakFooterInfo,
    pub mount_point: String,
    pub path_hash_seed: u64,
    pub entries: Vec<PakEntryInventory>,
    pub packages: PackageGrouping,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum PackageComponent {
    Uasset,
    Uexp,
    Ubulk,
    Uptnl,
}

impl PackageComponent {
    pub fn extension(self) -> &'static str {
        match self {
            Self::Uasset => ".uasset",
            Self::Uexp => ".uexp",
            Self::Ubulk => ".ubulk",
            Self::Uptnl => ".uptnl",
        }
    }

    fn from_path(path: &str) -> Option<(Self, &str)> {
        let lower = path.to_ascii_lowercase();
        for component in [Self::Uasset, Self::Uexp, Self::Ubulk, Self::Uptnl] {
            let extension = component.extension();
            if lower.ends_with(extension) {
                let stem_len = path.len().checked_sub(extension.len())?;
                return Some((component, &path[..stem_len]));
            }
        }
        None
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PackageGroup {
    pub base_path: String,
    pub components: BTreeMap<PackageComponent, String>,
    /// A package is incomplete when a sidecar exists without its `.uasset`.
    /// Such a group must be treated as opaque by higher merge layers.
    pub complete: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PackageGrouping {
    pub packages: Vec<PackageGroup>,
    pub loose_entries: Vec<String>,
}

/// Read-only information used to estimate the cost of decoding a selected
/// entry before a merge starts. The query never reads or decodes payload data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PakEntryDecodeInfo {
    pub compressed: bool,
    pub logical_size: u64,
    pub decoded_cache_present: bool,
    pub memory_cache_eligible: bool,
}

#[derive(Debug)]
struct EntryRecord {
    path: String,
    header_offset: u64,
    header_size: u64,
    /// Number of bytes stored after the entry header (compressed when the
    /// entry uses a codec).
    stored_size: u64,
    /// Logical byte count after decompression.
    size: u64,
    compressed: bool,
    oodle_compressed: bool,
    /// Strictly validated physical input ranges and logical output ranges for
    /// LZ4/Oodle blocks that are too large for repak's normal heap-backed
    /// block path. Ordinary blocks deliberately leave this as `None`.
    direct_decode_plan: Option<DirectDecodePlan>,
    /// Expected hash for subsequent reads. This is replaced with the verified
    /// actual hash only after the legacy stale-hash compatibility profile has
    /// validated the complete BinaryAsset package.
    payload_sha1: [u8; 20],
    stored_payload_sha1: [u8; 20],
    /// SHA-256 of the payload bytes stored in the archive. For an uncompressed
    /// entry these are also the logical bytes.
    stored_sha256: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DirectDecodeCodec {
    Lz4,
    Oodle,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DirectDecodeBlock {
    stored_start: u64,
    stored_end: u64,
    output_start: u64,
    output_end: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DirectDecodePlan {
    codec: DirectDecodeCodec,
    blocks: Vec<DirectDecodeBlock>,
}

/// A validated, read-only Pak archive.
///
/// Opening retains one read-only mapping of the source so later entry reads
/// reuse the operating system cache. `open_fast` defers compressed decoding;
/// strict `open` decodes once and retains each result for later consumers.
#[derive(Debug)]
pub struct PakArchive {
    path: PathBuf,
    file: File,
    source_modified: Option<std::time::SystemTime>,
    archive_mapping: Arc<memmap2::Mmap>,
    inventory: PakInventory,
    entries: BTreeMap<String, EntryRecord>,
    repak_reader: repak::PakReader,
    multithreaded: bool,
    decode_cache_policy: DecodeCachePolicy,
    decoded_entries: BTreeMap<String, Arc<Mutex<Option<Arc<CachedLogicalEntry>>>>>,
    #[cfg(test)]
    decode_count: std::sync::atomic::AtomicUsize,
}

#[derive(Debug)]
struct CachedLogicalEntry {
    data: CachedEntryData,
    sha256: [u8; 32],
}

#[derive(Debug)]
enum CachedEntryData {
    Owned {
        bytes: Vec<u8>,
        _reservation: resources::DecodedMemoryReservation,
    },
    TemporaryMapped {
        mapping: memmap2::Mmap,
        _file: tempfile::NamedTempFile,
    },
}

impl AsRef<[u8]> for CachedEntryData {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Owned { bytes, .. } => bytes,
            Self::TemporaryMapped { mapping, .. } => mapping,
        }
    }
}

/// A payload backed either by owned bytes or by a read-only file mapping.
/// The mapped form lets the deterministic repak writer consume large entries
/// without first materializing the whole entry in the Rust heap.
pub enum PakEntryData {
    Owned(Vec<u8>),
    Mapped(memmap2::Mmap),
    TemporaryMapped {
        mapping: memmap2::Mmap,
        _file: tempfile::NamedTempFile,
    },
    Shared(PakEntryCacheHandle),
    ArchiveSlice(PakEntryArchiveHandle),
}

/// Read-only handle to a decoded entry retained by its source archive.
/// Cloning the handle is constant-time and does not copy the entry bytes.
pub struct PakEntryCacheHandle(Arc<CachedLogicalEntry>);

/// A zero-copy view into the source Pak's persistent read-only mapping.
pub struct PakEntryArchiveHandle {
    mapping: Arc<memmap2::Mmap>,
    start: usize,
    end: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PakOpenProgress {
    Scanning {
        completed_bytes: u64,
        total_bytes: u64,
    },
    Decoding {
        completed_bytes: u64,
        total_bytes: u64,
        current_path: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PakWriteProgress {
    Writing {
        completed: usize,
        total: usize,
        current_path: Option<String>,
    },
    WritingBytes {
        completed_bytes: u64,
        total_bytes: u64,
        current_path: String,
    },
    Verifying,
    VerificationProgress {
        completed_bytes: u64,
        total_bytes: u64,
        current_path: Option<String>,
    },
}

#[derive(Debug)]
pub struct PakWriteResultWithSourceHashes {
    pub archive: PakArchive,
    /// Logical SHA-256 values calculated while repak consumed only the paths
    /// explicitly requested by the caller. Keys preserve the canonical path
    /// spelling used in the output Pak.
    pub source_sha256: BTreeMap<String, String>,
}

impl AsRef<[u8]> for PakEntryData {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Owned(bytes) => bytes,
            Self::Mapped(mapping) => mapping,
            Self::TemporaryMapped { mapping, .. } => mapping,
            Self::Shared(cached) => cached.0.data.as_ref(),
            Self::ArchiveSlice(cached) => &cached.mapping[cached.start..cached.end],
        }
    }
}

const fn default_true() -> bool {
    true
}

impl PakEntryData {
    #[allow(unsafe_code)]
    pub fn map_file(path: &Path, max_bytes: u64) -> Result<Self> {
        let file = File::open(path)?;
        let size = file.metadata()?.len();
        if size > max_bytes || size > usize::MAX as u64 {
            return Err(PakError::EntryTooLarge {
                path: path.display().to_string(),
                size,
                limit: max_bytes.min(usize::MAX as u64),
            });
        }
        if size == 0 {
            return Ok(Self::Owned(Vec::new()));
        }
        // SAFETY: the mapping is read-only, its length was checked against the
        // current file metadata, and `Mmap` owns the OS mapping after creation.
        let mapping = unsafe { memmap2::MmapOptions::new().len(size as usize).map(&file) }?;
        Ok(Self::Mapped(mapping))
    }
}

impl PakArchive {
    /// Opens an archive and performs the final, strict logical-content check.
    /// Compressed entries are decoded once and retained in the archive cache so
    /// later reference checks or output reads do not decode them again.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let cancellation = CancellationToken::new();
        Self::open_internal(
            path.as_ref(),
            LogicalValidation::StrictRetain,
            true,
            &cancellation,
            &mut |_| {},
        )
    }

    /// Opens an input archive without eagerly decoding every compressed file.
    /// Footer/index validation, the complete archive SHA-256, and every stored
    /// payload SHA-1/SHA-256 are still checked in one sequential physical pass.
    /// Logical bytes are decoded and cached only when requested.
    pub fn open_fast(path: impl AsRef<Path>) -> Result<Self> {
        let cancellation = CancellationToken::new();
        Self::open_internal(
            path.as_ref(),
            LogicalValidation::Deferred,
            true,
            &cancellation,
            &mut |_| {},
        )
    }

    pub fn open_with_progress_and_cancel<C>(
        path: impl AsRef<Path>,
        cancellation: &CancellationToken,
        mut progress: C,
    ) -> Result<Self>
    where
        C: FnMut(PakOpenProgress),
    {
        Self::open_internal(
            path.as_ref(),
            LogicalValidation::StrictRetain,
            true,
            cancellation,
            &mut progress,
        )
    }

    pub fn open_fast_with_progress_and_cancel<C>(
        path: impl AsRef<Path>,
        cancellation: &CancellationToken,
        mut progress: C,
    ) -> Result<Self>
    where
        C: FnMut(PakOpenProgress),
    {
        Self::open_internal(
            path.as_ref(),
            LogicalValidation::Deferred,
            true,
            cancellation,
            &mut progress,
        )
    }

    pub fn open_with_progress_cancel_and_threads<C>(
        path: impl AsRef<Path>,
        cancellation: &CancellationToken,
        multithreaded: bool,
        mut progress: C,
    ) -> Result<Self>
    where
        C: FnMut(PakOpenProgress),
    {
        Self::open_internal(
            path.as_ref(),
            LogicalValidation::StrictRetain,
            multithreaded,
            cancellation,
            &mut progress,
        )
    }

    pub fn open_fast_with_progress_cancel_and_threads<C>(
        path: impl AsRef<Path>,
        cancellation: &CancellationToken,
        multithreaded: bool,
        mut progress: C,
    ) -> Result<Self>
    where
        C: FnMut(PakOpenProgress),
    {
        Self::open_internal(
            path.as_ref(),
            LogicalValidation::Deferred,
            multithreaded,
            cancellation,
            &mut progress,
        )
    }

    fn open_internal(
        path: &Path,
        logical_validation: LogicalValidation,
        multithreaded: bool,
        cancellation: &CancellationToken,
        progress: &mut dyn FnMut(PakOpenProgress),
    ) -> Result<Self> {
        Self::open_internal_with_policy(
            path,
            logical_validation,
            multithreaded,
            cancellation,
            progress,
            DecodeCachePolicy::runtime()?,
        )
    }

    fn open_internal_with_policy(
        path: &Path,
        logical_validation: LogicalValidation,
        multithreaded: bool,
        cancellation: &CancellationToken,
        progress: &mut dyn FnMut(PakOpenProgress),
        decode_cache_policy: DecodeCachePolicy,
    ) -> Result<Self> {
        check_cancelled(cancellation)?;
        let path = path.to_path_buf();
        let mut file = open_archive_readonly(&path)?;
        let source_metadata = file.metadata()?;
        let archive_size = source_metadata.len();
        let source_modified = source_metadata.modified().ok();
        if archive_size < MIN_PAK_FOOTER_SIZE {
            return Err(PakError::TooSmall {
                actual: archive_size,
            });
        }
        let archive_mapping = Arc::new(map_complete_archive(&file, archive_size)?);

        let detected = read_footer(&mut file, archive_size)?;
        let footer = detected.footer.clone();
        let mut parsed = parse_and_validate_indexes(&mut file, &detected)?;

        if let Some(entry) = parsed.entries.values().find(|entry| entry.oodle_compressed) {
            prepare_oodle_support(&entry.path, Some(cancellation))?;
        }

        // Keep repak as a second, independently maintained parser and use its
        // bundled decoders after our strict index, slot, range, and hash checks.
        // Encryption remains unavailable. Oodle is delegated to repak's pinned
        // loader, including its on-demand runtime download.
        file.seek(SeekFrom::Start(0))?;
        let repak_reader = repak::PakBuilder::new()
            .parallel_blocks(multithreaded)
            .reader_with_version(&mut file, detected.repak_version)
            .map_err(map_repak_error)?;
        if repak_reader.version() != detected.repak_version {
            return Err(PakError::UnsupportedVersion {
                actual: repak_reader.version().version_major() as u32,
            });
        }
        if repak_reader.encrypted_index() {
            return Err(PakError::EncryptedIndex);
        }
        if repak_reader.mount_point() != parsed.mount_point {
            return Err(PakError::Corrupt(
                "the two Pak readers disagree about the Pak's base folder".to_owned(),
            ));
        }
        if repak_reader.path_hash_seed().unwrap_or(0) != parsed.path_hash_seed {
            return Err(PakError::Corrupt(
                "repak and strict parser disagree on path hash seed".to_owned(),
            ));
        }

        let repak_files: BTreeSet<_> = repak_reader.files().into_iter().collect();
        let strict_files: BTreeSet<_> = parsed.entries.values().map(|e| e.path.clone()).collect();
        if repak_files != strict_files {
            return Err(PakError::Corrupt(
                "the two Pak readers disagree about the files inside the Pak".to_owned(),
            ));
        }
        for entry in parsed.entries.values().filter(|entry| entry.compressed) {
            // Modern codecs are decoded block by block. A legacy blockless
            // Oodle entry uses a disk-backed destination below, so neither
            // path needs a combined stored+logical heap allocation.
            if entry.stored_size > usize::MAX as u64 || entry.size > usize::MAX as u64 {
                return Err(PakError::EntryTooLarge {
                    path: entry.path.clone(),
                    size: entry.stored_size.max(entry.size),
                    limit: usize::MAX as u64,
                });
            }
        }
        let compressed_logical_bytes = parsed
            .entries
            .values()
            .filter(|entry| entry.compressed)
            .try_fold(0_u64, |total, entry| total.checked_add(entry.size))
            .ok_or_else(|| PakError::Corrupt("compressed file sizes overflow".to_owned()))?;
        let total_work_bytes = if logical_validation.is_strict() {
            archive_size
                .checked_add(compressed_logical_bytes)
                .ok_or_else(|| PakError::Corrupt("verification size overflow".to_owned()))?
        } else {
            archive_size
        };
        let (archive_sha256, payload_hashes) = hash_archive_and_entry_payloads(
            archive_mapping.as_ref(),
            archive_size,
            total_work_bytes,
            &parsed.entries,
            cancellation,
            progress,
        )?;

        let mismatched_keys = parsed
            .entries
            .iter()
            .filter_map(|(key, entry)| {
                let actual = payload_hashes.get(key).expect("every entry was hashed").0;
                (actual != entry.payload_sha1).then(|| key.clone())
            })
            .collect::<Vec<_>>();
        for key in &mismatched_keys {
            let entry = parsed.entries.get(key).expect("mismatch key exists");
            let actual = payload_hashes.get(key).expect("mismatch hash exists").0;
            if detected.repak_version != repak::Version::V3
                || !validate_v3_stale_binary_asset_uexp(
                    archive_mapping.as_ref(),
                    &parsed.entries,
                    &payload_hashes,
                    key,
                    cancellation,
                )?
            {
                return Err(PakError::Sha1Mismatch {
                    region: format!("file {}", entry.path),
                    expected: hex::encode(entry.payload_sha1),
                    actual: hex::encode(actual),
                });
            }
        }
        for key in mismatched_keys {
            parsed
                .entries
                .get_mut(&key)
                .expect("mismatch key exists")
                .payload_sha1 = payload_hashes.get(&key).expect("mismatch hash exists").0;
        }

        for (key, entry) in &mut parsed.entries {
            entry.stored_sha256 = payload_hashes[key].1;
        }

        // Strict output verification decodes each compressed entry exactly
        // once. Fast input opening defers this work until the merge actually
        // compares, parses, or copies that entry.
        let decoded_entries = parsed
            .entries
            .iter()
            .filter(|(_, entry)| entry.compressed)
            .map(|(key, _)| (key.clone(), Arc::new(Mutex::new(None))))
            .collect::<BTreeMap<_, _>>();
        let mut logical_sha256 = BTreeMap::new();
        let mut initial_decode_count = 0_usize;
        let mut decoded_bytes = 0_u64;
        for (key, entry) in &parsed.entries {
            if entry.compressed && logical_validation.is_strict() {
                check_cancelled(cancellation)?;
                let entry_base = archive_size.checked_add(decoded_bytes).ok_or_else(|| {
                    PakError::Corrupt("verification progress overflow".to_owned())
                })?;
                const DECODE_PROGRESS_REPORT_STEP: u64 = 4 * 1024 * 1024;
                let mut last_reported = 0_u64;
                let mut reported_initial = false;
                let mut entry_progress = |entry_completed: u64| {
                    let should_report = if entry_completed == 0 {
                        !reported_initial
                    } else {
                        entry_completed == entry.size
                            || entry_completed.saturating_sub(last_reported)
                                >= DECODE_PROGRESS_REPORT_STEP
                    };
                    if !should_report {
                        return;
                    }
                    reported_initial = true;
                    last_reported = entry_completed;
                    let completed_bytes = entry_base
                        .checked_add(entry_completed)
                        .expect("validated verification progress fits u64");
                    progress(PakOpenProgress::Decoding {
                        completed_bytes,
                        total_bytes: total_work_bytes,
                        current_path: Some(entry.path.clone()),
                    });
                };
                let cached = Arc::new(decode_entry_with_progress(
                    &repak_reader,
                    archive_mapping.as_ref(),
                    entry,
                    Some(cancellation),
                    multithreaded,
                    &decode_cache_policy,
                    &mut entry_progress,
                )?);
                logical_sha256.insert(key.clone(), cached.sha256);
                if logical_validation.retains_decoded_entries() {
                    *decoded_entries[key].lock().map_err(|_| {
                        PakError::Corrupt("the decoded-file cache is unavailable".to_owned())
                    })? = Some(cached);
                    initial_decode_count = initial_decode_count.saturating_add(1);
                }
                decoded_bytes = decoded_bytes.checked_add(entry.size).ok_or_else(|| {
                    PakError::Corrupt("verification progress overflow".to_owned())
                })?;
            } else if !entry.compressed {
                logical_sha256.insert(key.clone(), entry.stored_sha256);
            }
        }
        if logical_validation.is_strict() && compressed_logical_bytes != 0 {
            progress(PakOpenProgress::Decoding {
                completed_bytes: total_work_bytes,
                total_bytes: total_work_bytes,
                current_path: None,
            });
        }

        let mut inventory_entries = Vec::new();
        inventory_entries
            .try_reserve_exact(parsed.entries.len())
            .map_err(|_| {
                PakError::UnsupportedLayout("the Pak inventory is too large to allocate".to_owned())
            })?;
        for (key, entry) in &parsed.entries {
            let payload_sha1 = payload_hashes[key].0;
            let sha256_is_logical = !entry.compressed || logical_validation.is_strict();
            let sha256 = logical_sha256
                .get(key)
                .copied()
                .unwrap_or(entry.stored_sha256);
            inventory_entries.push(PakEntryInventory {
                path: entry.path.clone(),
                size: entry.size,
                stored_size: entry.stored_size,
                compressed: entry.compressed,
                sha256: hex::encode(sha256),
                sha256_is_logical,
                header_offset: entry.header_offset,
                payload_sha1: hex::encode(payload_sha1),
                stored_payload_sha1: hex::encode(entry.stored_payload_sha1),
                payload_sha1_matches: payload_sha1 == entry.stored_payload_sha1,
            });
        }
        inventory_entries.sort_by_key(|entry| normalized_sort_key(&entry.path));

        let entry_paths: Vec<_> = inventory_entries.iter().map(|e| e.path.clone()).collect();
        let packages = group_packages(entry_paths.iter().map(String::as_str))?;
        let inventory = PakInventory {
            source_path: path.clone(),
            archive_size,
            archive_sha256,
            footer,
            mount_point: parsed.mount_point,
            path_hash_seed: parsed.path_hash_seed,
            entries: inventory_entries,
            packages,
        };

        Ok(Self {
            path,
            file,
            source_modified,
            archive_mapping,
            inventory,
            entries: parsed.entries,
            repak_reader,
            multithreaded,
            decode_cache_policy,
            decoded_entries,
            #[cfg(test)]
            decode_count: std::sync::atomic::AtomicUsize::new(initial_decode_count),
        })
    }

    pub fn inventory(&self) -> &PakInventory {
        &self.inventory
    }

    /// Modification time captured from the already-open source handle. This
    /// lets cached GUI inspections reject a path that changed before analysis
    /// without rereading and rehashing the complete Pak.
    pub fn source_modified(&self) -> Option<std::time::SystemTime> {
        self.source_modified
    }

    pub fn into_inventory(self) -> PakInventory {
        let Self {
            inventory, file, ..
        } = self;
        drop(file);
        inventory
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Releases decoded compressed-entry data owned by this archive.
    ///
    /// Input archives keep decoded entries so analysis and Pak creation do not
    /// decompress the same file twice. A completed merge can call this method
    /// to remove temporary mapped files and return the small in-memory working
    /// cache without closing the archive or discarding its validated index.
    pub fn release_decoded_cache(&self) -> usize {
        let mut released = 0_usize;
        for cache_cell in self.decoded_entries.values() {
            let mut cached = cache_cell
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if cached.take().is_some() {
                released = released.saturating_add(1);
            }
        }
        released
    }

    pub fn contains(&self, path: &str) -> bool {
        normalize_entry_path(path)
            .ok()
            .map(|path| self.entries.contains_key(&normalized_sort_key(&path)))
            .unwrap_or(false)
    }

    /// Returns the logical (decompressed) byte size recorded in the validated
    /// index without reading or decoding the entry payload.
    pub fn entry_size(&self, path: &str) -> Result<u64> {
        let normalized = normalize_entry_path(path)?;
        let key = normalized_sort_key(&normalized);
        self.entries
            .get(&key)
            .map(|entry| entry.size)
            .ok_or(PakError::MissingEntry(normalized))
    }

    /// Returns decode-cache metadata without touching the entry payload.
    pub fn entry_decode_info(&self, path: &str) -> Result<PakEntryDecodeInfo> {
        let normalized = normalize_entry_path(path)?;
        let key = normalized_sort_key(&normalized);
        let entry = self
            .entries
            .get(&key)
            .ok_or_else(|| PakError::MissingEntry(normalized.clone()))?;
        let decoded_cache_present = if entry.compressed {
            self.decoded_entries
                .get(&key)
                .ok_or_else(|| {
                    PakError::Corrupt(format!(
                        "compressed file cache is missing for {}",
                        entry.path
                    ))
                })?
                .lock()
                .map_err(|_| PakError::Corrupt("the decoded-file cache is unavailable".to_owned()))?
                .is_some()
        } else {
            false
        };
        Ok(PakEntryDecodeInfo {
            compressed: entry.compressed,
            logical_size: entry.size,
            decoded_cache_present,
            memory_cache_eligible: entry.compressed
                && entry.direct_decode_plan.is_none()
                && entry.size <= self.decode_cache_policy.memory_entry_threshold_bytes
                && entry.size <= usize::MAX as u64,
        })
    }

    /// Returns the SHA-256 of the logical, decompressed entry bytes. A
    /// compressed entry is decoded at most once for the lifetime of this
    /// archive; subsequent comparisons, reads, and output copies reuse the
    /// same memory- or file-backed cache.
    pub fn logical_sha256(&self, path: &str) -> Result<String> {
        self.logical_sha256_with_threads(path, self.multithreaded)
    }

    pub fn logical_sha256_with_threads(&self, path: &str, multithreaded: bool) -> Result<String> {
        self.logical_sha256_with_options(path, multithreaded, None)
    }

    pub fn logical_sha256_with_threads_and_cancel(
        &self,
        path: &str,
        multithreaded: bool,
        cancellation: &CancellationToken,
    ) -> Result<String> {
        self.logical_sha256_with_options(path, multithreaded, Some(cancellation))
    }

    fn logical_sha256_with_options(
        &self,
        path: &str,
        multithreaded: bool,
        cancellation: Option<&CancellationToken>,
    ) -> Result<String> {
        let normalized = normalize_entry_path(path)?;
        let key = normalized_sort_key(&normalized);
        let entry = self
            .entries
            .get(&key)
            .ok_or(PakError::MissingEntry(normalized))?;
        let digest = if entry.compressed {
            self.cached_compressed_entry(&key, entry, multithreaded, cancellation)?
                .sha256
        } else {
            entry.stored_sha256
        };
        Ok(hex::encode(digest))
    }

    fn cached_compressed_entry(
        &self,
        key: &str,
        entry: &EntryRecord,
        multithreaded: bool,
        cancellation: Option<&CancellationToken>,
    ) -> Result<Arc<CachedLogicalEntry>> {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return Err(PakError::Cancelled);
        }
        let cache_cell = self.decoded_entries.get(key).ok_or_else(|| {
            PakError::Corrupt(format!(
                "compressed file cache is missing for {}",
                entry.path
            ))
        })?;
        // The lock is per entry, not per archive: two different compressed
        // files can be decoded in parallel, while the same file is guaranteed
        // to be expanded only once.
        let mut cached_value = cache_cell
            .lock()
            .map_err(|_| PakError::Corrupt("the decoded-file cache is unavailable".to_owned()))?;
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return Err(PakError::Cancelled);
        }
        if let Some(cached) = cached_value.as_ref() {
            return Ok(Arc::clone(cached));
        }
        let cached = Arc::new(decode_entry(
            &self.repak_reader,
            self.archive_mapping.as_ref(),
            entry,
            cancellation,
            multithreaded,
            &self.decode_cache_policy,
        )?);
        #[cfg(test)]
        self.decode_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        *cached_value = Some(Arc::clone(&cached));
        Ok(cached)
    }

    pub fn read_entry(&self, path: &str) -> Result<Vec<u8>> {
        self.read_entry_limited(path, MAX_IN_MEMORY_ENTRY_BYTES)
    }

    pub fn read_entry_limited(&self, path: &str, max_bytes: u64) -> Result<Vec<u8>> {
        self.read_entry_limited_with_threads(path, max_bytes, self.multithreaded)
    }

    pub fn read_entry_limited_with_threads(
        &self,
        path: &str,
        max_bytes: u64,
        multithreaded: bool,
    ) -> Result<Vec<u8>> {
        self.read_entry_limited_with_options(path, max_bytes, multithreaded, None)
    }

    pub fn read_entry_limited_with_threads_and_cancel(
        &self,
        path: &str,
        max_bytes: u64,
        multithreaded: bool,
        cancellation: &CancellationToken,
    ) -> Result<Vec<u8>> {
        self.read_entry_limited_with_options(path, max_bytes, multithreaded, Some(cancellation))
    }

    fn read_entry_limited_with_options(
        &self,
        path: &str,
        max_bytes: u64,
        multithreaded: bool,
        cancellation: Option<&CancellationToken>,
    ) -> Result<Vec<u8>> {
        let normalized = normalize_entry_path(path)?;
        let key = normalized_sort_key(&normalized);
        let entry = self
            .entries
            .get(&key)
            .ok_or_else(|| PakError::MissingEntry(normalized.clone()))?;
        if entry.size > max_bytes || entry.size > usize::MAX as u64 {
            return Err(PakError::EntryTooLarge {
                path: entry.path.clone(),
                size: entry.size,
                limit: max_bytes.min(usize::MAX as u64),
            });
        }
        let mut output = Vec::new();
        output.try_reserve_exact(entry.size as usize).map_err(|_| {
            PakError::EntryAllocationFailed {
                path: entry.path.clone(),
                size: entry.size,
            }
        })?;
        self.read_entry_to_with_options(&entry.path, &mut output, multithreaded, cancellation)?;
        Ok(output)
    }

    pub fn read_entry_to<W: Write>(&self, path: &str, writer: &mut W) -> Result<u64> {
        self.read_entry_to_with_threads(path, writer, self.multithreaded)
    }

    pub fn read_entry_to_with_threads<W: Write>(
        &self,
        path: &str,
        writer: &mut W,
        multithreaded: bool,
    ) -> Result<u64> {
        self.read_entry_to_with_options(path, writer, multithreaded, None)
    }

    pub fn read_entry_to_with_threads_and_cancel<W: Write>(
        &self,
        path: &str,
        writer: &mut W,
        multithreaded: bool,
        cancellation: &CancellationToken,
    ) -> Result<u64> {
        self.read_entry_to_with_options(path, writer, multithreaded, Some(cancellation))
    }

    fn read_entry_to_with_options<W: Write>(
        &self,
        path: &str,
        writer: &mut W,
        multithreaded: bool,
        cancellation: Option<&CancellationToken>,
    ) -> Result<u64> {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return Err(PakError::Cancelled);
        }
        let normalized = normalize_entry_path(path)?;
        let key = normalized_sort_key(&normalized);
        let entry = self
            .entries
            .get(&key)
            .ok_or_else(|| PakError::MissingEntry(normalized.clone()))?;
        if entry.compressed {
            let cached = self.cached_compressed_entry(&key, entry, multithreaded, cancellation)?;
            writer.write_all(cached.data.as_ref())?;
            return Ok(entry.size);
        }
        let (start, end) = entry_payload_range(entry)?;
        writer.write_all(&self.archive_mapping[start..end])?;
        Ok(entry.size)
    }

    pub fn map_entry(&self, path: &str, max_bytes: u64) -> Result<PakEntryData> {
        self.map_entry_with_threads(path, max_bytes, self.multithreaded)
    }

    pub fn map_entry_with_threads(
        &self,
        path: &str,
        max_bytes: u64,
        multithreaded: bool,
    ) -> Result<PakEntryData> {
        self.map_entry_with_options(path, max_bytes, multithreaded, None)
    }

    pub fn map_entry_with_threads_and_cancel(
        &self,
        path: &str,
        max_bytes: u64,
        multithreaded: bool,
        cancellation: &CancellationToken,
    ) -> Result<PakEntryData> {
        self.map_entry_with_options(path, max_bytes, multithreaded, Some(cancellation))
    }

    fn map_entry_with_options(
        &self,
        path: &str,
        max_bytes: u64,
        multithreaded: bool,
        cancellation: Option<&CancellationToken>,
    ) -> Result<PakEntryData> {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return Err(PakError::Cancelled);
        }
        let normalized = normalize_entry_path(path)?;
        let key = normalized_sort_key(&normalized);
        let entry = self
            .entries
            .get(&key)
            .ok_or_else(|| PakError::MissingEntry(normalized.clone()))?;
        if entry.size > max_bytes || entry.size > usize::MAX as u64 {
            return Err(PakError::EntryTooLarge {
                path: entry.path.clone(),
                size: entry.size,
                limit: max_bytes.min(usize::MAX as u64),
            });
        }
        if entry.size == 0 {
            return Ok(PakEntryData::Owned(Vec::new()));
        }
        if entry.compressed {
            return Ok(PakEntryData::Shared(PakEntryCacheHandle(
                self.cached_compressed_entry(&key, entry, multithreaded, cancellation)?,
            )));
        }
        let (start, end) = entry_payload_range(entry)?;
        Ok(PakEntryData::ArchiveSlice(PakEntryArchiveHandle {
            mapping: Arc::clone(&self.archive_mapping),
            start,
            end,
        }))
    }
}

/// Performs a complete read-only inspection. Compressed files are decoded and
/// checked one at a time, then immediately released so inspection cannot retain
/// the whole archive's expanded contents.
pub fn inspect_pak(path: impl AsRef<Path>) -> Result<PakInventory> {
    inspect_pak_strict(path)
}

fn inspect_pak_strict(path: impl AsRef<Path>) -> Result<PakInventory> {
    let cancellation = CancellationToken::new();
    Ok(PakArchive::open_internal(
        path.as_ref(),
        LogicalValidation::StrictDiscard,
        true,
        &cancellation,
        &mut |_| {},
    )?
    .into_inventory())
}

/// Public core-API spelling retained by `lib.rs`.
pub fn inspect(path: impl AsRef<Path>) -> Result<PakInventory> {
    inspect_pak(path)
}

#[derive(Debug, Clone)]
pub struct PakWriteEntry {
    pub path: String,
    pub data: Vec<u8>,
}

impl PakWriteEntry {
    pub fn new(path: impl Into<String>, data: impl Into<Vec<u8>>) -> Self {
        Self {
            path: path.into(),
            data: data.into(),
        }
    }
}

/// Deterministically writes an uncompressed, unencrypted Pak v11 archive.
///
/// The output path is opened with `create_new`; callers must perform any
/// overwrite confirmation and atomic `.partial` promotion at a higher layer.
pub fn write_pak_v11(
    output_path: impl AsRef<Path>,
    mount_point: &str,
    entries: impl IntoIterator<Item = PakWriteEntry>,
) -> Result<PakInventory> {
    let output_path = output_path.as_ref();
    let output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output_path)
        .map_err(|error| {
            if error.kind() == io::ErrorKind::AlreadyExists {
                PakError::OutputExists(output_path.to_path_buf())
            } else {
                PakError::Io(error)
            }
        })?;

    let result = (|| {
        let mut writer = write_pak_v11_to(BufWriter::new(output), mount_point, entries)?;
        writer.flush()?;
        let output = writer
            .into_inner()
            .map_err(|error| PakError::Io(error.into_error()))?;
        output.sync_all()?;
        drop(output);
        inspect_pak_strict(output_path)
    })();
    if result.is_err() {
        // The file was created by this call with `create_new`, so cleanup can
        // never remove a pre-existing user file. The primary error is retained.
        let _ = std::fs::remove_file(output_path);
    }
    result
}

/// Memory-bounded deterministic writer.
///
/// Only normalized path metadata is retained while sorting. `provider` is
/// called exactly once per path in deterministic order, and its `Vec` is
/// dropped immediately after `repak::PakWriter::write_file` returns. This keeps
/// memory proportional to the largest individual entry rather than the whole
/// output archive. The provider must therefore be side-effect free with
/// respect to call order and return the final bytes for the requested path.
///
/// Like [`write_pak_v11`], the output is opened with `create_new`, fully
/// inspected after writing, and removed on failure only because this call has
/// proven that it created the file itself.
pub fn write_pak_v11_from_provider<I, P, F>(
    output_path: impl AsRef<Path>,
    mount_point: &str,
    paths: I,
    mut provider: F,
) -> Result<PakInventory>
where
    I: IntoIterator<Item = P>,
    P: Into<String>,
    F: FnMut(&str) -> Result<Vec<u8>>,
{
    write_pak_v11_from_data_provider(
        output_path,
        mount_point,
        paths,
        OutputCompression::None,
        |path| provider(path).map(PakEntryData::Owned),
    )
}

/// Deterministic writer variant whose provider may return read-only mapped
/// payloads. At most one mapping is alive while an entry is hashed and written.
pub fn write_pak_v11_from_mapped_provider<I, P, F>(
    output_path: impl AsRef<Path>,
    mount_point: &str,
    paths: I,
    provider: F,
) -> Result<PakInventory>
where
    I: IntoIterator<Item = P>,
    P: Into<String>,
    F: FnMut(&str) -> Result<PakEntryData>,
{
    write_pak_v11_from_data_provider(
        output_path,
        mount_point,
        paths,
        OutputCompression::None,
        provider,
    )
}

/// Writes a deterministic Pak v11 using the selected storage method.
///
/// Oodle is prepared before the output file is created. On Windows this also
/// verifies the exact runtime hash used by the pinned loader, including files
/// that were already present beside the executable.
pub fn write_pak_v11_from_mapped_provider_with_compression<I, P, F>(
    output_path: impl AsRef<Path>,
    mount_point: &str,
    paths: I,
    compression: OutputCompression,
    provider: F,
) -> Result<PakInventory>
where
    I: IntoIterator<Item = P>,
    P: Into<String>,
    F: FnMut(&str) -> Result<PakEntryData>,
{
    write_pak_v11_from_data_provider(output_path, mount_point, paths, compression, provider)
}

/// Writes and performs one strict full inspection while keeping the verified
/// archive open. Callers that need to read selected output entries can reuse
/// this handle instead of reopening and hashing the complete Pak again.
pub fn write_pak_v11_from_mapped_provider_with_compression_open<I, P, F>(
    output_path: impl AsRef<Path>,
    mount_point: &str,
    paths: I,
    compression: OutputCompression,
    provider: F,
) -> Result<PakArchive>
where
    I: IntoIterator<Item = P>,
    P: Into<String>,
    F: FnMut(&str) -> Result<PakEntryData>,
{
    let cancellation = CancellationToken::new();
    write_pak_v11_from_data_provider_open(
        output_path,
        mount_point,
        paths,
        compression,
        provider,
        true,
        &cancellation,
        |_| {},
    )
}

pub fn write_pak_v11_from_mapped_provider_with_compression_open_and_progress<I, P, F, C>(
    output_path: impl AsRef<Path>,
    mount_point: &str,
    paths: I,
    compression: OutputCompression,
    provider: F,
    progress: C,
) -> Result<PakArchive>
where
    I: IntoIterator<Item = P>,
    P: Into<String>,
    F: FnMut(&str) -> Result<PakEntryData>,
    C: FnMut(PakWriteProgress),
{
    let cancellation = CancellationToken::new();
    write_pak_v11_from_data_provider_open(
        output_path,
        mount_point,
        paths,
        compression,
        provider,
        true,
        &cancellation,
        progress,
    )
}

pub fn write_pak_v11_from_mapped_provider_with_compression_open_and_progress_and_threads<
    I,
    P,
    F,
    C,
>(
    output_path: impl AsRef<Path>,
    mount_point: &str,
    paths: I,
    compression: OutputCompression,
    provider: F,
    multithreaded: bool,
    progress: C,
) -> Result<PakArchive>
where
    I: IntoIterator<Item = P>,
    P: Into<String>,
    F: FnMut(&str) -> Result<PakEntryData>,
    C: FnMut(PakWriteProgress),
{
    let cancellation = CancellationToken::new();
    write_pak_v11_from_data_provider_open(
        output_path,
        mount_point,
        paths,
        compression,
        provider,
        multithreaded,
        &cancellation,
        progress,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn write_pak_v11_from_mapped_provider_with_compression_open_progress_threads_and_cancel<
    I,
    P,
    F,
    C,
>(
    output_path: impl AsRef<Path>,
    mount_point: &str,
    paths: I,
    compression: OutputCompression,
    provider: F,
    multithreaded: bool,
    cancellation: &CancellationToken,
    progress: C,
) -> Result<PakArchive>
where
    I: IntoIterator<Item = P>,
    P: Into<String>,
    F: FnMut(&str) -> Result<PakEntryData>,
    C: FnMut(PakWriteProgress),
{
    write_pak_v11_from_data_provider_open(
        output_path,
        mount_point,
        paths,
        compression,
        provider,
        multithreaded,
        cancellation,
        progress,
    )
}

/// Writes and strictly verifies a Pak while calculating logical source
/// SHA-256 values for only the explicitly selected canonical paths. Hashes are
/// updated from the exact slices consumed by the writer; the provider output
/// is never reopened or pre-scanned.
#[allow(clippy::too_many_arguments)]
pub fn write_pak_v11_from_mapped_provider_with_source_hashes<I, P, F, C, H, HP>(
    output_path: impl AsRef<Path>,
    mount_point: &str,
    paths: I,
    compression: OutputCompression,
    provider: F,
    multithreaded: bool,
    cancellation: &CancellationToken,
    progress: C,
    source_hash_paths: H,
) -> Result<PakWriteResultWithSourceHashes>
where
    I: IntoIterator<Item = P>,
    P: Into<String>,
    F: FnMut(&str) -> Result<PakEntryData>,
    C: FnMut(PakWriteProgress),
    H: IntoIterator<Item = HP>,
    HP: Into<String>,
{
    write_pak_v11_from_data_provider_open_with_source_hashes(
        output_path,
        mount_point,
        paths,
        compression,
        provider,
        multithreaded,
        cancellation,
        progress,
        source_hash_paths,
    )
}

fn write_repak_entry_with_optional_source_sha256<W, C>(
    writer: &mut repak::PakWriter<W>,
    path: &str,
    allow_compress: bool,
    data: &[u8],
    collect_source_hash: bool,
    mut progress: C,
) -> std::result::Result<Option<String>, repak::Error>
where
    W: Write + Seek,
    C: FnMut(u64, u64) -> bool,
{
    if collect_source_hash {
        let mut sha256 = Sha256::new();
        writer.write_file_with_progress_and_source_chunks(
            path,
            allow_compress,
            data,
            &mut progress,
            |chunk| sha256.update(chunk),
        )?;
        Ok(Some(hex::encode(sha256.finalize())))
    } else {
        writer.write_file_with_progress(path, allow_compress, data, progress)?;
        Ok(None)
    }
}

fn write_pak_v11_from_data_provider<I, P, F>(
    output_path: impl AsRef<Path>,
    mount_point: &str,
    paths: I,
    compression: OutputCompression,
    provider: F,
) -> Result<PakInventory>
where
    I: IntoIterator<Item = P>,
    P: Into<String>,
    F: FnMut(&str) -> Result<PakEntryData>,
{
    let cancellation = CancellationToken::new();
    Ok(write_pak_v11_from_data_provider_open(
        output_path,
        mount_point,
        paths,
        compression,
        provider,
        true,
        &cancellation,
        |_| {},
    )?
    .into_inventory())
}

#[allow(clippy::too_many_arguments)]
fn write_pak_v11_from_data_provider_open<I, P, F, C>(
    output_path: impl AsRef<Path>,
    mount_point: &str,
    paths: I,
    compression: OutputCompression,
    provider: F,
    multithreaded: bool,
    cancellation: &CancellationToken,
    progress: C,
) -> Result<PakArchive>
where
    I: IntoIterator<Item = P>,
    P: Into<String>,
    F: FnMut(&str) -> Result<PakEntryData>,
    C: FnMut(PakWriteProgress),
{
    Ok(write_pak_v11_from_data_provider_open_with_source_hashes(
        output_path,
        mount_point,
        paths,
        compression,
        provider,
        multithreaded,
        cancellation,
        progress,
        std::iter::empty::<String>(),
    )?
    .archive)
}

#[allow(clippy::too_many_arguments)]
fn write_pak_v11_from_data_provider_open_with_source_hashes<I, P, F, C, H, HP>(
    output_path: impl AsRef<Path>,
    mount_point: &str,
    paths: I,
    compression: OutputCompression,
    mut provider: F,
    multithreaded: bool,
    cancellation: &CancellationToken,
    mut progress: C,
    source_hash_paths: H,
) -> Result<PakWriteResultWithSourceHashes>
where
    I: IntoIterator<Item = P>,
    P: Into<String>,
    F: FnMut(&str) -> Result<PakEntryData>,
    C: FnMut(PakWriteProgress),
    H: IntoIterator<Item = HP>,
    HP: Into<String>,
{
    check_cancelled(cancellation)?;
    let output_path = output_path.as_ref();
    let mount_point = normalize_mount_point(mount_point)?;
    let sorted_paths = sort_and_validate_paths(paths)?;
    let mut source_hash_paths = sort_and_validate_selected_paths(source_hash_paths)?;
    for (key, requested_path) in &source_hash_paths {
        if !sorted_paths.contains_key(key) {
            return Err(PakError::MissingEntry(requested_path.clone()));
        }
    }
    prepare_output_compression(compression, Some(cancellation))?;

    let output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output_path)
        .map_err(|error| {
            if error.kind() == io::ErrorKind::AlreadyExists {
                PakError::OutputExists(output_path.to_path_buf())
            } else {
                PakError::Io(error)
            }
        })?;

    let mut source_sha256 = BTreeMap::new();
    let result = (|| {
        let builder = match compression {
            OutputCompression::None => repak::PakBuilder::new(),
            OutputCompression::Oodle => {
                repak::PakBuilder::new().compression([repak::Compression::Oodle])
            }
        }
        .parallel_blocks(multithreaded);
        let mut pak_writer = builder.writer(
            BufWriter::new(output),
            repak::Version::V11,
            mount_point,
            Some(0),
        );
        let total = sorted_paths.len();
        for (index, path) in sorted_paths.into_values().enumerate() {
            check_cancelled(cancellation)?;
            progress(PakWriteProgress::Writing {
                completed: index,
                total,
                current_path: Some(path.clone()),
            });
            let data = provider(&path)?;
            let entry_limit = match compression {
                OutputCompression::None => MAX_IN_MEMORY_ENTRY_BYTES,
                OutputCompression::Oodle => MAX_OODLE_OUTPUT_ENTRY_BYTES,
            };
            if data.as_ref().len() as u64 > entry_limit {
                return Err(PakError::EntryTooLarge {
                    path,
                    size: data.as_ref().len() as u64,
                    limit: entry_limit,
                });
            }
            // Cancellation is checked for every compression block, while UI
            // updates are batched so a multi-gigabyte entry cannot flood the
            // event channel. repak invokes this callback on the calling thread
            // in deterministic block order.
            const PROGRESS_REPORT_STEP: u64 = 4 * 1024 * 1024;
            let mut last_reported = 0_u64;
            let collect_source_hash = source_hash_paths
                .remove(&normalized_sort_key(&path))
                .is_some();
            let write_result = write_repak_entry_with_optional_source_sha256(
                &mut pak_writer,
                &path,
                compression == OutputCompression::Oodle,
                data.as_ref(),
                collect_source_hash,
                |completed_bytes, total_bytes| {
                    if cancellation.is_cancelled() {
                        return false;
                    }
                    if completed_bytes == 0
                        || completed_bytes == total_bytes
                        || completed_bytes.saturating_sub(last_reported) >= PROGRESS_REPORT_STEP
                    {
                        progress(PakWriteProgress::WritingBytes {
                            completed_bytes,
                            total_bytes,
                            current_path: path.clone(),
                        });
                        last_reported = completed_bytes;
                    }
                    !cancellation.is_cancelled()
                },
            );
            match write_result {
                Ok(Some(hash)) => {
                    source_sha256.insert(path.clone(), hash);
                }
                Ok(None) => {}
                Err(error) => {
                    if cancellation.is_cancelled() {
                        return Err(PakError::Cancelled);
                    }
                    return Err(map_repak_error(error));
                }
            }
            check_cancelled(cancellation)?;
            // `data` is intentionally dropped here before requesting the next
            // entry from the provider.
        }
        if let Some((_, missing)) = source_hash_paths.first_key_value() {
            return Err(PakError::MissingEntry(missing.clone()));
        }
        progress(PakWriteProgress::Writing {
            completed: total,
            total,
            current_path: None,
        });
        check_cancelled(cancellation)?;
        let mut writer = pak_writer.write_index().map_err(map_repak_error)?;
        writer.flush()?;
        let output = writer
            .into_inner()
            .map_err(|error| PakError::Io(error.into_error()))?;
        output.sync_all()?;
        drop(output);
        check_cancelled(cancellation)?;
        progress(PakWriteProgress::Verifying);
        let verification_cache_policy = DecodeCachePolicy::runtime()?;
        PakArchive::open_internal_with_policy(
            output_path,
            LogicalValidation::StrictDiscard,
            multithreaded,
            cancellation,
            &mut |verification| match verification {
                PakOpenProgress::Scanning {
                    completed_bytes,
                    total_bytes,
                } => progress(PakWriteProgress::VerificationProgress {
                    completed_bytes,
                    total_bytes,
                    current_path: None,
                }),
                PakOpenProgress::Decoding {
                    completed_bytes,
                    total_bytes,
                    current_path,
                } => progress(PakWriteProgress::VerificationProgress {
                    completed_bytes,
                    total_bytes,
                    current_path,
                }),
            },
            verification_cache_policy,
        )
    })();

    let result = result.map(|archive| PakWriteResultWithSourceHashes {
        archive,
        source_sha256,
    });
    if result.is_err() {
        let _ = std::fs::remove_file(output_path);
    }
    result
}

fn prepare_output_compression(
    compression: OutputCompression,
    cancellation: Option<&CancellationToken>,
) -> Result<()> {
    if compression == OutputCompression::None {
        return Ok(());
    }

    prepare_oodle_support("merged output", cancellation)
}

/// Returns the exact pure block layout used by the pinned v11 writer for an
/// Oodle-compressed output entry. No codec runtime is loaded and no payload is
/// allocated.
pub(crate) fn oodle_output_block_layout(logical_size: u64) -> Result<(u64, u64)> {
    let layout = repak::compression_block_layout(logical_size).map_err(map_repak_error)?;
    Ok((u64::from(layout.block_size), u64::from(layout.block_count)))
}

/// Returns Oodle's authoritative maximum encoded-buffer size for each distinct
/// output block size. The runtime is prepared once so disk preflight does not
/// compress input data or repeatedly load the codec.
pub(crate) fn oodle_output_block_bounds(
    raw_block_sizes: &BTreeSet<u64>,
    cancellation: Option<&CancellationToken>,
) -> Result<BTreeMap<u64, u64>> {
    if raw_block_sizes.is_empty() {
        return Ok(BTreeMap::new());
    }
    let oodle = match oodle_loader::oodle_with_cancel(|| {
        cancellation.is_some_and(CancellationToken::is_cancelled)
    }) {
        Ok(oodle) => oodle,
        Err(oodle_loader::Error::Cancelled) => return Err(PakError::Cancelled),
        Err(error) => return Err(oodle_prepare_error("merged output size estimate", error)),
    };
    raw_block_sizes
        .iter()
        .map(|&raw_size| {
            if cancellation.is_some_and(CancellationToken::is_cancelled) {
                return Err(PakError::Cancelled);
            }
            if raw_size == 0 || raw_size > u64::from(u32::MAX) {
                return Err(PakError::Corrupt(format!(
                    "invalid Oodle output block size {raw_size}"
                )));
            }
            let raw_size = usize::try_from(raw_size).map_err(|_| PakError::EntryTooLarge {
                path: "merged output size estimate".to_owned(),
                size: raw_size,
                limit: usize::MAX as u64,
            })?;
            let bound =
                oodle.compressed_buffer_size_needed(oodle_loader::Compressor::Mermaid, raw_size);
            Ok((raw_size as u64, bound as u64))
        })
        .collect()
}

fn prepare_oodle_support(context: &str, cancellation: Option<&CancellationToken>) -> Result<()> {
    match oodle_loader::oodle_with_cancel(|| {
        cancellation.is_some_and(CancellationToken::is_cancelled)
    }) {
        Ok(_) => Ok(()),
        Err(oodle_loader::Error::Cancelled) => Err(PakError::Cancelled),
        Err(error) => Err(oodle_prepare_error(context, error)),
    }
}

fn oodle_prepare_error(path: &str, error: impl std::fmt::Display) -> PakError {
    PakError::OodleUnavailable {
        path: path.to_owned(),
        reason: error.to_string(),
    }
}

/// Generic writer entry point used by tests and by callers that manage their
/// own temporary file. Entries are sorted by a case-insensitive normalized
/// key before being handed to repak.
pub fn write_pak_v11_to<W: Write + Seek>(
    writer: W,
    mount_point: &str,
    entries: impl IntoIterator<Item = PakWriteEntry>,
) -> Result<W> {
    let mount_point = normalize_mount_point(mount_point)?;
    let mut sorted = BTreeMap::<String, PakWriteEntry>::new();
    for mut entry in entries {
        entry.path = normalize_entry_path(&entry.path)?;
        let key = normalized_sort_key(&entry.path);
        if let Some(first) = sorted.get(&key) {
            return Err(PakError::DuplicatePath {
                first: first.path.clone(),
                second: entry.path,
            });
        }
        sorted.insert(key, entry);
    }
    if sorted.is_empty() {
        return Err(PakError::EmptyArchive);
    }

    let mut pak_writer =
        repak::PakBuilder::new().writer(writer, repak::Version::V11, mount_point, Some(0));
    for entry in sorted.into_values() {
        pak_writer
            .write_file(&entry.path, false, &entry.data)
            .map_err(map_repak_error)?;
    }
    pak_writer.write_index().map_err(map_repak_error)
}

fn sort_and_validate_paths<I, P>(paths: I) -> Result<BTreeMap<String, String>>
where
    I: IntoIterator<Item = P>,
    P: Into<String>,
{
    let mut sorted: BTreeMap<String, String> = BTreeMap::new();
    for path in paths {
        let path = normalize_entry_path(&path.into())?;
        let key = normalized_sort_key(&path);
        if let Some(first) = sorted.get(&key) {
            return Err(PakError::DuplicatePath {
                first: first.clone(),
                second: path,
            });
        }
        sorted.insert(key, path);
    }
    if sorted.is_empty() {
        return Err(PakError::EmptyArchive);
    }
    Ok(sorted)
}

fn sort_and_validate_selected_paths<I, P>(paths: I) -> Result<BTreeMap<String, String>>
where
    I: IntoIterator<Item = P>,
    P: Into<String>,
{
    let mut selected = BTreeMap::<String, String>::new();
    for path in paths {
        let path = normalize_entry_path(&path.into())?;
        let key = normalized_sort_key(&path);
        if let Some(first) = selected.get(&key) {
            return Err(PakError::DuplicatePath {
                first: first.clone(),
                second: path,
            });
        }
        selected.insert(key, path);
    }
    Ok(selected)
}

/// Reopens and fully hashes a produced archive. The expected inventory check
/// catches accidental path, size, or payload changes during promotion/copying.
pub fn verify_pak_v11(
    path: impl AsRef<Path>,
    expected: Option<&PakInventory>,
) -> Result<PakInventory> {
    let actual = inspect_pak_strict(path)?;
    if actual.footer.version != SUPPORTED_PAK_VERSION {
        return Err(PakError::UnsupportedVersion {
            actual: actual.footer.version,
        });
    }
    if let Some(expected) = expected {
        let expected_entries: Vec<_> = expected
            .entries
            .iter()
            .map(|e| (&e.path, e.size, e.stored_size, e.compressed, &e.sha256))
            .collect();
        let actual_entries: Vec<_> = actual
            .entries
            .iter()
            .map(|e| (&e.path, e.size, e.stored_size, e.compressed, &e.sha256))
            .collect();
        if expected.mount_point != actual.mount_point
            || expected.footer.compression_slots != actual.footer.compression_slots
            || expected_entries != actual_entries
        {
            return Err(PakError::Corrupt(
                "output inventory differs from the expected inventory".to_owned(),
            ));
        }
    }
    Ok(actual)
}

pub fn normalize_entry_path(path: &str) -> Result<String> {
    if path.is_empty() {
        return Err(invalid_path(path, "path is empty"));
    }
    if path.starts_with('/') || path.starts_with('\\') {
        return Err(invalid_path(path, "absolute paths are forbidden"));
    }
    if path.contains('\\') {
        return Err(invalid_path(path, "backslashes are forbidden"));
    }
    if path.chars().any(|c| c == '\0' || c.is_control()) {
        return Err(invalid_path(path, "NUL/control characters are forbidden"));
    }
    if path.contains(':') {
        return Err(invalid_path(
            path,
            "drive/device/alternate-stream separators are forbidden",
        ));
    }

    let mut components = Vec::new();
    for component in path.split('/') {
        if component.is_empty() {
            return Err(invalid_path(path, "empty path component is forbidden"));
        }
        if component == "." || component == ".." {
            return Err(invalid_path(path, "dot traversal components are forbidden"));
        }
        components.push(component);
    }
    Ok(components.join("/"))
}

pub fn normalize_mount_point(mount_point: &str) -> Result<String> {
    if mount_point.is_empty() {
        return Err(PakError::InvalidMountPoint {
            mount_point: mount_point.to_owned(),
            reason: "the Pak base folder is empty".to_owned(),
        });
    }
    if mount_point.starts_with('/') || mount_point.starts_with('\\') {
        return Err(PakError::InvalidMountPoint {
            mount_point: mount_point.to_owned(),
            reason: "an absolute Pak base folder is not allowed".to_owned(),
        });
    }
    if mount_point.contains('\\') || mount_point.chars().any(|c| c == '\0' || c.is_control()) {
        return Err(PakError::InvalidMountPoint {
            mount_point: mount_point.to_owned(),
            reason: "backslashes and NUL/control characters are forbidden".to_owned(),
        });
    }
    if mount_point
        .split('/')
        .next()
        .is_some_and(|c| c.contains(':'))
    {
        return Err(PakError::InvalidMountPoint {
            mount_point: mount_point.to_owned(),
            reason: "drive/device prefixes are forbidden".to_owned(),
        });
    }
    if mount_point.contains("//") {
        return Err(PakError::InvalidMountPoint {
            mount_point: mount_point.to_owned(),
            reason: "the Pak base folder contains an empty path segment".to_owned(),
        });
    }
    let mut normalized = mount_point.to_owned();
    if !normalized.ends_with('/') {
        normalized.push('/');
    }
    Ok(normalized)
}

pub fn group_packages<'a>(paths: impl IntoIterator<Item = &'a str>) -> Result<PackageGrouping> {
    let mut packages = BTreeMap::<String, PackageGroup>::new();
    let mut loose_entries = Vec::new();
    let mut seen = BTreeMap::<String, String>::new();

    for path in paths {
        let path = normalize_entry_path(path)?;
        let path_key = normalized_sort_key(&path);
        if let Some(first) = seen.insert(path_key, path.clone()) {
            return Err(PakError::DuplicatePath {
                first,
                second: path,
            });
        }
        if let Some((component, base_path)) = PackageComponent::from_path(&path) {
            let base_key = normalized_sort_key(base_path);
            let group = packages.entry(base_key).or_insert_with(|| PackageGroup {
                base_path: base_path.to_owned(),
                components: BTreeMap::new(),
                complete: false,
            });
            group.components.insert(component, path);
        } else {
            loose_entries.push(path);
        }
    }

    for package in packages.values_mut() {
        package.complete = package.components.contains_key(&PackageComponent::Uasset);
    }
    loose_entries.sort_by_key(|path| normalized_sort_key(path));
    Ok(PackageGrouping {
        packages: packages.into_values().collect(),
        loose_entries,
    })
}

#[derive(Debug)]
struct ParsedIndexes {
    mount_point: String,
    path_hash_seed: u64,
    entries: BTreeMap<String, EntryRecord>,
}

#[derive(Debug, Clone)]
struct IndexRegion {
    name: &'static str,
    offset: u64,
    size: u64,
    expected_sha1: [u8; 20],
}

const INPUT_REPAK_VERSIONS: [repak::Version; 13] = [
    repak::Version::V11,
    repak::Version::V10,
    repak::Version::V9,
    repak::Version::V8B,
    repak::Version::V8A,
    repak::Version::V7,
    repak::Version::V6,
    repak::Version::V5,
    repak::Version::V4,
    repak::Version::V3,
    repak::Version::V2,
    repak::Version::V1,
    repak::Version::V0,
];

#[derive(Debug, Clone)]
struct DetectedFooter {
    repak_version: repak::Version,
    footer_offset: u64,
    footer: PakFooterInfo,
    /// Compression slots with their original positions intact. Versions older
    /// than v8 use Unreal's fixed Zlib/Gzip/Oodle slots.
    compression_codecs: Vec<Option<String>>,
}

fn read_footer(file: &mut File, archive_size: u64) -> Result<DetectedFooter> {
    let mut recognized = Vec::new();
    let mut other_versions = BTreeSet::new();

    for repak_version in INPUT_REPAK_VERSIONS {
        let footer_size = repak_version.size() as u64;
        if archive_size < footer_size {
            continue;
        }
        let footer_offset = archive_size - footer_size;
        file.seek(SeekFrom::Start(footer_offset))?;
        let mut bytes = vec![0u8; footer_size as usize];
        file.read_exact(&mut bytes)?;

        let major = repak_version.version_major() as u32;
        let signature_offset = footer_prefix_size(major);
        let Some(signature) = bytes.get(signature_offset..signature_offset + 8) else {
            continue;
        };
        let magic = u32::from_le_bytes(signature[..4].try_into().expect("length checked"));
        if magic != PAK_MAGIC {
            continue;
        }
        let actual_version =
            u32::from_le_bytes(signature[4..8].try_into().expect("length checked"));
        if actual_version == major {
            recognized.push((repak_version, footer_offset, bytes));
        } else {
            other_versions.insert(actual_version);
        }
    }

    if recognized.len() > 1 {
        return Err(PakError::Corrupt(
            "archive contains multiple plausible Pak footers".to_owned(),
        ));
    }
    let Some((repak_version, footer_offset, bytes)) = recognized.pop() else {
        if let Some(actual) = other_versions.into_iter().next() {
            return Err(PakError::UnsupportedVersion { actual });
        }
        file.seek(SeekFrom::Start(archive_size - MIN_PAK_FOOTER_SIZE))?;
        let mut raw_magic = [0u8; 4];
        file.read_exact(&mut raw_magic)?;
        return Err(PakError::InvalidMagic {
            actual: u32::from_le_bytes(raw_magic),
            expected: PAK_MAGIC,
        });
    };

    parse_footer(repak_version, footer_offset, &bytes)
}

fn footer_prefix_size(version: u32) -> usize {
    usize::from(version >= 7) * 16 + usize::from(version >= 4)
}

fn parse_footer(
    repak_version: repak::Version,
    footer_offset: u64,
    bytes: &[u8],
) -> Result<DetectedFooter> {
    let version = repak_version.version_major() as u32;
    let mut cursor = SliceReader::new(bytes, "Pak footer");
    if version >= 7 {
        cursor.skip(16)?; // encryption GUID; deliberately never exposed as a key API
    }
    let encrypted_index = if version >= 4 {
        read_boolean(&mut cursor, "footer encryption flag")?
    } else {
        false
    };
    let magic = cursor.read_u32()?;
    if magic != PAK_MAGIC {
        return Err(PakError::InvalidMagic {
            actual: magic,
            expected: PAK_MAGIC,
        });
    }
    let actual_version = cursor.read_u32()?;
    if actual_version != version {
        return Err(PakError::UnsupportedVersion {
            actual: actual_version,
        });
    }
    if encrypted_index {
        return Err(PakError::EncryptedIndex);
    }
    let index_offset = cursor.read_u64()?;
    let index_size = cursor.read_u64()?;
    let index_sha1 = cursor.read_array_20()?;
    if version == 9 && read_boolean(&mut cursor, "frozen index flag")? {
        return Err(PakError::UnsupportedLayout(
            "frozen v9 indexes are not supported".to_owned(),
        ));
    }

    let compression_slot_count = if repak_version < repak::Version::V8A {
        0
    } else if repak_version < repak::Version::V8B {
        4
    } else {
        5
    };
    let mut compression_codecs = Vec::with_capacity(compression_slot_count);
    for _ in 0..compression_slot_count {
        let slot = cursor.read_bytes(32)?;
        let end = slot
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(slot.len());
        if slot[end..].iter().any(|byte| *byte != 0) {
            return Err(PakError::Corrupt(
                "compression slot has non-NUL data after terminator".to_owned(),
            ));
        }
        let name = (end != 0)
            .then(|| std::str::from_utf8(&slot[..end]))
            .transpose()
            .map_err(|_| PakError::Corrupt("compression slot is not UTF-8".to_owned()))?
            .map(str::to_owned);
        compression_codecs.push(name);
    }
    if repak_version < repak::Version::V8A {
        compression_codecs = vec![
            Some("Zlib".to_owned()),
            Some("Gzip".to_owned()),
            Some("Oodle".to_owned()),
        ];
    }
    let compression_slots = compression_codecs.iter().filter_map(Clone::clone).collect();
    cursor.finish()?;

    validate_region("primary index", index_offset, index_size, footer_offset)?;
    if index_size > MAX_INDEX_BYTES {
        return Err(PakError::UnsupportedLayout(format!(
            "primary index is {index_size} bytes (limit {MAX_INDEX_BYTES})"
        )));
    }
    Ok(DetectedFooter {
        repak_version,
        footer_offset,
        compression_codecs,
        footer: PakFooterInfo {
            version,
            encrypted_index,
            index_offset,
            index_size,
            index_sha1: hex::encode(index_sha1),
            compression_slots,
        },
    })
}

fn read_boolean(cursor: &mut SliceReader<'_>, name: &str) -> Result<bool> {
    match cursor.read_u8()? {
        0 => Ok(false),
        1 => Ok(true),
        value => Err(PakError::Corrupt(format!("{name} is not boolean: {value}"))),
    }
}

fn parse_and_validate_indexes(file: &mut File, detected: &DetectedFooter) -> Result<ParsedIndexes> {
    if detected.footer.version >= 10 {
        parse_and_validate_modern_indexes(file, detected)
    } else {
        parse_and_validate_legacy_index(file, detected)
    }
}

fn parse_and_validate_modern_indexes(
    file: &mut File,
    detected: &DetectedFooter,
) -> Result<ParsedIndexes> {
    let footer = &detected.footer;
    let expected_primary = decode_sha1(&footer.index_sha1)?;
    let primary = read_region_verified(
        file,
        &IndexRegion {
            name: "primary index",
            offset: footer.index_offset,
            size: footer.index_size,
            expected_sha1: expected_primary,
        },
        detected.footer_offset,
    )?;
    let mut cursor = SliceReader::new(&primary, "primary index");
    let mount_point = normalize_mount_point(&cursor.read_fstring()?)?;
    let record_count = cursor.read_u32()?;
    if record_count > MAX_ENTRY_COUNT {
        return Err(PakError::UnsupportedLayout(format!(
            "file count {record_count} exceeds limit {MAX_ENTRY_COUNT}"
        )));
    }
    let path_hash_seed = cursor.read_u64()?;
    let path_hash_region =
        read_optional_index_region(&mut cursor, "path hash index")?.ok_or_else(|| {
            PakError::UnsupportedLayout(format!("v{} path hash index is absent", footer.version))
        })?;
    let directory_region = read_optional_index_region(&mut cursor, "full directory index")?
        .ok_or_else(|| {
            PakError::UnsupportedLayout(format!(
                "v{} full directory index is absent",
                footer.version
            ))
        })?;
    let encoded_entries_size = cursor.read_u32()? as usize;
    let encoded_entries = cursor.read_bytes(encoded_entries_size)?;
    let non_encoded_count = cursor.read_u32()?;
    if non_encoded_count != 0 {
        return Err(PakError::UnsupportedLayout(format!(
            "{non_encoded_count} non-encoded entries are present"
        )));
    }
    cursor.finish()?;

    let footer_offset = detected.footer_offset;
    let primary_end = footer
        .index_offset
        .checked_add(footer.index_size)
        .ok_or_else(|| PakError::Corrupt("primary index range overflow".to_owned()))?;
    for region in [&path_hash_region, &directory_region] {
        if region.offset < primary_end {
            return Err(PakError::Corrupt(format!(
                "{} overlaps or precedes the primary index end",
                region.name
            )));
        }
        validate_region(region.name, region.offset, region.size, footer_offset)?;
        if region.size > MAX_INDEX_BYTES {
            return Err(PakError::UnsupportedLayout(format!(
                "{} is {} bytes (limit {})",
                region.name, region.size, MAX_INDEX_BYTES
            )));
        }
    }
    let combined_index_bytes = footer
        .index_size
        .checked_add(path_hash_region.size)
        .and_then(|value| value.checked_add(directory_region.size))
        .ok_or_else(|| PakError::Corrupt("combined index size overflow".to_owned()))?;
    if combined_index_bytes > MAX_COMBINED_INDEX_BYTES {
        return Err(PakError::UnsupportedLayout(format!(
            "combined indexes are {combined_index_bytes} bytes (limit {MAX_COMBINED_INDEX_BYTES})"
        )));
    }
    ensure_regions_disjoint(&path_hash_region, &directory_region)?;

    let hashed_entries = {
        let path_hash_bytes = read_region_verified(file, &path_hash_region, footer_offset)?;
        parse_path_hash_index(&path_hash_bytes, record_count, encoded_entries.len())?
    };
    let path_offsets = {
        let directory_bytes = read_region_verified(file, &directory_region, footer_offset)?;
        parse_full_directory_index(&directory_bytes, record_count)?
    };
    let directory_offsets: BTreeSet<_> = path_offsets.iter().map(|(_, offset)| *offset).collect();
    let hashed_offsets: BTreeSet<_> = hashed_entries.keys().copied().collect();
    if hashed_offsets != directory_offsets {
        return Err(PakError::Corrupt(
            "path hash and full directory indexes reference different encoded entries".to_owned(),
        ));
    }
    validate_path_hashes(&hashed_entries, &path_offsets, path_hash_seed)?;

    let mut entries: BTreeMap<String, EntryRecord> = BTreeMap::new();
    let mut occupied_regions = Vec::new();
    occupied_regions
        .try_reserve_exact(path_offsets.len())
        .map_err(|_| {
            PakError::UnsupportedLayout("the internal file table is too large".to_owned())
        })?;
    for (path, encoded_offset) in path_offsets {
        let encoded = parse_encoded_entry(encoded_entries, encoded_offset, &path)?;
        if encoded.encrypted {
            return Err(PakError::EncryptedEntry { path });
        }
        validate_compression_method(detected, encoded.compression_method, &path)?;
        let header_size = serialized_entry_header_size(
            detected.repak_version,
            encoded.compression_method != 0,
            encoded.block_sizes.len() as u32,
        )?;
        let data_end = encoded
            .header_offset
            .checked_add(header_size)
            .and_then(|offset| offset.checked_add(encoded.compressed_size))
            .ok_or_else(|| PakError::Corrupt("file data range overflow".to_owned()))?;
        if data_end > footer.index_offset {
            return Err(PakError::Corrupt(format!(
                "file {path} extends into the Pak file list"
            )));
        }
        let local = validate_local_entry_header(file, detected, &path, &encoded, header_size)?;
        let direct_decode_plan =
            build_direct_decode_plan(&local, encoded.header_offset, header_size, detected, &path)?;
        let payload_sha1 = local.payload_sha1;
        occupied_regions.push((encoded.header_offset, data_end, path.clone()));
        let key = normalized_sort_key(&path);
        if let Some(first) = entries.get(&key) {
            return Err(PakError::DuplicatePath {
                first: first.path.clone(),
                second: path,
            });
        }
        entries.insert(
            key,
            EntryRecord {
                path,
                header_offset: encoded.header_offset,
                header_size,
                stored_size: encoded.compressed_size,
                size: encoded.uncompressed_size,
                compressed: encoded.compression_method != 0,
                oodle_compressed: compression_method_name(detected, encoded.compression_method)
                    == Some("Oodle"),
                direct_decode_plan,
                payload_sha1,
                stored_payload_sha1: payload_sha1,
                stored_sha256: [0; 32],
            },
        );
    }
    occupied_regions.sort_by_key(|(start, _, _)| *start);
    for pair in occupied_regions.windows(2) {
        let (_, first_end, first_path) = &pair[0];
        let (second_start, _, second_path) = &pair[1];
        if second_start < first_end {
            return Err(PakError::Corrupt(format!(
                "file data ranges overlap: {first_path} and {second_path}"
            )));
        }
    }
    Ok(ParsedIndexes {
        mount_point,
        path_hash_seed,
        entries,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CompressionBlock {
    start: u64,
    end: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LegacyEntryMetadata {
    stored_offset: u64,
    compressed_size: u64,
    uncompressed_size: u64,
    compression_method: u32,
    timestamp: Option<u64>,
    payload_sha1: [u8; 20],
    blocks: Vec<CompressionBlock>,
    flags: u8,
    compression_block_size: u32,
}

fn parse_and_validate_legacy_index(
    file: &mut File,
    detected: &DetectedFooter,
) -> Result<ParsedIndexes> {
    let footer = &detected.footer;
    let primary = read_region_verified(
        file,
        &IndexRegion {
            name: "primary index",
            offset: footer.index_offset,
            size: footer.index_size,
            expected_sha1: decode_sha1(&footer.index_sha1)?,
        },
        detected.footer_offset,
    )?;
    let mut cursor = SliceReader::new(&primary, "legacy primary index");
    let mount_point = normalize_mount_point(&cursor.read_fstring()?)?;
    let entry_count = cursor.read_u32()?;
    if entry_count > MAX_ENTRY_COUNT {
        return Err(PakError::UnsupportedLayout(format!(
            "file count {entry_count} exceeds limit {MAX_ENTRY_COUNT}"
        )));
    }

    let mut entries = BTreeMap::<String, EntryRecord>::new();
    let mut occupied_regions = Vec::new();
    occupied_regions
        .try_reserve_exact(entry_count as usize)
        .map_err(|_| {
            PakError::UnsupportedLayout("the internal file table is too large".to_owned())
        })?;

    for _ in 0..entry_count {
        let path = normalize_entry_path(&cursor.read_fstring()?)?;
        let indexed = parse_legacy_entry(&mut cursor, detected, &path)?;
        let header_size = serialized_entry_header_size(
            detected.repak_version,
            indexed.compression_method != 0,
            indexed.blocks.len() as u32,
        )?;
        validate_compression_blocks(
            &indexed,
            indexed.stored_offset,
            header_size,
            detected,
            &path,
        )?;
        let data_end = indexed
            .stored_offset
            .checked_add(header_size)
            .and_then(|offset| offset.checked_add(indexed.compressed_size))
            .ok_or_else(|| PakError::Corrupt("file data range overflow".to_owned()))?;
        if data_end > footer.index_offset {
            return Err(PakError::Corrupt(format!(
                "file {path} extends into the Pak file list"
            )));
        }

        file.seek(SeekFrom::Start(indexed.stored_offset))?;
        let mut local_bytes = allocate_zeroed_buffer(header_size, "legacy file header")?;
        file.read_exact(&mut local_bytes)?;
        let mut local_cursor = SliceReader::new(&local_bytes, "legacy file header");
        let local = parse_legacy_entry(&mut local_cursor, detected, &path)?;
        local_cursor.finish()?;
        validate_compression_blocks(&local, indexed.stored_offset, header_size, detected, &path)?;
        if local.stored_offset != 0
            || local.compressed_size != indexed.compressed_size
            || local.uncompressed_size != indexed.uncompressed_size
            || local.compression_method != indexed.compression_method
            || local.timestamp != indexed.timestamp
            || local.payload_sha1 != indexed.payload_sha1
            || local.blocks != indexed.blocks
            || local.flags != indexed.flags
            || local.compression_block_size != indexed.compression_block_size
        {
            return Err(PakError::Corrupt(format!(
                "the file header for {path} disagrees with the Pak file list"
            )));
        }
        let direct_decode_plan =
            build_direct_decode_plan(&local, indexed.stored_offset, header_size, detected, &path)?;

        occupied_regions.push((indexed.stored_offset, data_end, path.clone()));
        let key = normalized_sort_key(&path);
        if let Some(first) = entries.get(&key) {
            return Err(PakError::DuplicatePath {
                first: first.path.clone(),
                second: path,
            });
        }
        entries.insert(
            key,
            EntryRecord {
                path,
                header_offset: indexed.stored_offset,
                header_size,
                stored_size: indexed.compressed_size,
                size: indexed.uncompressed_size,
                compressed: indexed.compression_method != 0,
                oodle_compressed: compression_method_name(detected, indexed.compression_method)
                    == Some("Oodle"),
                direct_decode_plan,
                payload_sha1: indexed.payload_sha1,
                stored_payload_sha1: indexed.payload_sha1,
                stored_sha256: [0; 32],
            },
        );
    }
    cursor.finish()?;

    occupied_regions.sort_by_key(|(start, _, _)| *start);
    for pair in occupied_regions.windows(2) {
        let (_, first_end, first_path) = &pair[0];
        let (second_start, _, second_path) = &pair[1];
        if second_start < first_end {
            return Err(PakError::Corrupt(format!(
                "file data ranges overlap: {first_path} and {second_path}"
            )));
        }
    }

    Ok(ParsedIndexes {
        mount_point,
        path_hash_seed: 0,
        entries,
    })
}

fn parse_legacy_entry(
    cursor: &mut SliceReader<'_>,
    detected: &DetectedFooter,
    path: &str,
) -> Result<LegacyEntryMetadata> {
    let repak_version = detected.repak_version;
    let version = repak_version.version_major() as u32;
    let stored_offset = cursor.read_u64()?;
    let compressed_size = cursor.read_u64()?;
    let uncompressed_size = cursor.read_u64()?;
    let compression_method = if repak_version == repak::Version::V8A {
        u32::from(cursor.read_u8()?)
    } else {
        cursor.read_u32()?
    };
    let timestamp = (version == 1).then(|| cursor.read_u64()).transpose()?;
    let payload_sha1 = cursor.read_array_20()?;

    validate_compression_method(detected, compression_method, path)?;
    if compression_method == 0 && compressed_size != uncompressed_size {
        return Err(PakError::Corrupt(format!(
            "uncompressed file {path} has different stored and logical sizes"
        )));
    }

    let blocks = if version >= 3 && compression_method != 0 {
        let count = cursor.read_u32()?;
        if count > MAX_COMPRESSION_BLOCKS {
            return Err(PakError::UnsupportedLayout(format!(
                "file {path} has {count} compression blocks (limit {MAX_COMPRESSION_BLOCKS})"
            )));
        }
        let mut blocks = Vec::new();
        blocks.try_reserve_exact(count as usize).map_err(|_| {
            PakError::UnsupportedLayout(format!(
                "the compression block list for {path} is too large"
            ))
        })?;
        for _ in 0..count {
            blocks.push(CompressionBlock {
                start: cursor.read_u64()?,
                end: cursor.read_u64()?,
            });
        }
        blocks
    } else {
        Vec::new()
    };

    let (flags, compression_block_size) = if version >= 3 {
        let flags = cursor.read_u8()?;
        let block_size = cursor.read_u32()?;
        if flags & 1 != 0 {
            return Err(PakError::EncryptedEntry {
                path: path.to_owned(),
            });
        }
        if flags & 2 != 0 {
            return Err(PakError::UnsupportedLayout(format!(
                "delete record cannot be merged as a Pak file: {path}"
            )));
        }
        if flags & !3 != 0 {
            return Err(PakError::Corrupt(format!(
                "file {path} has unknown flags {flags:#04x}"
            )));
        }
        if compression_method == 0 && block_size != 0 {
            return Err(PakError::Corrupt(format!(
                "uncompressed file {path} has a non-zero compression block size {block_size}"
            )));
        }
        if compression_method != 0 && blocks.len() > 1 && block_size == 0 {
            return Err(PakError::Corrupt(format!(
                "compressed file {path} has multiple blocks but a zero block size"
            )));
        }
        (flags, block_size)
    } else {
        (0, 0)
    };

    Ok(LegacyEntryMetadata {
        stored_offset,
        compressed_size,
        uncompressed_size,
        compression_method,
        timestamp,
        payload_sha1,
        blocks,
        flags,
        compression_block_size,
    })
}

fn serialized_entry_header_size(
    repak_version: repak::Version,
    compressed: bool,
    block_count: u32,
) -> Result<u64> {
    if block_count > MAX_COMPRESSION_BLOCKS {
        return Err(PakError::UnsupportedLayout(format!(
            "compression block count {block_count} exceeds limit {MAX_COMPRESSION_BLOCKS}"
        )));
    }
    let version = repak_version.version_major() as u32;
    let compression_index_size = if repak_version == repak::Version::V8A {
        1
    } else {
        4
    };
    let base = 24 + compression_index_size + u64::from(version == 1) * 8 + 20;
    let compression_blocks =
        u64::from(version >= 3 && compressed) * (4 + 16 * u64::from(block_count));
    let flags_and_block_size = u64::from(version >= 3) * 5;
    base.checked_add(compression_blocks)
        .and_then(|size| size.checked_add(flags_and_block_size))
        .ok_or_else(|| PakError::Corrupt("entry header size overflow".to_owned()))
}

fn validate_compression_method(
    detected: &DetectedFooter,
    compression_method: u32,
    path: &str,
) -> Result<()> {
    if compression_method == 0 {
        return Ok(());
    }
    let slot = usize::try_from(compression_method - 1)
        .map_err(|_| PakError::Corrupt("compression slot overflow".to_owned()))?;
    let Some(Some(method)) = detected.compression_codecs.get(slot) else {
        return Err(PakError::UnsupportedCompression {
            path: path.to_owned(),
            method: format!("unknown slot {compression_method}"),
        });
    };
    match method.as_str() {
        "Zlib" | "Gzip" | "Zstd" | "LZ4" | "Oodle" => Ok(()),
        _ => Err(PakError::UnsupportedCompression {
            path: path.to_owned(),
            method: method.clone(),
        }),
    }
}

fn compression_method_name(detected: &DetectedFooter, compression_method: u32) -> Option<&str> {
    let slot = usize::try_from(compression_method.checked_sub(1)?).ok()?;
    detected.compression_codecs.get(slot)?.as_deref()
}

fn validate_compression_blocks(
    entry: &LegacyEntryMetadata,
    physical_entry_offset: u64,
    header_size: u64,
    detected: &DetectedFooter,
    path: &str,
) -> Result<()> {
    if entry.compression_method == 0 {
        if !entry.blocks.is_empty() || entry.compressed_size != entry.uncompressed_size {
            return Err(PakError::Corrupt(format!(
                "uncompressed file {path} has compression metadata"
            )));
        }
        return Ok(());
    }

    let repak_version = detected.repak_version;
    let version = repak_version.version_major() as u32;
    if version < 3 {
        if !entry.blocks.is_empty() {
            return Err(PakError::Corrupt(format!(
                "old-format compressed file {path} unexpectedly has a block table"
            )));
        }
        return Ok(());
    }
    if entry.blocks.is_empty() {
        return Err(PakError::Corrupt(format!(
            "compressed file {path} has an empty block table"
        )));
    }

    let mut expected_start = if version >= 5 {
        header_size
    } else {
        physical_entry_offset
            .checked_add(header_size)
            .ok_or_else(|| PakError::Corrupt("compression block offset overflow".to_owned()))?
    };
    let mut total = 0u64;
    for block in &entry.blocks {
        if block.start != expected_start || block.end < block.start {
            return Err(PakError::Corrupt(format!(
                "compression blocks for {path} are not contiguous"
            )));
        }
        let length = block.end - block.start;
        total = total
            .checked_add(length)
            .ok_or_else(|| PakError::Corrupt("compression block size overflow".to_owned()))?;
        expected_start = block.end;
    }
    if total != entry.compressed_size {
        return Err(PakError::Corrupt(format!(
            "compression blocks for {path} total {total} bytes, expected {}",
            entry.compressed_size
        )));
    }
    Ok(())
}

fn build_direct_decode_plan(
    entry: &LegacyEntryMetadata,
    physical_entry_offset: u64,
    header_size: u64,
    detected: &DetectedFooter,
    path: &str,
) -> Result<Option<DirectDecodePlan>> {
    build_direct_decode_plan_with_thresholds(
        entry,
        physical_entry_offset,
        header_size,
        detected,
        path,
        DIRECT_DECODE_LOGICAL_BLOCK_THRESHOLD,
        DIRECT_DECODE_STORED_BLOCK_THRESHOLD,
    )
}

#[allow(clippy::too_many_arguments)]
fn build_direct_decode_plan_with_thresholds(
    entry: &LegacyEntryMetadata,
    physical_entry_offset: u64,
    header_size: u64,
    detected: &DetectedFooter,
    path: &str,
    logical_threshold: u64,
    stored_threshold: u64,
) -> Result<Option<DirectDecodePlan>> {
    let codec = match compression_method_name(detected, entry.compression_method) {
        Some("LZ4") => DirectDecodeCodec::Lz4,
        Some("Oodle") => DirectDecodeCodec::Oodle,
        _ => return Ok(None),
    };
    let payload_start = physical_entry_offset
        .checked_add(header_size)
        .ok_or_else(|| PakError::Corrupt("compressed payload position overflow".to_owned()))?;
    let payload_end = payload_start
        .checked_add(entry.compressed_size)
        .ok_or_else(|| PakError::Corrupt("compressed payload range overflow".to_owned()))?;
    let version = detected.repak_version.version_major() as u32;

    if version < 3 {
        if !entry.blocks.is_empty() {
            return Err(PakError::Corrupt(format!(
                "old-format compressed file {path} unexpectedly has a block table"
            )));
        }
        if entry.uncompressed_size == 0 {
            if entry.compressed_size != 0 {
                return Err(PakError::Corrupt(format!(
                    "compressed file {path} stores data for an empty logical file"
                )));
            }
            return Ok(None);
        }
        let requires_direct =
            entry.uncompressed_size > logical_threshold || entry.compressed_size > stored_threshold;
        return Ok(requires_direct.then(|| DirectDecodePlan {
            codec,
            blocks: vec![DirectDecodeBlock {
                stored_start: payload_start,
                stored_end: payload_end,
                output_start: 0,
                output_end: entry.uncompressed_size,
            }],
        }));
    }

    if entry.uncompressed_size == 0 {
        return Err(PakError::Corrupt(format!(
            "compressed file {path} declares an empty logical payload"
        )));
    }
    let logical_block_size = u64::from(entry.compression_block_size);
    if logical_block_size == 0 {
        return Err(PakError::Corrupt(format!(
            "compressed file {path} has a zero logical block size"
        )));
    }
    let expected_count = entry.uncompressed_size.div_ceil(logical_block_size);
    if u64::try_from(entry.blocks.len()).ok() != Some(expected_count) {
        return Err(PakError::Corrupt(format!(
            "compressed file {path} has {} blocks, expected {expected_count}",
            entry.blocks.len()
        )));
    }

    let mut direct_blocks = Vec::new();
    direct_blocks
        .try_reserve_exact(entry.blocks.len())
        .map_err(|_| {
            PakError::UnsupportedLayout(format!("the direct decode plan for {path} is too large"))
        })?;
    let mut output_start = 0_u64;
    let mut requires_direct = false;
    for block in &entry.blocks {
        let stored_start = if version >= 5 {
            physical_entry_offset
                .checked_add(block.start)
                .ok_or_else(|| {
                    PakError::Corrupt("compression block position overflow".to_owned())
                })?
        } else {
            block.start
        };
        let stored_end = if version >= 5 {
            physical_entry_offset
                .checked_add(block.end)
                .ok_or_else(|| PakError::Corrupt("compression block range overflow".to_owned()))?
        } else {
            block.end
        };
        if stored_start < payload_start || stored_end < stored_start || stored_end > payload_end {
            return Err(PakError::Corrupt(format!(
                "compression block for {path} is outside its stored payload"
            )));
        }
        let logical_size = (entry.uncompressed_size - output_start).min(logical_block_size);
        let output_end = output_start
            .checked_add(logical_size)
            .ok_or_else(|| PakError::Corrupt("logical compression range overflow".to_owned()))?;
        let stored_size = stored_end - stored_start;
        requires_direct |= logical_size > logical_threshold || stored_size > stored_threshold;
        direct_blocks.push(DirectDecodeBlock {
            stored_start,
            stored_end,
            output_start,
            output_end,
        });
        output_start = output_end;
    }
    if output_start != entry.uncompressed_size {
        return Err(PakError::Corrupt(format!(
            "compression blocks for {path} cover {output_start} logical bytes, expected {}",
            entry.uncompressed_size
        )));
    }
    Ok(requires_direct.then_some(DirectDecodePlan {
        codec,
        blocks: direct_blocks,
    }))
}

#[derive(Debug)]
struct EncodedEntry {
    header_offset: u64,
    compressed_size: u64,
    uncompressed_size: u64,
    compression_method: u32,
    compression_block_size: u32,
    block_sizes: Vec<u64>,
    encrypted: bool,
}

fn parse_encoded_entry(bytes: &[u8], offset: usize, path: &str) -> Result<EncodedEntry> {
    if offset >= bytes.len() {
        return Err(PakError::Corrupt(format!(
            "the file record position for {path} is outside the file table"
        )));
    }
    let mut cursor = SliceReader::new(&bytes[offset..], "file record");
    let bits = cursor.read_u32()?;
    let compression_method = (bits >> 23) & 0x3f;
    let encrypted = bits & (1 << 22) != 0;
    let block_count = (bits >> 6) & 0xffff;
    let block_size_code = bits & 0x3f;
    let compression_block_size = if block_size_code == 0x3f {
        cursor.read_u32()?
    } else {
        block_size_code << 11
    };
    let header_offset = read_encoded_int(&mut cursor, bits, 31)?;
    let uncompressed_size = read_encoded_int(&mut cursor, bits, 30)?;
    let compressed_size = if compression_method == 0 {
        uncompressed_size
    } else {
        read_encoded_int(&mut cursor, bits, 29)?
    };
    if compression_method == 0 && block_count != 0 {
        return Err(PakError::Corrupt(format!(
            "uncompressed file {path} declares {block_count} compression blocks"
        )));
    }
    if compression_method == 0 && compression_block_size != 0 {
        return Err(PakError::Corrupt(format!(
            "uncompressed file {path} declares compression block size {compression_block_size}"
        )));
    }
    if compression_method != 0 && block_count == 0 {
        return Err(PakError::Corrupt(format!(
            "compressed file {path} declares no compression blocks"
        )));
    }
    let mut block_sizes = Vec::new();
    block_sizes
        .try_reserve_exact(block_count as usize)
        .map_err(|_| {
            PakError::UnsupportedLayout(format!(
                "the compression block list for {path} is too large"
            ))
        })?;
    if compression_method != 0 {
        if block_count == 1 && !encrypted {
            block_sizes.push(compressed_size);
        } else {
            for _ in 0..block_count {
                block_sizes.push(u64::from(cursor.read_u32()?));
            }
        }
        if !encrypted {
            let block_total = block_sizes.iter().try_fold(0u64, |sum, size| {
                sum.checked_add(*size)
                    .ok_or_else(|| PakError::Corrupt("compression block size overflow".to_owned()))
            })?;
            if block_total != compressed_size {
                return Err(PakError::Corrupt(format!(
                    "compression blocks for {path} total {block_total} bytes, expected {compressed_size}"
                )));
            }
        }
    }
    Ok(EncodedEntry {
        header_offset,
        compressed_size,
        uncompressed_size,
        compression_method,
        compression_block_size,
        block_sizes,
        encrypted,
    })
}

fn read_encoded_int(cursor: &mut SliceReader<'_>, bits: u32, bit: u32) -> Result<u64> {
    if bits & (1 << bit) != 0 {
        Ok(cursor.read_u32()? as u64)
    } else {
        cursor.read_u64()
    }
}

fn validate_local_entry_header(
    file: &mut File,
    detected: &DetectedFooter,
    path: &str,
    encoded: &EncodedEntry,
    header_size: u64,
) -> Result<LegacyEntryMetadata> {
    file.seek(SeekFrom::Start(encoded.header_offset))?;
    let mut header = allocate_zeroed_buffer(header_size, "file header")?;
    file.read_exact(&mut header)?;
    let mut cursor = SliceReader::new(&header, "file header");
    let local = parse_legacy_entry(&mut cursor, detected, path)?;
    cursor.finish()?;
    validate_compression_blocks(&local, encoded.header_offset, header_size, detected, path)?;
    let local_block_sizes = local
        .blocks
        .iter()
        .map(|block| block.end - block.start)
        .collect::<Vec<_>>();
    if local.stored_offset != 0
        || local.compressed_size != encoded.compressed_size
        || local.uncompressed_size != encoded.uncompressed_size
        || local.compression_method != encoded.compression_method
        || local.blocks.len() != encoded.block_sizes.len()
        || local_block_sizes != encoded.block_sizes
        || local.flags != u8::from(encoded.encrypted)
        || local.compression_block_size != encoded.compression_block_size
    {
        return Err(PakError::Corrupt(format!(
            "the file header for {path} disagrees with the Pak file list"
        )));
    }
    Ok(local)
}

fn parse_full_directory_index(bytes: &[u8], expected_count: u32) -> Result<Vec<(String, usize)>> {
    let mut cursor = SliceReader::new(bytes, "full directory index");
    let directory_count = cursor.read_u32()?;
    if directory_count > MAX_ENTRY_COUNT {
        return Err(PakError::UnsupportedLayout(format!(
            "folder count {directory_count} exceeds limit {MAX_ENTRY_COUNT}"
        )));
    }
    let mut paths = Vec::new();
    paths
        .try_reserve_exact(expected_count as usize)
        .map_err(|_| {
            PakError::UnsupportedLayout("directory index exceeds memory budget".to_owned())
        })?;
    let mut seen = BTreeMap::<String, String>::new();
    for _ in 0..directory_count {
        let directory = cursor.read_fstring()?;
        let directory = directory.strip_prefix('/').unwrap_or(&directory);
        let file_count = cursor.read_u32()?;
        if file_count > MAX_ENTRY_COUNT
            || paths.len() + file_count as usize > MAX_ENTRY_COUNT as usize
        {
            return Err(PakError::UnsupportedLayout(
                "full directory index contains too many files".to_owned(),
            ));
        }
        for _ in 0..file_count {
            let file_name = cursor.read_fstring()?;
            let encoded_offset = cursor.read_i32()?;
            if encoded_offset < 0 {
                return Err(PakError::UnsupportedLayout(
                    "the folder list contains an unsupported file reference".to_owned(),
                ));
            }
            let path = normalize_entry_path(&format!("{directory}{file_name}"))?;
            let key = normalized_sort_key(&path);
            if let Some(first) = seen.insert(key, path.clone()) {
                return Err(PakError::DuplicatePath {
                    first,
                    second: path,
                });
            }
            paths.push((path, encoded_offset as usize));
        }
    }
    cursor.finish()?;
    if paths.len() != expected_count as usize {
        return Err(PakError::Corrupt(format!(
            "footer/index declares {expected_count} entries but directory index contains {}",
            paths.len()
        )));
    }
    Ok(paths)
}

fn parse_path_hash_index(
    bytes: &[u8],
    expected_count: u32,
    encoded_size: usize,
) -> Result<BTreeMap<usize, u64>> {
    let mut cursor = SliceReader::new(bytes, "path hash index");
    let count = cursor.read_u32()?;
    if count != expected_count {
        return Err(PakError::Corrupt(format!(
            "path hash index contains {count} records; expected {expected_count}"
        )));
    }
    let mut entries = BTreeMap::new();
    for _ in 0..count {
        let path_hash = cursor.read_u64()?;
        let encoded_offset = cursor.read_i32()?;
        if encoded_offset < 0 || encoded_offset as usize >= encoded_size {
            return Err(PakError::Corrupt(
                "the path lookup table points to an invalid file record".to_owned(),
            ));
        }
        if entries.insert(encoded_offset as usize, path_hash).is_some() {
            return Err(PakError::Corrupt(
                "the path lookup table points to the same file record more than once".to_owned(),
            ));
        }
    }
    // v11 writes a trailing collision/non-encoded table count. repak 0.2.3
    // always emits zero and does not support producing such records.
    let trailing_count = cursor.read_u32()?;
    if trailing_count != 0 {
        return Err(PakError::UnsupportedLayout(format!(
            "path hash index contains {trailing_count} trailing records"
        )));
    }
    cursor.finish()?;
    Ok(entries)
}

/// Verifies the v11 path-hash index using the algorithm implemented by the
/// pinned repak revision. Paths from the full-directory index are already
/// normalized and are relative to the Pak mount point; the mount point itself
/// is deliberately not part of the hash input.
fn validate_path_hashes(
    hashed_entries: &BTreeMap<usize, u64>,
    path_offsets: &[(String, usize)],
    path_hash_seed: u64,
) -> Result<()> {
    for (path, encoded_offset) in path_offsets {
        let stored = hashed_entries.get(encoded_offset).ok_or_else(|| {
            PakError::Corrupt(format!(
                "the path lookup table has no record for {path:?} at file position {encoded_offset}"
            ))
        })?;
        let expected = fnv64_path(path, path_hash_seed);
        if *stored != expected {
            return Err(PakError::Corrupt(format!(
                "the path check for {path:?} at file position {encoded_offset} does not match: expected {expected:#018x}, got {stored:#018x}"
            )));
        }
    }
    Ok(())
}

/// Unreal Pak v10+ path hash: FNV-1a 64 with the stored seed added to the
/// standard offset basis, over the lowercase path encoded as UTF-16LE.
fn fnv64_path(path: &str, seed: u64) -> u64 {
    const OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;

    let mut hash = OFFSET_BASIS.wrapping_add(seed);
    let lowercase = path.to_lowercase();
    for byte in lowercase.encode_utf16().flat_map(u16::to_le_bytes) {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(PRIME);
    }
    hash
}

fn read_optional_index_region(
    cursor: &mut SliceReader<'_>,
    name: &'static str,
) -> Result<Option<IndexRegion>> {
    match cursor.read_u32()? {
        0 => Ok(None),
        1 => Ok(Some(IndexRegion {
            name,
            offset: cursor.read_u64()?,
            size: cursor.read_u64()?,
            expected_sha1: cursor.read_array_20()?,
        })),
        value => Err(PakError::Corrupt(format!(
            "{name} presence flag is not boolean: {value}"
        ))),
    }
}

fn read_region_verified(file: &mut File, region: &IndexRegion, limit: u64) -> Result<Vec<u8>> {
    validate_region(region.name, region.offset, region.size, limit)?;
    if region.size > MAX_INDEX_BYTES || region.size > usize::MAX as u64 {
        return Err(PakError::UnsupportedLayout(format!(
            "{} is too large to inspect safely",
            region.name
        )));
    }
    file.seek(SeekFrom::Start(region.offset))?;
    let mut data = allocate_zeroed_buffer(region.size, region.name)?;
    file.read_exact(&mut data)?;
    let actual: [u8; 20] = Sha1::digest(&data).into();
    if actual != region.expected_sha1 {
        return Err(PakError::Sha1Mismatch {
            region: region.name.to_owned(),
            expected: hex::encode(region.expected_sha1),
            actual: hex::encode(actual),
        });
    }
    Ok(data)
}

fn allocate_zeroed_buffer(size: u64, context: &str) -> Result<Vec<u8>> {
    let len = usize::try_from(size).map_err(|_| {
        PakError::UnsupportedLayout(format!("{context} does not fit this build's address space"))
    })?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(len).map_err(|_| {
        PakError::UnsupportedLayout(format!("{context} is too large to allocate safely"))
    })?;
    bytes.resize(len, 0);
    Ok(bytes)
}

fn validate_region(name: &str, offset: u64, size: u64, limit: u64) -> Result<()> {
    let end = offset
        .checked_add(size)
        .ok_or_else(|| PakError::Corrupt(format!("{name} range overflows u64")))?;
    if size == 0 || offset >= limit || end > limit {
        return Err(PakError::Corrupt(format!(
            "{name} range {offset}..{end} lies outside 0..{limit}"
        )));
    }
    Ok(())
}

fn ensure_regions_disjoint(first: &IndexRegion, second: &IndexRegion) -> Result<()> {
    let first_end = first.offset + first.size;
    let second_end = second.offset + second.size;
    if first.offset < second_end && second.offset < first_end {
        return Err(PakError::Corrupt(format!(
            "{} and {} overlap",
            first.name, second.name
        )));
    }
    Ok(())
}

fn open_archive_readonly(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // Allow other readers, but prevent replacement, deletion, and writes
        // while archive hashes/indexes/payloads are bound to this handle.
        options.share_mode(0x0000_0001); // FILE_SHARE_READ
    }
    options.open(path)
}

#[allow(unsafe_code)]
fn map_complete_archive(file: &File, archive_size: u64) -> Result<memmap2::Mmap> {
    if archive_size > usize::MAX as u64 {
        return Err(PakError::UnsupportedLayout(format!(
            "the Pak is {archive_size} bytes, above this build's address-space limit"
        )));
    }
    // SAFETY: the mapping is read-only, its exact length came from the locked
    // file handle, and `PakArchive` retains both handle and mapping.
    Ok(unsafe {
        memmap2::MmapOptions::new()
            .len(archive_size as usize)
            .map(file)
    }?)
}

fn entry_payload_range(entry: &EntryRecord) -> Result<(usize, usize)> {
    let start = entry
        .header_offset
        .checked_add(entry.header_size)
        .ok_or_else(|| PakError::Corrupt("file contents position overflow".to_owned()))?;
    let end = start
        .checked_add(entry.size)
        .ok_or_else(|| PakError::Corrupt("file contents range overflow".to_owned()))?;
    let start = usize::try_from(start)
        .map_err(|_| PakError::Corrupt("file contents position is too large".to_owned()))?;
    let end = usize::try_from(end)
        .map_err(|_| PakError::Corrupt("file contents end is too large".to_owned()))?;
    Ok((start, end))
}

fn check_cancelled(cancellation: &CancellationToken) -> Result<()> {
    if cancellation.is_cancelled() {
        Err(PakError::Cancelled)
    } else {
        Ok(())
    }
}

struct PayloadHashAccumulator {
    key: String,
    start: u64,
    end: u64,
    sha1: Sha1,
    sha256: Sha256,
}

type PayloadHashes = BTreeMap<String, ([u8; 20], [u8; 32])>;

/// Calculates the archive identity and every stored payload identity during
/// one forward scan. Index/footer parsing necessarily performs a few small
/// random reads first, but the large data area is never walked once per hash.
fn hash_archive_and_entry_payloads(
    archive: &[u8],
    archive_size: u64,
    total_work_bytes: u64,
    entries: &BTreeMap<String, EntryRecord>,
    cancellation: &CancellationToken,
    progress: &mut dyn FnMut(PakOpenProgress),
) -> Result<(String, PayloadHashes)> {
    let mut payloads = Vec::new();
    payloads.try_reserve_exact(entries.len()).map_err(|_| {
        PakError::UnsupportedLayout("the payload hash table is too large".to_owned())
    })?;
    for (key, entry) in entries {
        let start = entry
            .header_offset
            .checked_add(entry.header_size)
            .ok_or_else(|| PakError::Corrupt("file contents position overflow".to_owned()))?;
        let end = start
            .checked_add(entry.stored_size)
            .ok_or_else(|| PakError::Corrupt("file contents range overflow".to_owned()))?;
        if end > archive_size {
            return Err(PakError::Corrupt(format!(
                "file {} extends beyond the end of the Pak",
                entry.path
            )));
        }
        payloads.push(PayloadHashAccumulator {
            key: key.clone(),
            start,
            end,
            sha1: Sha1::new(),
            sha256: Sha256::new(),
        });
    }
    payloads.sort_by_key(|payload| (payload.start, payload.end));

    let mut archive_sha256 = Sha256::new();
    let mut offset = 0_u64;
    let mut first_possible_payload = 0_usize;
    progress(PakOpenProgress::Scanning {
        completed_bytes: 0,
        total_bytes: total_work_bytes,
    });
    while offset < archive_size {
        check_cancelled(cancellation)?;
        let requested = (archive_size - offset).min(COPY_BUFFER_BYTES as u64) as usize;
        let buffer = &archive[offset as usize..offset as usize + requested];
        archive_sha256.update(buffer);
        let chunk_end = offset + requested as u64;

        while first_possible_payload < payloads.len()
            && payloads[first_possible_payload].end <= offset
        {
            first_possible_payload += 1;
        }
        let mut index = first_possible_payload;
        while index < payloads.len() && payloads[index].start < chunk_end {
            let overlap_start = payloads[index].start.max(offset);
            let overlap_end = payloads[index].end.min(chunk_end);
            if overlap_start < overlap_end {
                let start = (overlap_start - offset) as usize;
                let end = (overlap_end - offset) as usize;
                payloads[index].sha1.update(&buffer[start..end]);
                payloads[index].sha256.update(&buffer[start..end]);
            }
            index += 1;
        }
        offset = chunk_end;
        progress(PakOpenProgress::Scanning {
            completed_bytes: offset,
            total_bytes: total_work_bytes,
        });
    }

    let mut hashes = BTreeMap::new();
    for payload in payloads {
        hashes.insert(
            payload.key,
            (
                payload.sha1.finalize().into(),
                payload.sha256.finalize().into(),
            ),
        );
    }
    Ok((hex::encode(archive_sha256.finalize()), hashes))
}

/// Some legacy v3 mod producers rewrite a DB `.uexp` payload without updating
/// the SHA-1 duplicated in its local header and index record. Treating every
/// such mismatch as harmless would hide arbitrary corruption, so this narrow
/// compatibility path is limited to a fully parseable BinaryAsset with a
/// correctly hashed same-basename `.uasset` and a matching Unreal package tag.
/// The caller additionally guarantees that every other mismatched entry is
/// independently subjected to this same `.uexp`-only profile.
fn validate_v3_stale_binary_asset_uexp(
    archive: &[u8],
    entries: &BTreeMap<String, EntryRecord>,
    payload_hashes: &BTreeMap<String, ([u8; 20], [u8; 32])>,
    key: &str,
    cancellation: &CancellationToken,
) -> Result<bool> {
    let Some(entry) = entries.get(key) else {
        return Ok(false);
    };
    if entry.compressed {
        return Ok(false);
    }
    let lower = entry.path.to_ascii_lowercase();
    let Some(stem) = lower.strip_suffix(".uexp") else {
        return Ok(false);
    };
    let companion_key = normalized_sort_key(&format!("{stem}.uasset"));
    let Some(companion) = entries.get(&companion_key) else {
        return Ok(false);
    };
    let Some((companion_actual_sha1, _)) = payload_hashes.get(&companion_key) else {
        return Ok(false);
    };
    if *companion_actual_sha1 != companion.stored_payload_sha1 {
        return Ok(false);
    }

    let maximum_uexp_size = MAX_BINARY_ASSET_PAYLOAD_BYTES
        .saturating_add(crate::binary_asset::PREFIX_SIZE)
        .saturating_add(crate::binary_asset::BINARY_ASSET_FOOTER_SIZE)
        .saturating_add(PACKAGE_TAG_SIZE) as u64;
    let Some(uexp) = read_entry_payload_slice(archive, entry, maximum_uexp_size)? else {
        return Ok(false);
    };
    let Some(uasset) = read_entry_payload_slice(archive, companion, MAX_STALE_HASH_UASSET_BYTES)?
    else {
        return Ok(false);
    };
    let Ok(package_tag) = validate_binary_asset_structure_with_cancel(uexp, cancellation) else {
        if cancellation.is_cancelled() {
            return Err(PakError::Cancelled);
        }
        return Ok(false);
    };
    if package_tag != UNREAL_PACKAGE_TAG
        || uasset.get(..PACKAGE_TAG_SIZE) != Some(package_tag.as_slice())
    {
        return Ok(false);
    }
    Ok(true)
}

fn read_entry_payload_slice<'a>(
    archive: &'a [u8],
    entry: &EntryRecord,
    maximum_size: u64,
) -> Result<Option<&'a [u8]>> {
    if entry.compressed {
        return Ok(None);
    }
    if entry.size > maximum_size || entry.size > usize::MAX as u64 {
        return Ok(None);
    }
    let (start, end) = entry_payload_range(entry)?;
    let bytes = archive.get(start..end).ok_or_else(|| {
        PakError::Corrupt(format!(
            "file {} extends beyond the end of the Pak",
            entry.path
        ))
    })?;
    Ok(Some(bytes))
}

fn decode_entry(
    reader: &repak::PakReader,
    archive: &[u8],
    entry: &EntryRecord,
    cancellation: Option<&CancellationToken>,
    multithreaded: bool,
    cache_policy: &DecodeCachePolicy,
) -> Result<CachedLogicalEntry> {
    decode_entry_with_progress(
        reader,
        archive,
        entry,
        cancellation,
        multithreaded,
        cache_policy,
        &mut |_| {},
    )
}

#[allow(unsafe_code)]
fn decode_entry_with_progress(
    reader: &repak::PakReader,
    archive: &[u8],
    entry: &EntryRecord,
    cancellation: Option<&CancellationToken>,
    multithreaded: bool,
    cache_policy: &DecodeCachePolicy,
    logical_progress: &mut dyn FnMut(u64),
) -> Result<CachedLogicalEntry> {
    if cancellation.is_some_and(CancellationToken::is_cancelled) {
        return Err(PakError::Cancelled);
    }
    logical_progress(0);
    let mut source = io::Cursor::new(archive);
    if entry.direct_decode_plan.is_none()
        && entry.size <= cache_policy.memory_entry_threshold_bytes
        && let Some(reservation) = resources::try_reserve_decoded_memory(entry.size)
    {
        let mut bytes = Vec::new();
        if bytes.try_reserve_exact(entry.size as usize).is_ok() {
            let mut verified = LogicalEntryWriter::new_cancellable_with_progress(
                &mut bytes,
                entry.size,
                cancellation,
                logical_progress,
            );
            if let Err(error) = reader.read_file_with_parallel_blocks(
                &entry.path,
                &mut source,
                &mut verified,
                multithreaded,
            ) {
                if cancellation.is_some_and(CancellationToken::is_cancelled) {
                    return Err(PakError::Cancelled);
                }
                return Err(map_repak_entry_error(error, &entry.path));
            }
            let (_, sha256) = verified.finish()?;
            return Ok(CachedLogicalEntry {
                data: CachedEntryData::Owned {
                    bytes,
                    _reservation: reservation,
                },
                sha256,
            });
        }
        // The reservation is released and the entry falls through to a
        // temporary mapping when the allocator cannot satisfy the request.
    }

    let mut temporary_builder = tempfile::Builder::new();
    temporary_builder.prefix("pak-merger-decoded-");
    let mut temporary = if let Some(cache_directory) = &cache_policy.cache_directory {
        temporary_builder.tempfile_in(cache_directory)?
    } else {
        temporary_builder.tempfile()?
    };
    {
        use fs2::FileExt;
        // Startup cleanup removes only stale decoded files whose ownership
        // lock can be acquired. Keeping this lock on the NamedTempFile handle
        // protects an active cache even if another process starts meanwhile.
        temporary.as_file().lock_exclusive()?;
    }
    let cache_directory = temporary.path().parent().unwrap_or_else(|| Path::new("."));
    let headroom = (entry.size / 20).max(cache_policy.minimum_disk_headroom_bytes);
    let mut disk_reservation =
        resources::reserve_temporary_disk(cache_directory, entry.size, headroom)?.map_err(
            |shortage| PakError::InsufficientCacheDisk {
                path: entry.path.clone(),
                required: shortage.required,
                available: shortage.available,
            },
        )?;

    #[cfg(test)]
    if cache_policy.cancel_after_disk_reservation
        && let Some(cancellation) = cancellation
    {
        cancellation.cancel();
    }
    if cancellation.is_some_and(CancellationToken::is_cancelled) {
        return Err(PakError::Cancelled);
    }

    // Oversized LZ4/Oodle blocks are decoded directly from the read-only Pak
    // mapping into disjoint slices of the temporary output mapping. This keeps
    // both the stored block and logical block off the Rust heap. Pak v0-v2
    // blockless Oodle entries use the same one-block plan when large enough.
    if let Some(plan) = &entry.direct_decode_plan {
        let logical_size = usize::try_from(entry.size).map_err(|_| PakError::EntryTooLarge {
            path: entry.path.clone(),
            size: entry.size,
            limit: usize::MAX as u64,
        })?;
        temporary.as_file_mut().set_len(entry.size)?;
        let mut mapping = if logical_size == 0 {
            return Err(PakError::Corrupt(format!(
                "compressed file {} declares an empty logical payload",
                entry.path
            )));
        } else {
            // SAFETY: the temporary file is exclusively owned here, was sized
            // to the validated logical length above, and remains alive for the
            // complete lifetime of the mapping.
            unsafe {
                memmap2::MmapOptions::new()
                    .len(logical_size)
                    .map_mut(temporary.as_file())
            }?
        };
        let oodle = match plan.codec {
            DirectDecodeCodec::Lz4 => None,
            DirectDecodeCodec::Oodle => Some(
                oodle_loader::oodle().map_err(|error| oodle_prepare_error(&entry.path, error))?,
            ),
        };
        let mut sha256 = Sha256::new();
        for block in &plan.blocks {
            if cancellation.is_some_and(CancellationToken::is_cancelled) {
                return Err(PakError::Cancelled);
            }
            let stored_start = usize::try_from(block.stored_start)
                .map_err(|_| PakError::Corrupt("stored block position is too large".to_owned()))?;
            let stored_end = usize::try_from(block.stored_end)
                .map_err(|_| PakError::Corrupt("stored block end is too large".to_owned()))?;
            let output_start = usize::try_from(block.output_start)
                .map_err(|_| PakError::Corrupt("logical block position is too large".to_owned()))?;
            let output_end = usize::try_from(block.output_end)
                .map_err(|_| PakError::Corrupt("logical block end is too large".to_owned()))?;
            let stored = archive.get(stored_start..stored_end).ok_or_else(|| {
                PakError::Corrupt(format!(
                    "compressed block for {} extends beyond the end of the Pak",
                    entry.path
                ))
            })?;
            let output = mapping.get_mut(output_start..output_end).ok_or_else(|| {
                PakError::Corrupt(format!(
                    "logical block for {} extends beyond its declared size",
                    entry.path
                ))
            })?;
            let expected = output.len();
            let written = match plan.codec {
                DirectDecodeCodec::Lz4 => lz4_flex::block::decompress_into(stored, output)
                    .map_err(|error| PakError::DecompressionFailed {
                        path: entry.path.clone(),
                        reason: format!("LZ4 block could not be decoded: {error}"),
                    })?,
                DirectDecodeCodec::Oodle => oodle
                    .expect("Oodle decoder is prepared for an Oodle plan")
                    .decompress(stored, output)
                    .try_into()
                    .map_err(|_| PakError::DecompressionFailed {
                        path: entry.path.clone(),
                        reason: "Oodle returned a negative decoded size".to_owned(),
                    })?,
            };
            if written != expected {
                let codec_name = match plan.codec {
                    DirectDecodeCodec::Lz4 => "LZ4",
                    DirectDecodeCodec::Oodle => "Oodle",
                };
                return Err(PakError::DecompressionFailed {
                    path: entry.path.clone(),
                    reason: format!("{codec_name} produced {written} bytes, expected {expected}"),
                });
            }
            sha256.update(output);
            disk_reservation.record_materialized(block.output_end - block.output_start);
            logical_progress(block.output_end);
        }
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return Err(PakError::Cancelled);
        }
        let sha256 = sha256.finalize().into();
        let mapping = mapping.make_read_only()?;
        drop(disk_reservation);
        return Ok(CachedLogicalEntry {
            data: CachedEntryData::TemporaryMapped {
                mapping,
                _file: temporary,
            },
            sha256,
        });
    }

    let sha256 = {
        let mut reserved_writer = ReservedTemporaryWriter {
            inner: temporary.as_file_mut(),
            reservation: &mut disk_reservation,
        };
        let mut verified = LogicalEntryWriter::new_cancellable_with_progress(
            &mut reserved_writer,
            entry.size,
            cancellation,
            logical_progress,
        );
        if let Err(error) = reader.read_file_with_parallel_blocks(
            &entry.path,
            &mut source,
            &mut verified,
            multithreaded,
        ) {
            if cancellation.is_some_and(CancellationToken::is_cancelled) {
                return Err(PakError::Cancelled);
            }
            return Err(map_repak_entry_error(error, &entry.path));
        }
        let (_, sha256) = verified.finish()?;
        sha256
    };
    temporary.as_file_mut().flush()?;
    // A complete file is now visible to the filesystem's available-space
    // accounting. Normally no pending bytes remain, but dropping the guard is
    // also the failure-safe for short writes and cancellation.
    drop(disk_reservation);
    let mapping = if entry.size == 0 {
        let reservation = resources::try_reserve_decoded_memory(0)
            .expect("a zero-byte cache reservation always fits");
        return Ok(CachedLogicalEntry {
            data: CachedEntryData::Owned {
                bytes: Vec::new(),
                _reservation: reservation,
            },
            sha256,
        });
    } else {
        // SAFETY: the temporary file remains owned by `CachedEntryData`, the
        // decoded byte count was checked above, and the mapping is read-only.
        unsafe {
            memmap2::MmapOptions::new()
                .len(entry.size as usize)
                .map(temporary.as_file())
        }?
    };
    Ok(CachedLogicalEntry {
        data: CachedEntryData::TemporaryMapped {
            mapping,
            _file: temporary,
        },
        sha256,
    })
}

struct ReservedTemporaryWriter<'a> {
    inner: &'a mut File,
    reservation: &'a mut resources::TemporaryDiskReservation,
}

impl Write for ReservedTemporaryWriter<'_> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let written = self.inner.write(buffer)?;
        self.reservation.record_materialized(written as u64);
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

struct LogicalEntryWriter<'a, W> {
    inner: &'a mut W,
    sha256: Sha256,
    written: u64,
    expected: u64,
    cancellation: Option<&'a CancellationToken>,
    progress: Option<&'a mut dyn FnMut(u64)>,
}

impl<'a, W: Write> LogicalEntryWriter<'a, W> {
    #[cfg(test)]
    fn new_cancellable(
        inner: &'a mut W,
        expected: u64,
        cancellation: Option<&'a CancellationToken>,
    ) -> Self {
        Self {
            inner,
            sha256: Sha256::new(),
            written: 0,
            expected,
            cancellation,
            progress: None,
        }
    }

    fn new_cancellable_with_progress(
        inner: &'a mut W,
        expected: u64,
        cancellation: Option<&'a CancellationToken>,
        progress: &'a mut dyn FnMut(u64),
    ) -> Self {
        Self {
            inner,
            sha256: Sha256::new(),
            written: 0,
            expected,
            cancellation,
            progress: Some(progress),
        }
    }

    fn finish(self) -> Result<(u64, [u8; 32])> {
        if self.written != self.expected {
            return Err(PakError::Corrupt(format!(
                "decoded file size is {} bytes, expected {}",
                self.written, self.expected
            )));
        }
        Ok((self.written, self.sha256.finalize().into()))
    }
}

impl<W: Write> Write for LogicalEntryWriter<'_, W> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if self
            .cancellation
            .is_some_and(CancellationToken::is_cancelled)
        {
            // `io::copy` and `Write::write_all` deliberately retry
            // `Interrupted`. Cancellation is terminal here, so use a
            // non-retryable kind and let `decode_entry` translate it to
            // `PakError::Cancelled` after checking the token.
            return Err(io::Error::other("operation cancelled"));
        }
        let buffer_len = u64::try_from(buffer.len()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "decoded chunk is too large")
        })?;
        let next = self.written.checked_add(buffer_len).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "decoded file size overflow")
        })?;
        if next > self.expected {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "decoded file is larger than its declared size",
            ));
        }
        let written = self.inner.write(buffer)?;
        self.sha256.update(&buffer[..written]);
        self.written += written as u64;
        if let Some(progress) = self.progress.as_deref_mut() {
            progress(self.written);
        }
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

fn decode_sha1(value: &str) -> Result<[u8; 20]> {
    let bytes =
        hex::decode(value).map_err(|_| PakError::Corrupt("invalid SHA-1 encoding".to_owned()))?;
    bytes
        .try_into()
        .map_err(|_| PakError::Corrupt("invalid SHA-1 length".to_owned()))
}

fn normalized_sort_key(path: &str) -> String {
    path.to_lowercase()
}

fn invalid_path(path: &str, reason: &str) -> PakError {
    PakError::InvalidPath {
        path: path.to_owned(),
        reason: reason.to_owned(),
    }
}

fn map_repak_error(error: repak::Error) -> PakError {
    match error {
        repak::Error::Encryption | repak::Error::Encrypted => PakError::EncryptedIndex,
        repak::Error::Compression => PakError::UnsupportedCompression {
            path: "<unknown>".to_owned(),
            method: "compressed data".to_owned(),
        },
        repak::Error::Oodle => PakError::UnsupportedCompression {
            path: "<unknown>".to_owned(),
            method: "Oodle".to_owned(),
        },
        repak::Error::OodleFailed(error) => PakError::OodleUnavailable {
            path: "<unknown>".to_owned(),
            reason: error.to_string(),
        },
        other => PakError::Repak(other.to_string()),
    }
}

fn map_repak_entry_error(error: repak::Error, path: &str) -> PakError {
    match error {
        repak::Error::Encryption | repak::Error::Encrypted => PakError::EncryptedEntry {
            path: path.to_owned(),
        },
        repak::Error::Compression => PakError::UnsupportedCompression {
            path: path.to_owned(),
            method: "compressed data".to_owned(),
        },
        repak::Error::Oodle => PakError::UnsupportedCompression {
            path: path.to_owned(),
            method: "Oodle".to_owned(),
        },
        repak::Error::OodleFailed(error) => PakError::OodleUnavailable {
            path: path.to_owned(),
            reason: error.to_string(),
        },
        repak::Error::DecompressionFailed(method) => PakError::DecompressionFailed {
            path: path.to_owned(),
            reason: method.to_string(),
        },
        repak::Error::MissingEntry(_) => PakError::MissingEntry(path.to_owned()),
        other => PakError::DecompressionFailed {
            path: path.to_owned(),
            reason: other.to_string(),
        },
    }
}

struct SliceReader<'a> {
    data: &'a [u8],
    position: usize,
    context: &'static str,
}

impl<'a> SliceReader<'a> {
    fn new(data: &'a [u8], context: &'static str) -> Self {
        Self {
            data,
            position: 0,
            context,
        }
    }

    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.position)
    }

    fn read_bytes(&mut self, length: usize) -> Result<&'a [u8]> {
        let end = self
            .position
            .checked_add(length)
            .ok_or_else(|| PakError::Corrupt(format!("{} cursor overflow", self.context)))?;
        if end > self.data.len() {
            return Err(PakError::Corrupt(format!(
                "unexpected end of {} (wanted {} bytes, {} remain)",
                self.context,
                length,
                self.remaining()
            )));
        }
        let bytes = &self.data[self.position..end];
        self.position = end;
        Ok(bytes)
    }

    fn skip(&mut self, length: usize) -> Result<()> {
        self.read_bytes(length).map(|_| ())
    }

    fn read_u8(&mut self) -> Result<u8> {
        Ok(self.read_bytes(1)?[0])
    }

    fn read_u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(
            self.read_bytes(4)?.try_into().expect("length checked"),
        ))
    }

    fn read_i32(&mut self) -> Result<i32> {
        Ok(i32::from_le_bytes(
            self.read_bytes(4)?.try_into().expect("length checked"),
        ))
    }

    fn read_u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(
            self.read_bytes(8)?.try_into().expect("length checked"),
        ))
    }

    fn read_array_20(&mut self) -> Result<[u8; 20]> {
        Ok(self.read_bytes(20)?.try_into().expect("length checked"))
    }

    fn read_fstring(&mut self) -> Result<String> {
        let length = self.read_i32()?;
        if length == 0 {
            return Ok(String::new());
        }
        if length == i32::MIN {
            return Err(PakError::Corrupt(format!(
                "invalid FString length in {}",
                self.context
            )));
        }
        if length > 0 {
            let length = length as usize;
            if length > MAX_INDEX_BYTES as usize || length > self.remaining() {
                return Err(PakError::Corrupt(format!(
                    "invalid ANSI FString length {length} in {}",
                    self.context
                )));
            }
            let bytes = self.read_bytes(length)?;
            if bytes.last() != Some(&0) {
                return Err(PakError::Corrupt(format!(
                    "ANSI FString is not NUL terminated in {}",
                    self.context
                )));
            }
            String::from_utf8(bytes[..bytes.len() - 1].to_vec())
                .map_err(|_| PakError::Corrupt(format!("non-UTF-8 FString in {}", self.context)))
        } else {
            let units = length.unsigned_abs() as usize;
            let byte_length = units
                .checked_mul(2)
                .ok_or_else(|| PakError::Corrupt("UTF-16 FString length overflow".to_owned()))?;
            if byte_length > MAX_INDEX_BYTES as usize || byte_length > self.remaining() {
                return Err(PakError::Corrupt(format!(
                    "invalid UTF-16 FString length {units} in {}",
                    self.context
                )));
            }
            let bytes = self.read_bytes(byte_length)?;
            let utf16: Vec<u16> = bytes
                .chunks_exact(2)
                .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                .collect();
            if utf16.last() != Some(&0) {
                return Err(PakError::Corrupt(format!(
                    "UTF-16 FString is not NUL terminated in {}",
                    self.context
                )));
            }
            String::from_utf16(&utf16[..utf16.len() - 1])
                .map_err(|_| PakError::Corrupt(format!("invalid UTF-16 in {}", self.context)))
        }
    }

    fn finish(&self) -> Result<()> {
        if self.remaining() != 0 {
            return Err(PakError::Corrupt(format!(
                "{} has {} trailing bytes",
                self.context,
                self.remaining()
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::io::Cursor;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn archive_handle_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<PakArchive>();
    }

    #[test]
    fn cancelled_logical_entry_writer_returns_a_terminal_io_error() {
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let mut destination = Vec::new();
        let mut writer =
            LogicalEntryWriter::new_cancellable(&mut destination, 1, Some(&cancellation));

        let error = writer.write(b"x").unwrap_err();
        assert_ne!(error.kind(), io::ErrorKind::Interrupted);
        assert_eq!(error.kind(), io::ErrorKind::Other);
    }

    #[test]
    fn path_validation_rejects_unsafe_forms() {
        for path in [
            "",
            "/absolute.uasset",
            "C:/drive.uasset",
            "../escape.uasset",
            "a/../escape.uasset",
            "a//b.uasset",
            "a\\b.uasset",
            "a/./b.uasset",
            "a/\0b.uasset",
        ] {
            assert!(normalize_entry_path(path).is_err(), "accepted {path:?}");
        }
        assert_eq!(
            normalize_entry_path("Local/DataBase/EnemyID.uasset").unwrap(),
            "Local/DataBase/EnemyID.uasset"
        );
        assert_eq!(
            normalize_entry_path("데이터/기술 설명.uasset").unwrap(),
            "데이터/기술 설명.uasset"
        );
    }

    #[test]
    fn unicode_entry_paths_round_trip_through_v11_indexes() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("unicode-path.pak");
        write_pak_v11(
            &path,
            "../../../예시/Content/",
            [PakWriteEntry::new(
                "데이터/기술 설명.bin",
                b"unicode path".to_vec(),
            )],
        )
        .unwrap();

        let archive = PakArchive::open(&path).unwrap();
        assert_eq!(archive.inventory().mount_point, "../../../예시/Content/");
        assert_eq!(
            archive.read_entry("데이터/기술 설명.bin").unwrap(),
            b"unicode path"
        );
    }

    #[test]
    fn grouping_is_case_insensitive_and_marks_incomplete_packages() {
        let grouping = group_packages([
            "Local/DB/Foo.uasset",
            "Local/DB/Foo.uexp",
            "Local/DB/Only.ubulk",
            "notes/readme.txt",
        ])
        .unwrap();
        assert_eq!(grouping.packages.len(), 2);
        assert!(grouping.packages.iter().any(|group| group.complete));
        assert!(grouping.packages.iter().any(|group| !group.complete));
        assert_eq!(grouping.loose_entries, ["notes/readme.txt"]);
    }

    #[test]
    fn duplicate_paths_are_rejected_case_insensitively() {
        let result = group_packages(["A/Foo.uasset", "a/foo.UASSET"]);
        assert!(matches!(result, Err(PakError::DuplicatePath { .. })));
    }

    #[test]
    fn impossible_index_buffer_allocation_fails_without_panicking() {
        assert!(matches!(
            allocate_zeroed_buffer(u64::MAX, "hostile index"),
            Err(PakError::UnsupportedLayout(_))
        ));
    }

    #[test]
    fn writer_is_deterministic_and_round_trips() {
        let mount = "../../../Game/Content/";
        let entries_a = vec![
            PakWriteEntry::new("B/Two.uexp", b"two".to_vec()),
            PakWriteEntry::new("A/One.uasset", b"one".to_vec()),
        ];
        let entries_b = vec![
            PakWriteEntry::new("A/One.uasset", b"one".to_vec()),
            PakWriteEntry::new("B/Two.uexp", b"two".to_vec()),
        ];
        let first = write_pak_v11_to(Cursor::new(Vec::new()), mount, entries_a)
            .unwrap()
            .into_inner();
        let second = write_pak_v11_to(Cursor::new(Vec::new()), mount, entries_b)
            .unwrap()
            .into_inner();
        assert_eq!(first, second);

        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("pak-merger-{}-{unique}.pak", std::process::id()));
        std::fs::write(&path, first).unwrap();
        let archive = PakArchive::open(&path).unwrap();
        assert_eq!(archive.inventory().mount_point, mount);
        assert_eq!(archive.read_entry("A/One.uasset").unwrap(), b"one");
        assert_eq!(archive.read_entry("B/Two.uexp").unwrap(), b"two");
        drop(archive);
        std::fs::remove_file(path).unwrap();
    }

    fn write_source_hash_test_pak(
        payload: &[u8],
        compressed: bool,
        collect_source_hash: Option<bool>,
    ) -> (Vec<u8>, Option<String>) {
        let builder = if compressed {
            repak::PakBuilder::new()
                .compression([repak::Compression::Zstd])
                .parallel_blocks(true)
        } else {
            repak::PakBuilder::new()
        };
        let mut writer = builder.writer(
            Cursor::new(Vec::new()),
            repak::Version::V11,
            "../../../Example/Content/".to_owned(),
            Some(0x1234_5678),
        );
        let source_hash = if let Some(collect_source_hash) = collect_source_hash {
            write_repak_entry_with_optional_source_sha256(
                &mut writer,
                "Data/Observed.uexp",
                compressed,
                payload,
                collect_source_hash,
                |_, _| true,
            )
            .unwrap()
        } else {
            writer
                .write_file_with_progress("Data/Observed.uexp", compressed, payload, |_, _| true)
                .unwrap();
            None
        };
        (writer.write_index().unwrap().into_inner(), source_hash)
    }

    #[test]
    fn selected_source_hashes_cover_compressed_and_uncompressed_writer_input_once() {
        for compressed in [false, true] {
            let payload_size = if compressed {
                repak::COMPRESSION_BLOCK_SIZE as usize * 5 + 257
            } else {
                4 * 1024 * 1024 + 257
            };
            let payload = (0..payload_size)
                .map(|index| ((index * 31) % 251) as u8)
                .collect::<Vec<_>>();
            let expected_hash = hex::encode(Sha256::digest(&payload));

            let (legacy, _) = write_source_hash_test_pak(&payload, compressed, None);
            let (observed, source_hash) =
                write_source_hash_test_pak(&payload, compressed, Some(true));
            let (not_selected, absent_hash) =
                write_source_hash_test_pak(&payload, compressed, Some(false));

            assert_eq!(observed, legacy);
            assert_eq!(not_selected, legacy);
            assert_eq!(source_hash.as_deref(), Some(expected_hash.as_str()));
            assert_eq!(absent_hash, None);
        }
    }

    #[test]
    fn selected_source_hash_api_uses_written_bytes_and_preserves_legacy_output() {
        let directory = tempfile::tempdir().unwrap();
        let observed_path = directory.path().join("observed.pak");
        let legacy_path = directory.path().join("legacy.pak");
        let cancellation = CancellationToken::new();
        let paths = ["B/Other.bin", "A/Target.uexp"];
        let target = b"BBBB";
        let same_size_wrong_value = b"AAAA";
        let provider = |path: &str| {
            Ok(PakEntryData::Owned(match path {
                "A/Target.uexp" => target.to_vec(),
                "B/Other.bin" => b"other".to_vec(),
                _ => return Err(PakError::MissingEntry(path.to_owned())),
            }))
        };

        let result = write_pak_v11_from_mapped_provider_with_source_hashes(
            &observed_path,
            "../../../Example/Content/",
            paths,
            OutputCompression::None,
            provider,
            true,
            &cancellation,
            |_| {},
            ["a/TARGET.uexp"],
        )
        .unwrap();
        assert_eq!(result.source_sha256.len(), 1);
        assert_eq!(
            result.source_sha256.get("A/Target.uexp"),
            Some(&hex::encode(Sha256::digest(target)))
        );
        assert_ne!(
            result.source_sha256["A/Target.uexp"],
            hex::encode(Sha256::digest(same_size_wrong_value))
        );
        assert!(!result.source_sha256.contains_key("B/Other.bin"));
        assert_eq!(result.archive.read_entry("A/Target.uexp").unwrap(), target);

        let legacy_archive =
            write_pak_v11_from_mapped_provider_with_compression_open_progress_threads_and_cancel(
                &legacy_path,
                "../../../Example/Content/",
                paths,
                OutputCompression::None,
                provider,
                true,
                &cancellation,
                |_| {},
            )
            .unwrap();
        assert_eq!(
            std::fs::read(&observed_path).unwrap(),
            std::fs::read(&legacy_path).unwrap()
        );
        drop(legacy_archive);
        drop(result);
    }

    #[test]
    fn selected_source_hash_api_rejects_a_missing_path_before_creating_output() {
        let directory = tempfile::tempdir().unwrap();
        let output_path = directory.path().join("must-not-exist.pak");
        let cancellation = CancellationToken::new();
        let error = write_pak_v11_from_mapped_provider_with_source_hashes(
            &output_path,
            "../../../Example/Content/",
            ["A/Present.bin"],
            OutputCompression::None,
            |_| Ok(PakEntryData::Owned(b"present".to_vec())),
            true,
            &cancellation,
            |_| {},
            ["A/Missing.bin"],
        )
        .unwrap_err();

        assert!(matches!(error, PakError::MissingEntry(path) if path == "A/Missing.bin"));
        assert!(!output_path.exists());
    }

    #[test]
    fn uncompressed_output_never_initializes_oodle() {
        prepare_output_compression(OutputCompression::None, None).unwrap();
    }

    #[test]
    fn external_oodle_output_is_deterministic_when_enabled() {
        if std::env::var_os("PAK_MERGER_TEST_OODLE_OUTPUT").is_none() {
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        let payload = vec![0x5a; 400_000];
        let mut hashes = Vec::new();
        for name in ["First.pak", "Second.pak"] {
            let output = temp.path().join(name);
            let inventory = write_pak_v11_from_mapped_provider_with_compression(
                &output,
                "../../../Example/Content/",
                ["Data/Large.bin"],
                OutputCompression::Oodle,
                |_| Ok(PakEntryData::Owned(payload.clone())),
            )
            .unwrap();
            assert_eq!(inventory.footer.compression_slots, ["Oodle"]);
            assert!(inventory.entries[0].compressed);
            assert!(inventory.entries[0].stored_size < inventory.entries[0].size);
            hashes.push(inventory.archive_sha256);
        }
        assert_eq!(hashes[0], hashes[1]);
    }

    #[test]
    fn every_repak_input_version_round_trips_through_strict_reader() {
        for version in INPUT_REPAK_VERSIONS.into_iter().rev() {
            let bytes = synthetic_uncompressed_pak(version);
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join(format!("synthetic-{version}.pak"));
            std::fs::write(&path, bytes).unwrap();

            let archive = PakArchive::open(&path)
                .unwrap_or_else(|error| panic!("strict reader rejected repak {version}: {error}"));
            assert_eq!(
                archive.inventory().footer.version,
                version.version_major() as u32
            );
            assert_eq!(archive.read_entry("A/One.uasset").unwrap(), b"one");
        }
    }

    #[test]
    fn supported_compressed_entries_are_decoded_and_compared_logically() {
        let payload = (0..420_000u32)
            .map(|value| (value.wrapping_mul(31) % 251) as u8)
            .collect::<Vec<_>>();
        let cases = [
            (repak::Version::V3, repak::Compression::Zlib),
            (repak::Version::V5, repak::Compression::Gzip),
            (repak::Version::V8A, repak::Compression::Zlib),
            (repak::Version::V8B, repak::Compression::Zstd),
            (repak::Version::V11, repak::Compression::Zlib),
            (repak::Version::V11, repak::Compression::Gzip),
            (repak::Version::V11, repak::Compression::Zstd),
            (repak::Version::V11, repak::Compression::LZ4),
        ];

        for (version, compression) in cases {
            let bytes = synthetic_compressed_pak(version, compression, &payload);
            let directory = tempfile::tempdir().unwrap();
            let path = directory
                .path()
                .join(format!("compressed-{version}-{compression}.pak"));
            std::fs::write(&path, bytes).unwrap();

            let archive = PakArchive::open(&path).unwrap_or_else(|error| {
                panic!("strict reader rejected {version}/{compression}: {error}")
            });
            let entry = &archive.inventory().entries[0];
            assert_eq!(entry.size, payload.len() as u64);
            assert_eq!(entry.sha256, hex::encode(Sha256::digest(&payload)));
            assert!(entry.sha256_is_logical);
            assert!(entry.payload_sha1_matches);
            assert_eq!(
                archive
                    .decode_count
                    .load(std::sync::atomic::Ordering::Relaxed),
                1
            );
            assert_eq!(archive.read_entry("A/Compressed.bin").unwrap(), payload);
            assert_eq!(
                archive
                    .map_entry("A/Compressed.bin", MAX_IN_MEMORY_ENTRY_BYTES)
                    .unwrap()
                    .as_ref(),
                payload
            );
            assert_eq!(
                archive
                    .decode_count
                    .load(std::sync::atomic::Ordering::Relaxed),
                1,
                "strict verification, read, and mapping must share one decode"
            );
        }
    }

    #[test]
    fn ordinary_lz4_blocks_keep_the_standard_repak_path() {
        let payload = (0..420_000u32)
            .map(|value| (value.wrapping_mul(13) % 251) as u8)
            .collect::<Vec<_>>();
        let bytes =
            synthetic_compressed_pak(repak::Version::V11, repak::Compression::LZ4, &payload);
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("ordinary-lz4.pak");
        std::fs::write(&path, bytes).unwrap();

        let archive = PakArchive::open_fast(&path).unwrap();
        let entry = archive.entries.values().next().unwrap();
        assert!(entry.direct_decode_plan.is_none());
        assert_eq!(archive.read_entry(&entry.path).unwrap(), payload);
    }

    #[test]
    fn oversized_contiguous_blocks_build_compact_physical_decode_plans() {
        let physical_entry_offset = 0x20_000_u64;
        let header_size = 73_u64;
        let stored_size = DIRECT_DECODE_STORED_BLOCK_THRESHOLD + 1;
        let logical_size = DIRECT_DECODE_LOGICAL_BLOCK_THRESHOLD + 1;
        let mut detected = detected_for_plan_test(repak::Version::V5, "Oodle");
        let relative = LegacyEntryMetadata {
            stored_offset: physical_entry_offset,
            compressed_size: stored_size,
            uncompressed_size: logical_size,
            compression_method: 1,
            timestamp: None,
            payload_sha1: [0; 20],
            blocks: vec![CompressionBlock {
                start: header_size,
                end: header_size + stored_size,
            }],
            flags: 0,
            compression_block_size: logical_size as u32,
        };
        validate_compression_blocks(
            &relative,
            physical_entry_offset,
            header_size,
            &detected,
            "Large/Relative.bin",
        )
        .unwrap();
        let plan = build_direct_decode_plan(
            &relative,
            physical_entry_offset,
            header_size,
            &detected,
            "Large/Relative.bin",
        )
        .unwrap()
        .unwrap();
        assert_eq!(plan.codec, DirectDecodeCodec::Oodle);
        assert_eq!(plan.blocks.len(), 1);
        assert_eq!(
            plan.blocks[0],
            DirectDecodeBlock {
                stored_start: physical_entry_offset + header_size,
                stored_end: physical_entry_offset + header_size + stored_size,
                output_start: 0,
                output_end: logical_size,
            }
        );

        detected.repak_version = repak::Version::V4;
        detected.footer.version = 4;
        let absolute = LegacyEntryMetadata {
            blocks: vec![CompressionBlock {
                start: physical_entry_offset + header_size,
                end: physical_entry_offset + header_size + stored_size,
            }],
            ..relative
        };
        let absolute_plan = build_direct_decode_plan(
            &absolute,
            physical_entry_offset,
            header_size,
            &detected,
            "Large/Absolute.bin",
        )
        .unwrap()
        .unwrap();
        assert_eq!(absolute_plan.blocks, plan.blocks);
    }

    #[test]
    fn direct_decode_plan_thresholds_and_malformed_ranges_are_fail_closed() {
        let detected = detected_for_plan_test(repak::Version::V5, "LZ4");
        let physical_entry_offset = 4096_u64;
        let header_size = 64_u64;
        let ordinary = LegacyEntryMetadata {
            stored_offset: physical_entry_offset,
            compressed_size: DIRECT_DECODE_STORED_BLOCK_THRESHOLD,
            uncompressed_size: DIRECT_DECODE_LOGICAL_BLOCK_THRESHOLD,
            compression_method: 1,
            timestamp: None,
            payload_sha1: [0; 20],
            blocks: vec![CompressionBlock {
                start: header_size,
                end: header_size + DIRECT_DECODE_STORED_BLOCK_THRESHOLD,
            }],
            flags: 0,
            compression_block_size: DIRECT_DECODE_LOGICAL_BLOCK_THRESHOLD as u32,
        };
        assert!(
            build_direct_decode_plan(
                &ordinary,
                physical_entry_offset,
                header_size,
                &detected,
                "Small/Boundary.bin",
            )
            .unwrap()
            .is_none()
        );

        let wrong_count = LegacyEntryMetadata {
            uncompressed_size: ordinary.uncompressed_size + 1,
            ..ordinary.clone()
        };
        assert!(matches!(
            build_direct_decode_plan(
                &wrong_count,
                physical_entry_offset,
                header_size,
                &detected,
                "Bad/Count.bin",
            ),
            Err(PakError::Corrupt(message)) if message.contains("expected 2")
        ));

        let overflow = LegacyEntryMetadata {
            compressed_size: 1,
            uncompressed_size: 1,
            blocks: vec![CompressionBlock {
                start: header_size,
                end: header_size + 1,
            }],
            compression_block_size: 1,
            ..ordinary
        };
        assert!(matches!(
            build_direct_decode_plan(
                &overflow,
                u64::MAX - header_size + 1,
                header_size,
                &detected,
                "Bad/Overflow.bin",
            ),
            Err(PakError::Corrupt(message)) if message.contains("overflow")
        ));
    }

    #[test]
    fn direct_lz4_decode_writes_straight_to_temporary_mapping() {
        let payload = b"direct mapped LZ4 payload".repeat(128);
        let stored = lz4_flex::block::compress(&payload);
        let standard_pak = synthetic_uncompressed_pak(repak::Version::V11);
        let mut reader_source = Cursor::new(standard_pak);
        let reader = repak::PakBuilder::new()
            .reader_with_version(&mut reader_source, repak::Version::V11)
            .unwrap();
        let entry = EntryRecord {
            path: "A/Direct.bin".to_owned(),
            header_offset: 0,
            header_size: 0,
            stored_size: stored.len() as u64,
            size: payload.len() as u64,
            compressed: true,
            oodle_compressed: false,
            direct_decode_plan: Some(DirectDecodePlan {
                codec: DirectDecodeCodec::Lz4,
                blocks: vec![DirectDecodeBlock {
                    stored_start: 0,
                    stored_end: stored.len() as u64,
                    output_start: 0,
                    output_end: payload.len() as u64,
                }],
            }),
            payload_sha1: [0; 20],
            stored_payload_sha1: [0; 20],
            stored_sha256: [0; 32],
        };
        let cache_directory = tempfile::tempdir().unwrap();
        let cache_policy = DecodeCachePolicy {
            memory_entry_threshold_bytes: u64::MAX,
            minimum_disk_headroom_bytes: 0,
            cache_directory: Some(cache_directory.path().to_path_buf()),
            cancel_after_disk_reservation: false,
        };

        let decoded = decode_entry(&reader, &stored, &entry, None, true, &cache_policy).unwrap();
        assert!(matches!(
            &decoded.data,
            CachedEntryData::TemporaryMapped { .. }
        ));
        assert_eq!(decoded.data.as_ref(), payload);
        let expected_sha256: [u8; 32] = Sha256::digest(&payload).into();
        assert_eq!(decoded.sha256, expected_sha256);
    }

    #[test]
    fn fast_open_defers_and_caches_compressed_logical_bytes() {
        let payload = (0..700_000u32)
            .map(|value| (value.wrapping_mul(17) % 251) as u8)
            .collect::<Vec<_>>();
        let bytes =
            synthetic_compressed_pak(repak::Version::V11, repak::Compression::Zstd, &payload);
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("lazy-compressed.pak");
        std::fs::write(&path, bytes).unwrap();

        let archive = PakArchive::open_fast_with_progress_cancel_and_threads(
            &path,
            &CancellationToken::new(),
            false,
            |_| {},
        )
        .unwrap();
        assert!(!archive.inventory().entries[0].sha256_is_logical);
        assert_eq!(
            archive
                .decode_count
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
        assert_eq!(
            archive.entry_size("A/Compressed.bin").unwrap(),
            payload.len() as u64
        );
        assert_eq!(
            archive
                .decode_count
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
            "metadata-only sizing must not decode an entry"
        );
        let cancelled = CancellationToken::new();
        cancelled.cancel();
        assert!(matches!(
            archive.logical_sha256_with_threads_and_cancel("A/Compressed.bin", true, &cancelled,),
            Err(PakError::Cancelled)
        ));
        assert_eq!(
            archive
                .decode_count
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
        let expected = hex::encode(Sha256::digest(&payload));
        assert_eq!(
            archive.logical_sha256("A/Compressed.bin").unwrap(),
            expected
        );
        assert_eq!(
            archive.logical_sha256("A/Compressed.bin").unwrap(),
            expected
        );
        assert_eq!(archive.read_entry("A/Compressed.bin").unwrap(), payload);
        assert_eq!(
            archive
                .map_entry("A/Compressed.bin", MAX_IN_MEMORY_ENTRY_BYTES)
                .unwrap()
                .as_ref(),
            payload
        );
        assert_eq!(
            archive
                .decode_count
                .load(std::sync::atomic::Ordering::Relaxed),
            1,
            "all logical consumers must reuse the first decode"
        );
    }

    #[test]
    fn strict_discard_validation_hashes_then_releases_each_compressed_entry() {
        let payload = (0..700_000u32)
            .map(|value| (value.wrapping_mul(19) % 251) as u8)
            .collect::<Vec<_>>();
        let bytes =
            synthetic_compressed_pak(repak::Version::V11, repak::Compression::Zstd, &payload);
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("strict-discard.pak");
        std::fs::write(&path, bytes).unwrap();
        let cancellation = CancellationToken::new();

        let archive = PakArchive::open_internal(
            &path,
            LogicalValidation::StrictDiscard,
            false,
            &cancellation,
            &mut |_| {},
        )
        .unwrap();
        assert!(archive.inventory().entries[0].sha256_is_logical);
        assert_eq!(
            archive.inventory().entries[0].sha256,
            hex::encode(Sha256::digest(&payload))
        );
        assert_eq!(
            archive
                .decode_count
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
            "verification-only decoding must not populate the merge cache"
        );
        assert!(
            archive
                .decoded_entries
                .values()
                .all(|cache| cache.lock().unwrap().is_none())
        );
        let info = archive.entry_decode_info("A/Compressed.bin").unwrap();
        assert!(info.compressed);
        assert_eq!(info.logical_size, payload.len() as u64);
        assert!(!info.decoded_cache_present);
        assert!(info.memory_cache_eligible);
    }

    #[test]
    fn public_inspection_checks_compressed_logical_bytes_without_retaining_them() {
        let payload = vec![0x45; 700_000];
        let bytes =
            synthetic_compressed_pak(repak::Version::V11, repak::Compression::Zstd, &payload);
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("structural-inspection.pak");
        std::fs::write(&path, bytes).unwrap();

        let inventory = inspect_pak(&path).unwrap();
        assert!(inventory.entries[0].sha256_is_logical);
        assert_eq!(
            inventory.entries[0].sha256,
            hex::encode(Sha256::digest(&payload))
        );
    }

    #[test]
    fn small_compressed_entry_can_spill_to_one_reused_temporary_mapping_and_be_released() {
        let payload = (0..900_000u32)
            .map(|value| (value.wrapping_mul(43) % 251) as u8)
            .collect::<Vec<_>>();
        let bytes =
            synthetic_compressed_pak(repak::Version::V11, repak::Compression::Zstd, &payload);
        let directory = tempfile::tempdir().unwrap();
        let cache_directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("disk-cached-compressed.pak");
        std::fs::write(&path, bytes).unwrap();

        let mut archive = PakArchive::open_fast(&path).unwrap();
        archive.decode_cache_policy = DecodeCachePolicy {
            memory_entry_threshold_bytes: 0,
            minimum_disk_headroom_bytes: 0,
            cache_directory: Some(cache_directory.path().to_path_buf()),
            cancel_after_disk_reservation: false,
        };

        let expected_hash = hex::encode(Sha256::digest(&payload));
        assert_eq!(
            archive.logical_sha256("A/Compressed.bin").unwrap(),
            expected_hash
        );
        assert_eq!(
            archive.logical_sha256("A/Compressed.bin").unwrap(),
            expected_hash
        );
        assert_eq!(archive.read_entry("A/Compressed.bin").unwrap(), payload);
        let mapped = archive
            .map_entry("A/Compressed.bin", MAX_IN_MEMORY_ENTRY_BYTES)
            .unwrap();
        assert!(matches!(&mapped, PakEntryData::Shared(_)));
        assert_eq!(mapped.as_ref(), payload);
        assert_eq!(
            archive
                .decode_count
                .load(std::sync::atomic::Ordering::Relaxed),
            1,
            "disk-backed consumers must all reuse the first decode"
        );

        let key = normalized_sort_key("A/Compressed.bin");
        let cached = archive.decoded_entries[&key].lock().unwrap();
        let temporary_path = match &cached.as_ref().unwrap().data {
            CachedEntryData::TemporaryMapped { _file, .. } => _file.path().to_path_buf(),
            CachedEntryData::Owned { .. } => panic!("entry unexpectedly remained in memory"),
        };
        assert!(temporary_path.starts_with(cache_directory.path()));
        assert!(temporary_path.exists());
        #[cfg(windows)]
        {
            use fs2::FileExt;
            let competing = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&temporary_path)
                .unwrap();
            assert!(competing.try_lock_exclusive().is_err());
        }
        drop(cached);
        drop(mapped);
        assert_eq!(archive.release_decoded_cache(), 1);
        assert_eq!(archive.release_decoded_cache(), 0);
        assert!(
            !temporary_path.exists(),
            "releasing the cache must remove its decoded temporary file"
        );
        assert_eq!(
            std::fs::read_dir(cache_directory.path()).unwrap().count(),
            0
        );
    }

    #[test]
    fn cancellation_after_disk_reservation_cleans_up_and_allows_retry() {
        let payload = (0..1_100_000u32)
            .map(|value| (value.wrapping_mul(47) % 251) as u8)
            .collect::<Vec<_>>();
        let bytes =
            synthetic_compressed_pak(repak::Version::V11, repak::Compression::Zstd, &payload);
        let directory = tempfile::tempdir().unwrap();
        let cache_directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("cancelled-disk-cache.pak");
        std::fs::write(&path, bytes).unwrap();

        let mut archive = PakArchive::open_fast(&path).unwrap();
        archive.decode_cache_policy = DecodeCachePolicy {
            memory_entry_threshold_bytes: 0,
            minimum_disk_headroom_bytes: 0,
            cache_directory: Some(cache_directory.path().to_path_buf()),
            cancel_after_disk_reservation: true,
        };
        let cancellation = CancellationToken::new();
        assert!(matches!(
            archive
                .logical_sha256_with_threads_and_cancel("A/Compressed.bin", true, &cancellation,),
            Err(PakError::Cancelled)
        ));
        assert_eq!(
            archive
                .decode_count
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
        assert_eq!(
            std::fs::read_dir(cache_directory.path()).unwrap().count(),
            0
        );

        archive.decode_cache_policy.cancel_after_disk_reservation = false;
        let retry = CancellationToken::new();
        assert_eq!(
            archive
                .logical_sha256_with_threads_and_cancel("A/Compressed.bin", true, &retry)
                .unwrap(),
            hex::encode(Sha256::digest(&payload))
        );
        assert_eq!(
            archive
                .decode_count
                .load(std::sync::atomic::Ordering::Relaxed),
            1,
            "the cancelled attempt must not populate or poison the cache"
        );
    }

    #[test]
    fn uncompressed_mapping_reuses_the_complete_archive_mapping() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("mapped-input.pak");
        std::fs::write(&path, synthetic_uncompressed_pak(repak::Version::V11)).unwrap();
        let archive = PakArchive::open_fast(&path).unwrap();
        let mapped = archive
            .map_entry("A/One.uasset", MAX_IN_MEMORY_ENTRY_BYTES)
            .unwrap();
        assert!(matches!(&mapped, PakEntryData::ArchiveSlice(_)));
        assert_eq!(mapped.as_ref(), b"one");
    }

    #[test]
    fn fast_open_reports_scan_progress_and_honors_cancellation() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("progress-input.pak");
        let bytes = synthetic_uncompressed_pak(repak::Version::V11);
        std::fs::write(&path, &bytes).unwrap();
        let cancellation = CancellationToken::new();
        let mut updates = Vec::new();
        let archive =
            PakArchive::open_fast_with_progress_and_cancel(&path, &cancellation, |progress| {
                updates.push(progress)
            })
            .unwrap();
        assert_eq!(archive.inventory().archive_size, bytes.len() as u64);
        assert_eq!(
            archive.inventory().archive_sha256,
            hex::encode(Sha256::digest(&bytes))
        );
        assert_eq!(
            archive.inventory().entries[0].payload_sha1,
            hex::encode(Sha1::digest(b"one"))
        );
        assert!(matches!(
            updates.last(),
            Some(PakOpenProgress::Scanning {
                completed_bytes,
                total_bytes,
            }) if completed_bytes == total_bytes && *total_bytes == bytes.len() as u64
        ));

        let cancelled = CancellationToken::new();
        cancelled.cancel();
        assert!(matches!(
            PakArchive::open_fast_with_progress_and_cancel(&path, &cancelled, |_| {}),
            Err(PakError::Cancelled)
        ));
    }

    #[test]
    fn oodle_is_allowed_and_unknown_compression_slots_are_rejected() {
        let mut detected = read_footer_from_bytes(&synthetic_uncompressed_pak(repak::Version::V11));
        detected.compression_codecs[0] = Some("Oodle".to_owned());
        validate_compression_method(&detected, 1, "A/Oodle.bin").unwrap();
        detected.compression_codecs[0] = Some("CustomCodec".to_owned());
        assert!(matches!(
            validate_compression_method(&detected, 1, "A/Unknown.bin"),
            Err(PakError::UnsupportedCompression { method, .. }) if method == "CustomCodec"
        ));
    }

    #[test]
    fn legacy_index_sha1_corruption_is_rejected_before_parsing() {
        let mut bytes = synthetic_uncompressed_pak(repak::Version::V3);
        let footer_offset = bytes.len() - MIN_PAK_FOOTER_SIZE as usize;
        let index_offset = read_test_u64(&bytes, footer_offset + 8) as usize;
        bytes[index_offset] ^= 1;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("corrupt-v3-index.pak");
        std::fs::write(&path, bytes).unwrap();
        let error = PakArchive::open(&path).unwrap_err();
        assert!(matches!(error, PakError::Sha1Mismatch { .. }));
    }

    #[test]
    fn v3_stale_uexp_hash_is_accepted_only_after_binary_asset_validation() {
        let original_uexp = synthetic_binary_asset(1);
        let mut modified_uexp = original_uexp.clone();
        let row_id_offset = synthetic_binary_asset_row_id_offset(&modified_uexp);
        modified_uexp[row_id_offset] = 2;
        let mut bytes = synthetic_v3_database_pak(Some(synthetic_uasset()), &original_uexp);
        replace_unique_payload(&mut bytes, &original_uexp, &modified_uexp);

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("stale-v3-db.pak");
        std::fs::write(&path, bytes).unwrap();
        let archive = PakArchive::open(&path).unwrap();
        let entry = archive
            .inventory()
            .entries
            .iter()
            .find(|entry| entry.path.ends_with(".uexp"))
            .unwrap();
        assert!(!entry.payload_sha1_matches);
        assert_eq!(
            entry.stored_payload_sha1,
            hex::encode(Sha1::digest(&original_uexp))
        );
        assert_eq!(
            entry.payload_sha1,
            hex::encode(Sha1::digest(&modified_uexp))
        );
        assert_eq!(archive.read_entry("DB/Table.uexp").unwrap(), modified_uexp);
        let parsed = BinaryAsset::parse(&archive.read_entry("DB/Table.uexp").unwrap()).unwrap();
        assert!(parsed.row(2).unwrap().is_some());

        let normalized_bytes = write_pak_v11_to(
            Cursor::new(Vec::new()),
            &archive.inventory().mount_point,
            [
                PakWriteEntry::new(
                    "DB/Table.uasset",
                    archive.read_entry("DB/Table.uasset").unwrap(),
                ),
                PakWriteEntry::new(
                    "DB/Table.uexp",
                    archive.read_entry("DB/Table.uexp").unwrap(),
                ),
            ],
        )
        .unwrap()
        .into_inner();
        let normalized_path = directory.path().join("normalized-v11-db.pak");
        std::fs::write(&normalized_path, normalized_bytes).unwrap();
        let normalized = PakArchive::open(&normalized_path).unwrap();
        assert_eq!(normalized.inventory().footer.version, 11);
        assert!(
            normalized
                .inventory()
                .entries
                .iter()
                .all(|entry| entry.payload_sha1_matches)
        );
        assert_eq!(
            normalized.read_entry("DB/Table.uexp").unwrap(),
            modified_uexp
        );
    }

    #[test]
    fn v3_stale_hash_on_uasset_remains_fatal() {
        let uasset = synthetic_uasset();
        let mut modified_uasset = uasset.clone();
        *modified_uasset.last_mut().unwrap() ^= 1;
        let mut bytes = synthetic_v3_database_pak(Some(uasset.clone()), &synthetic_binary_asset(1));
        replace_unique_payload(&mut bytes, &uasset, &modified_uasset);

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("stale-v3-uasset.pak");
        std::fs::write(&path, bytes).unwrap();
        assert!(matches!(
            PakArchive::open(&path),
            Err(PakError::Sha1Mismatch { .. })
        ));

        let non_unreal_tag = [0x11, 0x22, 0x33, 0x44];
        let mut matching_wrong_uasset = synthetic_uasset();
        matching_wrong_uasset[..PACKAGE_TAG_SIZE].copy_from_slice(&non_unreal_tag);
        let mut matching_wrong_uexp = synthetic_binary_asset(1);
        let tag_offset = matching_wrong_uexp.len() - PACKAGE_TAG_SIZE;
        matching_wrong_uexp[tag_offset..].copy_from_slice(&non_unreal_tag);
        let mut modified_matching_wrong_uexp = matching_wrong_uexp.clone();
        let row_id_offset = synthetic_binary_asset_row_id_offset(&modified_matching_wrong_uexp);
        modified_matching_wrong_uexp[row_id_offset] = 2;
        let mut bytes =
            synthetic_v3_database_pak(Some(matching_wrong_uasset), &matching_wrong_uexp);
        replace_unique_payload(
            &mut bytes,
            &matching_wrong_uexp,
            &modified_matching_wrong_uexp,
        );
        let path = directory
            .path()
            .join("matching-non-unreal-tag-stale-v3-uexp.pak");
        std::fs::write(&path, bytes).unwrap();
        assert!(matches!(
            PakArchive::open(&path),
            Err(PakError::Sha1Mismatch { .. })
        ));
    }

    #[test]
    fn v3_stale_uexp_hash_requires_parseable_binary_asset() {
        let original_uexp = synthetic_binary_asset(1);
        let mut invalid_uexp = original_uexp.clone();
        invalid_uexp[crate::binary_asset::PREFIX_SIZE] = 0xc1;
        let mut bytes = synthetic_v3_database_pak(Some(synthetic_uasset()), &original_uexp);
        replace_unique_payload(&mut bytes, &original_uexp, &invalid_uexp);

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("invalid-stale-v3-uexp.pak");
        std::fs::write(&path, bytes).unwrap();
        assert!(matches!(
            PakArchive::open(&path),
            Err(PakError::Sha1Mismatch { .. })
        ));
    }

    #[test]
    fn v3_stale_uexp_hash_requires_valid_same_basename_companion() {
        let original_uexp = synthetic_binary_asset(1);
        let mut modified_uexp = original_uexp.clone();
        let row_id_offset = synthetic_binary_asset_row_id_offset(&modified_uexp);
        modified_uexp[row_id_offset] = 2;
        let mut bytes = synthetic_v3_database_pak(None, &original_uexp);
        replace_unique_payload(&mut bytes, &original_uexp, &modified_uexp);

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("orphan-stale-v3-uexp.pak");
        std::fs::write(&path, bytes).unwrap();
        assert!(matches!(
            PakArchive::open(&path),
            Err(PakError::Sha1Mismatch { .. })
        ));

        let mut wrong_tag = synthetic_uasset();
        wrong_tag[..PACKAGE_TAG_SIZE].copy_from_slice(&[0x11, 0x22, 0x33, 0x44]);
        let mut bytes = synthetic_v3_database_pak(Some(wrong_tag), &original_uexp);
        replace_unique_payload(&mut bytes, &original_uexp, &modified_uexp);
        let path = directory.path().join("wrong-tag-stale-v3-uexp.pak");
        std::fs::write(&path, bytes).unwrap();
        assert!(matches!(
            PakArchive::open(&path),
            Err(PakError::Sha1Mismatch { .. })
        ));
    }

    #[test]
    fn path_hash_matches_pinned_repak_vectors() {
        assert_eq!(fnv64_path("A/One.uasset", 0), 0x9b16_e7a9_5f63_9c4c);
        assert_eq!(
            fnv64_path("Local/DataBase/EnemyID.uexp", 0),
            0xefbc_da6f_5fe6_aa74
        );
        assert_eq!(
            fnv64_path("A/One.uasset", 0x1234_5678),
            0x6af8_5c63_e04f_8944
        );
        assert_eq!(fnv64_path("A/One.uasset", 0), fnv64_path("a/one.UASSET", 0));
    }

    #[test]
    fn archive_rejects_path_hash_value_even_when_index_sha1s_are_valid() {
        let mut archive = single_entry_archive();
        let locations = locate_test_indexes(&archive);
        let hash_offset = locations.path_hash.start + 4;
        let corrupted = read_test_u64(&archive, hash_offset) ^ 1;
        archive[hash_offset..hash_offset + 8].copy_from_slice(&corrupted.to_le_bytes());
        refresh_test_hashes(&mut archive, &locations, true);

        assert_path_hash_archive_rejected(archive);
    }

    #[test]
    fn archive_rejects_changed_seed_even_when_primary_sha1_is_valid() {
        let mut archive = single_entry_archive();
        let locations = locate_test_indexes(&archive);
        let corrupted = read_test_u64(&archive, locations.seed_offset).wrapping_add(1);
        archive[locations.seed_offset..locations.seed_offset + 8]
            .copy_from_slice(&corrupted.to_le_bytes());
        refresh_test_hashes(&mut archive, &locations, false);

        assert_path_hash_archive_rejected(archive);
    }

    #[test]
    fn provider_writer_loads_one_entry_at_a_time_in_sorted_order() {
        let path = unique_temp_pak("provider");
        let source = BTreeMap::from([
            ("a/One.uasset".to_owned(), b"one".to_vec()),
            ("B/Two.uexp".to_owned(), b"two".to_vec()),
        ]);
        let mut calls = Vec::new();
        let inventory = write_pak_v11_from_provider(
            &path,
            "../../../Game/Content/",
            ["B/Two.uexp", "a/One.uasset"],
            |entry_path| {
                calls.push(entry_path.to_owned());
                Ok(source.get(entry_path).unwrap().clone())
            },
        )
        .unwrap();
        assert_eq!(calls, ["a/One.uasset", "B/Two.uexp"]);
        assert_eq!(inventory.entries.len(), 2);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn writer_reports_byte_progress_for_its_single_final_verification() {
        let path = unique_temp_pak("verification-progress");
        let mut updates = Vec::new();
        let payload_len = 10 * 1024 * 1024 + 17;
        let archive =
            write_pak_v11_from_mapped_provider_with_compression_open_and_progress_and_threads(
                &path,
                "../../../Game/Content/",
                ["A/One.bin"],
                OutputCompression::None,
                |_| Ok(PakEntryData::Owned(vec![0x5a; payload_len])),
                false,
                |progress| updates.push(progress),
            )
            .unwrap();
        let writing_bytes = updates
            .iter()
            .filter_map(|progress| match progress {
                PakWriteProgress::WritingBytes {
                    completed_bytes,
                    total_bytes,
                    current_path,
                } => Some((*completed_bytes, *total_bytes, current_path.as_str())),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            writing_bytes.first(),
            Some(&(0, payload_len as u64, "A/One.bin"))
        );
        assert_eq!(
            writing_bytes.last(),
            Some(&(payload_len as u64, payload_len as u64, "A/One.bin"))
        );
        assert!(writing_bytes.windows(2).all(|pair| pair[0].0 < pair[1].0));
        assert!(
            writing_bytes
                .iter()
                .all(|(_, total, _)| *total == payload_len as u64)
        );
        assert!(
            writing_bytes.len() <= 4,
            "4 MiB UI batching should avoid one event per writer chunk"
        );
        assert!(updates.iter().any(|progress| matches!(
            progress,
            PakWriteProgress::VerificationProgress {
                completed_bytes,
                total_bytes,
                current_path: None,
            } if completed_bytes == total_bytes && *total_bytes == archive.inventory().archive_size
        )));
        drop(archive);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn writer_cancellation_during_large_entry_cleans_partial() {
        let path = unique_temp_pak("writing-cancel");
        let cancellation = CancellationToken::new();
        let signal = cancellation.clone();
        let result =
            write_pak_v11_from_mapped_provider_with_compression_open_progress_threads_and_cancel(
                &path,
                "../../../Game/Content/",
                ["A/Large.bin"],
                OutputCompression::None,
                |_| Ok(PakEntryData::Owned(vec![0x5a; 12 * 1024 * 1024])),
                true,
                &cancellation,
                |progress| {
                    if matches!(
                        progress,
                        PakWriteProgress::WritingBytes {
                            completed_bytes,
                            ..
                        } if completed_bytes >= 4 * 1024 * 1024
                    ) {
                        signal.cancel();
                    }
                },
            );
        assert!(matches!(result, Err(PakError::Cancelled)));
        assert!(!path.exists());
    }

    #[test]
    fn writer_cancellation_reaches_final_verification_and_cleans_partial() {
        let path = unique_temp_pak("verification-cancel");
        let cancellation = CancellationToken::new();
        let signal = cancellation.clone();
        let result =
            write_pak_v11_from_mapped_provider_with_compression_open_progress_threads_and_cancel(
                &path,
                "../../../Game/Content/",
                ["A/One.bin"],
                OutputCompression::None,
                |_| Ok(PakEntryData::Owned(vec![0x5a; 1024])),
                true,
                &cancellation,
                |progress| {
                    if progress == PakWriteProgress::Verifying {
                        signal.cancel();
                    }
                },
            );
        assert!(matches!(result, Err(PakError::Cancelled)));
        assert!(!path.exists());
    }

    #[test]
    fn provider_writer_removes_only_its_own_failed_output() {
        let failed_path = unique_temp_pak("provider-failure");
        let error = write_pak_v11_from_provider(
            &failed_path,
            "../../../Game/Content/",
            ["A/One.uasset"],
            |_| Err(PakError::Corrupt("provider failed".to_owned())),
        )
        .unwrap_err();
        assert!(matches!(error, PakError::Corrupt(_)));
        assert!(!failed_path.exists());

        let existing_path = unique_temp_pak("provider-existing");
        std::fs::write(&existing_path, b"keep me").unwrap();
        let error = write_pak_v11_from_provider(
            &existing_path,
            "../../../Game/Content/",
            ["A/One.uasset"],
            |_| Ok(b"one".to_vec()),
        )
        .unwrap_err();
        assert!(matches!(error, PakError::OutputExists(_)));
        assert_eq!(std::fs::read(&existing_path).unwrap(), b"keep me");
        std::fs::remove_file(existing_path).unwrap();
    }

    /// Optional local compatibility test. Real game/mod files stay untracked;
    /// CI simply skips this when no fixture path is supplied.
    #[test]
    fn external_pak_fixture_when_configured() {
        let Some(path) = std::env::var_os("PAK_MERGER_TEST_PAK") else {
            return;
        };
        let archive = PakArchive::open(path).unwrap();
        assert!(!archive.inventory().entries.is_empty());
        eprintln!(
            "validated Pak v{} with {} entries",
            archive.inventory().footer.version,
            archive.inventory().entries.len()
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 32,
            max_shrink_iters: 256,
            failure_persistence: None,
            rng_seed: proptest::test_runner::RngSeed::Fixed(0x5041_4B01),
            .. ProptestConfig::default()
        })]

        /// Any byte sequence shorter than the minimum footer must be
        /// rejected before index parsing. The temporary file and every result
        /// are dropped in-scope so Windows never retains a test archive handle.
        #[test]
        fn arbitrary_short_archives_fail_closed_without_panicking(
            bytes in prop::collection::vec(any::<u8>(), 0..MIN_PAK_FOOTER_SIZE as usize)
        ) {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("short.pak");
            std::fs::write(&path, &bytes).unwrap();

            let result = PakArchive::open(&path);
            prop_assert!(
                matches!(result, Err(PakError::TooSmall { .. })),
                "short archive was not rejected as TooSmall"
            );
            drop(result);
        }

        /// A non-boolean encryption flag is malformed regardless of every
        /// other footer byte and must always fail before repak is consulted.
        #[test]
        fn malformed_footer_flags_fail_closed(
            prefix in prop::collection::vec(any::<u8>(), 0..128),
            invalid_flag in 2_u8..=u8::MAX,
        ) {
            let mut archive = prefix;
            let mut footer = vec![0_u8; PAK_V11_FOOTER_SIZE as usize];
            footer[16] = invalid_flag;
            footer[17..21].copy_from_slice(&PAK_MAGIC.to_le_bytes());
            footer[21..25].copy_from_slice(&SUPPORTED_PAK_VERSION.to_le_bytes());
            archive.extend_from_slice(&footer);

            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("bad-footer.pak");
            std::fs::write(&path, &archive).unwrap();

            let result = PakArchive::open(&path);
            prop_assert!(matches!(result, Err(PakError::Corrupt(_))));
            drop(result);
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 64,
            max_shrink_iters: 512,
            failure_persistence: None,
            rng_seed: proptest::test_runner::RngSeed::Fixed(0x5041_4B02),
            .. ProptestConfig::default()
        })]

        /// The full-directory walker is fed untrusted index bytes. Repeating
        /// the parse must produce the same value/error and never panic.
        #[test]
        fn arbitrary_directory_indexes_are_deterministic_and_never_panic(
            bytes in prop::collection::vec(any::<u8>(), 0..256),
            expected_count in 0_u32..32,
        ) {
            let first = parse_full_directory_index(&bytes, expected_count);
            let second = parse_full_directory_index(&bytes, expected_count);
            match (first, second) {
                (Ok(left), Ok(right)) => {
                    prop_assert_eq!(&left, &right);
                    prop_assert_eq!(left.len(), expected_count as usize);
                }
                (Err(left), Err(right)) => prop_assert_eq!(left.to_string(), right.to_string()),
                _ => prop_assert!(false, "directory index parsing was nondeterministic"),
            }
        }

        /// Compact entry records have bit-controlled variable widths. Random
        /// tables and offsets exercise every checked read without allocating
        /// based on attacker-controlled sizes.
        #[test]
        fn compact_entry_parser_is_deterministic_and_never_panic(
            bytes in prop::collection::vec(any::<u8>(), 0..96),
            offset in 0_usize..128,
        ) {
            let first = parse_encoded_entry(&bytes, offset, "Fuzz/Entry.uexp");
            let second = parse_encoded_entry(&bytes, offset, "Fuzz/Entry.uexp");
            match (first, second) {
                (Ok(left), Ok(right)) => {
                    prop_assert_eq!(left.header_offset, right.header_offset);
                    prop_assert_eq!(left.compressed_size, right.compressed_size);
                    prop_assert_eq!(left.uncompressed_size, right.uncompressed_size);
                    prop_assert_eq!(left.compression_method, right.compression_method);
                    prop_assert_eq!(left.compression_block_size, right.compression_block_size);
                    prop_assert_eq!(left.block_sizes, right.block_sizes);
                    prop_assert_eq!(left.encrypted, right.encrypted);
                    prop_assert!(offset < bytes.len());
                }
                (Err(left), Err(right)) => prop_assert_eq!(left.to_string(), right.to_string()),
                _ => prop_assert!(false, "compact entry parsing was nondeterministic"),
            }
        }
    }

    fn unique_temp_pak(label: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "pak-merger-{label}-{}-{unique}.pak",
            std::process::id()
        ))
    }

    fn synthetic_uncompressed_pak(version: repak::Version) -> Vec<u8> {
        let path_hash_seed = ((version.version_major() as u32) >= 10).then_some(0x1234_5678_u64);
        let mut writer = repak::PakBuilder::new().writer(
            Cursor::new(Vec::new()),
            version,
            "../../../Game/Content/".to_owned(),
            path_hash_seed,
        );
        writer.write_file("A/One.uasset", false, b"one").unwrap();
        writer.write_index().unwrap().into_inner()
    }

    fn synthetic_compressed_pak(
        version: repak::Version,
        compression: repak::Compression,
        payload: &[u8],
    ) -> Vec<u8> {
        let path_hash_seed = ((version.version_major() as u32) >= 10).then_some(0x1234_5678_u64);
        let mut writer = repak::PakBuilder::new().compression([compression]).writer(
            Cursor::new(Vec::new()),
            version,
            "../../../Game/Content/".to_owned(),
            path_hash_seed,
        );
        writer
            .write_file("A/Compressed.bin", true, payload)
            .unwrap();
        writer.write_index().unwrap().into_inner()
    }

    fn read_footer_from_bytes(bytes: &[u8]) -> DetectedFooter {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("footer.pak");
        std::fs::write(&path, bytes).unwrap();
        let mut file = File::open(path).unwrap();
        read_footer(&mut file, bytes.len() as u64).unwrap()
    }

    fn detected_for_plan_test(version: repak::Version, codec: &str) -> DetectedFooter {
        DetectedFooter {
            repak_version: version,
            footer_offset: u64::MAX,
            footer: PakFooterInfo {
                version: version.version_major() as u32,
                encrypted_index: false,
                index_offset: 0,
                index_size: 0,
                index_sha1: String::new(),
                compression_slots: vec![codec.to_owned()],
            },
            compression_codecs: vec![Some(codec.to_owned())],
        }
    }

    fn synthetic_v3_database_pak(uasset: Option<Vec<u8>>, uexp: &[u8]) -> Vec<u8> {
        let mut writer = repak::PakBuilder::new().writer(
            Cursor::new(Vec::new()),
            repak::Version::V3,
            "../../../Game/Content/".to_owned(),
            None,
        );
        if let Some(uasset) = uasset {
            writer
                .write_file("DB/Table.uasset", false, &uasset)
                .unwrap();
        }
        writer.write_file("DB/Table.uexp", false, uexp).unwrap();
        writer.write_index().unwrap().into_inner()
    }

    fn synthetic_uasset() -> Vec<u8> {
        let mut bytes = vec![0xC1, 0x83, 0x2A, 0x9E];
        bytes.extend_from_slice(b"synthetic-uasset-companion");
        bytes
    }

    fn synthetic_binary_asset(row_id: u8) -> Vec<u8> {
        assert!(row_id <= 0x7f);
        let mut payload = vec![0x81, 0xaa];
        payload.extend_from_slice(b"m_DataList");
        payload.extend_from_slice(&[0x91, 0x81, 0xa4]);
        payload.extend_from_slice(b"m_id");
        payload.push(row_id);

        let mut bytes = vec![0; crate::binary_asset::PREFIX_SIZE];
        bytes[6..10].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&payload);
        bytes.extend_from_slice(&[0; crate::binary_asset::BINARY_ASSET_FOOTER_SIZE]);
        bytes.extend_from_slice(&[0xC1, 0x83, 0x2A, 0x9E]);
        BinaryAsset::parse(&bytes).unwrap();
        bytes
    }

    fn synthetic_binary_asset_row_id_offset(bytes: &[u8]) -> usize {
        let payload_size = u32::from_le_bytes(bytes[6..10].try_into().unwrap()) as usize;
        crate::binary_asset::PREFIX_SIZE + payload_size - 1
    }

    fn replace_unique_payload(archive: &mut [u8], original: &[u8], replacement: &[u8]) {
        assert_eq!(original.len(), replacement.len());
        let matches = archive
            .windows(original.len())
            .enumerate()
            .filter_map(|(offset, bytes)| (bytes == original).then_some(offset))
            .collect::<Vec<_>>();
        assert_eq!(matches.len(), 1, "payload fixture must occur exactly once");
        archive[matches[0]..matches[0] + replacement.len()].copy_from_slice(replacement);
    }

    struct TestIndexLocations {
        primary: std::ops::Range<usize>,
        path_hash: std::ops::Range<usize>,
        seed_offset: usize,
        path_hash_sha1_offset: usize,
        primary_sha1_offset: usize,
    }

    fn single_entry_archive() -> Vec<u8> {
        write_pak_v11_to(
            Cursor::new(Vec::new()),
            "../../../Game/Content/",
            [PakWriteEntry::new("A/One.uasset", b"one".to_vec())],
        )
        .unwrap()
        .into_inner()
    }

    fn locate_test_indexes(archive: &[u8]) -> TestIndexLocations {
        let footer_offset = archive.len() - PAK_V11_FOOTER_SIZE as usize;
        let index_offset = read_test_u64(archive, footer_offset + 25) as usize;
        let index_size = read_test_u64(archive, footer_offset + 33) as usize;
        let primary = index_offset..index_offset + index_size;
        let mut cursor = SliceReader::new(&archive[primary.clone()], "test primary index");
        cursor.read_fstring().unwrap();
        cursor.read_u32().unwrap();
        let seed_offset = index_offset + cursor.position;
        cursor.read_u64().unwrap();
        assert_eq!(cursor.read_u32().unwrap(), 1);
        let path_hash_offset = cursor.read_u64().unwrap() as usize;
        let path_hash_size = cursor.read_u64().unwrap() as usize;
        let path_hash_sha1_offset = index_offset + cursor.position;
        cursor.read_array_20().unwrap();

        TestIndexLocations {
            primary,
            path_hash: path_hash_offset..path_hash_offset + path_hash_size,
            seed_offset,
            path_hash_sha1_offset,
            primary_sha1_offset: footer_offset + 41,
        }
    }

    fn refresh_test_hashes(
        archive: &mut [u8],
        locations: &TestIndexLocations,
        path_hash_changed: bool,
    ) {
        if path_hash_changed {
            let path_hash_sha1: [u8; 20] =
                Sha1::digest(&archive[locations.path_hash.clone()]).into();
            archive[locations.path_hash_sha1_offset..locations.path_hash_sha1_offset + 20]
                .copy_from_slice(&path_hash_sha1);
        }
        let primary_sha1: [u8; 20] = Sha1::digest(&archive[locations.primary.clone()]).into();
        archive[locations.primary_sha1_offset..locations.primary_sha1_offset + 20]
            .copy_from_slice(&primary_sha1);
    }

    fn read_test_u64(bytes: &[u8], offset: usize) -> u64 {
        u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
    }

    fn assert_path_hash_archive_rejected(archive: Vec<u8>) {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("corrupt-path-hash.pak");
        std::fs::write(&path, archive).unwrap();
        let error = match PakArchive::open(&path) {
            Ok(_) => panic!("archive with an invalid path hash was accepted"),
            Err(error) => error,
        };
        assert!(
            matches!(&error, PakError::Corrupt(message) if message.contains("path check")),
            "unexpected error: {error}"
        );
    }
}
