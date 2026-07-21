//! Lossless reader and splice writer for supported `BinaryAsset` `.uexp` data.
//!
//! Existing nodes are copied as bytes or replaced with a complete node from an
//! input file. There is no generic MessagePack re-encoding path.

use crate::control::CancellationToken;
use crate::types::AtomicGroup;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fmt;
use std::ops::Range;
use std::sync::Arc;

pub const PREFIX_SIZE: usize = 10;
pub const BINARY_ASSET_FOOTER_SIZE: usize = 4;
pub const PACKAGE_TAG_SIZE: usize = 4;
pub const MAX_MESSAGEPACK_DEPTH: usize = 128;

/// BinaryAsset stores the payload length as an unsigned 32-bit value. On the
/// supported x64 build the format itself is therefore the only payload-size
/// ceiling; large payloads are indexed from their file mapping instead of
/// being retained as one decoded tree.
pub const MAX_BINARY_ASSET_PAYLOAD_BYTES: usize = u32::MAX as usize;
/// Maximum total nodes in one MessagePack parse, including container nodes.
///
/// Large cooked database tables legitimately exceed one million nodes. The
/// higher ceiling supports large combined tables on machines with enough RAM;
/// allocations still use fallible reserve operations.
pub const MAX_MESSAGEPACK_NODES: usize = 32_000_000;
/// Maximum cumulative array items plus map entries in one parse. Map keys and
/// values are additionally charged against `MAX_MESSAGEPACK_NODES`.
///
/// Real SkillID-family assets cross the old 500,000-item budget. This ceiling
/// leaves room for much larger mod collections without weakening depth and
/// allocation checks.
pub const MAX_MESSAGEPACK_CONTAINER_ITEMS: usize = 16_000_000;
/// Maximum total bytes copied into owned strings, binary values, and extension
/// values by one parse. These bytes exist in addition to the retained payload.
pub const MAX_MESSAGEPACK_OWNED_BYTES: usize = 2 * 1024 * 1024 * 1024;

pub type RowId = i64;

// IEEE-754 values at and beyond 2^precision no longer identify every adjacent
// integer uniquely. Row IDs encoded as floats are therefore accepted only in
// the consecutive-integer safe range for their original MessagePack marker.
const MAX_SAFE_F32_ROW_ID: f64 = 16_777_215.0; // 2^24 - 1
const MAX_SAFE_F64_ROW_ID: f64 = 9_007_199_254_740_991.0; // 2^53 - 1

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BinaryAssetError {
    TooShort {
        actual: usize,
        minimum: usize,
    },
    PayloadLengthOverflow(u32),
    PayloadLengthMismatch {
        header_end: usize,
        expected_end: usize,
    },
    UnexpectedEof {
        offset: usize,
        needed: usize,
        available: usize,
    },
    UnsupportedMarker {
        marker: u8,
        offset: usize,
    },
    InvalidUtf8 {
        offset: usize,
    },
    MessagePackDepthLimit {
        limit: usize,
    },
    MessagePackBudgetExceeded {
        resource: &'static str,
        requested: usize,
        limit: usize,
    },
    MessagePackAllocationFailed {
        resource: &'static str,
        requested: usize,
    },
    MessagePackTrailingData {
        parsed: usize,
        expected: usize,
    },
    Cancelled,
    ExpectedMap(&'static str),
    ExpectedArray(&'static str),
    MissingField(String),
    DuplicateField(String),
    NonStringMapKey,
    MissingRowId,
    MissingRow(RowId),
    InvalidRowId,
    DuplicateRowId(RowId),
    CarrierIndexOutOfRange {
        carrier: usize,
        input_count: usize,
    },
    InvalidDonorIndex {
        donor: usize,
        input_count: usize,
    },
    RowIdMismatch {
        carrier: RowId,
        donor: RowId,
    },
    OverlappingFieldSelection(String),
    OverlappingArrayElementSelection {
        field: String,
        index: usize,
    },
    ParallelArrayLengthMismatch {
        field: String,
        expected: usize,
        actual: usize,
    },
    ArrayIndexOutOfRange {
        field: String,
        index: usize,
        len: usize,
    },
    MissingExpectedArrayLength,
    RowSelectionContainsId,
    UnresolvedRowCollision(RowId),
    InvalidRowChoice {
        row_id: RowId,
        donor: usize,
    },
    LengthOverflow,
}

impl fmt::Display for BinaryAssetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort { actual, minimum } => {
                write!(
                    f,
                    "the game database file is {actual} bytes; at least {minimum} bytes are required"
                )
            }
            Self::PayloadLengthOverflow(value) => {
                write!(
                    f,
                    "database data length {value} is too large for this system"
                )
            }
            Self::PayloadLengthMismatch {
                header_end,
                expected_end,
            } => write!(
                f,
                "the database data ends at {header_end}, but its ending records require {expected_end}"
            ),
            Self::UnexpectedEof {
                offset,
                needed,
                available,
            } => write!(
                f,
                "a database value at {offset} needs {needed} bytes, but only {available} remain"
            ),
            Self::UnsupportedMarker { marker, offset } => {
                write!(
                    f,
                    "unsupported database value format 0x{marker:02X} at {offset}"
                )
            }
            Self::InvalidUtf8 { offset } => write!(f, "invalid UTF-8 string at {offset}"),
            Self::MessagePackDepthLimit { limit } => {
                write!(
                    f,
                    "database values are nested beyond the {limit}-level safety limit"
                )
            }
            Self::MessagePackBudgetExceeded {
                resource,
                requested,
                limit,
            } => write!(
                f,
                "the database is too large to process safely: {resource} requires {requested}, limit {limit}"
            ),
            Self::MessagePackAllocationFailed {
                resource,
                requested,
            } => write!(f, "not enough memory for {requested} database {resource}"),
            Self::MessagePackTrailingData { parsed, expected } => write!(
                f,
                "the database value ended at {parsed}, but the data section ends at {expected}"
            ),
            Self::Cancelled => write!(f, "operation cancelled"),
            Self::ExpectedMap(label) => write!(f, "{label} must contain named fields"),
            Self::ExpectedArray(label) => write!(f, "{label} must be a list"),
            Self::MissingField(field) => write!(f, "missing required field {field}"),
            Self::DuplicateField(field) => write!(f, "field {field} appears twice"),
            Self::NonStringMapKey => write!(f, "a database row contains an unnamed field"),
            Self::MissingRowId => write!(f, "database row is missing m_id"),
            Self::MissingRow(id) => write!(f, "database does not contain m_id {id}"),
            Self::InvalidRowId => write!(
                f,
                "m_id must be a whole number that can be represented safely"
            ),
            Self::DuplicateRowId(id) => write!(f, "duplicate m_id {id}"),
            Self::CarrierIndexOutOfRange {
                carrier,
                input_count,
            } => write!(
                f,
                "base Pak index {carrier} is outside the {input_count} database inputs"
            ),
            Self::InvalidDonorIndex { donor, input_count } => write!(
                f,
                "selected Pak index {donor} is outside the {input_count} database inputs"
            ),
            Self::RowIdMismatch { carrier, donor } => write!(
                f,
                "cannot copy selected row {donor} into base Pak row {carrier}"
            ),
            Self::OverlappingFieldSelection(field) => {
                write!(f, "field {field} was selected from more than one Pak")
            }
            Self::OverlappingArrayElementSelection { field, index } => write!(
                f,
                "list item {field}[{index}] was selected from more than one Pak"
            ),
            Self::ParallelArrayLengthMismatch {
                field,
                expected,
                actual,
            } => write!(
                f,
                "linked list {field} has {actual} items; expected exactly {expected}"
            ),
            Self::ArrayIndexOutOfRange { field, index, len } => write!(
                f,
                "linked list item {field}[{index}] is outside the {len}-item list"
            ),
            Self::MissingExpectedArrayLength => {
                write!(f, "linked-array selection is missing its analyzed length")
            }
            Self::RowSelectionContainsId => {
                write!(f, "m_id cannot be replaced during a field merge")
            }
            Self::UnresolvedRowCollision(id) => {
                write!(
                    f,
                    "new row {id} has different values in multiple Paks; choose which Pak to use"
                )
            }
            Self::InvalidRowChoice { row_id, donor } => write!(
                f,
                "Pak {donor} does not contain a selectable value for new row {row_id}"
            ),
            Self::LengthOverflow => write!(f, "a database list is too large to write"),
        }
    }
}

impl std::error::Error for BinaryAssetError {}

pub type Result<T> = std::result::Result<T, BinaryAssetError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntegerValue {
    Signed(i64),
    Unsigned(u64),
}

impl IntegerValue {
    pub fn as_i64(self) -> Option<i64> {
        match self {
            Self::Signed(value) => Some(value),
            Self::Unsigned(value) => i64::try_from(value).ok(),
        }
    }

    fn canonical_i128(self) -> i128 {
        match self {
            Self::Signed(value) => i128::from(value),
            Self::Unsigned(value) => i128::from(value),
        }
    }
}

/// Converts an IEEE-754 value to the exact integer it represents when that
/// integer fits in MessagePack's native `i64`/`u64` domain.
///
/// This is used only for semantic comparison and hashing. The parsed marker,
/// raw byte range, and selected source bytes remain unchanged.
fn exact_messagepack_integer_from_float(value: f64) -> Option<i128> {
    const U64_EXCLUSIVE_MAX_AS_F64: f64 = 18_446_744_073_709_551_616.0;
    const I64_MIN_AS_F64: f64 = -9_223_372_036_854_775_808.0;

    if !value.is_finite() || value.fract() != 0.0 {
        return None;
    }

    if value >= 0.0 {
        // `u64::MAX as f64` rounds to 2^64, so compare against the explicit
        // exclusive boundary before using Rust's saturating float-to-int cast.
        if value >= U64_EXCLUSIVE_MAX_AS_F64 {
            return None;
        }
        let integer = value as u64;
        (integer as f64 == value).then_some(i128::from(integer))
    } else {
        if value < I64_MIN_AS_F64 {
            return None;
        }
        let integer = value as i64;
        (integer as f64 == value).then_some(i128::from(integer))
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum MsgpackKind {
    Nil,
    Boolean(bool),
    Integer(IntegerValue),
    Float(f64),
    String(String),
    Binary(Vec<u8>),
    Array(Vec<MsgpackNode>),
    Map(Vec<MapEntry>),
    Extension { type_tag: i8, data: Vec<u8> },
}

#[derive(Debug, Clone, PartialEq)]
pub struct MapEntry {
    pub key: MsgpackNode,
    pub value: MsgpackNode,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MsgpackNode {
    /// The original MessagePack marker byte.
    pub marker: u8,
    /// Range in the parsed byte slice, including marker and body.
    pub range: Range<usize>,
    /// Offset immediately after the container/string header. For scalar
    /// values this is also the body start and is informational only.
    pub header_end: usize,
    pub kind: MsgpackKind,
}

impl MsgpackNode {
    pub fn raw<'a>(&self, source: &'a [u8]) -> &'a [u8] {
        &source[self.range.clone()]
    }

    pub fn raw_sha256(&self, source: &[u8]) -> String {
        sha256_hex(self.raw(source))
    }

    pub fn semantic_sha256(&self) -> String {
        let mut digest = Sha256::new();
        self.update_semantic_digest(&mut digest);
        hex::encode_upper(digest.finalize())
    }

    pub fn semantic_eq(&self, other: &Self) -> bool {
        semantic_kind_eq(&self.kind, &other.kind)
    }

    pub fn is_scalar(&self) -> bool {
        !matches!(self.kind, MsgpackKind::Array(_) | MsgpackKind::Map(_))
    }

    pub fn type_name(&self) -> &'static str {
        match self.kind {
            MsgpackKind::Nil => "nil",
            MsgpackKind::Boolean(_) => "boolean",
            MsgpackKind::Integer(_) => "integer",
            MsgpackKind::Float(_) => "float",
            MsgpackKind::String(_) => "string",
            MsgpackKind::Binary(_) => "binary",
            MsgpackKind::Array(_) => "array",
            MsgpackKind::Map(_) => "map",
            MsgpackKind::Extension { .. } => "extension",
        }
    }

    pub fn as_array(&self) -> Option<&[MsgpackNode]> {
        match &self.kind {
            MsgpackKind::Array(items) => Some(items),
            _ => None,
        }
    }

    pub fn as_map(&self) -> Option<&[MapEntry]> {
        match &self.kind {
            MsgpackKind::Map(entries) => Some(entries),
            _ => None,
        }
    }

    pub fn string_value(&self) -> Option<&str> {
        match &self.kind {
            MsgpackKind::String(value) => Some(value),
            _ => None,
        }
    }

    pub fn integer_value(&self) -> Option<IntegerValue> {
        match self.kind {
            MsgpackKind::Integer(value) => Some(value),
            _ => None,
        }
    }

    /// Returns a unique string-keyed map value. Duplicate matching keys are a
    /// structural error instead of being silently resolved by first/last wins.
    pub fn map_get(&self, field: &str) -> Result<Option<&MsgpackNode>> {
        let entries = self
            .as_map()
            .ok_or(BinaryAssetError::ExpectedMap("MessagePack node"))?;
        let mut found = None;
        for entry in entries {
            if entry.key.string_value() == Some(field) {
                if found.is_some() {
                    return Err(BinaryAssetError::DuplicateField(field.to_owned()));
                }
                found = Some(&entry.value);
            }
        }
        Ok(found)
    }

    pub fn map_fields(&self) -> Result<Vec<(&str, &MsgpackNode)>> {
        let entries = self
            .as_map()
            .ok_or(BinaryAssetError::ExpectedMap("database row"))?;
        let mut names = HashSet::new();
        names.try_reserve(entries.len()).map_err(|_| {
            BinaryAssetError::MessagePackAllocationFailed {
                resource: "map-field names",
                requested: entries.len(),
            }
        })?;
        let mut output = Vec::new();
        output.try_reserve_exact(entries.len()).map_err(|_| {
            BinaryAssetError::MessagePackAllocationFailed {
                resource: "map-field views",
                requested: entries.len(),
            }
        })?;
        for entry in entries {
            let name = entry
                .key
                .string_value()
                .ok_or(BinaryAssetError::NonStringMapKey)?;
            if !names.insert(name) {
                return Err(BinaryAssetError::DuplicateField(name.to_owned()));
            }
            output.push((name, &entry.value));
        }
        Ok(output)
    }

    fn update_semantic_digest(&self, digest: &mut Sha256) {
        match &self.kind {
            MsgpackKind::Nil => digest.update([0]),
            MsgpackKind::Boolean(value) => digest.update([1, u8::from(*value)]),
            MsgpackKind::Integer(value) => {
                digest.update([2]);
                digest.update(value.canonical_i128().to_be_bytes());
            }
            MsgpackKind::Float(value) => {
                if let Some(integer) = exact_messagepack_integer_from_float(*value) {
                    digest.update([2]);
                    digest.update(integer.to_be_bytes());
                } else {
                    digest.update([3]);
                    let canonical = if value.is_nan() {
                        f64::NAN.to_bits()
                    } else if *value == 0.0 {
                        0.0f64.to_bits()
                    } else {
                        value.to_bits()
                    };
                    digest.update(canonical.to_be_bytes());
                }
            }
            MsgpackKind::String(value) => {
                digest.update([4]);
                hash_len(digest, value.len());
                digest.update(value.as_bytes());
            }
            MsgpackKind::Binary(value) => {
                digest.update([5]);
                hash_len(digest, value.len());
                digest.update(value);
            }
            MsgpackKind::Array(items) => {
                digest.update([6]);
                hash_len(digest, items.len());
                for item in items {
                    item.update_semantic_digest(digest);
                }
            }
            MsgpackKind::Map(entries) => {
                digest.update([7]);
                hash_len(digest, entries.len());
                // The target data relies on stable map shape/order. Preserve that order in
                // the semantic identity while ignoring representation markers.
                for entry in entries {
                    entry.key.update_semantic_digest(digest);
                    entry.value.update_semantic_digest(digest);
                }
            }
            MsgpackKind::Extension { type_tag, data } => {
                digest.update([8, *type_tag as u8]);
                hash_len(digest, data.len());
                digest.update(data);
            }
        }
    }
}

/// Returns the logical database row ID without changing its raw MessagePack
/// representation.
///
/// Native integer markers retain the full signed `i64` domain. Some existing
/// plain mod Paks were produced by generic encoders that rewrote `m_id` as an
/// IEEE-754 value, so finite, integral float32/float64 nodes are also accepted
/// inside their consecutive-integer safe ranges (2^24-1 and 2^53-1). `-0.0`
/// intentionally maps to logical ID 0 and therefore participates in ordinary
/// duplicate-ID detection. Fractional, non-finite, unknown-marker, and
/// precision-ambiguous values fail closed.
pub fn logical_row_id(row: &MsgpackNode) -> Result<RowId> {
    let value = row.map_get("m_id")?.ok_or(BinaryAssetError::MissingRowId)?;
    logical_row_id_value(value)
}

fn logical_row_id_value(value: &MsgpackNode) -> Result<RowId> {
    match value.kind {
        MsgpackKind::Integer(integer) => integer.as_i64().ok_or(BinaryAssetError::InvalidRowId),
        MsgpackKind::Float(float) => {
            let max_safe = match value.marker {
                0xca => MAX_SAFE_F32_ROW_ID,
                0xcb => MAX_SAFE_F64_ROW_ID,
                _ => return Err(BinaryAssetError::InvalidRowId),
            };
            if !float.is_finite() || float.fract() != 0.0 || float.abs() > max_safe {
                return Err(BinaryAssetError::InvalidRowId);
            }
            let integer = float as RowId;
            if integer as f64 != float {
                return Err(BinaryAssetError::InvalidRowId);
            }
            Ok(integer)
        }
        _ => Err(BinaryAssetError::InvalidRowId),
    }
}

fn hash_len(digest: &mut Sha256, len: usize) {
    digest.update((len as u64).to_be_bytes());
}

fn semantic_kind_eq(left: &MsgpackKind, right: &MsgpackKind) -> bool {
    match (left, right) {
        (MsgpackKind::Nil, MsgpackKind::Nil) => true,
        (MsgpackKind::Boolean(a), MsgpackKind::Boolean(b)) => a == b,
        (MsgpackKind::Integer(a), MsgpackKind::Integer(b)) => {
            a.canonical_i128() == b.canonical_i128()
        }
        (MsgpackKind::Integer(integer), MsgpackKind::Float(float))
        | (MsgpackKind::Float(float), MsgpackKind::Integer(integer)) => {
            exact_messagepack_integer_from_float(*float) == Some(integer.canonical_i128())
        }
        (MsgpackKind::Float(a), MsgpackKind::Float(b)) => (a.is_nan() && b.is_nan()) || a == b,
        (MsgpackKind::String(a), MsgpackKind::String(b)) => a == b,
        (MsgpackKind::Binary(a), MsgpackKind::Binary(b)) => a == b,
        (MsgpackKind::Array(a), MsgpackKind::Array(b)) => {
            a.len() == b.len() && a.iter().zip(b).all(|(x, y)| x.semantic_eq(y))
        }
        (MsgpackKind::Map(a), MsgpackKind::Map(b)) => {
            a.len() == b.len()
                && a.iter()
                    .zip(b)
                    .all(|(x, y)| x.key.semantic_eq(&y.key) && x.value.semantic_eq(&y.value))
        }
        (
            MsgpackKind::Extension {
                type_tag: at,
                data: ad,
            },
            MsgpackKind::Extension {
                type_tag: bt,
                data: bd,
            },
        ) => at == bt && ad == bd,
        _ => false,
    }
}

#[derive(Clone, Copy)]
pub struct NodeRef<'a> {
    pub node: &'a MsgpackNode,
    pub source: &'a [u8],
}

impl<'a> NodeRef<'a> {
    pub fn raw(self) -> &'a [u8] {
        self.node.raw(self.source)
    }

    pub fn raw_sha256(self) -> String {
        self.node.raw_sha256(self.source)
    }

    pub fn semantic_sha256(self) -> String {
        self.node.semantic_sha256()
    }
}

/// One validated, allocation-bounded lookup view over a database row map.
///
/// Construction checks every key once, so duplicate and non-string fields
/// remain structural errors. Callers that inspect several atomic units can
/// then reuse the same O(1) field lookup instead of rescanning the row map for
/// every field in every unit.
#[derive(Debug)]
pub struct RowFieldIndex<'a> {
    row: NodeRef<'a>,
    ordered: Vec<(&'a str, &'a MsgpackNode)>,
    by_name: HashMap<&'a str, &'a MsgpackNode>,
}

impl<'a> RowFieldIndex<'a> {
    pub fn new(row: NodeRef<'a>) -> Result<Self> {
        let entries = row
            .node
            .as_map()
            .ok_or(BinaryAssetError::ExpectedMap("database row"))?;
        let mut ordered = Vec::new();
        ordered.try_reserve_exact(entries.len()).map_err(|_| {
            BinaryAssetError::MessagePackAllocationFailed {
                resource: "map-field views",
                requested: entries.len(),
            }
        })?;
        let mut by_name = HashMap::new();
        by_name.try_reserve(entries.len()).map_err(|_| {
            BinaryAssetError::MessagePackAllocationFailed {
                resource: "map-field index",
                requested: entries.len(),
            }
        })?;
        for entry in entries {
            let name = entry
                .key
                .string_value()
                .ok_or(BinaryAssetError::NonStringMapKey)?;
            if by_name.insert(name, &entry.value).is_some() {
                return Err(BinaryAssetError::DuplicateField(name.to_owned()));
            }
            ordered.push((name, &entry.value));
        }
        #[cfg(test)]
        TEST_ROW_FIELD_INDEX_BUILDS.with(|count| count.set(count.get() + 1));
        Ok(Self {
            row,
            ordered,
            by_name,
        })
    }

    pub fn fields(&self) -> &[(&'a str, &'a MsgpackNode)] {
        &self.ordered
    }

    pub fn len(&self) -> usize {
        self.ordered.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ordered.is_empty()
    }

    pub fn get(&self, field: &str) -> Option<&'a MsgpackNode> {
        self.by_name.get(field).copied()
    }

    pub fn row_id(&self) -> Result<RowId> {
        let value = self.get("m_id").ok_or(BinaryAssetError::MissingRowId)?;
        logical_row_id_value(value)
    }

    pub fn field_ref(&self, field: &str) -> Result<NodeRef<'a>> {
        let node = self
            .get(field)
            .ok_or_else(|| BinaryAssetError::MissingField(field.to_owned()))?;
        Ok(NodeRef {
            node,
            source: self.row.source,
        })
    }

    pub fn atomic_group_value(&self, unit: &AtomicGroup, field: &str) -> Result<NodeRef<'a>> {
        let node = self.field_ref(field)?;
        if let Some(index) = unit.array_index {
            let items = node.node.as_array().ok_or(BinaryAssetError::ExpectedArray(
                "audited parallel-array field",
            ))?;
            let expected = unit
                .expected_array_len
                .ok_or(BinaryAssetError::MissingExpectedArrayLength)?;
            if items.len() != expected {
                return Err(BinaryAssetError::ParallelArrayLengthMismatch {
                    field: field.to_owned(),
                    expected,
                    actual: items.len(),
                });
            }
            let selected =
                items
                    .get(index)
                    .ok_or_else(|| BinaryAssetError::ArrayIndexOutOfRange {
                        field: field.to_owned(),
                        index,
                        len: items.len(),
                    })?;
            Ok(NodeRef {
                node: selected,
                source: self.row.source,
            })
        } else {
            Ok(node)
        }
    }

    pub fn atomic_group_hashes(&self, unit: &AtomicGroup) -> Result<AtomicUnitHashes> {
        hash_atomic_values(
            unit,
            |field| self.atomic_group_value(unit, field),
            |field| self.field_ref(field),
        )
    }
}

#[cfg(test)]
std::thread_local! {
    static TEST_ROW_FIELD_INDEX_BUILDS: std::cell::Cell<usize> = const {
        std::cell::Cell::new(0)
    };
}

#[cfg(test)]
pub(crate) fn reset_test_row_field_index_builds() {
    TEST_ROW_FIELD_INDEX_BUILDS.with(|count| count.set(0));
}

#[cfg(test)]
pub(crate) fn test_row_field_index_builds() -> usize {
    TEST_ROW_FIELD_INDEX_BUILDS.with(std::cell::Cell::get)
}

impl fmt::Debug for NodeRef<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NodeRef")
            .field("marker", &format_args!("0x{:02X}", self.node.marker))
            .field("range", &self.node.range)
            .field("kind", &self.node.type_name())
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct BinaryAsset {
    pub prefix: [u8; PREFIX_SIZE],
    pub payload: Vec<u8>,
    pub footer: [u8; BINARY_ASSET_FOOTER_SIZE],
    pub package_tag: [u8; PACKAGE_TAG_SIZE],
    pub root: MsgpackNode,
    pub original_size: usize,
    /// Validated `m_DataList` array index -> row ID mapping.
    row_ids: Vec<RowId>,
    /// Validated row ID -> `m_DataList` array index mapping.
    row_indices: HashMap<RowId, usize>,
}

/// A compact, read-only index over a BinaryAsset whose bytes are owned by the
/// caller-provided backing object.
///
/// Unlike [`BinaryAsset`], this type neither builds nor retains a complete
/// MessagePack tree and does not copy the payload. A non-allocating structural
/// walk records each validated row range; only one row at a time is parsed to
/// validate its logical ID. Later, individual rows are parsed on demand, so
/// keeping indexes for several Paks costs O(row count) metadata rather than
/// O(total MessagePack node count) resident heap.
pub struct IndexedBinaryAsset {
    pub prefix: [u8; PREFIX_SIZE],
    pub footer: [u8; BINARY_ASSET_FOOTER_SIZE],
    pub package_tag: [u8; PACKAGE_TAG_SIZE],
    pub original_size: usize,
    backing: Arc<dyn BinaryAssetBacking>,
    payload_range: Range<usize>,
    data_list_range: Range<usize>,
    data_list_marker: u8,
    row_ids: Vec<RowId>,
    row_lookup: CompactRowLookup,
    row_ranges: Vec<Range<usize>>,
}

/// Most cooked databases store `m_DataList` in strictly increasing `m_id`
/// order. In that common case the existing row-id vector is also the lookup
/// index, so retaining a second hash table would only multiply session memory.
/// Unordered inputs remain fully supported through the fallback map.
#[derive(Debug)]
enum CompactRowLookup {
    Sorted,
    Unordered(HashMap<RowId, usize>),
}

impl CompactRowLookup {
    fn index_of(&self, row_ids: &[RowId], id: RowId) -> Option<usize> {
        match self {
            Self::Sorted => row_ids.binary_search(&id).ok(),
            Self::Unordered(indices) => indices.get(&id).copied(),
        }
    }

    fn retained_bytes(&self) -> usize {
        match self {
            Self::Sorted => 0,
            Self::Unordered(indices) => indices
                .capacity()
                .saturating_mul(std::mem::size_of::<(RowId, usize)>()),
        }
    }
}

trait BinaryAssetBacking: Send + Sync {
    fn as_bytes(&self) -> &[u8];
}

impl<T> BinaryAssetBacking for T
where
    T: AsRef<[u8]> + Send + Sync,
{
    fn as_bytes(&self) -> &[u8] {
        self.as_ref()
    }
}

impl fmt::Debug for IndexedBinaryAsset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IndexedBinaryAsset")
            .field("original_size", &self.original_size)
            .field("payload_range", &self.payload_range)
            .field("data_list_range", &self.data_list_range)
            .field("row_count", &self.row_ids.len())
            .finish_non_exhaustive()
    }
}

/// One on-demand parsed row from an [`IndexedBinaryAsset`]. The node owns only
/// its parsed metadata and decoded scalar values; exact raw bytes remain a
/// borrowed slice of the shared Pak/mmap backing.
#[derive(Debug)]
pub struct IndexedRow<'a> {
    pub index: usize,
    pub id: RowId,
    pub node: MsgpackNode,
    pub source: &'a [u8],
}

impl IndexedRow<'_> {
    pub fn node_ref(&self) -> NodeRef<'_> {
        NodeRef {
            node: &self.node,
            source: self.source,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct RowView<'a> {
    pub index: usize,
    pub id: RowId,
    pub node: &'a MsgpackNode,
    pub source: &'a [u8],
}

impl<'a> RowView<'a> {
    pub fn node_ref(self) -> NodeRef<'a> {
        NodeRef {
            node: self.node,
            source: self.source,
        }
    }
}

impl BinaryAsset {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        Self::parse_internal(bytes, None)
    }

    pub fn parse_with_cancel(bytes: &[u8], cancellation: &CancellationToken) -> Result<Self> {
        Self::parse_internal(bytes, Some(cancellation))
    }

    fn parse_internal(bytes: &[u8], cancellation: Option<&CancellationToken>) -> Result<Self> {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return Err(BinaryAssetError::Cancelled);
        }
        let minimum = PREFIX_SIZE + BINARY_ASSET_FOOTER_SIZE + PACKAGE_TAG_SIZE;
        if bytes.len() < minimum {
            return Err(BinaryAssetError::TooShort {
                actual: bytes.len(),
                minimum,
            });
        }

        let payload_length_u32 = u32::from_le_bytes(bytes[6..10].try_into().expect("fixed range"));
        let payload_length = usize::try_from(payload_length_u32)
            .map_err(|_| BinaryAssetError::PayloadLengthOverflow(payload_length_u32))?;
        enforce_budget_limit(
            "payload bytes",
            payload_length,
            MAX_BINARY_ASSET_PAYLOAD_BYTES,
        )?;
        let payload_end = PREFIX_SIZE
            .checked_add(payload_length)
            .ok_or(BinaryAssetError::LengthOverflow)?;
        let expected_end = bytes.len() - BINARY_ASSET_FOOTER_SIZE - PACKAGE_TAG_SIZE;
        if payload_end != expected_end {
            return Err(BinaryAssetError::PayloadLengthMismatch {
                header_end: payload_end,
                expected_end,
            });
        }

        let mut payload = Vec::new();
        payload.try_reserve_exact(payload_length).map_err(|_| {
            BinaryAssetError::MessagePackAllocationFailed {
                resource: "payload bytes",
                requested: payload_length,
            }
        })?;
        payload.extend_from_slice(&bytes[PREFIX_SIZE..payload_end]);
        let root = parse_messagepack_with_limits_and_cancel(
            &payload,
            default_parse_limits(),
            cancellation,
        )?;
        let (row_ids, row_indices) = validate_and_index_rows(&root, cancellation)?;
        let asset = Self {
            prefix: bytes[..PREFIX_SIZE].try_into().expect("fixed range"),
            payload,
            footer: bytes[payload_end..payload_end + BINARY_ASSET_FOOTER_SIZE]
                .try_into()
                .expect("fixed range"),
            package_tag: bytes[bytes.len() - PACKAGE_TAG_SIZE..]
                .try_into()
                .expect("fixed range"),
            root,
            original_size: bytes.len(),
            row_ids,
            row_indices,
        };
        Ok(asset)
    }

    pub fn data_list(&self) -> Result<&MsgpackNode> {
        let node = self
            .root
            .map_get("m_DataList")?
            .ok_or_else(|| BinaryAssetError::MissingField("m_DataList".to_owned()))?;
        if node.as_array().is_none() {
            return Err(BinaryAssetError::ExpectedArray("m_DataList"));
        }
        Ok(node)
    }

    /// Returns all rows in their original array order in O(R), using the row
    /// IDs validated and cached during `parse`.
    pub fn rows(&self) -> Result<Vec<RowView<'_>>> {
        let items = self
            .data_list()?
            .as_array()
            .expect("data_list validates the type");
        debug_assert_eq!(items.len(), self.row_ids.len());
        let mut rows = Vec::new();
        rows.try_reserve_exact(items.len()).map_err(|_| {
            BinaryAssetError::MessagePackAllocationFailed {
                resource: "row views",
                requested: items.len(),
            }
        })?;
        for (index, (&id, node)) in self.row_ids.iter().zip(items).enumerate() {
            rows.push(RowView {
                index,
                id,
                node,
                source: &self.payload,
            });
        }
        Ok(rows)
    }

    /// Looks up a row in expected O(1) time without rebuilding all row views.
    pub fn row(&self, id: RowId) -> Result<Option<RowView<'_>>> {
        let Some(&index) = self.row_indices.get(&id) else {
            return Ok(None);
        };
        let items = self
            .data_list()?
            .as_array()
            .expect("data_list validates the type");
        let node = items
            .get(index)
            .expect("validated row index remains in m_DataList bounds");
        Ok(Some(RowView {
            index,
            id,
            node,
            source: &self.payload,
        }))
    }

    /// Number of validated rows in `m_DataList`.
    pub fn row_count(&self) -> usize {
        self.row_ids.len()
    }

    /// Returns a validated row by its original array position without
    /// allocating an intermediate collection of row views.
    pub fn row_at(&self, index: usize) -> Result<Option<RowView<'_>>> {
        let Some(&id) = self.row_ids.get(index) else {
            return Ok(None);
        };
        let items = self
            .data_list()?
            .as_array()
            .expect("data_list validates the type");
        let node = items
            .get(index)
            .expect("validated row index remains in m_DataList bounds");
        Ok(Some(RowView {
            index,
            id,
            node,
            source: &self.payload,
        }))
    }

    /// Validated row IDs in the same order as `m_DataList`.
    pub fn row_ids(&self) -> &[RowId] {
        &self.row_ids
    }

    pub fn contains_row(&self, id: RowId) -> bool {
        self.row_indices.contains_key(&id)
    }

    /// Encodes only the replacement `m_DataList` array header while retaining
    /// the carrier's marker family. This is used by the disk-backed writer so
    /// row bodies never have to be collected in memory.
    pub fn data_list_header_for_len(&self, row_count: usize) -> Result<Vec<u8>> {
        encode_array_header_like(self.data_list()?.marker, row_count)
    }

    /// Materializes the API's sorted row map in O(R), without revalidating row
    /// maps or constructing an intermediate `Vec<RowView>`.
    pub fn row_index(&self) -> Result<BTreeMap<RowId, RowView<'_>>> {
        let items = self
            .data_list()?
            .as_array()
            .expect("data_list validates the type");
        debug_assert_eq!(items.len(), self.row_ids.len());
        let mut output = BTreeMap::new();
        for (index, (&id, node)) in self.row_ids.iter().zip(items).enumerate() {
            output.insert(
                id,
                RowView {
                    index,
                    id,
                    node,
                    source: &self.payload,
                },
            );
        }
        Ok(output)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(self.original_size);
        output.extend_from_slice(&self.prefix);
        output.extend_from_slice(&self.payload);
        output.extend_from_slice(&self.footer);
        output.extend_from_slice(&self.package_tag);
        output
    }

    /// Rebuild only `m_DataList`, retaining the carrier payload around it and
    /// retaining each supplied row as exact raw bytes.
    pub fn rebuild_data_list(&self, row_bytes: &[Vec<u8>]) -> Result<Vec<u8>> {
        validate_raw_rows(row_bytes)?;
        let list = self.data_list()?;
        let mut new_list = encode_array_header_like(list.marker, row_bytes.len())?;
        for row in row_bytes {
            new_list.extend_from_slice(row);
        }

        let new_payload_len = self
            .payload
            .len()
            .checked_sub(list.range.end - list.range.start)
            .and_then(|len| len.checked_add(new_list.len()))
            .ok_or(BinaryAssetError::LengthOverflow)?;
        let payload_len_u32 =
            u32::try_from(new_payload_len).map_err(|_| BinaryAssetError::LengthOverflow)?;

        let mut new_payload = Vec::with_capacity(new_payload_len);
        new_payload.extend_from_slice(&self.payload[..list.range.start]);
        new_payload.extend_from_slice(&new_list);
        new_payload.extend_from_slice(&self.payload[list.range.end..]);

        let mut prefix = self.prefix;
        prefix[6..10].copy_from_slice(&payload_len_u32.to_le_bytes());
        let mut output = Vec::with_capacity(
            PREFIX_SIZE + new_payload.len() + BINARY_ASSET_FOOTER_SIZE + PACKAGE_TAG_SIZE,
        );
        output.extend_from_slice(&prefix);
        output.extend_from_slice(&new_payload);
        output.extend_from_slice(&self.footer);
        output.extend_from_slice(&self.package_tag);

        // Every supplied row was validated above. Complete-file readback is a
        // caller-level final verification so production writers do not parse
        // the same rebuilt database twice.
        Ok(output)
    }
}

impl IndexedBinaryAsset {
    /// Validates a BinaryAsset while retaining `bytes` itself as the immutable
    /// source. `bytes` may be an archive slice, a decoded-cache handle, or a
    /// temporary-file mmap; it is never copied into a payload `Vec`.
    pub fn parse_backed<T>(bytes: T) -> Result<Self>
    where
        T: AsRef<[u8]> + Send + Sync + 'static,
    {
        Self::parse_backed_internal(bytes, None, None)
    }

    pub fn parse_backed_with_cancel<T>(bytes: T, cancellation: &CancellationToken) -> Result<Self>
    where
        T: AsRef<[u8]> + Send + Sync + 'static,
    {
        Self::parse_backed_internal(bytes, Some(cancellation), None)
    }

    /// Validates and indexes a BinaryAsset while reporting how many payload
    /// bytes have been structurally scanned. The callback is deliberately
    /// synchronous: callers can update a UI without retaining another copy of
    /// the database or introducing a second indexing pass.
    pub fn parse_backed_with_cancel_and_progress<T, F>(
        bytes: T,
        cancellation: &CancellationToken,
        mut progress: F,
    ) -> Result<Self>
    where
        T: AsRef<[u8]> + Send + Sync + 'static,
        F: FnMut(usize, usize),
    {
        Self::parse_backed_internal(bytes, Some(cancellation), Some(&mut progress))
    }

    fn parse_backed_internal<T>(
        bytes: T,
        cancellation: Option<&CancellationToken>,
        progress: Option<&mut dyn FnMut(usize, usize)>,
    ) -> Result<Self>
    where
        T: AsRef<[u8]> + Send + Sync + 'static,
    {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return Err(BinaryAssetError::Cancelled);
        }
        let all = bytes.as_ref();
        let minimum = PREFIX_SIZE + BINARY_ASSET_FOOTER_SIZE + PACKAGE_TAG_SIZE;
        if all.len() < minimum {
            return Err(BinaryAssetError::TooShort {
                actual: all.len(),
                minimum,
            });
        }

        let payload_length_u32 = u32::from_le_bytes(all[6..10].try_into().expect("fixed range"));
        let payload_length = usize::try_from(payload_length_u32)
            .map_err(|_| BinaryAssetError::PayloadLengthOverflow(payload_length_u32))?;
        enforce_budget_limit(
            "payload bytes",
            payload_length,
            MAX_BINARY_ASSET_PAYLOAD_BYTES,
        )?;
        let payload_end = PREFIX_SIZE
            .checked_add(payload_length)
            .ok_or(BinaryAssetError::LengthOverflow)?;
        let expected_end = all.len() - BINARY_ASSET_FOOTER_SIZE - PACKAGE_TAG_SIZE;
        if payload_end != expected_end {
            return Err(BinaryAssetError::PayloadLengthMismatch {
                header_end: payload_end,
                expected_end,
            });
        }

        let payload = &all[PREFIX_SIZE..payload_end];
        let index = index_messagepack_database(payload, cancellation, progress)?;

        let prefix = all[..PREFIX_SIZE].try_into().expect("fixed range");
        let footer = all[payload_end..payload_end + BINARY_ASSET_FOOTER_SIZE]
            .try_into()
            .expect("fixed range");
        let package_tag = all[all.len() - PACKAGE_TAG_SIZE..]
            .try_into()
            .expect("fixed range");
        let original_size = all.len();
        // No references into `bytes` escape the scope above. Moving it into an
        // Arc now keeps every recorded range valid for the index lifetime.
        let backing: Arc<dyn BinaryAssetBacking> = Arc::new(bytes);
        Ok(Self {
            prefix,
            footer,
            package_tag,
            original_size,
            backing,
            payload_range: PREFIX_SIZE..payload_end,
            data_list_range: index.data_list_range,
            data_list_marker: index.data_list_marker,
            row_ids: index.row_ids,
            row_lookup: index.row_lookup,
            row_ranges: index.row_ranges,
        })
    }

    pub fn payload(&self) -> &[u8] {
        &self.backing.as_bytes()[self.payload_range.clone()]
    }

    pub fn bytes(&self) -> &[u8] {
        self.backing.as_bytes()
    }

    pub fn data_list_range(&self) -> Range<usize> {
        self.data_list_range.clone()
    }

    pub fn data_list_header_for_len(&self, row_count: usize) -> Result<Vec<u8>> {
        encode_array_header_like(self.data_list_marker, row_count)
    }

    pub fn row_count(&self) -> usize {
        self.row_ids.len()
    }

    pub fn row_ids(&self) -> &[RowId] {
        &self.row_ids
    }

    pub fn contains_row(&self, id: RowId) -> bool {
        self.row_lookup.index_of(&self.row_ids, id).is_some()
    }

    pub fn row(&self, id: RowId) -> Result<Option<IndexedRow<'_>>> {
        self.row_internal(id, None)
    }

    pub fn row_with_cancel(
        &self,
        id: RowId,
        cancellation: &CancellationToken,
    ) -> Result<Option<IndexedRow<'_>>> {
        self.row_internal(id, Some(cancellation))
    }

    fn row_internal(
        &self,
        id: RowId,
        cancellation: Option<&CancellationToken>,
    ) -> Result<Option<IndexedRow<'_>>> {
        let Some(index) = self.row_lookup.index_of(&self.row_ids, id) else {
            return Ok(None);
        };
        self.row_at_internal(index, cancellation)
    }

    pub fn row_at(&self, index: usize) -> Result<Option<IndexedRow<'_>>> {
        self.row_at_internal(index, None)
    }

    pub fn row_at_with_cancel(
        &self,
        index: usize,
        cancellation: &CancellationToken,
    ) -> Result<Option<IndexedRow<'_>>> {
        self.row_at_internal(index, Some(cancellation))
    }

    fn row_at_internal(
        &self,
        index: usize,
        cancellation: Option<&CancellationToken>,
    ) -> Result<Option<IndexedRow<'_>>> {
        let Some((&id, range)) = self.row_ids.get(index).zip(self.row_ranges.get(index)) else {
            return Ok(None);
        };
        let source = &self.payload()[range.clone()];
        let node =
            parse_messagepack_with_limits_and_cancel(source, default_parse_limits(), cancellation)?;
        let parsed_id = logical_row_id(&node)?;
        if parsed_id != id {
            return Err(BinaryAssetError::RowIdMismatch {
                carrier: id,
                donor: parsed_id,
            });
        }
        Ok(Some(IndexedRow {
            index,
            id,
            node,
            source,
        }))
    }

    /// Heap bytes retained by the compact index itself, excluding the shared
    /// immutable file mapping/cache that owns the actual Pak entry.
    pub fn retained_index_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
            .saturating_add(
                self.row_ids
                    .capacity()
                    .saturating_mul(std::mem::size_of::<RowId>()),
            )
            .saturating_add(
                self.row_ranges
                    .capacity()
                    .saturating_mul(std::mem::size_of::<Range<usize>>()),
            )
            .saturating_add(self.row_lookup.retained_bytes())
    }

    #[cfg(test)]
    fn backing_ptr(&self) -> *const u8 {
        self.backing.as_bytes().as_ptr()
    }
}

/// Validates a complete BinaryAsset directly from a borrowed slice without
/// copying its payload or retaining a provider-wide MessagePack tree. This is
/// used by compatibility checks that need only the envelope/package tag.
pub fn validate_binary_asset_structure_with_cancel(
    bytes: &[u8],
    cancellation: &CancellationToken,
) -> Result<[u8; PACKAGE_TAG_SIZE]> {
    if cancellation.is_cancelled() {
        return Err(BinaryAssetError::Cancelled);
    }
    let minimum = PREFIX_SIZE + BINARY_ASSET_FOOTER_SIZE + PACKAGE_TAG_SIZE;
    if bytes.len() < minimum {
        return Err(BinaryAssetError::TooShort {
            actual: bytes.len(),
            minimum,
        });
    }
    let payload_length_u32 = u32::from_le_bytes(bytes[6..10].try_into().expect("fixed range"));
    let payload_length = usize::try_from(payload_length_u32)
        .map_err(|_| BinaryAssetError::PayloadLengthOverflow(payload_length_u32))?;
    enforce_budget_limit(
        "payload bytes",
        payload_length,
        MAX_BINARY_ASSET_PAYLOAD_BYTES,
    )?;
    let payload_end = PREFIX_SIZE
        .checked_add(payload_length)
        .ok_or(BinaryAssetError::LengthOverflow)?;
    let expected_end = bytes.len() - BINARY_ASSET_FOOTER_SIZE - PACKAGE_TAG_SIZE;
    if payload_end != expected_end {
        return Err(BinaryAssetError::PayloadLengthMismatch {
            header_end: payload_end,
            expected_end,
        });
    }
    index_messagepack_database(&bytes[PREFIX_SIZE..payload_end], Some(cancellation), None)?;
    Ok(bytes[bytes.len() - PACKAGE_TAG_SIZE..]
        .try_into()
        .expect("fixed range"))
}

fn validate_and_index_rows(
    root: &MsgpackNode,
    cancellation: Option<&CancellationToken>,
) -> Result<(Vec<RowId>, HashMap<RowId, usize>)> {
    let data_list = root
        .map_get("m_DataList")?
        .ok_or_else(|| BinaryAssetError::MissingField("m_DataList".to_owned()))?;
    let items = data_list
        .as_array()
        .ok_or(BinaryAssetError::ExpectedArray("m_DataList"))?;

    let mut row_ids = Vec::new();
    row_ids.try_reserve_exact(items.len()).map_err(|_| {
        BinaryAssetError::MessagePackAllocationFailed {
            resource: "row IDs",
            requested: items.len(),
        }
    })?;
    let mut row_indices = HashMap::new();
    row_indices.try_reserve(items.len()).map_err(|_| {
        BinaryAssetError::MessagePackAllocationFailed {
            resource: "row index entries",
            requested: items.len(),
        }
    })?;

    for (index, node) in items.iter().enumerate() {
        if index % 4096 == 0 && cancellation.is_some_and(CancellationToken::is_cancelled) {
            return Err(BinaryAssetError::Cancelled);
        }
        node.map_fields()?;
        let id = logical_row_id(node)?;
        if row_indices.insert(id, index).is_some() {
            return Err(BinaryAssetError::DuplicateRowId(id));
        }
        row_ids.push(id);
    }
    Ok((row_ids, row_indices))
}

#[derive(Debug, Clone, Copy)]
struct ParseLimits {
    payload_bytes: usize,
    nodes: usize,
    container_items: usize,
    owned_bytes: usize,
    depth: usize,
}

fn default_parse_limits() -> ParseLimits {
    ParseLimits {
        // Parsed trees are processed one database group at a time and are no
        // longer retained in a process-wide semantic cache. Keep only absolute
        // format/hostile-input guards here; do not reject a valid table based
        // on a snapshot of currently available RAM.
        payload_bytes: MAX_BINARY_ASSET_PAYLOAD_BYTES,
        nodes: MAX_MESSAGEPACK_NODES,
        container_items: MAX_MESSAGEPACK_CONTAINER_ITEMS,
        owned_bytes: MAX_MESSAGEPACK_OWNED_BYTES,
        depth: MAX_MESSAGEPACK_DEPTH,
    }
}

fn indexed_scan_limits(payload_bytes: usize) -> ParseLimits {
    // Unlike the full parser, the index scanner does not allocate one object
    // per visited node and does not copy string/binary bodies. Every charged
    // node, container item, and body byte must still consume source bytes.
    let structural_items = payload_bytes.max(1);
    ParseLimits {
        payload_bytes: MAX_BINARY_ASSET_PAYLOAD_BYTES,
        nodes: structural_items,
        container_items: structural_items,
        owned_bytes: payload_bytes,
        depth: MAX_MESSAGEPACK_DEPTH,
    }
}

#[derive(Debug)]
struct ParseBudget<'a> {
    limits: ParseLimits,
    nodes: usize,
    container_items: usize,
    owned_bytes: usize,
    cancellation: Option<&'a CancellationToken>,
}

struct DatabaseMessagepackIndex {
    data_list_range: Range<usize>,
    data_list_marker: u8,
    row_ids: Vec<RowId>,
    row_lookup: CompactRowLookup,
    row_ranges: Vec<Range<usize>>,
}

impl<'a> ParseBudget<'a> {
    fn new(limits: ParseLimits, cancellation: Option<&'a CancellationToken>) -> Self {
        Self {
            limits,
            nodes: 0,
            container_items: 0,
            owned_bytes: 0,
            cancellation,
        }
    }

    fn charge_node(&mut self) -> Result<()> {
        if self.nodes.is_multiple_of(4096)
            && self
                .cancellation
                .is_some_and(CancellationToken::is_cancelled)
        {
            return Err(BinaryAssetError::Cancelled);
        }
        charge_budget(&mut self.nodes, 1, self.limits.nodes, "nodes")
    }

    fn charge_container_items(&mut self, count: usize) -> Result<()> {
        charge_budget(
            &mut self.container_items,
            count,
            self.limits.container_items,
            "container items",
        )
    }

    fn charge_owned_bytes(&mut self, count: usize) -> Result<()> {
        charge_budget(
            &mut self.owned_bytes,
            count,
            self.limits.owned_bytes,
            "owned string/binary/extension bytes",
        )
    }
}

fn enforce_budget_limit(resource: &'static str, requested: usize, limit: usize) -> Result<()> {
    if requested > limit {
        return Err(BinaryAssetError::MessagePackBudgetExceeded {
            resource,
            requested,
            limit,
        });
    }
    Ok(())
}

fn charge_budget(
    used: &mut usize,
    amount: usize,
    limit: usize,
    resource: &'static str,
) -> Result<()> {
    let requested =
        used.checked_add(amount)
            .ok_or(BinaryAssetError::MessagePackBudgetExceeded {
                resource,
                requested: usize::MAX,
                limit,
            })?;
    enforce_budget_limit(resource, requested, limit)?;
    *used = requested;
    Ok(())
}

/// Builds the persistent database index without retaining a provider-wide
/// MessagePack tree. The scanner validates the complete payload, while each
/// `m_DataList` row is materialized only long enough to validate its map and
/// logical ID.
fn index_messagepack_database(
    bytes: &[u8],
    cancellation: Option<&CancellationToken>,
    mut progress: Option<&mut dyn FnMut(usize, usize)>,
) -> Result<DatabaseMessagepackIndex> {
    // Use format-derived structural bounds rather than the smaller full-AST
    // budgets so a valid multi-gigabyte database can remain disk-backed.
    let limits = indexed_scan_limits(bytes.len());
    enforce_budget_limit("payload bytes", bytes.len(), limits.payload_bytes)?;
    let mut budget = ParseBudget::new(limits, cancellation);
    if limits.depth == 0 {
        return Err(BinaryAssetError::MessagePackDepthLimit { limit: 0 });
    }
    budget.charge_node()?;
    let (_, mut offset, entry_count) = scan_map_header(bytes, 0)?;
    if let Some(report) = progress.as_deref_mut() {
        report(offset, bytes.len());
    }
    budget.charge_container_items(entry_count)?;
    let mut found: Option<DatabaseMessagepackIndex> = None;

    for _ in 0..entry_count {
        let key_start = offset;
        let key_end = scan_node_end(bytes, key_start, 1, &mut budget)?;
        let key = scanned_string_value(bytes, key_start, key_end)?;
        offset = key_end;
        if key == Some("m_DataList") {
            if found.is_some() {
                return Err(BinaryAssetError::DuplicateField("m_DataList".to_owned()));
            }
            let list_start = offset;
            budget.charge_node()?;
            let (marker, rows_start, row_count) = scan_array_header(bytes, list_start)?;
            budget.charge_container_items(row_count)?;
            let available = bytes.len().saturating_sub(rows_start);
            if row_count > available {
                return Err(BinaryAssetError::UnexpectedEof {
                    offset: rows_start,
                    needed: row_count,
                    available,
                });
            }

            let mut row_ids = Vec::new();
            row_ids.try_reserve_exact(row_count).map_err(|_| {
                BinaryAssetError::MessagePackAllocationFailed {
                    resource: "row IDs",
                    requested: row_count,
                }
            })?;
            // Delay allocating a hash table until the first out-of-order ID.
            // Strictly increasing IDs can use `row_ids.binary_search()` later.
            let mut unordered_indices: Option<HashMap<RowId, usize>> = None;
            let mut row_ranges = Vec::new();
            row_ranges.try_reserve_exact(row_count).map_err(|_| {
                BinaryAssetError::MessagePackAllocationFailed {
                    resource: "row byte ranges",
                    requested: row_count,
                }
            })?;

            offset = rows_start;
            for index in 0..row_count {
                if index % 4096 == 0 && cancellation.is_some_and(CancellationToken::is_cancelled) {
                    return Err(BinaryAssetError::Cancelled);
                }
                let row_start = offset;
                let (row_end, id) = scan_database_row_id(bytes, row_start, 2, &mut budget)?;
                offset = row_end;
                if let Some(indices) = unordered_indices.as_mut() {
                    if indices.insert(id, index).is_some() {
                        return Err(BinaryAssetError::DuplicateRowId(id));
                    }
                } else if let Some(previous) = row_ids.last().copied()
                    && id <= previous
                {
                    if id == previous {
                        return Err(BinaryAssetError::DuplicateRowId(id));
                    }
                    let mut indices = HashMap::new();
                    indices.try_reserve(row_count).map_err(|_| {
                        BinaryAssetError::MessagePackAllocationFailed {
                            resource: "row index entries",
                            requested: row_count,
                        }
                    })?;
                    for (previous_index, previous_id) in row_ids.iter().copied().enumerate() {
                        let replaced = indices.insert(previous_id, previous_index);
                        debug_assert!(replaced.is_none());
                    }
                    if indices.insert(id, index).is_some() {
                        return Err(BinaryAssetError::DuplicateRowId(id));
                    }
                    unordered_indices = Some(indices);
                }
                row_ids.push(id);
                row_ranges.push(row_start..offset);
                if let Some(report) = progress.as_deref_mut()
                    && (index.is_multiple_of(4096)
                        || offset == bytes.len()
                        || offset.saturating_sub(row_start) >= 64 * 1024 * 1024)
                {
                    report(offset, bytes.len());
                }
            }
            found = Some(DatabaseMessagepackIndex {
                data_list_range: list_start..offset,
                data_list_marker: marker,
                row_ids,
                row_lookup: unordered_indices
                    .map_or(CompactRowLookup::Sorted, CompactRowLookup::Unordered),
                row_ranges,
            });
        } else {
            offset = scan_node_end(bytes, offset, 1, &mut budget)?;
        }
        if let Some(report) = progress.as_deref_mut() {
            report(offset, bytes.len());
        }
    }
    if offset != bytes.len() {
        return Err(BinaryAssetError::MessagePackTrailingData {
            parsed: offset,
            expected: bytes.len(),
        });
    }
    if let Some(report) = progress {
        report(bytes.len(), bytes.len());
    }
    found.ok_or_else(|| BinaryAssetError::MissingField("m_DataList".to_owned()))
}

/// Validates one complete database row while materializing only its scalar
/// `m_id`. The compact index does not need a temporary AST for every field;
/// full rows are parsed later only when comparison or output selection asks
/// for them.
fn scan_database_row_id(
    bytes: &[u8],
    start: usize,
    depth: usize,
    budget: &mut ParseBudget<'_>,
) -> Result<(usize, RowId)> {
    if depth > budget.limits.depth {
        return Err(BinaryAssetError::MessagePackDepthLimit {
            limit: budget.limits.depth,
        });
    }
    budget.charge_node()?;
    let (_, mut offset, field_count) =
        scan_map_header(bytes, start).map_err(|error| match error {
            BinaryAssetError::ExpectedMap(_) => BinaryAssetError::ExpectedMap("database row"),
            other => other,
        })?;
    budget.charge_container_items(field_count)?;
    let mut names = HashSet::new();
    names
        .try_reserve(field_count)
        .map_err(|_| BinaryAssetError::MessagePackAllocationFailed {
            resource: "map-field names",
            requested: field_count,
        })?;
    let child_depth = depth
        .checked_add(1)
        .ok_or(BinaryAssetError::LengthOverflow)?;
    let mut row_id = None;
    for _ in 0..field_count {
        let key_start = offset;
        let key_end = scan_node_end(bytes, key_start, child_depth, budget)?;
        let name = scanned_string_value(bytes, key_start, key_end)?
            .ok_or(BinaryAssetError::NonStringMapKey)?;
        if !names.insert(name) {
            return Err(BinaryAssetError::DuplicateField(name.to_owned()));
        }
        let value_start = key_end;
        let value_end = scan_node_end(bytes, value_start, child_depth, budget)?;
        if name == "m_id" {
            let value = parse_messagepack_with_limits_and_cancel(
                &bytes[value_start..value_end],
                default_parse_limits(),
                budget.cancellation,
            )?;
            row_id = Some(logical_row_id_value(&value)?);
        }
        offset = value_end;
    }
    Ok((offset, row_id.ok_or(BinaryAssetError::MissingRowId)?))
}

fn scan_node_end(
    bytes: &[u8],
    start: usize,
    depth: usize,
    budget: &mut ParseBudget<'_>,
) -> Result<usize> {
    if depth > budget.limits.depth {
        return Err(BinaryAssetError::MessagePackDepthLimit {
            limit: budget.limits.depth,
        });
    }
    budget.charge_node()?;
    need(bytes, start, 1)?;
    let marker = bytes[start];
    let offset = checked_add_offset(start, 1)?;
    if marker <= 0x7f || marker >= 0xe0 {
        return Ok(offset);
    }
    if marker & 0xe0 == 0xa0 {
        return scan_string_body(bytes, offset, usize::from(marker & 0x1f), budget);
    }
    if marker & 0xf0 == 0x90 {
        return scan_array_items(bytes, offset, usize::from(marker & 0x0f), depth, budget);
    }
    if marker & 0xf0 == 0x80 {
        return scan_map_entries(bytes, offset, usize::from(marker & 0x0f), depth, budget);
    }
    match marker {
        0xc0 | 0xc2 | 0xc3 => Ok(offset),
        0xc4 => {
            need(bytes, offset, 1)?;
            scan_binary_body(
                bytes,
                checked_add_offset(offset, 1)?,
                usize::from(bytes[offset]),
                budget,
            )
        }
        0xc5 => scan_binary_body(
            bytes,
            checked_add_offset(offset, 2)?,
            usize::from(read_u16(bytes, offset)?),
            budget,
        ),
        0xc6 => scan_binary_body(
            bytes,
            checked_add_offset(offset, 4)?,
            usize_from_u32(read_u32(bytes, offset)?)?,
            budget,
        ),
        0xc7 => {
            need(bytes, offset, 1)?;
            scan_extension_body(
                bytes,
                checked_add_offset(offset, 1)?,
                usize::from(bytes[offset]),
                budget,
            )
        }
        0xc8 => scan_extension_body(
            bytes,
            checked_add_offset(offset, 2)?,
            usize::from(read_u16(bytes, offset)?),
            budget,
        ),
        0xc9 => scan_extension_body(
            bytes,
            checked_add_offset(offset, 4)?,
            usize_from_u32(read_u32(bytes, offset)?)?,
            budget,
        ),
        0xca => scan_fixed_body(bytes, offset, 4),
        0xcb => scan_fixed_body(bytes, offset, 8),
        0xcc | 0xd0 => scan_fixed_body(bytes, offset, 1),
        0xcd | 0xd1 => scan_fixed_body(bytes, offset, 2),
        0xce | 0xd2 => scan_fixed_body(bytes, offset, 4),
        0xcf | 0xd3 => scan_fixed_body(bytes, offset, 8),
        0xd4 => scan_extension_body(bytes, offset, 1, budget),
        0xd5 => scan_extension_body(bytes, offset, 2, budget),
        0xd6 => scan_extension_body(bytes, offset, 4, budget),
        0xd7 => scan_extension_body(bytes, offset, 8, budget),
        0xd8 => scan_extension_body(bytes, offset, 16, budget),
        0xd9 => {
            need(bytes, offset, 1)?;
            scan_string_body(
                bytes,
                checked_add_offset(offset, 1)?,
                usize::from(bytes[offset]),
                budget,
            )
        }
        0xda => scan_string_body(
            bytes,
            checked_add_offset(offset, 2)?,
            usize::from(read_u16(bytes, offset)?),
            budget,
        ),
        0xdb => scan_string_body(
            bytes,
            checked_add_offset(offset, 4)?,
            usize_from_u32(read_u32(bytes, offset)?)?,
            budget,
        ),
        0xdc => scan_array_items(
            bytes,
            checked_add_offset(offset, 2)?,
            usize::from(read_u16(bytes, offset)?),
            depth,
            budget,
        ),
        0xdd => scan_array_items(
            bytes,
            checked_add_offset(offset, 4)?,
            usize_from_u32(read_u32(bytes, offset)?)?,
            depth,
            budget,
        ),
        0xde => scan_map_entries(
            bytes,
            checked_add_offset(offset, 2)?,
            usize::from(read_u16(bytes, offset)?),
            depth,
            budget,
        ),
        0xdf => scan_map_entries(
            bytes,
            checked_add_offset(offset, 4)?,
            usize_from_u32(read_u32(bytes, offset)?)?,
            depth,
            budget,
        ),
        _ => Err(BinaryAssetError::UnsupportedMarker {
            marker,
            offset: start,
        }),
    }
}

fn scan_fixed_body(bytes: &[u8], body: usize, len: usize) -> Result<usize> {
    need(bytes, body, len)?;
    checked_add_offset(body, len)
}

fn scan_string_body(
    bytes: &[u8],
    body: usize,
    len: usize,
    budget: &mut ParseBudget<'_>,
) -> Result<usize> {
    let end = scan_fixed_body(bytes, body, len)?;
    std::str::from_utf8(&bytes[body..end])
        .map_err(|_| BinaryAssetError::InvalidUtf8 { offset: body })?;
    budget.charge_owned_bytes(len)?;
    Ok(end)
}

fn scan_binary_body(
    bytes: &[u8],
    body: usize,
    len: usize,
    budget: &mut ParseBudget<'_>,
) -> Result<usize> {
    let end = scan_fixed_body(bytes, body, len)?;
    budget.charge_owned_bytes(len)?;
    Ok(end)
}

fn scan_extension_body(
    bytes: &[u8],
    type_offset: usize,
    len: usize,
    budget: &mut ParseBudget<'_>,
) -> Result<usize> {
    need(bytes, type_offset, 1)?;
    scan_binary_body(bytes, checked_add_offset(type_offset, 1)?, len, budget)
}

fn scan_array_items(
    bytes: &[u8],
    items_start: usize,
    len: usize,
    depth: usize,
    budget: &mut ParseBudget<'_>,
) -> Result<usize> {
    budget.charge_container_items(len)?;
    let available = bytes.len().saturating_sub(items_start);
    if len > available {
        return Err(BinaryAssetError::UnexpectedEof {
            offset: items_start,
            needed: len,
            available,
        });
    }
    let child_depth = depth
        .checked_add(1)
        .ok_or(BinaryAssetError::LengthOverflow)?;
    let mut offset = items_start;
    for _ in 0..len {
        offset = scan_node_end(bytes, offset, child_depth, budget)?;
    }
    Ok(offset)
}

fn scan_map_entries(
    bytes: &[u8],
    entries_start: usize,
    len: usize,
    depth: usize,
    budget: &mut ParseBudget<'_>,
) -> Result<usize> {
    budget.charge_container_items(len)?;
    let available = bytes.len().saturating_sub(entries_start);
    let minimum = len.checked_mul(2).ok_or(BinaryAssetError::LengthOverflow)?;
    if minimum > available {
        return Err(BinaryAssetError::UnexpectedEof {
            offset: entries_start,
            needed: minimum,
            available,
        });
    }
    let child_depth = depth
        .checked_add(1)
        .ok_or(BinaryAssetError::LengthOverflow)?;
    let mut offset = entries_start;
    for _ in 0..len {
        offset = scan_node_end(bytes, offset, child_depth, budget)?;
        offset = scan_node_end(bytes, offset, child_depth, budget)?;
    }
    Ok(offset)
}

fn scan_map_header(bytes: &[u8], start: usize) -> Result<(u8, usize, usize)> {
    need(bytes, start, 1)?;
    let marker = bytes[start];
    let offset = checked_add_offset(start, 1)?;
    if marker & 0xf0 == 0x80 {
        return Ok((marker, offset, usize::from(marker & 0x0f)));
    }
    match marker {
        0xde => Ok((
            marker,
            checked_add_offset(offset, 2)?,
            usize::from(read_u16(bytes, offset)?),
        )),
        0xdf => Ok((
            marker,
            checked_add_offset(offset, 4)?,
            usize_from_u32(read_u32(bytes, offset)?)?,
        )),
        _ => Err(BinaryAssetError::ExpectedMap("MessagePack root")),
    }
}

fn scan_array_header(bytes: &[u8], start: usize) -> Result<(u8, usize, usize)> {
    need(bytes, start, 1)?;
    let marker = bytes[start];
    let offset = checked_add_offset(start, 1)?;
    if marker & 0xf0 == 0x90 {
        return Ok((marker, offset, usize::from(marker & 0x0f)));
    }
    match marker {
        0xdc => Ok((
            marker,
            checked_add_offset(offset, 2)?,
            usize::from(read_u16(bytes, offset)?),
        )),
        0xdd => Ok((
            marker,
            checked_add_offset(offset, 4)?,
            usize_from_u32(read_u32(bytes, offset)?)?,
        )),
        _ => Err(BinaryAssetError::ExpectedArray("m_DataList")),
    }
}

fn scanned_string_value(bytes: &[u8], start: usize, end: usize) -> Result<Option<&str>> {
    let marker = bytes[start];
    let offset = checked_add_offset(start, 1)?;
    let (body, len) = if marker & 0xe0 == 0xa0 {
        (offset, usize::from(marker & 0x1f))
    } else {
        match marker {
            0xd9 => {
                need(bytes, offset, 1)?;
                (checked_add_offset(offset, 1)?, usize::from(bytes[offset]))
            }
            0xda => (
                checked_add_offset(offset, 2)?,
                usize::from(read_u16(bytes, offset)?),
            ),
            0xdb => (
                checked_add_offset(offset, 4)?,
                usize_from_u32(read_u32(bytes, offset)?)?,
            ),
            _ => return Ok(None),
        }
    };
    let string_end = checked_add_offset(body, len)?;
    if string_end != end {
        return Err(BinaryAssetError::MessagePackTrailingData {
            parsed: string_end,
            expected: end,
        });
    }
    std::str::from_utf8(&bytes[body..end])
        .map(Some)
        .map_err(|_| BinaryAssetError::InvalidUtf8 { offset: body })
}

/// Parses exactly one MessagePack node. Trailing bytes are rejected.
pub fn parse_messagepack(bytes: &[u8]) -> Result<MsgpackNode> {
    parse_messagepack_with_limits(bytes, default_parse_limits())
}

fn parse_messagepack_with_limits(bytes: &[u8], limits: ParseLimits) -> Result<MsgpackNode> {
    parse_messagepack_with_limits_and_cancel(bytes, limits, None)
}

fn parse_messagepack_with_limits_and_cancel(
    bytes: &[u8],
    limits: ParseLimits,
    cancellation: Option<&CancellationToken>,
) -> Result<MsgpackNode> {
    enforce_budget_limit("payload bytes", bytes.len(), limits.payload_bytes)?;
    let mut budget = ParseBudget::new(limits, cancellation);
    let (node, end) = parse_node(bytes, 0, 0, &mut budget)?;
    if end != bytes.len() {
        return Err(BinaryAssetError::MessagePackTrailingData {
            parsed: end,
            expected: bytes.len(),
        });
    }
    Ok(node)
}

fn parse_node(
    bytes: &[u8],
    start: usize,
    depth: usize,
    budget: &mut ParseBudget<'_>,
) -> Result<(MsgpackNode, usize)> {
    if depth > budget.limits.depth {
        return Err(BinaryAssetError::MessagePackDepthLimit {
            limit: budget.limits.depth,
        });
    }
    budget.charge_node()?;
    need(bytes, start, 1)?;
    let marker = bytes[start];
    let offset = checked_add_offset(start, 1)?;

    if marker <= 0x7f {
        return Ok((
            scalar_node(
                marker,
                start,
                offset,
                MsgpackKind::Integer(IntegerValue::Unsigned(u64::from(marker))),
            ),
            offset,
        ));
    }
    if marker >= 0xe0 {
        return Ok((
            scalar_node(
                marker,
                start,
                offset,
                MsgpackKind::Integer(IntegerValue::Signed(i64::from(marker as i8))),
            ),
            offset,
        ));
    }
    if marker & 0xe0 == 0xa0 {
        return parse_string(
            bytes,
            start,
            marker,
            offset,
            usize::from(marker & 0x1f),
            budget,
        );
    }
    if marker & 0xf0 == 0x90 {
        return parse_array(
            bytes,
            start,
            marker,
            offset,
            usize::from(marker & 0x0f),
            depth,
            budget,
        );
    }
    if marker & 0xf0 == 0x80 {
        return parse_map(
            bytes,
            start,
            marker,
            offset,
            usize::from(marker & 0x0f),
            depth,
            budget,
        );
    }

    match marker {
        0xc0 => Ok((scalar_node(marker, start, offset, MsgpackKind::Nil), offset)),
        0xc2 | 0xc3 => Ok((
            scalar_node(marker, start, offset, MsgpackKind::Boolean(marker == 0xc3)),
            offset,
        )),
        0xc4 => {
            need(bytes, offset, 1)?;
            parse_binary(
                bytes,
                start,
                marker,
                checked_add_offset(offset, 1)?,
                usize::from(bytes[offset]),
                budget,
            )
        }
        0xc5 => {
            let len = usize::from(read_u16(bytes, offset)?);
            parse_binary(
                bytes,
                start,
                marker,
                checked_add_offset(offset, 2)?,
                len,
                budget,
            )
        }
        0xc6 => {
            let len = usize_from_u32(read_u32(bytes, offset)?)?;
            parse_binary(
                bytes,
                start,
                marker,
                checked_add_offset(offset, 4)?,
                len,
                budget,
            )
        }
        0xc7 => {
            need(bytes, offset, 1)?;
            parse_extension(
                bytes,
                start,
                marker,
                checked_add_offset(offset, 1)?,
                usize::from(bytes[offset]),
                budget,
            )
        }
        0xc8 => {
            let len = usize::from(read_u16(bytes, offset)?);
            parse_extension(
                bytes,
                start,
                marker,
                checked_add_offset(offset, 2)?,
                len,
                budget,
            )
        }
        0xc9 => {
            let len = usize_from_u32(read_u32(bytes, offset)?)?;
            parse_extension(
                bytes,
                start,
                marker,
                checked_add_offset(offset, 4)?,
                len,
                budget,
            )
        }
        0xca => {
            let bits = read_u32(bytes, offset)?;
            let end = checked_add_offset(offset, 4)?;
            Ok((
                scalar_node(
                    marker,
                    start,
                    end,
                    MsgpackKind::Float(f32::from_bits(bits) as f64),
                ),
                end,
            ))
        }
        0xcb => {
            let bits = read_u64(bytes, offset)?;
            let end = checked_add_offset(offset, 8)?;
            Ok((
                scalar_node(marker, start, end, MsgpackKind::Float(f64::from_bits(bits))),
                end,
            ))
        }
        0xcc => integer_unsigned(bytes, start, marker, offset, 1),
        0xcd => integer_unsigned(bytes, start, marker, offset, 2),
        0xce => integer_unsigned(bytes, start, marker, offset, 4),
        0xcf => integer_unsigned(bytes, start, marker, offset, 8),
        0xd0 => integer_signed(bytes, start, marker, offset, 1),
        0xd1 => integer_signed(bytes, start, marker, offset, 2),
        0xd2 => integer_signed(bytes, start, marker, offset, 4),
        0xd3 => integer_signed(bytes, start, marker, offset, 8),
        0xd4 => parse_extension(bytes, start, marker, offset, 1, budget),
        0xd5 => parse_extension(bytes, start, marker, offset, 2, budget),
        0xd6 => parse_extension(bytes, start, marker, offset, 4, budget),
        0xd7 => parse_extension(bytes, start, marker, offset, 8, budget),
        0xd8 => parse_extension(bytes, start, marker, offset, 16, budget),
        0xd9 => {
            need(bytes, offset, 1)?;
            parse_string(
                bytes,
                start,
                marker,
                checked_add_offset(offset, 1)?,
                usize::from(bytes[offset]),
                budget,
            )
        }
        0xda => {
            let len = usize::from(read_u16(bytes, offset)?);
            parse_string(
                bytes,
                start,
                marker,
                checked_add_offset(offset, 2)?,
                len,
                budget,
            )
        }
        0xdb => {
            let len = usize_from_u32(read_u32(bytes, offset)?)?;
            parse_string(
                bytes,
                start,
                marker,
                checked_add_offset(offset, 4)?,
                len,
                budget,
            )
        }
        0xdc => {
            let len = usize::from(read_u16(bytes, offset)?);
            parse_array(
                bytes,
                start,
                marker,
                checked_add_offset(offset, 2)?,
                len,
                depth,
                budget,
            )
        }
        0xdd => {
            let len = usize_from_u32(read_u32(bytes, offset)?)?;
            parse_array(
                bytes,
                start,
                marker,
                checked_add_offset(offset, 4)?,
                len,
                depth,
                budget,
            )
        }
        0xde => {
            let len = usize::from(read_u16(bytes, offset)?);
            parse_map(
                bytes,
                start,
                marker,
                checked_add_offset(offset, 2)?,
                len,
                depth,
                budget,
            )
        }
        0xdf => {
            let len = usize_from_u32(read_u32(bytes, offset)?)?;
            parse_map(
                bytes,
                start,
                marker,
                checked_add_offset(offset, 4)?,
                len,
                depth,
                budget,
            )
        }
        _ => Err(BinaryAssetError::UnsupportedMarker {
            marker,
            offset: start,
        }),
    }
}

fn scalar_node(marker: u8, start: usize, end: usize, kind: MsgpackKind) -> MsgpackNode {
    MsgpackNode {
        marker,
        range: start..end,
        // `parse_node` proves one byte is available at `start`, so this cannot
        // wrap even on a maximally sized address space.
        header_end: start + 1,
        kind,
    }
}

fn parse_string(
    bytes: &[u8],
    start: usize,
    marker: u8,
    body: usize,
    len: usize,
    budget: &mut ParseBudget<'_>,
) -> Result<(MsgpackNode, usize)> {
    need(bytes, body, len)?;
    let end = body
        .checked_add(len)
        .ok_or(BinaryAssetError::LengthOverflow)?;
    let decoded = std::str::from_utf8(&bytes[body..end])
        .map_err(|_| BinaryAssetError::InvalidUtf8 { offset: body })?;
    budget.charge_owned_bytes(len)?;
    let mut value = String::new();
    value
        .try_reserve_exact(len)
        .map_err(|_| BinaryAssetError::MessagePackAllocationFailed {
            resource: "string bytes",
            requested: len,
        })?;
    value.push_str(decoded);
    Ok((
        MsgpackNode {
            marker,
            range: start..end,
            header_end: body,
            kind: MsgpackKind::String(value),
        },
        end,
    ))
}

fn parse_binary(
    bytes: &[u8],
    start: usize,
    marker: u8,
    body: usize,
    len: usize,
    budget: &mut ParseBudget<'_>,
) -> Result<(MsgpackNode, usize)> {
    need(bytes, body, len)?;
    let end = body
        .checked_add(len)
        .ok_or(BinaryAssetError::LengthOverflow)?;
    budget.charge_owned_bytes(len)?;
    let mut value = Vec::new();
    value
        .try_reserve_exact(len)
        .map_err(|_| BinaryAssetError::MessagePackAllocationFailed {
            resource: "binary bytes",
            requested: len,
        })?;
    value.extend_from_slice(&bytes[body..end]);
    Ok((
        MsgpackNode {
            marker,
            range: start..end,
            header_end: body,
            kind: MsgpackKind::Binary(value),
        },
        end,
    ))
}

fn parse_extension(
    bytes: &[u8],
    start: usize,
    marker: u8,
    type_offset: usize,
    len: usize,
    budget: &mut ParseBudget<'_>,
) -> Result<(MsgpackNode, usize)> {
    need(bytes, type_offset, 1)?;
    let body = checked_add_offset(type_offset, 1)?;
    need(bytes, body, len)?;
    let end = body
        .checked_add(len)
        .ok_or(BinaryAssetError::LengthOverflow)?;
    budget.charge_owned_bytes(len)?;
    let mut data = Vec::new();
    data.try_reserve_exact(len)
        .map_err(|_| BinaryAssetError::MessagePackAllocationFailed {
            resource: "extension bytes",
            requested: len,
        })?;
    data.extend_from_slice(&bytes[body..end]);
    Ok((
        MsgpackNode {
            marker,
            range: start..end,
            header_end: body,
            kind: MsgpackKind::Extension {
                type_tag: bytes[type_offset] as i8,
                data,
            },
        },
        end,
    ))
}

fn parse_array(
    bytes: &[u8],
    start: usize,
    marker: u8,
    items_start: usize,
    len: usize,
    depth: usize,
    budget: &mut ParseBudget<'_>,
) -> Result<(MsgpackNode, usize)> {
    budget.charge_container_items(len)?;
    let available = bytes.len().saturating_sub(items_start);
    if len > available {
        return Err(BinaryAssetError::UnexpectedEof {
            offset: items_start,
            needed: len,
            available,
        });
    }
    let mut items = Vec::new();
    items
        .try_reserve_exact(len)
        .map_err(|_| BinaryAssetError::MessagePackAllocationFailed {
            resource: "array items",
            requested: len,
        })?;
    let mut offset = items_start;
    let child_depth = depth
        .checked_add(1)
        .ok_or(BinaryAssetError::LengthOverflow)?;
    for _ in 0..len {
        let (item, end) = parse_node(bytes, offset, child_depth, budget)?;
        items.push(item);
        offset = end;
    }
    Ok((
        MsgpackNode {
            marker,
            range: start..offset,
            header_end: items_start,
            kind: MsgpackKind::Array(items),
        },
        offset,
    ))
}

fn parse_map(
    bytes: &[u8],
    start: usize,
    marker: u8,
    entries_start: usize,
    len: usize,
    depth: usize,
    budget: &mut ParseBudget<'_>,
) -> Result<(MsgpackNode, usize)> {
    budget.charge_container_items(len)?;
    let available = bytes.len().saturating_sub(entries_start);
    let minimum = len.checked_mul(2).ok_or(BinaryAssetError::LengthOverflow)?;
    if minimum > available {
        return Err(BinaryAssetError::UnexpectedEof {
            offset: entries_start,
            needed: minimum,
            available,
        });
    }
    let mut entries = Vec::new();
    entries
        .try_reserve_exact(len)
        .map_err(|_| BinaryAssetError::MessagePackAllocationFailed {
            resource: "map entries",
            requested: len,
        })?;
    let mut offset = entries_start;
    let child_depth = depth
        .checked_add(1)
        .ok_or(BinaryAssetError::LengthOverflow)?;
    for _ in 0..len {
        let (key, key_end) = parse_node(bytes, offset, child_depth, budget)?;
        let (value, value_end) = parse_node(bytes, key_end, child_depth, budget)?;
        entries.push(MapEntry { key, value });
        offset = value_end;
    }
    Ok((
        MsgpackNode {
            marker,
            range: start..offset,
            header_end: entries_start,
            kind: MsgpackKind::Map(entries),
        },
        offset,
    ))
}

fn integer_unsigned(
    bytes: &[u8],
    start: usize,
    marker: u8,
    body: usize,
    width: usize,
) -> Result<(MsgpackNode, usize)> {
    need(bytes, body, width)?;
    let end = checked_add_offset(body, width)?;
    let value = match width {
        1 => u64::from(bytes[body]),
        2 => u64::from(u16::from_be_bytes(bytes[body..end].try_into().unwrap())),
        4 => u64::from(u32::from_be_bytes(bytes[body..end].try_into().unwrap())),
        8 => u64::from_be_bytes(bytes[body..end].try_into().unwrap()),
        _ => unreachable!("fixed MessagePack integer width"),
    };
    Ok((
        scalar_node(
            marker,
            start,
            end,
            MsgpackKind::Integer(IntegerValue::Unsigned(value)),
        ),
        end,
    ))
}

fn integer_signed(
    bytes: &[u8],
    start: usize,
    marker: u8,
    body: usize,
    width: usize,
) -> Result<(MsgpackNode, usize)> {
    need(bytes, body, width)?;
    let end = checked_add_offset(body, width)?;
    let value = match width {
        1 => i64::from(bytes[body] as i8),
        2 => i64::from(i16::from_be_bytes(bytes[body..end].try_into().unwrap())),
        4 => i64::from(i32::from_be_bytes(bytes[body..end].try_into().unwrap())),
        8 => i64::from_be_bytes(bytes[body..end].try_into().unwrap()),
        _ => unreachable!("fixed MessagePack integer width"),
    };
    Ok((
        scalar_node(
            marker,
            start,
            end,
            MsgpackKind::Integer(IntegerValue::Signed(value)),
        ),
        end,
    ))
}

fn need(bytes: &[u8], offset: usize, len: usize) -> Result<()> {
    let available = bytes.len().saturating_sub(offset);
    let end = offset
        .checked_add(len)
        .ok_or(BinaryAssetError::LengthOverflow)?;
    if offset > bytes.len() || end > bytes.len() {
        return Err(BinaryAssetError::UnexpectedEof {
            offset,
            needed: len,
            available,
        });
    }
    Ok(())
}

fn checked_add_offset(offset: usize, amount: usize) -> Result<usize> {
    offset
        .checked_add(amount)
        .ok_or(BinaryAssetError::LengthOverflow)
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16> {
    need(bytes, offset, 2)?;
    let end = checked_add_offset(offset, 2)?;
    Ok(u16::from_be_bytes(bytes[offset..end].try_into().unwrap()))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    need(bytes, offset, 4)?;
    let end = checked_add_offset(offset, 4)?;
    Ok(u32::from_be_bytes(bytes[offset..end].try_into().unwrap()))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64> {
    need(bytes, offset, 8)?;
    let end = checked_add_offset(offset, 8)?;
    Ok(u64::from_be_bytes(bytes[offset..end].try_into().unwrap()))
}

fn usize_from_u32(value: u32) -> Result<usize> {
    usize::try_from(value).map_err(|_| BinaryAssetError::LengthOverflow)
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode_upper(Sha256::digest(bytes))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AtomicUnitHashes {
    pub raw_sha256: String,
    pub semantic_sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AtomicUnitComparison {
    pub semantic_equal: bool,
    pub raw_equal: bool,
}

/// Returns the exact raw node selected by an atomic group for one field. For
/// audited parallel arrays this is the element node at `array_index`; for all
/// other units it is the complete top-level value node.
pub fn atomic_group_value<'a>(
    row: NodeRef<'a>,
    unit: &AtomicGroup,
    field: &str,
) -> Result<NodeRef<'a>> {
    RowFieldIndex::new(row)?.atomic_group_value(unit, field)
}

fn hash_atomic_values<'a>(
    unit: &AtomicGroup,
    mut value_for: impl FnMut(&str) -> Result<NodeRef<'a>>,
    mut parent_for: impl FnMut(&str) -> Result<NodeRef<'a>>,
) -> Result<AtomicUnitHashes> {
    let mut raw_digest = Sha256::new();
    let mut semantic_digest = Sha256::new();
    if let Some(index) = unit.array_index {
        raw_digest.update(b"PAK-MERGER-RAW-INDEXED-ATOMIC-UNIT-V1");
        semantic_digest.update(b"PAK-MERGER-SEMANTIC-INDEXED-ATOMIC-UNIT-V1");
        raw_digest.update((index as u64).to_be_bytes());
        semantic_digest.update((index as u64).to_be_bytes());
        let expected = unit
            .expected_array_len
            .ok_or(BinaryAssetError::MissingExpectedArrayLength)?;
        raw_digest.update((expected as u64).to_be_bytes());
        semantic_digest.update((expected as u64).to_be_bytes());
    } else {
        raw_digest.update(b"PAK-MERGER-RAW-ATOMIC-UNIT-V1");
        semantic_digest.update(b"PAK-MERGER-SEMANTIC-ATOMIC-UNIT-V1");
    }
    for field in &unit.fields {
        if field == "m_id" {
            return Err(BinaryAssetError::RowSelectionContainsId);
        }
        let node = value_for(field)?;
        let name = field.as_bytes();
        hash_len(&mut raw_digest, name.len());
        hash_len(&mut semantic_digest, name.len());
        raw_digest.update(name);
        semantic_digest.update(name);
        if unit.array_index.is_some() {
            let parent = parent_for(field)?;
            let parent_raw = parent.raw();
            let header_len = parent.node.header_end - parent.node.range.start;
            hash_len(&mut raw_digest, header_len);
            raw_digest.update(&parent_raw[..header_len]);
        }
        let raw = node.raw();
        hash_len(&mut raw_digest, raw.len());
        raw_digest.update(raw);
        node.node.update_semantic_digest(&mut semantic_digest);
    }
    Ok(AtomicUnitHashes {
        raw_sha256: hex::encode_upper(raw_digest.finalize()),
        semantic_sha256: hex::encode_upper(semantic_digest.finalize()),
    })
}

/// Hashes a multi-field unit with explicit field-name/length framing. Raw and
/// semantic identities intentionally diverge when values are equal but their
/// MessagePack markers differ.
pub fn atomic_unit_hashes(row: NodeRef<'_>, fields: &[String]) -> Result<AtomicUnitHashes> {
    let unit = AtomicGroup {
        id: String::new(),
        fields: fields.to_vec(),
        compound: fields.len() > 1,
        array_index: None,
        expected_array_len: None,
    };
    RowFieldIndex::new(row)?.atomic_group_hashes(&unit)
}

/// Hashes either complete fields or the selected element from each parallel
/// array, depending on the audited atomic-group selector.
pub fn atomic_group_hashes(row: NodeRef<'_>, unit: &AtomicGroup) -> Result<AtomicUnitHashes> {
    RowFieldIndex::new(row)?.atomic_group_hashes(unit)
}

pub fn compare_atomic_units(
    left: NodeRef<'_>,
    right: NodeRef<'_>,
    fields: &[String],
) -> Result<AtomicUnitComparison> {
    let left = atomic_unit_hashes(left, fields)?;
    let right = atomic_unit_hashes(right, fields)?;
    Ok(AtomicUnitComparison {
        semantic_equal: left.semantic_sha256 == right.semantic_sha256,
        raw_equal: left.raw_sha256 == right.raw_sha256,
    })
}

/// Splices complete raw value nodes into a carrier map. The carrier's marker,
/// key bytes, key order, and every unselected value remain byte-identical.
pub fn splice_map_fields(
    carrier: NodeRef<'_>,
    replacements: &BTreeMap<String, NodeRef<'_>>,
) -> Result<Vec<u8>> {
    let carrier_fields = RowFieldIndex::new(carrier)?;
    let entries = carrier
        .node
        .as_map()
        .ok_or(BinaryAssetError::ExpectedMap("base Pak row"))?;
    for field in replacements.keys() {
        if field == "m_id" {
            return Err(BinaryAssetError::RowSelectionContainsId);
        }
        if carrier_fields.get(field).is_none() {
            return Err(BinaryAssetError::MissingField(field.clone()));
        }
    }

    let header_len = carrier.node.header_end - carrier.node.range.start;
    let carrier_raw = carrier.raw();
    let mut output = Vec::with_capacity(carrier_raw.len());
    output.extend_from_slice(&carrier_raw[..header_len]);
    for entry in entries {
        output.extend_from_slice(entry.key.raw(carrier.source));
        let name = entry
            .key
            .string_value()
            .ok_or(BinaryAssetError::NonStringMapKey)?;
        if let Some(replacement) = replacements.get(name) {
            output.extend_from_slice(replacement.raw());
        } else {
            output.extend_from_slice(entry.value.raw(carrier.source));
        }
    }
    Ok(output)
}

#[derive(Debug, Clone)]
pub struct AtomicDonorSelection {
    pub fields: Vec<String>,
    pub donor_input: usize,
    pub array_index: Option<usize>,
    pub expected_array_len: Option<usize>,
}

fn splice_map_raw_fields(
    carrier_fields: &RowFieldIndex<'_>,
    replacements: &BTreeMap<String, Vec<u8>>,
) -> Result<Vec<u8>> {
    let carrier = carrier_fields.row;
    let entries = carrier
        .node
        .as_map()
        .ok_or(BinaryAssetError::ExpectedMap("base Pak row"))?;
    for field in replacements.keys() {
        if field == "m_id" {
            return Err(BinaryAssetError::RowSelectionContainsId);
        }
        if carrier_fields.get(field).is_none() {
            return Err(BinaryAssetError::MissingField(field.clone()));
        }
    }
    let header_len = carrier.node.header_end - carrier.node.range.start;
    let carrier_raw = carrier.raw();
    let mut output = Vec::with_capacity(carrier_raw.len());
    output.extend_from_slice(&carrier_raw[..header_len]);
    for entry in entries {
        output.extend_from_slice(entry.key.raw(carrier.source));
        let name = entry
            .key
            .string_value()
            .ok_or(BinaryAssetError::NonStringMapKey)?;
        if let Some(replacement) = replacements.get(name) {
            output.extend_from_slice(replacement);
        } else {
            output.extend_from_slice(entry.value.raw(carrier.source));
        }
    }
    Ok(output)
}

fn splice_array_element_bytes(
    field: &str,
    carrier_array: NodeRef<'_>,
    expected_len: usize,
    replacements: &BTreeMap<usize, Vec<u8>>,
) -> Result<Vec<u8>> {
    let items = carrier_array
        .node
        .as_array()
        .ok_or(BinaryAssetError::ExpectedArray(
            "audited parallel-array field",
        ))?;
    if items.len() != expected_len {
        return Err(BinaryAssetError::ParallelArrayLengthMismatch {
            field: field.to_owned(),
            expected: expected_len,
            actual: items.len(),
        });
    }
    if let Some((&index, _)) = replacements
        .iter()
        .find(|(index, _)| **index >= items.len())
    {
        return Err(BinaryAssetError::ArrayIndexOutOfRange {
            field: field.to_owned(),
            index,
            len: items.len(),
        });
    }
    let raw = carrier_array.raw();
    let header_len = carrier_array.node.header_end - carrier_array.node.range.start;
    let mut output = Vec::with_capacity(raw.len());
    output.extend_from_slice(&raw[..header_len]);
    for (index, item) in items.iter().enumerate() {
        if let Some(replacement) = replacements.get(&index) {
            output.extend_from_slice(replacement);
        } else {
            output.extend_from_slice(item.raw(carrier_array.source));
        }
    }
    Ok(output)
}

/// Applies one or more whole-field/atomic-group choices to an existing row.
/// Values are never converted or encoded; they are copied from donor rows.
pub fn merge_row_atomic_units(
    inputs: &[&BinaryAsset],
    carrier_input: usize,
    row_id: RowId,
    selections: &[AtomicDonorSelection],
) -> Result<Vec<u8>> {
    let carrier_asset =
        inputs
            .get(carrier_input)
            .ok_or(BinaryAssetError::CarrierIndexOutOfRange {
                carrier: carrier_input,
                input_count: inputs.len(),
            })?;
    let carrier_row = carrier_asset
        .row(row_id)?
        .ok_or(BinaryAssetError::MissingRow(row_id))?;
    let mut rows = Vec::new();
    rows.try_reserve_exact(inputs.len()).map_err(|_| {
        BinaryAssetError::MessagePackAllocationFailed {
            resource: "row merge inputs",
            requested: inputs.len(),
        }
    })?;
    for asset in inputs {
        rows.push(asset.row(row_id)?);
    }
    let row_refs: Vec<_> = rows
        .iter()
        .map(|row| row.as_ref().map(|row| row.node_ref()))
        .collect();
    merge_row_atomic_node_refs(carrier_row.node_ref(), &row_refs, selections)
}

/// Applies raw atomic selections to already parsed rows. This is the compact
/// index writer's entry point: it keeps only the current row from each Pak in
/// memory instead of retaining every provider's complete BinaryAsset tree.
pub fn merge_row_atomic_node_refs(
    carrier_row: NodeRef<'_>,
    inputs: &[Option<NodeRef<'_>>],
    selections: &[AtomicDonorSelection],
) -> Result<Vec<u8>> {
    let carrier_fields = RowFieldIndex::new(carrier_row)?;
    let carrier_id = carrier_fields.row_id()?;
    enum PendingReplacement {
        Whole(Vec<u8>),
        Indexed {
            expected_len: usize,
            elements: BTreeMap<usize, Vec<u8>>,
        },
    }
    let mut pending: BTreeMap<String, PendingReplacement> = BTreeMap::new();
    let selected_donors = selections
        .iter()
        .map(|selection| selection.donor_input)
        .collect::<BTreeSet<_>>();
    let mut donor_fields = BTreeMap::new();
    for donor_input in selected_donors {
        let donor_row = inputs
            .get(donor_input)
            .ok_or(BinaryAssetError::InvalidDonorIndex {
                donor: donor_input,
                input_count: inputs.len(),
            })?
            .ok_or(BinaryAssetError::MissingRow(carrier_id))?;
        donor_fields.insert(donor_input, RowFieldIndex::new(donor_row)?);
    }

    for selection in selections {
        let donor_fields = donor_fields
            .get(&selection.donor_input)
            .expect("selected donor field index is available");
        let donor_id = donor_fields.row_id()?;
        if donor_id != carrier_id {
            return Err(BinaryAssetError::RowIdMismatch {
                carrier: carrier_id,
                donor: donor_id,
            });
        }
        let unit = AtomicGroup {
            id: String::new(),
            fields: selection.fields.clone(),
            compound: selection.fields.len() > 1 || selection.array_index.is_some(),
            array_index: selection.array_index,
            expected_array_len: selection.expected_array_len,
        };
        for field in &selection.fields {
            if field == "m_id" {
                return Err(BinaryAssetError::RowSelectionContainsId);
            }
            let donor_value = donor_fields.atomic_group_value(&unit, field)?;
            if let Some(index) = selection.array_index {
                let expected_len = selection
                    .expected_array_len
                    .ok_or(BinaryAssetError::MissingExpectedArrayLength)?;
                match pending
                    .entry(field.clone())
                    .or_insert_with(|| PendingReplacement::Indexed {
                        expected_len,
                        elements: BTreeMap::new(),
                    }) {
                    PendingReplacement::Whole(_) => {
                        return Err(BinaryAssetError::OverlappingFieldSelection(field.clone()));
                    }
                    PendingReplacement::Indexed {
                        expected_len: existing_len,
                        elements,
                    } => {
                        if *existing_len != expected_len {
                            return Err(BinaryAssetError::ParallelArrayLengthMismatch {
                                field: field.clone(),
                                expected: *existing_len,
                                actual: expected_len,
                            });
                        }
                        if elements.insert(index, donor_value.raw().to_vec()).is_some() {
                            return Err(BinaryAssetError::OverlappingArrayElementSelection {
                                field: field.clone(),
                                index,
                            });
                        }
                    }
                }
            } else if pending
                .insert(
                    field.clone(),
                    PendingReplacement::Whole(donor_value.raw().to_vec()),
                )
                .is_some()
            {
                return Err(BinaryAssetError::OverlappingFieldSelection(field.clone()));
            }
        }
    }
    let mut replacements = BTreeMap::new();
    for (field, pending) in pending {
        let bytes = match pending {
            PendingReplacement::Whole(bytes) => bytes,
            PendingReplacement::Indexed {
                expected_len,
                elements,
            } => {
                let carrier_value = carrier_fields.field_ref(&field)?;
                splice_array_element_bytes(&field, carrier_value, expected_len, &elements)?
            }
        };
        replacements.insert(field, bytes);
    }
    splice_map_raw_fields(&carrier_fields, &replacements)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RowVariantSource {
    pub input_index: usize,
    pub raw_sha256: String,
    pub semantic_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewRowCollision {
    pub row_id: RowId,
    pub variants: Vec<RowVariantSource>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UniqueRowUnionPlan {
    pub appended_ids: Vec<RowId>,
    pub deduplicated_ids: Vec<RowId>,
    pub encoding_drift_ids: Vec<RowId>,
    pub collisions: Vec<NewRowCollision>,
}

/// Finds rows absent from the carrier. IDs are appended in numeric order. A
/// semantic disagreement at the same new ID is never auto-resolved.
pub fn plan_unique_row_union(
    inputs: &[&BinaryAsset],
    carrier_input: usize,
) -> Result<UniqueRowUnionPlan> {
    let carrier = inputs
        .get(carrier_input)
        .ok_or(BinaryAssetError::CarrierIndexOutOfRange {
            carrier: carrier_input,
            input_count: inputs.len(),
        })?;
    let carrier_ids: BTreeSet<RowId> = carrier.rows()?.iter().map(|row| row.id).collect();
    let mut new_rows: BTreeMap<RowId, Vec<RowVariantSource>> = BTreeMap::new();

    for (input_index, asset) in inputs.iter().enumerate() {
        if input_index == carrier_input {
            continue;
        }
        for row in asset.rows()? {
            if carrier_ids.contains(&row.id) {
                continue;
            }
            let source = row.node_ref();
            new_rows.entry(row.id).or_default().push(RowVariantSource {
                input_index,
                raw_sha256: source.raw_sha256(),
                semantic_sha256: source.semantic_sha256(),
            });
        }
    }

    let mut plan = UniqueRowUnionPlan {
        appended_ids: Vec::new(),
        deduplicated_ids: Vec::new(),
        encoding_drift_ids: Vec::new(),
        collisions: Vec::new(),
    };
    for (row_id, variants) in new_rows {
        let semantic: BTreeSet<&str> = variants
            .iter()
            .map(|variant| variant.semantic_sha256.as_str())
            .collect();
        if semantic.len() > 1 {
            plan.collisions.push(NewRowCollision { row_id, variants });
            continue;
        }
        let raw: BTreeSet<&str> = variants
            .iter()
            .map(|variant| variant.raw_sha256.as_str())
            .collect();
        plan.appended_ids.push(row_id);
        if variants.len() > 1 {
            plan.deduplicated_ids.push(row_id);
        }
        if raw.len() > 1 {
            plan.encoding_drift_ids.push(row_id);
        }
    }
    Ok(plan)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UniqueRowUnionOutput {
    pub rows: Vec<Vec<u8>>,
    pub appended_ids: Vec<RowId>,
    pub deduplicated_ids: Vec<RowId>,
    pub encoding_drift_ids: Vec<RowId>,
}

/// Builds the raw row sequence for a carrier plus all non-colliding unique
/// rows. `collision_choices` maps a new row ID to its chosen input index.
pub fn build_unique_row_union(
    inputs: &[&BinaryAsset],
    carrier_input: usize,
    collision_choices: &BTreeMap<RowId, usize>,
) -> Result<UniqueRowUnionOutput> {
    let carrier = inputs
        .get(carrier_input)
        .ok_or(BinaryAssetError::CarrierIndexOutOfRange {
            carrier: carrier_input,
            input_count: inputs.len(),
        })?;
    let plan = plan_unique_row_union(inputs, carrier_input)?;
    let carrier_rows = carrier.rows()?;
    let mut rows: Vec<Vec<u8>> = carrier_rows
        .iter()
        .map(|row| row.node_ref().raw().to_vec())
        .collect();
    let input_rows = inputs
        .iter()
        .map(|asset| asset.row_index())
        .collect::<Result<Vec<_>>>()?;

    let mut all_new_ids: BTreeSet<RowId> = plan.appended_ids.iter().copied().collect();
    all_new_ids.extend(plan.collisions.iter().map(|collision| collision.row_id));

    for row_id in all_new_ids {
        let chosen_input = if let Some(collision) = plan
            .collisions
            .iter()
            .find(|collision| collision.row_id == row_id)
        {
            let donor = *collision_choices
                .get(&row_id)
                .ok_or(BinaryAssetError::UnresolvedRowCollision(row_id))?;
            if !collision
                .variants
                .iter()
                .any(|variant| variant.input_index == donor)
            {
                return Err(BinaryAssetError::InvalidRowChoice { row_id, donor });
            }
            donor
        } else {
            // First input in caller order is the deterministic donor when all
            // semantic values agree and the carrier has no such row.
            inputs
                .iter()
                .enumerate()
                .filter(|(index, _)| *index != carrier_input)
                .find_map(|(index, _)| input_rows[index].contains_key(&row_id).then_some(index))
                .ok_or(BinaryAssetError::MissingRow(row_id))?
        };
        let donor_row = input_rows[chosen_input].get(&row_id).copied().ok_or(
            BinaryAssetError::InvalidRowChoice {
                row_id,
                donor: chosen_input,
            },
        )?;
        rows.push(donor_row.node_ref().raw().to_vec());
    }

    Ok(UniqueRowUnionOutput {
        rows,
        appended_ids: all_sorted_ids(&plan),
        deduplicated_ids: plan.deduplicated_ids,
        encoding_drift_ids: plan.encoding_drift_ids,
    })
}

fn all_sorted_ids(plan: &UniqueRowUnionPlan) -> Vec<RowId> {
    let mut ids: BTreeSet<RowId> = plan.appended_ids.iter().copied().collect();
    ids.extend(plan.collisions.iter().map(|collision| collision.row_id));
    ids.into_iter().collect()
}

fn validate_raw_rows(rows: &[Vec<u8>]) -> Result<()> {
    let mut ids = BTreeSet::new();
    for raw in rows {
        let row = parse_messagepack(raw)?;
        if row.as_map().is_none() {
            return Err(BinaryAssetError::ExpectedMap("output m_DataList row"));
        }
        row.map_fields()?;
        let id = logical_row_id(&row)?;
        if !ids.insert(id) {
            return Err(BinaryAssetError::DuplicateRowId(id));
        }
    }
    Ok(())
}

fn encode_array_header_like(marker: u8, len: usize) -> Result<Vec<u8>> {
    if marker & 0xf0 == 0x90 {
        if len <= 15 {
            return Ok(vec![0x90 | len as u8]);
        }
        if len <= usize::from(u16::MAX) {
            let mut output = vec![0xdc];
            output.extend_from_slice(&(len as u16).to_be_bytes());
            return Ok(output);
        }
    } else if marker == 0xdc && len <= usize::from(u16::MAX) {
        let mut output = vec![0xdc];
        output.extend_from_slice(&(len as u16).to_be_bytes());
        return Ok(output);
    }

    let len = u32::try_from(len).map_err(|_| BinaryAssetError::LengthOverflow)?;
    let mut output = vec![0xdd];
    output.extend_from_slice(&len.to_be_bytes());
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn fixstr(value: &str) -> Vec<u8> {
        assert!(value.len() <= 31);
        let mut out = vec![0xa0 | value.len() as u8];
        out.extend_from_slice(value.as_bytes());
        out
    }

    fn row_with_raw_id(id: &[u8], x: &[u8], y: &[u8]) -> Vec<u8> {
        let mut out = vec![0x83];
        out.extend(fixstr("m_id"));
        out.extend_from_slice(id);
        out.extend(fixstr("x"));
        out.extend_from_slice(x);
        out.extend(fixstr("y"));
        out.extend_from_slice(y);
        out
    }

    fn row(id: u8, x: &[u8], y: &[u8]) -> Vec<u8> {
        row_with_raw_id(&[id], x, y)
    }

    fn float32(value: f32) -> Vec<u8> {
        let mut out = vec![0xca];
        out.extend_from_slice(&value.to_bits().to_be_bytes());
        out
    }

    fn float64(value: f64) -> Vec<u8> {
        let mut out = vec![0xcb];
        out.extend_from_slice(&value.to_bits().to_be_bytes());
        out
    }

    fn int64(value: i64) -> Vec<u8> {
        let mut out = vec![0xd3];
        out.extend_from_slice(&value.to_be_bytes());
        out
    }

    fn uint64(value: u64) -> Vec<u8> {
        let mut out = vec![0xcf];
        out.extend_from_slice(&value.to_be_bytes());
        out
    }

    fn asset(rows: &[Vec<u8>], array_marker: u8) -> Vec<u8> {
        let mut payload = vec![0x81];
        payload.extend(fixstr("m_DataList"));
        match array_marker {
            0x90 => payload.push(0x90 | rows.len() as u8),
            0xdc => {
                payload.push(0xdc);
                payload.extend_from_slice(&(rows.len() as u16).to_be_bytes());
            }
            _ => panic!("unsupported test marker"),
        }
        for row in rows {
            payload.extend_from_slice(row);
        }
        let mut prefix = [0x11; PREFIX_SIZE];
        prefix[6..10].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        let mut out = prefix.to_vec();
        out.extend(payload);
        out.extend([0xFA, 0xFB, 0xFC, 0xFD]);
        out.extend([0xC1, 0x83, 0x2A, 0x9E]);
        out
    }

    #[test]
    fn parses_binary_asset_and_preserves_all_sections() {
        let bytes = asset(&[row(1, &[0xcc, 1], &[0x92, 1, 0xc3])], 0xdc);
        let parsed = BinaryAsset::parse(&bytes).unwrap();
        assert_eq!(parsed.rows().unwrap()[0].id, 1);
        assert_eq!(parsed.data_list().unwrap().marker, 0xdc);
        assert_eq!(parsed.to_bytes(), bytes);
        assert_eq!(parsed.footer, [0xFA, 0xFB, 0xFC, 0xFD]);
        assert_eq!(parsed.package_tag, [0xC1, 0x83, 0x2A, 0x9E]);
    }

    #[test]
    fn compact_index_shares_backing_and_parses_only_requested_rows() {
        struct TrackedBytes {
            bytes: Vec<u8>,
            drops: Arc<AtomicUsize>,
        }
        impl AsRef<[u8]> for TrackedBytes {
            fn as_ref(&self) -> &[u8] {
                &self.bytes
            }
        }
        impl Drop for TrackedBytes {
            fn drop(&mut self) {
                self.drops.fetch_add(1, Ordering::SeqCst);
            }
        }

        let mut large_binary = vec![0xc6];
        large_binary.extend_from_slice(&(2_u32 * 1024 * 1024).to_be_bytes());
        large_binary.resize(large_binary.len() + 2 * 1024 * 1024, 0x5a);
        let bytes = asset(
            &[row(7, &large_binary, &[2]), row(3, &[0xcc, 9], &[4])],
            0x90,
        );
        let original_ptr = bytes.as_ptr();
        let drops = Arc::new(AtomicUsize::new(0));
        let indexed = IndexedBinaryAsset::parse_backed(TrackedBytes {
            bytes,
            drops: Arc::clone(&drops),
        })
        .unwrap();

        assert_eq!(indexed.backing_ptr(), original_ptr);
        assert_eq!(indexed.row_ids(), [7, 3]);
        assert!(indexed.retained_index_bytes() < 4 * 1024);
        assert!(indexed.bytes().len() > 2 * 1024 * 1024);
        let first_hash = indexed.row(7).unwrap().unwrap().node_ref().raw_sha256();
        let repeated_hash = indexed.row(7).unwrap().unwrap().node_ref().raw_sha256();
        assert_eq!(first_hash, repeated_hash);

        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<IndexedBinaryAsset>();
        drop(indexed);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn compact_index_reports_monotonic_payload_progress_without_a_second_parse() {
        let rows = (1..=32_u8)
            .map(|id| row(id, &[0xcc, id], &[id]))
            .collect::<Vec<_>>();
        let bytes = asset(&rows, 0xdc);
        let cancellation = CancellationToken::new();
        let mut events = Vec::new();
        let indexed = IndexedBinaryAsset::parse_backed_with_cancel_and_progress(
            bytes,
            &cancellation,
            |completed, total| events.push((completed, total)),
        )
        .unwrap();

        assert_eq!(indexed.row_count(), rows.len());
        assert!(!events.is_empty());
        assert!(events.windows(2).all(|pair| pair[0].0 <= pair[1].0));
        let (completed, total) = events.last().copied().unwrap();
        assert_eq!(completed, total);
        assert_eq!(total, indexed.payload().len());
    }

    #[test]
    fn compact_indexes_retain_row_metadata_not_provider_asts() {
        let mut indexes = Vec::new();
        let mut retained = 0_usize;
        let mut backed = 0_usize;
        for provider in 0..16_u8 {
            let rows = (1..=64_u8)
                .map(|id| row(id, &[provider], &[id]))
                .collect::<Vec<_>>();
            let index = IndexedBinaryAsset::parse_backed(asset(&rows, 0xdc)).unwrap();
            retained += index.retained_index_bytes();
            backed += index.bytes().len();
            indexes.push(index);
        }
        assert_eq!(indexes.len(), 16);
        assert!(retained < 16 * 64 * 128);
        assert!(backed > 0);
        // A row is reconstructed from its exact backing range on demand and
        // repeated provider access does not change its raw identity.
        let hashes = indexes
            .iter()
            .map(|asset| asset.row(32).unwrap().unwrap().node_ref().raw_sha256())
            .collect::<Vec<_>>();
        assert_eq!(hashes.len(), 16);
        assert_eq!(
            hashes[0],
            indexes[0].row(32).unwrap().unwrap().node_ref().raw_sha256()
        );
    }

    #[test]
    fn compact_index_uses_sorted_ids_without_a_duplicate_hash_table() {
        let sorted = IndexedBinaryAsset::parse_backed(asset(
            &[row(1, &[1], &[2]), row(3, &[3], &[4]), row(9, &[5], &[6])],
            0x90,
        ))
        .unwrap();
        assert!(matches!(sorted.row_lookup, CompactRowLookup::Sorted));
        assert!(sorted.contains_row(3));
        assert_eq!(sorted.row(9).unwrap().unwrap().id, 9);
        assert!(sorted.row(7).unwrap().is_none());

        let unordered = IndexedBinaryAsset::parse_backed(asset(
            &[row(7, &[1], &[2]), row(3, &[3], &[4]), row(9, &[5], &[6])],
            0x90,
        ))
        .unwrap();
        assert!(matches!(
            unordered.row_lookup,
            CompactRowLookup::Unordered(_)
        ));
        assert!(unordered.contains_row(3));
        assert_eq!(unordered.row(7).unwrap().unwrap().id, 7);
    }

    #[test]
    fn parse_caches_validated_row_ids_in_both_directions() {
        let bytes = asset(
            &[row(7, &[1], &[2]), row(3, &[3], &[4]), row(9, &[5], &[6])],
            0x90,
        );
        let parsed = BinaryAsset::parse(&bytes).unwrap();
        assert_eq!(parsed.row_ids, [7, 3, 9]);
        assert_eq!(parsed.row_indices.get(&7), Some(&0));
        assert_eq!(parsed.row_indices.get(&3), Some(&1));
        assert_eq!(parsed.row_indices.get(&9), Some(&2));
        assert_eq!(parsed.row(3).unwrap().unwrap().index, 1);
        assert_eq!(
            parsed
                .rows()
                .unwrap()
                .into_iter()
                .map(|row| row.id)
                .collect::<Vec<_>>(),
            [7, 3, 9]
        );

        let cloned = parsed.clone();
        assert_eq!(cloned.row(9).unwrap().unwrap().index, 2);
    }

    #[test]
    fn logical_row_id_accepts_only_safe_integral_float_encodings() {
        let read = |id: Vec<u8>| {
            let bytes = row_with_raw_id(&id, &[1], &[2]);
            let node = parse_messagepack(&bytes).unwrap();
            logical_row_id(&node)
        };

        assert_eq!(read(float32(151_922.0)).unwrap(), 151_922);
        assert_eq!(read(float64(-151_922.0)).unwrap(), -151_922);
        assert_eq!(
            read(float32(MAX_SAFE_F32_ROW_ID as f32)).unwrap(),
            MAX_SAFE_F32_ROW_ID as RowId
        );
        assert_eq!(
            read(float64(MAX_SAFE_F64_ROW_ID)).unwrap(),
            MAX_SAFE_F64_ROW_ID as RowId
        );
        assert_eq!(read(float64(-0.0)).unwrap(), 0);

        for invalid in [
            float32(1.5),
            float32(16_777_216.0),
            float32(f32::NAN),
            float32(f32::INFINITY),
            float32(f32::NEG_INFINITY),
            float64(1.5),
            float64(9_007_199_254_740_992.0),
            float64(f64::NAN),
            float64(f64::INFINITY),
            float64(f64::NEG_INFINITY),
        ] {
            assert!(matches!(read(invalid), Err(BinaryAssetError::InvalidRowId)));
        }
    }

    #[test]
    fn negative_float_zero_collides_with_integer_zero() {
        let duplicate = asset(
            &[
                row(0, &[1], &[2]),
                row_with_raw_id(&float64(-0.0), &[3], &[4]),
            ],
            0x90,
        );
        assert!(matches!(
            BinaryAsset::parse(&duplicate),
            Err(BinaryAssetError::DuplicateRowId(0))
        ));
    }

    #[test]
    fn rejects_declared_tens_of_millions_of_tiny_nodes_before_allocation() {
        let mut declared = vec![0xdd];
        declared.extend_from_slice(&50_000_000u32.to_be_bytes());
        assert!(matches!(
            parse_messagepack(&declared),
            Err(BinaryAssetError::MessagePackBudgetExceeded {
                resource: "container items",
                requested: 50_000_000,
                limit: MAX_MESSAGEPACK_CONTAINER_ITEMS,
            })
        ));
    }

    #[test]
    fn rejects_maximum_container_declaration_before_reserve() {
        let mut declared = vec![0xdf];
        declared.extend_from_slice(&u32::MAX.to_be_bytes());
        assert!(matches!(
            parse_messagepack(&declared),
            Err(BinaryAssetError::MessagePackBudgetExceeded {
                resource: "container items",
                requested,
                limit: MAX_MESSAGEPACK_CONTAINER_ITEMS,
            }) if requested == u32::MAX as usize
        ));
    }

    #[test]
    fn default_payload_limits_are_absolute_not_available_memory_snapshots() {
        let limits = default_parse_limits();
        assert_eq!(limits.payload_bytes, MAX_BINARY_ASSET_PAYLOAD_BYTES);
        assert_eq!(limits.owned_bytes, MAX_MESSAGEPACK_OWNED_BYTES);
        assert_eq!(MAX_BINARY_ASSET_PAYLOAD_BYTES, u32::MAX as usize);

        let large_mapped_payload = 2_168_493_135_usize;
        let indexed = indexed_scan_limits(large_mapped_payload);
        assert_eq!(indexed.payload_bytes, u32::MAX as usize);
        assert_eq!(indexed.nodes, large_mapped_payload);
        assert_eq!(indexed.container_items, large_mapped_payload);
        assert_eq!(indexed.owned_bytes, large_mapped_payload);
    }

    #[test]
    fn enforces_node_owned_byte_depth_and_payload_budgets() {
        let node_limits = ParseLimits {
            nodes: 3,
            ..default_parse_limits()
        };
        assert!(matches!(
            parse_messagepack_with_limits(&[0x93, 0xc0, 0xc0, 0xc0], node_limits),
            Err(BinaryAssetError::MessagePackBudgetExceeded {
                resource: "nodes",
                requested: 4,
                limit: 3,
            })
        ));

        let container_limits = ParseLimits {
            container_items: 3,
            ..default_parse_limits()
        };
        assert!(matches!(
            parse_messagepack_with_limits(&[0x92, 0x92, 0xc0, 0xc0, 0xc0], container_limits,),
            Err(BinaryAssetError::MessagePackBudgetExceeded {
                resource: "container items",
                requested: 4,
                limit: 3,
            })
        ));

        let owned_limits = ParseLimits {
            owned_bytes: 5,
            ..default_parse_limits()
        };
        assert!(matches!(
            parse_messagepack_with_limits(
                &[0x92, 0xa3, b'a', b'b', b'c', 0xa3, b'd', b'e', b'f'],
                owned_limits,
            ),
            Err(BinaryAssetError::MessagePackBudgetExceeded {
                resource: "owned string/binary/extension bytes",
                requested: 6,
                limit: 5,
            })
        ));

        let depth_limits = ParseLimits {
            depth: 1,
            ..default_parse_limits()
        };
        assert!(matches!(
            parse_messagepack_with_limits(&[0x91, 0x91, 0xc0], depth_limits),
            Err(BinaryAssetError::MessagePackDepthLimit { limit: 1 })
        ));

        let payload_limits = ParseLimits {
            payload_bytes: 3,
            ..default_parse_limits()
        };
        assert!(matches!(
            parse_messagepack_with_limits(&[0x93, 0xc0, 0xc0, 0xc0], payload_limits),
            Err(BinaryAssetError::MessagePackBudgetExceeded {
                resource: "payload bytes",
                requested: 4,
                limit: 3,
            })
        ));
    }

    #[test]
    fn semantic_hash_ignores_integer_marker_but_raw_hash_does_not() {
        let fix = parse_messagepack(&[1]).unwrap();
        let uint8 = parse_messagepack(&[0xcc, 1]).unwrap();
        assert!(fix.semantic_eq(&uint8));
        assert_eq!(fix.semantic_sha256(), uint8.semantic_sha256());
        assert_ne!(fix.raw_sha256(&[1]), uint8.raw_sha256(&[0xcc, 1]));
    }

    #[test]
    fn exact_integral_floats_share_integer_semantics_without_changing_raw_bytes() {
        let integer_bytes = [1];
        let float32_bytes = float32(1.0);
        let float64_bytes = float64(1.0);
        let integer = parse_messagepack(&integer_bytes).unwrap();
        let float32 = parse_messagepack(&float32_bytes).unwrap();
        let float64 = parse_messagepack(&float64_bytes).unwrap();

        assert!(integer.semantic_eq(&float32));
        assert!(float32.semantic_eq(&integer));
        assert!(integer.semantic_eq(&float64));
        assert_eq!(integer.semantic_sha256(), float32.semantic_sha256());
        assert_eq!(integer.semantic_sha256(), float64.semantic_sha256());

        assert_eq!(float32.raw(&float32_bytes), float32_bytes);
        assert_eq!(float64.raw(&float64_bytes), float64_bytes);
        assert_ne!(
            integer.raw_sha256(&integer_bytes),
            float32.raw_sha256(&float32_bytes)
        );
        assert_ne!(
            integer.raw_sha256(&integer_bytes),
            float64.raw_sha256(&float64_bytes)
        );
    }

    #[test]
    fn negative_float_zero_shares_integer_zero_semantics() {
        let integer_bytes = [0];
        let float_bytes = float64(-0.0);
        let integer = parse_messagepack(&integer_bytes).unwrap();
        let float = parse_messagepack(&float_bytes).unwrap();

        assert!(integer.semantic_eq(&float));
        assert_eq!(integer.semantic_sha256(), float.semantic_sha256());
        assert_ne!(
            integer.raw_sha256(&integer_bytes),
            float.raw_sha256(&float_bytes)
        );
    }

    #[test]
    fn exact_integral_floats_cover_the_representable_messagepack_integer_domain() {
        let signed_bytes = int64(i64::MIN);
        let signed_float_bytes = float64(i64::MIN as f64);
        let signed = parse_messagepack(&signed_bytes).unwrap();
        let signed_float = parse_messagepack(&signed_float_bytes).unwrap();
        assert!(signed.semantic_eq(&signed_float));
        assert_eq!(signed.semantic_sha256(), signed_float.semantic_sha256());

        // This is the largest f64-representable integer below 2^64.
        let unsigned_value = u64::MAX - 2_047;
        let unsigned_bytes = uint64(unsigned_value);
        let unsigned_float_bytes = float64(unsigned_value as f64);
        let unsigned = parse_messagepack(&unsigned_bytes).unwrap();
        let unsigned_float = parse_messagepack(&unsigned_float_bytes).unwrap();
        assert!(unsigned.semantic_eq(&unsigned_float));
        assert_eq!(unsigned.semantic_sha256(), unsigned_float.semantic_sha256());
    }

    #[test]
    fn non_integral_non_finite_and_out_of_range_floats_do_not_match_integers() {
        let one = parse_messagepack(&[1]).unwrap();
        for bytes in [
            float32(1.5),
            float64(1.5),
            float32(f32::NAN),
            float64(f64::NAN),
            float32(f32::INFINITY),
            float64(f64::INFINITY),
            float32(f32::NEG_INFINITY),
            float64(f64::NEG_INFINITY),
        ] {
            let float = parse_messagepack(&bytes).unwrap();
            assert!(!one.semantic_eq(&float));
            assert_ne!(one.semantic_sha256(), float.semantic_sha256());
        }

        // f64 cannot distinguish u64::MAX from the exclusive 2^64 boundary.
        // The range check must therefore reject it instead of collapsing it
        // onto the largest MessagePack unsigned integer.
        let unsigned_max_bytes = uint64(u64::MAX);
        let two_to_64_bytes = float64(18_446_744_073_709_551_616.0);
        let unsigned_max = parse_messagepack(&unsigned_max_bytes).unwrap();
        let two_to_64 = parse_messagepack(&two_to_64_bytes).unwrap();
        assert!(!unsigned_max.semantic_eq(&two_to_64));
        assert_ne!(unsigned_max.semantic_sha256(), two_to_64.semantic_sha256());

        let signed_min_bytes = int64(i64::MIN);
        let below_signed_min_bytes = float64(-9_223_372_036_854_777_856.0);
        let signed_min = parse_messagepack(&signed_min_bytes).unwrap();
        let below_signed_min = parse_messagepack(&below_signed_min_bytes).unwrap();
        assert!(!signed_min.semantic_eq(&below_signed_min));
        assert_ne!(
            signed_min.semantic_sha256(),
            below_signed_min.semantic_sha256()
        );
    }

    #[test]
    fn atomic_unit_hash_reports_encoding_drift_without_value_conflict() {
        let left_bytes = row(1, &[1], &[2]);
        let right_bytes = row(1, &[0xcc, 1], &[2]);
        let left = parse_messagepack(&left_bytes).unwrap();
        let right = parse_messagepack(&right_bytes).unwrap();
        let comparison = compare_atomic_units(
            NodeRef {
                node: &left,
                source: &left_bytes,
            },
            NodeRef {
                node: &right,
                source: &right_bytes,
            },
            &["x".to_owned()],
        )
        .unwrap();
        assert!(comparison.semantic_equal);
        assert!(!comparison.raw_equal);
    }

    #[test]
    fn selected_field_uses_exact_donor_node_and_retains_carrier_order() {
        let carrier_bytes = asset(&[row(1, &[0xcc, 1], &[0x92, 1, 0xc3])], 0x90);
        let donor_bytes = asset(&[row(1, &[0xcd, 0, 2], &[0x92, 9, 0xc2])], 0x90);
        let carrier = BinaryAsset::parse(&carrier_bytes).unwrap();
        let donor = BinaryAsset::parse(&donor_bytes).unwrap();
        let merged_row = merge_row_atomic_units(
            &[&carrier, &donor],
            0,
            1,
            &[AtomicDonorSelection {
                fields: vec!["x".to_owned()],
                donor_input: 1,
                array_index: None,
                expected_array_len: None,
            }],
        )
        .unwrap();
        let merged = parse_messagepack(&merged_row).unwrap();
        let x = merged.map_get("x").unwrap().unwrap();
        let y = merged.map_get("y").unwrap().unwrap();
        assert_eq!(x.raw(&merged_row), [0xcd, 0, 2]);
        assert_eq!(y.raw(&merged_row), [0x92, 1, 0xc3]);
        assert_eq!(
            merged
                .as_map()
                .unwrap()
                .iter()
                .map(|entry| entry.key.string_value().unwrap())
                .collect::<Vec<_>>(),
            ["m_id", "x", "y"]
        );
    }

    #[test]
    fn row_lookup_failure_is_distinct_from_a_missing_m_id_field() {
        let carrier = BinaryAsset::parse(&asset(&[row(1, &[1], &[2])], 0x90)).unwrap();
        assert_eq!(
            merge_row_atomic_units(&[&carrier], 0, 2, &[]).unwrap_err(),
            BinaryAssetError::MissingRow(2)
        );

        let row_without_id_bytes = [0x81, 0xa1, b'x', 0x01];
        let row_without_id = parse_messagepack(&row_without_id_bytes).unwrap();
        assert_eq!(
            logical_row_id(&row_without_id).unwrap_err(),
            BinaryAssetError::MissingRowId
        );
    }

    #[test]
    fn row_field_index_rejects_duplicate_fields_before_lookup_reuse() {
        let row_bytes = [0x82, 0xa1, b'x', 1, 0xa1, b'x', 2];
        let row = parse_messagepack(&row_bytes).unwrap();

        let error = RowFieldIndex::new(NodeRef {
            node: &row,
            source: &row_bytes,
        })
        .unwrap_err();

        assert_eq!(error, BinaryAssetError::DuplicateField("x".to_owned()));
    }

    #[test]
    fn indexed_selection_requires_an_analyzed_array_length() {
        let carrier_bytes = asset(&[row(1, &[0x91, 1], &[2])], 0x90);
        let donor_bytes = asset(&[row(1, &[0x91, 3], &[2])], 0x90);
        let carrier = BinaryAsset::parse(&carrier_bytes).unwrap();
        let donor = BinaryAsset::parse(&donor_bytes).unwrap();

        let error = merge_row_atomic_units(
            &[&carrier, &donor],
            0,
            1,
            &[AtomicDonorSelection {
                fields: vec!["x".to_owned()],
                donor_input: 1,
                array_index: Some(0),
                expected_array_len: None,
            }],
        )
        .unwrap_err();
        assert_eq!(error, BinaryAssetError::MissingExpectedArrayLength);
        assert_eq!(
            error.to_string(),
            "linked-array selection is missing its analyzed length"
        );
    }

    #[test]
    fn integer_carrier_and_float_donor_share_a_logical_row_without_reencoding_id() {
        let carrier_bytes = asset(&[row(1, &[0xcc, 1], &[2])], 0x90);
        let donor_bytes = asset(&[row_with_raw_id(&float64(1.0), &[0xcd, 0, 9], &[3])], 0x90);
        let carrier = BinaryAsset::parse(&carrier_bytes).unwrap();
        let donor = BinaryAsset::parse(&donor_bytes).unwrap();
        let merged_row = merge_row_atomic_units(
            &[&carrier, &donor],
            0,
            1,
            &[AtomicDonorSelection {
                fields: vec!["x".to_owned()],
                donor_input: 1,
                array_index: None,
                expected_array_len: None,
            }],
        )
        .unwrap();
        let merged = parse_messagepack(&merged_row).unwrap();
        assert_eq!(
            merged.map_get("m_id").unwrap().unwrap().raw(&merged_row),
            [1]
        );
        assert_eq!(
            merged.map_get("x").unwrap().unwrap().raw(&merged_row),
            [0xcd, 0, 9]
        );
    }

    #[test]
    fn indexed_parallel_array_selections_splice_exact_elements_from_two_donors() {
        let carrier_bytes = asset(
            &[row(
                1,
                &[0x93, 0xcc, 1, 0xcc, 2, 0xcc, 3],
                &[0xdc, 0, 3, 0xd0, 4, 0xd0, 5, 0xd0, 6],
            )],
            0x90,
        );
        let donor_a_bytes = asset(
            &[row(
                1,
                &[0x93, 0xcd, 0, 10, 0xcc, 2, 0xcc, 3],
                &[0x93, 0xd1, 0, 40, 0xd0, 5, 0xd0, 6],
            )],
            0x90,
        );
        let donor_b_bytes = asset(
            &[row(
                1,
                &[0x93, 0xcc, 1, 0xd1, 0, 20, 0xcc, 3],
                &[0x93, 0xd0, 4, 0xd2, 0, 0, 0, 50, 0xd0, 6],
            )],
            0x90,
        );
        let carrier = BinaryAsset::parse(&carrier_bytes).unwrap();
        let donor_a = BinaryAsset::parse(&donor_a_bytes).unwrap();
        let donor_b = BinaryAsset::parse(&donor_b_bytes).unwrap();
        reset_test_row_field_index_builds();
        let merged_row = merge_row_atomic_units(
            &[&carrier, &donor_a, &donor_b],
            0,
            1,
            &[
                AtomicDonorSelection {
                    fields: vec!["x".to_owned(), "y".to_owned()],
                    donor_input: 1,
                    array_index: Some(0),
                    expected_array_len: Some(3),
                },
                AtomicDonorSelection {
                    fields: vec!["x".to_owned(), "y".to_owned()],
                    donor_input: 2,
                    array_index: Some(1),
                    expected_array_len: Some(3),
                },
            ],
        )
        .unwrap();
        assert_eq!(test_row_field_index_builds(), 3);
        let merged = parse_messagepack(&merged_row).unwrap();
        let x = merged.map_get("x").unwrap().unwrap();
        let y = merged.map_get("y").unwrap().unwrap();
        // The carrier container marker/header and untouched index 2 survive,
        // while each selected element keeps the exact donor marker and width.
        assert_eq!(
            x.raw(&merged_row),
            [0x93, 0xcd, 0, 10, 0xd1, 0, 20, 0xcc, 3]
        );
        assert_eq!(
            y.raw(&merged_row),
            [0xdc, 0, 3, 0xd1, 0, 40, 0xd2, 0, 0, 0, 50, 0xd0, 6]
        );
    }

    #[test]
    fn indexed_hash_reports_parent_array_marker_drift() {
        let fix_bytes = row(1, &[0x92, 1, 2], &[0x92, 3, 4]);
        let array16_bytes = row(1, &[0xdc, 0, 2, 1, 2], &[0xdc, 0, 2, 3, 4]);
        let fix = parse_messagepack(&fix_bytes).unwrap();
        let array16 = parse_messagepack(&array16_bytes).unwrap();
        let unit = AtomicGroup {
            id: "group:test[0]".to_owned(),
            fields: vec!["x".to_owned(), "y".to_owned()],
            compound: true,
            array_index: Some(0),
            expected_array_len: Some(2),
        };
        let fix_hashes = atomic_group_hashes(
            NodeRef {
                node: &fix,
                source: &fix_bytes,
            },
            &unit,
        )
        .unwrap();
        let array16_hashes = atomic_group_hashes(
            NodeRef {
                node: &array16,
                source: &array16_bytes,
            },
            &unit,
        )
        .unwrap();
        assert_eq!(fix_hashes.semantic_sha256, array16_hashes.semantic_sha256);
        assert_ne!(fix_hashes.raw_sha256, array16_hashes.raw_sha256);
    }

    #[test]
    fn unique_rows_are_sorted_deduplicated_and_raw_preserved() {
        let carrier = BinaryAsset::parse(&asset(&[row(1, &[1], &[2])], 0x90)).unwrap();
        let donor_a = BinaryAsset::parse(&asset(&[row(2, &[0xcc, 7], &[3])], 0x90)).unwrap();
        let donor_b =
            BinaryAsset::parse(&asset(&[row(2, &[7], &[3]), row(3, &[8], &[4])], 0x90)).unwrap();
        let inputs = [&carrier, &donor_a, &donor_b];
        let plan = plan_unique_row_union(&inputs, 0).unwrap();
        assert_eq!(plan.appended_ids, [2, 3]);
        assert_eq!(plan.deduplicated_ids, [2]);
        assert_eq!(plan.encoding_drift_ids, [2]);
        assert!(plan.collisions.is_empty());

        let union = build_unique_row_union(&inputs, 0, &BTreeMap::new()).unwrap();
        assert_eq!(union.rows.len(), 3);
        // First donor wins only because both new row 2 values are semantic-equal.
        assert_eq!(
            union.rows[1],
            donor_a.row(2).unwrap().unwrap().node_ref().raw()
        );
        let rebuilt = carrier.rebuild_data_list(&union.rows).unwrap();
        let readback = BinaryAsset::parse(&rebuilt).unwrap();
        assert_eq!(
            readback
                .rows()
                .unwrap()
                .iter()
                .map(|row| row.id)
                .collect::<Vec<_>>(),
            [1, 2, 3]
        );
    }

    #[test]
    fn float_id_new_row_union_preserves_the_complete_donor_row() {
        let carrier = BinaryAsset::parse(&asset(&[row(1, &[1], &[2])], 0x90)).unwrap();
        let donor_row = row_with_raw_id(&float64(2.0), &[0xcd, 0, 7], &[3]);
        let donor = BinaryAsset::parse(&asset(std::slice::from_ref(&donor_row), 0x90)).unwrap();
        let inputs = [&carrier, &donor];

        let plan = plan_unique_row_union(&inputs, 0).unwrap();
        assert_eq!(plan.appended_ids, [2]);
        assert!(plan.collisions.is_empty());

        let union = build_unique_row_union(&inputs, 0, &BTreeMap::new()).unwrap();
        assert_eq!(union.rows[1], donor_row);
        let rebuilt = carrier.rebuild_data_list(&union.rows).unwrap();
        let readback = BinaryAsset::parse(&rebuilt).unwrap();
        let appended = readback.row(2).unwrap().unwrap();
        assert_eq!(appended.node_ref().raw(), union.rows[1]);
        assert_eq!(appended.node.map_get("m_id").unwrap().unwrap().marker, 0xcb);
    }

    #[test]
    fn different_new_rows_require_an_explicit_choice() {
        let carrier = BinaryAsset::parse(&asset(&[row(1, &[1], &[2])], 0x90)).unwrap();
        let donor_a = BinaryAsset::parse(&asset(&[row(2, &[7], &[3])], 0x90)).unwrap();
        let donor_b = BinaryAsset::parse(&asset(&[row(2, &[8], &[3])], 0x90)).unwrap();
        let inputs = [&carrier, &donor_a, &donor_b];
        let plan = plan_unique_row_union(&inputs, 0).unwrap();
        assert_eq!(plan.collisions.len(), 1);
        assert!(matches!(
            build_unique_row_union(&inputs, 0, &BTreeMap::new()),
            Err(BinaryAssetError::UnresolvedRowCollision(2))
        ));
        let output = build_unique_row_union(&inputs, 0, &BTreeMap::from([(2, 2)])).unwrap();
        assert_eq!(
            output.rows[1],
            donor_b.row(2).unwrap().unwrap().node_ref().raw()
        );
    }

    #[test]
    fn rejects_payload_mismatch_and_trailing_messagepack() {
        let mut bytes = asset(&[row(1, &[1], &[2])], 0x90);
        bytes[6..10].copy_from_slice(&1u32.to_le_bytes());
        assert!(matches!(
            BinaryAsset::parse(&bytes),
            Err(BinaryAssetError::PayloadLengthMismatch { .. })
        ));
        assert!(matches!(
            parse_messagepack(&[0xc0, 0xc0]),
            Err(BinaryAssetError::MessagePackTrailingData { .. })
        ));
    }

    #[test]
    fn rejects_duplicate_ids_during_parse_and_rebuild() {
        let duplicate = asset(&[row(1, &[1], &[2]), row(1, &[3], &[4])], 0x90);
        assert!(matches!(
            BinaryAsset::parse(&duplicate),
            Err(BinaryAssetError::DuplicateRowId(1))
        ));
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 96,
            max_shrink_iters: 512,
            failure_persistence: None,
            rng_seed: proptest::test_runner::RngSeed::Fixed(0x4D50_0101),
            .. ProptestConfig::default()
        })]

        /// The lossless MessagePack walker operates directly on untrusted
        /// bytes. Successful parses must cover the entire input and repeated
        /// parses must have identical raw and semantic identities.
        #[test]
        fn arbitrary_messagepack_is_deterministic_and_never_panics(
            bytes in prop::collection::vec(any::<u8>(), 0..512)
        ) {
            let first = parse_messagepack(&bytes);
            let second = parse_messagepack(&bytes);
            match (first, second) {
                (Ok(left), Ok(right)) => {
                    prop_assert_eq!(left.raw(&bytes), bytes.as_slice());
                    prop_assert_eq!(right.raw(&bytes), bytes.as_slice());
                    prop_assert_eq!(left.semantic_sha256(), right.semantic_sha256());
                    prop_assert!(left.semantic_eq(&right));
                }
                (Err(left), Err(right)) => prop_assert_eq!(left.to_string(), right.to_string()),
                _ => prop_assert!(false, "MessagePack parsing was nondeterministic"),
            }
        }

        /// Random framed data must either round-trip byte-for-byte as a valid
        /// BinaryAsset or be rejected consistently; no generic re-encode path
        /// is involved in the successful case.
        #[test]
        fn arbitrary_binary_assets_are_deterministic_and_never_panic(
            bytes in prop::collection::vec(any::<u8>(), 0..768)
        ) {
            let first = BinaryAsset::parse(&bytes);
            let second = BinaryAsset::parse(&bytes);
            match (first, second) {
                (Ok(left), Ok(right)) => {
                    prop_assert_eq!(left.to_bytes(), bytes.as_slice());
                    prop_assert_eq!(right.to_bytes(), bytes.as_slice());
                }
                (Err(left), Err(right)) => prop_assert_eq!(left.to_string(), right.to_string()),
                _ => prop_assert!(false, "BinaryAsset parsing was nondeterministic"),
            }
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 32,
            max_shrink_iters: 128,
            failure_persistence: None,
            rng_seed: proptest::test_runner::RngSeed::Fixed(0x4D50_0102),
            .. ProptestConfig::default()
        })]

        /// Length-prefixed markers with a truncated length header are always
        /// malformed. This targets the checked-read boundary for every 8/16/32
        /// bit string, binary, extension, array, and map family.
        #[test]
        fn truncated_length_headers_fail_closed(
            marker in prop::sample::select(vec![
                0xc4_u8, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9,
                0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
            ]),
            cut in 0_usize..4,
        ) {
            let width = match marker {
                0xc4 | 0xc7 | 0xd9 => 1,
                0xc5 | 0xc8 | 0xda | 0xdc | 0xde => 2,
                0xc6 | 0xc9 | 0xdb | 0xdd | 0xdf => 4,
                _ => unreachable!(),
            };
            let supplied = cut % width;
            let mut bytes = vec![marker];
            bytes.resize(1 + supplied, 0);
            prop_assert!(parse_messagepack(&bytes).is_err());
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 48,
            max_shrink_iters: 256,
            failure_persistence: None,
            rng_seed: proptest::test_runner::RngSeed::Fixed(0x4D50_0103),
            .. ProptestConfig::default()
        })]

        /// Valid generated databases must produce the same row order, IDs,
        /// and exact row ranges in the allocating and compact parsers.
        #[test]
        fn compact_and_allocating_parsers_agree_on_generated_databases(
            values in prop::collection::vec((any::<i8>(), any::<i8>()), 0..40)
        ) {
            let rows = values
                .iter()
                .enumerate()
                .map(|(index, (x, y))| {
                    row(
                        (index + 1) as u8,
                        &[0xd0, *x as u8],
                        &[0xd0, *y as u8],
                    )
                })
                .collect::<Vec<_>>();
            let marker = if rows.len() <= 15 { 0x90 } else { 0xdc };
            let bytes = asset(&rows, marker);
            let allocating = BinaryAsset::parse(&bytes).unwrap();
            let compact = IndexedBinaryAsset::parse_backed(bytes).unwrap();

            prop_assert_eq!(allocating.row_ids(), compact.row_ids());
            prop_assert_eq!(allocating.row_count(), compact.row_count());
            for index in 0..allocating.row_count() {
                let allocating_row = allocating.row_at(index).unwrap().unwrap();
                let compact_row = compact.row_at(index).unwrap().unwrap();
                prop_assert_eq!(allocating_row.id, compact_row.id);
                prop_assert_eq!(allocating_row.node_ref().raw(), compact_row.node_ref().raw());
            }
        }

        /// Random raw replacements preserve every unselected map field and
        /// every unselected array element byte-for-byte.
        #[test]
        fn raw_splices_change_only_selected_values(
            x in any::<i8>(),
            y in any::<i8>(),
            replacement in any::<i8>(),
            replace_x in any::<bool>(),
            array_values in prop::collection::vec(any::<i8>(), 1..32),
            selected_seed in any::<usize>(),
        ) {
            let carrier_bytes = row(1, &[0xd0, x as u8], &[0xd0, y as u8]);
            let carrier_node = parse_messagepack(&carrier_bytes).unwrap();
            let carrier_ref = NodeRef { node: &carrier_node, source: &carrier_bytes };
            let carrier_fields = RowFieldIndex::new(carrier_ref).unwrap();
            let selected_field = if replace_x { "x" } else { "y" };
            let mut field_replacements = BTreeMap::new();
            field_replacements.insert(selected_field.to_owned(), vec![0xd0, replacement as u8]);
            let merged_row = splice_map_raw_fields(&carrier_fields, &field_replacements).unwrap();
            let merged_node = parse_messagepack(&merged_row).unwrap();
            let merged_fields = merged_node.map_fields().unwrap();
            prop_assert_eq!(
                merged_fields.iter().map(|(name, _)| *name).collect::<Vec<_>>(),
                vec!["m_id", "x", "y"]
            );
            for (name, node) in merged_fields {
                let expected = if name == selected_field {
                    &[0xd0, replacement as u8][..]
                } else {
                    carrier_node.map_get(name).unwrap().unwrap().raw(&carrier_bytes)
                };
                prop_assert_eq!(node.raw(&merged_row), expected);
            }

            let mut array_bytes = encode_array_header_like(0x90, array_values.len()).unwrap();
            for value in &array_values {
                array_bytes.extend_from_slice(&[0xd0, *value as u8]);
            }
            let array_node = parse_messagepack(&array_bytes).unwrap();
            let selected = selected_seed % array_values.len();
            let replacement_bytes = vec![0xd0, replacement as u8];
            let mut element_replacements = BTreeMap::new();
            element_replacements.insert(selected, replacement_bytes.clone());
            let merged_array = splice_array_element_bytes(
                "values",
                NodeRef { node: &array_node, source: &array_bytes },
                array_values.len(),
                &element_replacements,
            )
            .unwrap();
            let merged_array_node = parse_messagepack(&merged_array).unwrap();
            let original_items = array_node.as_array().unwrap();
            let merged_items = merged_array_node.as_array().unwrap();
            prop_assert_eq!(original_items.len(), merged_items.len());
            for (index, (original, merged)) in
                original_items.iter().zip(merged_items.iter()).enumerate()
            {
                let expected = if index == selected {
                    replacement_bytes.as_slice()
                } else {
                    original.raw(&array_bytes)
                };
                prop_assert_eq!(merged.raw(&merged_array), expected);
            }
        }
    }

    /// Array headers retain their family where possible and promote at
    /// the exact fixarray/array16 boundaries. Both walkers must consume
    /// the complete generated value, including array32 promotion.
    #[test]
    fn encoded_array_headers_round_trip_across_family_boundaries() {
        for marker in [0x90_u8, 0xdc, 0xdd] {
            for len in [0_usize, 1, 15, 16, 17, 65_535, 65_536] {
                let mut bytes = encode_array_header_like(marker, len).unwrap();
                bytes.extend(std::iter::repeat_n(0xc0, len));
                let parsed = parse_messagepack(&bytes).unwrap();
                assert_eq!(parsed.as_array().unwrap().len(), len);

                let mut budget = ParseBudget::new(indexed_scan_limits(bytes.len()), None);
                assert_eq!(
                    scan_node_end(&bytes, 0, 0, &mut budget).unwrap(),
                    bytes.len()
                );

                let expected_marker = if marker & 0xf0 == 0x90 && len <= 15 {
                    0x90 | len as u8
                } else if marker != 0xdd && len <= usize::from(u16::MAX) {
                    0xdc
                } else {
                    0xdd
                };
                assert_eq!(bytes[0], expected_marker);
            }
        }
    }
}
