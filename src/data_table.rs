//! Reader for cooked Unreal Engine 4 `UDataTable` databases.
//!
//! The export body of a cooked `UDataTable` is:
//!
//! ```text
//! UObject tagged-property block      one tag: { RowStruct: ObjectProperty }
//! FName "None"                       block terminator
//! int32                              0
//! int32 NumRows
//! repeat NumRows:
//!     FName RowName
//!     tagged-property block
//!     FName "None"
//! ```
//!
//! Two properties of the format make a lossless merge possible, and both are
//! enforced here rather than assumed:
//!
//! * every property tag declares its value `Size`, so a correct walk consumes
//!   exactly that many bytes. A mismatch is an error, never a skip — that is
//!   what stops a misunderstood construct from being silently mis-spliced.
//! * an `FName` is always 8 bytes (`int32` index + `int32` number), so
//!   retargeting one at another package's name table never changes any length.
//!
//! Values are never decoded. Rows and fields are byte ranges plus the positions
//! of the `FName` fields inside them, which is all a splice needs.

use crate::ue_package::{NameEntry, Ue4Package};
use std::collections::HashMap;
use std::ops::Range;
use std::sync::Arc;
use thiserror::Error;

/// Serialised size of an `FName` reference inside export data.
pub const FNAME_SIZE: usize = 8;

const NONE: &str = "None";
const MAX_ROWS: usize = 4_000_000;
const MAX_FIELDS_PER_ROW: usize = 4_096;
const MAX_DEPTH: usize = 32;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DataTableError {
    #[error("export body ends inside {field}")]
    UnexpectedEnd { field: &'static str },
    #[error("name index {index} is outside the package name table")]
    UnknownName { index: i32 },
    #[error("{context}: value walk consumed {walked} bytes but the tag declares {declared}")]
    SizeMismatch {
        context: String,
        declared: i64,
        walked: i64,
    },
    #[error("unsupported property type {found} at byte {at}")]
    UnsupportedProperty { at: usize, found: String },
    #[error("unsupported struct {found}; its byte layout is unknown")]
    UnsupportedStruct { found: String },
    #[error("unsupported FText history type {found}")]
    UnsupportedTextHistory { found: i8 },
    #[error("duplicate row name {name}")]
    DuplicateRow { name: String },
    #[error("row {row} repeats the property {field}, which this reader cannot address")]
    DuplicateField { row: String, field: String },
    #[error("the object property block is not the expected single RowStruct tag")]
    UnexpectedObjectBlock,
    #[error("the {field} trailer between the object block and the rows is not zero")]
    UnexpectedTrailer { field: &'static str },
    #[error("{field} {count} exceeds the supported maximum {limit}")]
    TooMany {
        field: &'static str,
        count: u64,
        limit: usize,
    },
    #[error("nested property depth exceeds {MAX_DEPTH}")]
    DepthLimit,
    #[error("export body has {remaining} trailing bytes after the last row")]
    TrailingBytes { remaining: usize },
}

type Result<T> = std::result::Result<T, DataTableError>;

/// Structs Unreal serialises as a fixed binary blob. None of them contains an
/// `FName`, so their bytes are position-independent and copy verbatim.
fn native_binary_struct_size(name: &str) -> Option<usize> {
    Some(match name {
        "Vector" | "Rotator" | "IntVector" => 12,
        "Vector2D" | "IntPoint" => 8,
        "Vector4" | "Quat" | "LinearColor" | "Plane" | "IntRect" => 16,
        "Color" | "FrameNumber" => 4,
        "Guid" => 16,
        "Timespan" | "DateTime" => 8,
        "Box2D" => 17,
        "Box" => 25,
        "TwoVectors" => 24,
        "Matrix" => 64,
        _ => return None,
    })
}

/// Structs serialised as `FName` + `FString` (an `FSoftObjectPath`).
fn is_soft_path_struct(name: &str) -> bool {
    matches!(
        name,
        "SoftObjectPath" | "SoftClassPath" | "StringAssetReference" | "StringClassReference"
    )
}

/// Fixed-width property values, excluding the context-sensitive ones.
fn fixed_value_size(property_type: &str) -> Option<usize> {
    Some(match property_type {
        "Int8Property" => 1,
        "Int16Property" | "UInt16Property" => 2,
        "IntProperty" | "UInt32Property" | "FloatProperty" => 4,
        "Int64Property" | "UInt64Property" | "DoubleProperty" => 8,
        _ => return None,
    })
}

/// One property of one row: the bytes covering its tag and value, and the
/// positions of every `FName` inside them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RowField {
    pub name: String,
    /// Serialised property type, e.g. `IntProperty`.
    pub property_type: String,
    /// Tag header plus value. Replacing exactly this range replaces the field.
    pub range: Range<usize>,
    /// The value alone, without the tag header.
    pub value_range: Range<usize>,
    /// A `BoolProperty` keeps its value in the tag rather than the value bytes.
    pub bool_value: Option<bool>,
    /// Absolute offsets of every `FName` within `range`, tag headers included.
    /// A retarget has to rewrite all of them.
    pub fname_sites: Vec<usize>,
    /// The subset of `fname_sites` holding property VALUES, so the only ones
    /// that can name a row of another table.
    pub value_fname_sites: Vec<usize>,
    /// Absolute offsets of `FPackageIndex` values within `range`. A field with
    /// any of these can only be spliced when both packages resolve them
    /// identically.
    pub package_index_sites: Vec<usize>,
}

impl RowField {
    /// True when the field's bytes are position-independent apart from their
    /// `FName` references, so a retarget is all a splice needs.
    pub fn is_name_retargetable(&self) -> bool {
        self.package_index_sites.is_empty()
    }

    /// Every row name this field could be referencing.
    ///
    /// Only value `FName`s count. An array or struct carries its own property
    /// tags *inside* the parent's value bytes, so taking every `FName` in the
    /// value range would also collect nested property names and type names and
    /// then report them as references to rows that do not exist.
    pub fn referenced_names(&self, body: &[u8], names: &[NameEntry]) -> Vec<String> {
        self.value_fname_sites
            .iter()
            .filter_map(|site| body.get(*site..*site + FNAME_SIZE))
            .map(|raw| render_fname(raw, names))
            // Three kinds of value are not row names: `None` is Unreal's empty
            // reference, a value holding `::` is an enum literal such as
            // `EAILMENT_TYPE::NewEnumerator0`, and one starting with `/` is an
            // asset path from a soft object reference. The measurements that
            // established these rules excluded all three, so the check has to
            // exclude them too or it would report breaks the measurement never
            // saw.
            .filter(|value| {
                !value.is_empty()
                    && value != NONE
                    && !value.contains("::")
                    && !value.starts_with('/')
            })
            .collect()
    }

    /// The value rendered for a human choosing between two Paks.
    ///
    /// This must show the VALUE, never the tag header: the header begins with
    /// the property-name `FName`, which is identical for every row, so showing
    /// it would make every variant look the same and leave the user unable to
    /// tell the two Paks apart.
    pub fn preview(&self, body: &[u8], names: &[NameEntry]) -> String {
        const MAX: usize = 60;
        let value = body.get(self.value_range.clone()).unwrap_or_default();
        let rendered = match self.property_type.as_str() {
            "BoolProperty" => match self.bool_value {
                Some(true) => "true".to_owned(),
                Some(false) => "false".to_owned(),
                None => "?".to_owned(),
            },
            "Int8Property" => render_int(value, 1, true),
            "Int16Property" => render_int(value, 2, true),
            "UInt16Property" => render_int(value, 2, false),
            "IntProperty" => render_int(value, 4, true),
            "UInt32Property" => render_int(value, 4, false),
            "Int64Property" => render_int(value, 8, true),
            "UInt64Property" => render_int(value, 8, false),
            "FloatProperty" => value
                .get(..4)
                .map(|raw| f32::from_le_bytes(raw.try_into().expect("checked")).to_string())
                .unwrap_or_default(),
            "DoubleProperty" => value
                .get(..8)
                .map(|raw| f64::from_le_bytes(raw.try_into().expect("checked")).to_string())
                .unwrap_or_default(),
            "NameProperty" | "EnumProperty" => render_fname(value, names),
            "ByteProperty" => {
                if value.len() == FNAME_SIZE {
                    render_fname(value, names)
                } else {
                    render_int(value, 1, false)
                }
            }
            "StrProperty" => render_fstring(value).0,
            "TextProperty" => render_ftext(value),
            "SoftObjectProperty" | "SoftClassProperty" | "AssetObjectProperty" => {
                let asset = render_fname(value, names);
                let (sub, _) = render_fstring(value.get(FNAME_SIZE..).unwrap_or_default());
                if sub.is_empty() {
                    asset
                } else {
                    format!("{asset}.{sub}")
                }
            }
            "ObjectProperty" | "ClassProperty" | "InterfaceProperty" | "LazyObjectProperty" => {
                format!("reference {}", render_int(value, 4, true))
            }
            "ArrayProperty" | "SetProperty" | "MapProperty" => {
                format!("{} entries", render_int(value, 4, true))
            }
            "StructProperty" => format!("{} bytes", value.len()),
            other => format!("{other} ({} bytes)", value.len()),
        };
        truncate_display(&rendered, MAX)
    }
}

fn truncate_display(text: &str, max: usize) -> String {
    let cleaned: String = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    if cleaned.chars().count() <= max {
        return cleaned;
    }
    cleaned.chars().take(max).collect::<String>() + "…"
}

fn render_int(value: &[u8], width: usize, signed: bool) -> String {
    let Some(raw) = value.get(..width) else {
        return String::new();
    };
    let mut buffer = [0_u8; 8];
    buffer[..width].copy_from_slice(raw);
    let unsigned = u64::from_le_bytes(buffer);
    if !signed {
        return unsigned.to_string();
    }
    let shift = 64 - width * 8;
    (((unsigned << shift) as i64) >> shift).to_string()
}

fn render_fname(value: &[u8], names: &[NameEntry]) -> String {
    let Some(raw) = value.get(..FNAME_SIZE) else {
        return String::new();
    };
    let index = i32::from_le_bytes(raw[..4].try_into().expect("checked"));
    let number = i32::from_le_bytes(raw[4..8].try_into().expect("checked"));
    let text = usize::try_from(index)
        .ok()
        .and_then(|index| names.get(index))
        .map_or("<unknown>", |entry| entry.text.as_str());
    if number <= 0 {
        text.to_owned()
    } else {
        format!("{text}_{}", number - 1)
    }
}

/// Decodes an `FString` and reports how many bytes it occupied.
fn render_fstring(value: &[u8]) -> (String, usize) {
    let Some(raw) = value.get(..4) else {
        return (String::new(), 0);
    };
    let length = i32::from_le_bytes(raw.try_into().expect("checked"));
    if length == 0 {
        return (String::new(), 4);
    }
    if length > 0 {
        let count = length as usize;
        let Some(bytes) = value.get(4..4 + count) else {
            return (String::new(), 4);
        };
        let text = String::from_utf8_lossy(bytes.strip_suffix(b"\0").unwrap_or(bytes));
        return (text.into_owned(), 4 + count);
    }
    let units = length.unsigned_abs() as usize;
    let Some(bytes) = value.get(4..4 + units * 2) else {
        return (String::new(), 4);
    };
    let utf16: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    let text = String::from_utf16_lossy(&utf16);
    (text.trim_end_matches('\0').to_owned(), 4 + units * 2)
}

/// `FText`: flags, history type, then history-specific strings. The source
/// string is what a human recognises, so that is what is shown.
fn render_ftext(value: &[u8]) -> String {
    let Some(history) = value.get(4).map(|byte| *byte as i8) else {
        return String::new();
    };
    let rest = value.get(5..).unwrap_or_default();
    match history {
        -1 => {
            let has = rest
                .get(..4)
                .map(|raw| i32::from_le_bytes(raw.try_into().expect("checked")))
                .unwrap_or(0);
            if has == 0 {
                return "(empty)".to_owned();
            }
            render_fstring(rest.get(4..).unwrap_or_default()).0
        }
        0 => {
            // namespace, key, then the source string.
            let (_, used) = render_fstring(rest);
            let (_, used_key) = render_fstring(rest.get(used..).unwrap_or_default());
            render_fstring(rest.get(used + used_key..).unwrap_or_default()).0
        }
        other => format!("(text history {other})"),
    }
}

/// A row's decoded structure. Field order is the serialised order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RowLayout {
    pub fields: Vec<RowField>,
}

impl RowLayout {
    pub fn field(&self, name: &str) -> Option<&RowField> {
        self.fields.iter().find(|field| field.name == name)
    }

    pub fn field_names(&self) -> impl Iterator<Item = &str> {
        self.fields.iter().map(|field| field.name.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RowSpan {
    pub name: Arc<str>,
    /// The whole row: `FName RowName`, its property block, and the terminator.
    pub range: Range<usize>,
    /// Position of the row's own `FName`, which also needs retargeting.
    pub name_site: usize,
}

/// Structural index over one cooked `UDataTable` export body.
///
/// Holds `O(row count)` metadata; individual rows are walked on demand.
#[derive(Debug, Clone)]
pub struct DataTableIndex {
    /// Object-level tagged-property block plus its `None` terminator.
    pub object_block: Range<usize>,
    /// The `int32` zero trailer and `int32 NumRows` that follow it.
    pub row_count_field: usize,
    pub rows: Vec<RowSpan>,
    lookup: HashMap<Arc<str>, usize>,
    /// Length of the export body, excluding the trailing package tag.
    pub body_len: usize,
}

impl DataTableIndex {
    /// Walks an export body and records every row.
    ///
    /// `body` must be exactly the export payload — `SerialSize` bytes, without
    /// the trailing 4-byte package tag.
    pub fn parse(body: &[u8], package: &Ue4Package) -> Result<Self> {
        let mut walker = Walker::new(body, &package.names);

        let object_start = 0;
        let object_tags = walker.tagged_block(object_start, "object property block")?;
        if object_tags.len() != 1 || object_tags[0].name != "RowStruct" {
            return Err(DataTableError::UnexpectedObjectBlock);
        }
        let object_end = walker.offset;

        if walker.i32("zero trailer")? != 0 {
            return Err(DataTableError::UnexpectedTrailer {
                field: "zero-int32",
            });
        }
        let row_count_field = walker.offset;
        let row_count = walker.i32("NumRows")?;
        let row_count = usize::try_from(row_count).map_err(|_| DataTableError::TooMany {
            field: "NumRows",
            count: row_count.max(0) as u64,
            limit: MAX_ROWS,
        })?;
        if row_count > MAX_ROWS {
            return Err(DataTableError::TooMany {
                field: "NumRows",
                count: row_count as u64,
                limit: MAX_ROWS,
            });
        }

        walker.in_row = true;
        let mut rows = Vec::new();
        rows.try_reserve_exact(row_count)
            .map_err(|_| DataTableError::TooMany {
                field: "NumRows",
                count: row_count as u64,
                limit: MAX_ROWS,
            })?;
        let mut lookup = HashMap::with_capacity(row_count);
        for _ in 0..row_count {
            let start = walker.offset;
            let name_site = start;
            let name: Arc<str> = walker.fname("row name")?.into();
            walker.tagged_block(walker.offset, "row property block")?;
            let span = RowSpan {
                name: Arc::clone(&name),
                range: start..walker.offset,
                name_site,
            };
            if lookup.insert(Arc::clone(&name), rows.len()).is_some() {
                return Err(DataTableError::DuplicateRow {
                    name: name.to_string(),
                });
            }
            rows.push(span);
        }

        if walker.offset != body.len() {
            return Err(DataTableError::TrailingBytes {
                remaining: body.len().saturating_sub(walker.offset),
            });
        }

        Ok(Self {
            object_block: object_start..object_end,
            row_count_field,
            rows,
            lookup,
            body_len: body.len(),
        })
    }

    pub fn row_index(&self, name: &str) -> Option<usize> {
        self.lookup.get(name).copied()
    }

    pub fn row(&self, name: &str) -> Option<&RowSpan> {
        self.row_index(name).map(|index| &self.rows[index])
    }

    /// Walks one row again to produce its field ranges. Done on demand so a
    /// large table costs one span per row rather than one entry per property.
    pub fn row_layout(&self, body: &[u8], package: &Ue4Package, index: usize) -> Result<RowLayout> {
        let span = self
            .rows
            .get(index)
            .ok_or(DataTableError::UnexpectedEnd { field: "row index" })?;
        let mut walker = Walker::new(body, &package.names);
        walker.in_row = true;
        walker.offset = span.range.start + FNAME_SIZE;
        let tags = walker.tagged_block(walker.offset, "row property block")?;

        let mut fields = Vec::with_capacity(tags.len());
        for tag in tags {
            if fields.len() >= MAX_FIELDS_PER_ROW {
                return Err(DataTableError::TooMany {
                    field: "row properties",
                    count: fields.len() as u64 + 1,
                    limit: MAX_FIELDS_PER_ROW,
                });
            }
            if fields
                .iter()
                .any(|existing: &RowField| existing.name == tag.name)
            {
                return Err(DataTableError::DuplicateField {
                    row: span.name.to_string(),
                    field: tag.name,
                });
            }
            fields.push(RowField {
                name: tag.name,
                property_type: tag.property_type,
                range: tag.range,
                value_range: tag.value_range,
                bool_value: tag.bool_value,
                fname_sites: tag.fname_sites,
                value_fname_sites: tag.value_fname_sites,
                package_index_sites: tag.package_index_sites,
            });
        }
        Ok(RowLayout { fields })
    }

    /// Every `FName` position in a row, including the row's own name.
    pub fn row_fname_sites(
        &self,
        body: &[u8],
        package: &Ue4Package,
        index: usize,
    ) -> Result<Vec<usize>> {
        let span = self
            .rows
            .get(index)
            .ok_or(DataTableError::UnexpectedEnd { field: "row index" })?;
        let mut walker = Walker::new(body, &package.names);
        walker.in_row = true;
        walker.offset = span.range.start;
        walker.fname("row name")?;
        walker.tagged_block(walker.offset, "row property block")?;
        Ok(walker.fname_sites)
    }
}

struct TagSpan {
    name: String,
    property_type: String,
    /// Tag header plus value bytes.
    range: Range<usize>,
    value_range: Range<usize>,
    bool_value: Option<bool>,
    fname_sites: Vec<usize>,
    value_fname_sites: Vec<usize>,
    package_index_sites: Vec<usize>,
}

struct Walker<'a> {
    bytes: &'a [u8],
    names: &'a [NameEntry],
    offset: usize,
    fname_sites: Vec<usize>,
    /// The `fname_sites` entries that are property values rather than tag
    /// metadata. Kept apart so a reference check can tell a value that names a
    /// row from a nested property name that names nothing.
    value_fname_sites: Vec<usize>,
    package_index_sites: Vec<usize>,
    depth: usize,
    /// Set while walking row data. The object-level block legitimately holds a
    /// `RowStruct: ObjectProperty`, but a package index inside a row cannot be
    /// retargeted by name, so only rows refuse it.
    in_row: bool,
}

impl<'a> Walker<'a> {
    fn new(bytes: &'a [u8], names: &'a [NameEntry]) -> Self {
        Self {
            bytes,
            names,
            offset: 0,
            fname_sites: Vec::new(),
            value_fname_sites: Vec::new(),
            package_index_sites: Vec::new(),
            depth: 0,
            in_row: false,
        }
    }

    fn i32(&mut self, field: &'static str) -> Result<i32> {
        let raw = self
            .bytes
            .get(self.offset..self.offset + 4)
            .ok_or(DataTableError::UnexpectedEnd { field })?;
        self.offset += 4;
        Ok(i32::from_le_bytes(raw.try_into().expect("fixed range")))
    }

    fn i8(&mut self, field: &'static str) -> Result<i8> {
        let raw = *self
            .bytes
            .get(self.offset)
            .ok_or(DataTableError::UnexpectedEnd { field })?;
        self.offset += 1;
        Ok(raw as i8)
    }

    fn skip(&mut self, amount: usize, field: &'static str) -> Result<()> {
        self.offset = self
            .offset
            .checked_add(amount)
            .filter(|end| *end <= self.bytes.len())
            .ok_or(DataTableError::UnexpectedEnd { field })?;
        Ok(())
    }

    /// Reads an `FName` that belongs to a property tag — a property name, a
    /// type name, a struct name. Retargeted like any other, never a reference.
    fn fname(&mut self, field: &'static str) -> Result<String> {
        self.read_fname(field, false)
    }

    /// Reads an `FName` that is a property VALUE, and so may name a row.
    fn value_fname(&mut self, field: &'static str) -> Result<String> {
        self.read_fname(field, true)
    }

    fn read_fname(&mut self, field: &'static str, is_value: bool) -> Result<String> {
        let site = self.offset;
        let index = self.i32(field)?;
        let number = self.i32(field)?;
        let entry = usize::try_from(index)
            .ok()
            .and_then(|index| self.names.get(index))
            .ok_or(DataTableError::UnknownName { index })?;
        // Unreal instance numbers are non-negative. A negative one means the
        // walk is reading something that is not an FName, so refuse rather
        // than fabricate a name.
        let suffix = match number {
            0 => None,
            positive if positive > 0 => Some(positive - 1),
            _ => return Err(DataTableError::UnknownName { index: number }),
        };
        self.fname_sites.push(site);
        if is_value {
            self.value_fname_sites.push(site);
        }
        Ok(match suffix {
            None => entry.text.clone(),
            Some(suffix) => format!("{}_{suffix}", entry.text),
        })
    }

    fn fstring(&mut self, field: &'static str) -> Result<()> {
        let length = self.i32(field)?;
        let bytes = if length >= 0 {
            usize::try_from(length).map_err(|_| DataTableError::UnexpectedEnd { field })?
        } else {
            length
                .checked_neg()
                .and_then(|value| usize::try_from(value).ok())
                .and_then(|units| units.checked_mul(2))
                .ok_or(DataTableError::UnexpectedEnd { field })?
        };
        self.skip(bytes, field)
    }

    /// Walks tagged properties until the `None` terminator, returning one span
    /// per property. `self.offset` ends just past the terminator.
    fn tagged_block(&mut self, start: usize, context: &'static str) -> Result<Vec<TagSpan>> {
        if self.depth >= MAX_DEPTH {
            return Err(DataTableError::DepthLimit);
        }
        self.offset = start;
        let mut spans = Vec::new();
        loop {
            let tag_start = self.offset;
            let sites_before = self.fname_sites.len();
            let value_sites_before = self.value_fname_sites.len();
            let indices_before = self.package_index_sites.len();
            let Some(tag) = self.read_tag(context)? else {
                return Ok(spans);
            };
            let value_start = self.offset;
            self.depth += 1;
            let result = self.value(&tag.property_type, &tag.extra, tag.size, false);
            self.depth -= 1;
            let end = result?;
            let declared = i64::from(tag.size);
            let walked = (end as i64) - (value_start as i64);
            if walked != declared {
                return Err(DataTableError::SizeMismatch {
                    context: format!("{context}: {}:{}", tag.name, tag.property_type),
                    declared,
                    walked,
                });
            }
            self.offset = end;
            spans.push(TagSpan {
                name: tag.name,
                property_type: tag.property_type,
                range: tag_start..end,
                value_range: value_start..end,
                bool_value: tag.bool_value,
                fname_sites: self.fname_sites[sites_before..].to_vec(),
                value_fname_sites: self.value_fname_sites[value_sites_before..].to_vec(),
                package_index_sites: self.package_index_sites[indices_before..].to_vec(),
            });
        }
    }

    fn read_tag(&mut self, context: &'static str) -> Result<Option<PropertyTag>> {
        let name = self.fname("property name")?;
        if name == NONE {
            return Ok(None);
        }
        let property_type = self.fname("property type")?;
        let size = self.i32("property size")?;
        if size < 0 {
            return Err(DataTableError::SizeMismatch {
                context: format!("{context}: {name}:{property_type}"),
                declared: i64::from(size),
                walked: 0,
            });
        }
        let _array_index = self.i32("property array index")?;
        let mut extra = TagExtra::default();
        let mut bool_value = None;
        match property_type.as_str() {
            "StructProperty" => {
                extra.struct_name = Some(self.fname("struct name")?);
                self.skip(16, "struct guid")?;
            }
            "BoolProperty" => {
                bool_value = Some(
                    *self
                        .bytes
                        .get(self.offset)
                        .ok_or(DataTableError::UnexpectedEnd {
                            field: "bool value",
                        })?
                        != 0,
                );
                self.skip(1, "bool value")?;
            }
            "ByteProperty" | "EnumProperty" => {
                extra.enum_name = Some(self.fname("enum name")?);
            }
            "ArrayProperty" | "SetProperty" => {
                extra.inner = Some(self.fname("inner type")?);
            }
            "MapProperty" => {
                extra.key = Some(self.fname("map key type")?);
                extra.value = Some(self.fname("map value type")?);
            }
            _ => {}
        }
        let has_guid = *self
            .bytes
            .get(self.offset)
            .ok_or(DataTableError::UnexpectedEnd {
                field: "property guid flag",
            })?;
        self.offset += 1;
        if has_guid != 0 {
            self.skip(16, "property guid")?;
        }
        Ok(Some(PropertyTag {
            name,
            property_type,
            size,
            extra,
            bool_value,
        }))
    }

    /// Walks one property value and returns the offset just past it.
    ///
    /// `declared` is the tag's `Size`, or `None` for a container element, which
    /// carries no size of its own. `in_container` changes two encodings: a bool
    /// element is a real byte, and a raw byte element is one byte.
    fn value(
        &mut self,
        property_type: &str,
        extra: &TagExtra,
        declared: i32,
        in_container: bool,
    ) -> Result<usize> {
        self.value_inner(property_type, extra, Some(declared), in_container)
    }

    fn element(&mut self, property_type: &str) -> Result<usize> {
        self.value_inner(property_type, &TagExtra::default(), None, true)
    }

    fn value_inner(
        &mut self,
        property_type: &str,
        extra: &TagExtra,
        declared: Option<i32>,
        in_container: bool,
    ) -> Result<usize> {
        if self.depth >= MAX_DEPTH {
            return Err(DataTableError::DepthLimit);
        }
        match property_type {
            // A tagged bool keeps its value in the tag; a container element is
            // a real byte.
            "BoolProperty" => {
                if in_container {
                    self.skip(1, "bool element")?;
                }
                Ok(self.offset)
            }
            // A byte property is an FName when the tag says 8 bytes.
            "ByteProperty" => {
                if declared == Some(FNAME_SIZE as i32) {
                    self.value_fname("byte enum value")?;
                } else {
                    self.skip(usize::try_from(declared.unwrap_or(1)).unwrap_or(1), "byte")?;
                }
                Ok(self.offset)
            }
            "NameProperty" | "EnumProperty" => {
                self.value_fname("name value")?;
                Ok(self.offset)
            }
            "StrProperty" => {
                self.fstring("string value")?;
                Ok(self.offset)
            }
            "TextProperty" => self.text_value(declared),
            "SoftObjectProperty" | "SoftClassProperty" | "AssetObjectProperty" => {
                self.value_fname("soft object path")?;
                self.fstring("soft object sub path")?;
                Ok(self.offset)
            }
            // An FPackageIndex points into the import/export tables, not the
            // name table, so it cannot be retargeted by name. Its position is
            // recorded; the writer refuses to splice a field containing one
            // unless donor and carrier resolve it to the same identity.
            "ObjectProperty" | "ClassProperty" | "InterfaceProperty" | "LazyObjectProperty" => {
                if self.in_row {
                    self.package_index_sites.push(self.offset);
                }
                self.skip(4, "package index")?;
                Ok(self.offset)
            }
            "StructProperty" => self.struct_value(extra.struct_name.as_deref(), declared),
            "ArrayProperty" => self.array_value(extra.inner.as_deref(), declared),
            "SetProperty" => self.set_value(extra.inner.as_deref(), declared),
            "MapProperty" => self.map_value(extra.key.as_deref(), extra.value.as_deref(), declared),
            other => {
                if let Some(size) = fixed_value_size(other) {
                    self.skip(size, "fixed value")?;
                    return Ok(self.offset);
                }
                Err(DataTableError::UnsupportedProperty {
                    at: self.offset,
                    found: other.to_owned(),
                })
            }
        }
    }

    fn text_value(&mut self, declared: Option<i32>) -> Result<usize> {
        let start = self.offset;
        self.skip(4, "FText flags")?;
        let history = self.i8("FText history type")?;
        match history {
            -1 => {
                if self.i32("FText has culture-invariant string")? != 0 {
                    self.fstring("FText culture-invariant string")?;
                }
            }
            0 => {
                self.fstring("FText namespace")?;
                self.fstring("FText key")?;
                self.fstring("FText source string")?;
            }
            other => return Err(DataTableError::UnsupportedTextHistory { found: other }),
        }
        self.check_declared("FText", start, declared)?;
        Ok(self.offset)
    }

    fn struct_value(&mut self, struct_name: Option<&str>, declared: Option<i32>) -> Result<usize> {
        let name = struct_name.unwrap_or_default();
        if is_soft_path_struct(name) {
            let start = self.offset;
            self.value_fname("soft path asset name")?;
            self.fstring("soft path sub path")?;
            self.check_declared("soft path struct", start, declared)?;
            return Ok(self.offset);
        }
        if let Some(size) = native_binary_struct_size(name) {
            if let Some(declared) = declared
                && declared as usize != size
            {
                return Err(DataTableError::SizeMismatch {
                    context: format!("native struct {name}"),
                    declared: i64::from(declared),
                    walked: size as i64,
                });
            }
            self.skip(size, "native struct")?;
            return Ok(self.offset);
        }
        // Container elements carry neither a size nor a struct name, so a
        // tagged block terminated by "None" is the only readable form.
        if declared.is_none() && struct_name.is_none() {
            let here = self.offset;
            self.depth += 1;
            let result = self.tagged_block(here, "struct element");
            self.depth -= 1;
            result?;
            return Ok(self.offset);
        }
        let start = self.offset;
        self.depth += 1;
        let result = self.tagged_block(start, "struct property");
        self.depth -= 1;
        result?;
        self.check_declared("struct", start, declared)?;
        Ok(self.offset)
    }

    fn array_value(&mut self, inner: Option<&str>, declared: Option<i32>) -> Result<usize> {
        let start = self.offset;
        let count = self.i32("array count")?;
        let count = usize::try_from(count).map_err(|_| DataTableError::UnexpectedEnd {
            field: "array count",
        })?;
        let inner = inner.ok_or_else(|| DataTableError::UnsupportedProperty {
            at: start,
            found: "ArrayProperty without an inner type".to_owned(),
        })?;

        if inner == "StructProperty" {
            // Arrays of structs carry one inner FPropertyTag before the
            // elements; it names the element struct.
            let tag = self.read_tag("array inner tag")?.ok_or_else(|| {
                DataTableError::UnsupportedProperty {
                    at: start,
                    found: "array of struct without an inner tag".to_owned(),
                }
            })?;
            let element_struct = tag.extra.struct_name.clone().unwrap_or_default();
            let body_end = match declared {
                Some(declared) => start
                    .checked_add(usize::try_from(declared).unwrap_or(0))
                    .ok_or(DataTableError::UnexpectedEnd {
                        field: "array body",
                    })?,
                None => usize::MAX,
            };
            if let Some(size) = native_binary_struct_size(&element_struct) {
                let need = count
                    .checked_mul(size)
                    .ok_or(DataTableError::UnexpectedEnd {
                        field: "array body",
                    })?;
                self.skip(need, "array of native structs")?;
            } else {
                for _ in 0..count {
                    self.depth += 1;
                    let here = self.offset;
                    let result = self.tagged_block(here, "array struct element");
                    self.depth -= 1;
                    result?;
                }
            }
            if body_end != usize::MAX && self.offset != body_end {
                return Err(DataTableError::SizeMismatch {
                    context: format!("array of struct {element_struct}"),
                    declared: i64::from(declared.unwrap_or(0)),
                    walked: (self.offset as i64) - (start as i64),
                });
            }
            return Ok(self.offset);
        }

        for _ in 0..count {
            self.depth += 1;
            let result = self.element(inner);
            self.depth -= 1;
            result?;
        }
        self.check_declared("array", start, declared)?;
        Ok(self.offset)
    }

    fn set_value(&mut self, inner: Option<&str>, declared: Option<i32>) -> Result<usize> {
        let start = self.offset;
        self.skip(4, "set removal count")?;
        let count = self.i32("set count")?;
        let count = usize::try_from(count)
            .map_err(|_| DataTableError::UnexpectedEnd { field: "set count" })?;
        let inner = inner.ok_or_else(|| DataTableError::UnsupportedProperty {
            at: start,
            found: "SetProperty without an inner type".to_owned(),
        })?;
        for _ in 0..count {
            self.depth += 1;
            let result = self.element(inner);
            self.depth -= 1;
            result?;
        }
        self.check_declared("set", start, declared)?;
        Ok(self.offset)
    }

    fn map_value(
        &mut self,
        key: Option<&str>,
        value: Option<&str>,
        declared: Option<i32>,
    ) -> Result<usize> {
        let start = self.offset;
        self.skip(4, "map removal count")?;
        let count = self.i32("map count")?;
        let count = usize::try_from(count)
            .map_err(|_| DataTableError::UnexpectedEnd { field: "map count" })?;
        let key = key.ok_or_else(|| DataTableError::UnsupportedProperty {
            at: start,
            found: "MapProperty without a key type".to_owned(),
        })?;
        let value = value.ok_or_else(|| DataTableError::UnsupportedProperty {
            at: start,
            found: "MapProperty without a value type".to_owned(),
        })?;
        for _ in 0..count {
            self.depth += 1;
            let result = self.element(key).and_then(|_| self.element(value));
            self.depth -= 1;
            result?;
        }
        self.check_declared("map", start, declared)?;
        Ok(self.offset)
    }

    fn check_declared(&self, what: &str, start: usize, declared: Option<i32>) -> Result<()> {
        let Some(declared) = declared else {
            return Ok(());
        };
        let walked = (self.offset as i64) - (start as i64);
        if walked != i64::from(declared) {
            return Err(DataTableError::SizeMismatch {
                context: what.to_owned(),
                declared: i64::from(declared),
                walked,
            });
        }
        Ok(())
    }
}

#[derive(Debug, Default, Clone)]
struct TagExtra {
    struct_name: Option<String>,
    enum_name: Option<String>,
    inner: Option<String>,
    key: Option<String>,
    value: Option<String>,
}

struct PropertyTag {
    name: String,
    property_type: String,
    size: i32,
    extra: TagExtra,
    bool_value: Option<bool>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ue_package::encode_name_entry;

    /// Minimal name table plus the helpers to emit tags against it.
    struct Builder {
        names: Vec<String>,
        body: Vec<u8>,
    }

    impl Builder {
        fn new() -> Self {
            Self {
                names: Vec::new(),
                body: Vec::new(),
            }
        }

        fn name_index(&mut self, text: &str) -> i32 {
            if let Some(index) = self.names.iter().position(|name| name == text) {
                return index as i32;
            }
            self.names.push(text.to_owned());
            (self.names.len() - 1) as i32
        }

        fn fname(&mut self, text: &str) {
            let index = self.name_index(text);
            self.body.extend_from_slice(&index.to_le_bytes());
            self.body.extend_from_slice(&0_i32.to_le_bytes());
        }

        fn i32(&mut self, value: i32) {
            self.body.extend_from_slice(&value.to_le_bytes());
        }

        /// Emits one property tag and its value.
        fn tag(&mut self, name: &str, property_type: &str, value: &[u8], extra: Option<&str>) {
            self.fname(name);
            self.fname(property_type);
            self.i32(value.len() as i32);
            self.i32(0);
            match property_type {
                "StructProperty" => {
                    self.fname(extra.expect("struct name"));
                    self.body.extend_from_slice(&[0; 16]);
                }
                "BoolProperty" => self.body.push(0),
                "ByteProperty" | "EnumProperty" => self.fname(extra.expect("enum name")),
                "ArrayProperty" => self.fname(extra.expect("inner type")),
                _ => {}
            }
            self.body.push(0); // has_guid
            self.body.extend_from_slice(value);
        }

        fn none(&mut self) {
            self.fname(NONE);
        }

        fn package(&mut self) -> Ue4Package {
            // A name table is all DataTableIndex needs from the package.
            let mut bytes = Vec::new();
            for name in &self.names {
                bytes.extend_from_slice(&encode_name_entry(name, [0, 0, 0, 0]).unwrap());
            }
            crate::ue_package::Ue4Package::from_name_table_for_tests(&self.names)
        }
    }

    fn fname_bytes(builder: &mut Builder, text: &str) -> Vec<u8> {
        let index = builder.name_index(text);
        let mut out = index.to_le_bytes().to_vec();
        out.extend_from_slice(&0_i32.to_le_bytes());
        out
    }

    fn simple_table(rows: &[(&str, i32)]) -> (Vec<u8>, Ue4Package) {
        let mut builder = Builder::new();
        // Object block: a single RowStruct ObjectProperty tag is required, but
        // ObjectProperty is refused inside rows only, so emit it as raw bytes.
        builder.fname("RowStruct");
        builder.fname("ObjectProperty");
        builder.i32(4);
        builder.i32(0);
        builder.body.push(0);
        builder.i32(-5);
        builder.none();
        builder.i32(0); // zero trailer
        builder.i32(rows.len() as i32);
        for (name, value) in rows {
            builder.fname(name);
            builder.tag("Amount", "IntProperty", &value.to_le_bytes(), None);
            let label = fname_bytes(&mut builder, "Label");
            builder.tag("Kind", "NameProperty", &label, None);
            builder.none();
        }
        let package = builder.package();
        (builder.body.clone(), package)
    }

    #[test]
    fn indexes_rows_and_locates_every_field_and_fname() {
        let (body, package) = simple_table(&[("ROW_A", 7), ("ROW_B", 9)]);
        let index = DataTableIndex::parse(&body, &package).unwrap();

        assert_eq!(index.rows.len(), 2);
        assert_eq!(index.rows[0].name.as_ref(), "ROW_A");
        assert_eq!(index.rows[1].name.as_ref(), "ROW_B");
        assert_eq!(index.row_index("ROW_B"), Some(1));
        assert_eq!(index.row_index("missing"), None);
        assert_eq!(index.body_len, body.len());
        // Rows are contiguous and cover the body to its end.
        assert_eq!(index.rows[0].range.end, index.rows[1].range.start);
        assert_eq!(index.rows[1].range.end, body.len());

        let layout = index.row_layout(&body, &package, 0).unwrap();
        assert_eq!(layout.field_names().collect::<Vec<_>>(), ["Amount", "Kind"]);
        let amount = layout.field("Amount").unwrap();
        // An IntProperty value carries no FName; its tag header carries two.
        assert_eq!(amount.fname_sites.len(), 2);
        let kind = layout.field("Kind").unwrap();
        assert_eq!(kind.fname_sites.len(), 3);
        // The row-wide list adds the row's own name and the "None" terminator,
        // which is itself a name-table reference and so also needs retargeting.
        let sites = index.row_fname_sites(&body, &package, 0).unwrap();
        assert!(sites.contains(&index.rows[0].name_site));
        assert_eq!(
            sites.len(),
            1 + amount.fname_sites.len() + kind.fname_sites.len() + 1
        );
        // Field spans stop at the last tag, so they exclude the terminator.
        assert!(kind.range.end < index.rows[0].range.end);
    }

    #[test]
    fn a_declared_size_that_does_not_match_the_walk_is_an_error() {
        let (mut body, package) = simple_table(&[("ROW_A", 1)]);
        // Corrupt the first row property's declared size.
        let index = DataTableIndex::parse(&body, &package).unwrap();
        let layout = index.row_layout(&body, &package, 0).unwrap();
        let size_field = layout.field("Amount").unwrap().range.start + 2 * FNAME_SIZE;
        body[size_field..size_field + 4].copy_from_slice(&99_i32.to_le_bytes());

        let error = DataTableIndex::parse(&body, &package).unwrap_err();
        assert!(
            matches!(error, DataTableError::SizeMismatch { .. }),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn duplicate_row_names_are_refused() {
        let (body, package) = simple_table(&[("ROW_A", 1), ("ROW_A", 2)]);
        let error = DataTableIndex::parse(&body, &package).unwrap_err();
        assert!(
            matches!(error, DataTableError::DuplicateRow { .. }),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn a_package_index_inside_a_row_marks_only_that_field_unretargetable() {
        // An FPackageIndex points into the import/export tables, so it cannot
        // be retargeted by name. That must disqualify the one field carrying
        // it, not the whole table: real tables such as OT2's AilmentData nest
        // an ObjectProperty inside one array while every other field is
        // ordinary data.
        let mut builder = Builder::new();
        builder.fname("RowStruct");
        builder.fname("ObjectProperty");
        builder.i32(4);
        builder.i32(0);
        builder.body.push(0);
        builder.i32(-5);
        builder.none();
        builder.i32(0);
        builder.i32(1);
        builder.fname("ROW_A");
        builder.tag("Amount", "IntProperty", &7_i32.to_le_bytes(), None);
        builder.tag("Ref", "ObjectProperty", &(-2_i32).to_le_bytes(), None);
        builder.none();
        let package = builder.package();

        let index = DataTableIndex::parse(&builder.body, &package).unwrap();
        let layout = index.row_layout(&builder.body, &package, 0).unwrap();

        let amount = layout.field("Amount").unwrap();
        assert!(amount.is_name_retargetable());
        assert!(amount.package_index_sites.is_empty());

        let reference = layout.field("Ref").unwrap();
        assert!(!reference.is_name_retargetable());
        assert_eq!(reference.package_index_sites.len(), 1);
        // The recorded site is the FPackageIndex itself, at the end of the tag.
        assert_eq!(
            reference.package_index_sites[0],
            reference.range.end - 4,
            "the site must point at the 4-byte package index"
        );
    }

    /// Walks every cooked `UDataTable` in a local game tree. Ignored by default
    /// because the game files are not redistributable and absent from CI.
    ///
    /// ```text
    /// PAK_MERGER_UE4_PACKAGE_DIR=<cooked tree> \
    ///   cargo test --lib data_table -- --ignored --nocapture
    /// ```
    #[test]
    #[ignore = "requires a local cooked UE4 package tree"]
    fn walks_every_real_cooked_data_table_exactly() {
        let Ok(root) = std::env::var("PAK_MERGER_UE4_PACKAGE_DIR") else {
            panic!("set PAK_MERGER_UE4_PACKAGE_DIR to a directory of cooked .uasset files");
        };
        let mut tables = 0_usize;
        let mut rows = 0_usize;
        let mut fname_sites = 0_usize;
        let mut failures: Vec<String> = Vec::new();
        let mut package_index_tables: std::collections::BTreeSet<String> =
            std::collections::BTreeSet::new();
        let mut stack = vec![std::path::PathBuf::from(root)];
        while let Some(directory) = stack.pop() {
            for entry in std::fs::read_dir(&directory).expect("readable directory") {
                let path = entry.expect("readable entry").path();
                if path.is_dir() {
                    stack.push(path);
                    continue;
                }
                if path.extension().and_then(|value| value.to_str()) != Some("uasset") {
                    continue;
                }
                let uasset = std::fs::read(&path).expect("readable .uasset");
                let Ok(package) = Ue4Package::parse(&uasset) else {
                    continue;
                };
                let uexp_path = path.with_extension("uexp");
                let Ok(uexp) = std::fs::read(&uexp_path) else {
                    continue;
                };
                let Ok(serial) = usize::try_from(package.serial_size) else {
                    continue;
                };
                let Some(body) = uexp.get(..serial) else {
                    continue;
                };
                if package.export_class != "DataTable" {
                    continue;
                }
                let index = match DataTableIndex::parse(body, &package) {
                    Ok(index) => index,
                    Err(error) => {
                        failures.push(format!("{}: {error}", path.display()));
                        continue;
                    }
                };
                tables += 1;
                rows += index.rows.len();
                // Field layouts must round-trip too: every row's fields have to
                // tile the row body between the name and the terminator.
                for row_index in 0..index.rows.len() {
                    let layout = index
                        .row_layout(body, &package, row_index)
                        .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
                    let span = &index.rows[row_index];
                    let mut cursor = span.range.start + FNAME_SIZE;
                    for field in &layout.fields {
                        assert_eq!(field.range.start, cursor, "{}", path.display());
                        cursor = field.range.end;
                    }
                    assert_eq!(
                        cursor + FNAME_SIZE,
                        span.range.end,
                        "{} row {}",
                        path.display(),
                        span.name
                    );
                    fname_sites += index
                        .row_fname_sites(body, &package, row_index)
                        .expect("row fname sites")
                        .len();
                    if layout
                        .fields
                        .iter()
                        .any(|field| !field.is_name_retargetable())
                    {
                        package_index_tables.insert(path.display().to_string());
                    }
                }
            }
        }
        assert!(failures.is_empty(), "walk failures: {failures:#?}");
        assert!(tables > 0, "no cooked DataTables were found");
        println!("walked {tables} DataTables, {rows} rows, {fname_sites} FName sites");
        println!(
            "{} tables carry an FPackageIndex in row data",
            package_index_tables.len()
        );
    }

    #[test]
    fn trailing_bytes_after_the_last_row_are_refused() {
        let (mut body, package) = simple_table(&[("ROW_A", 1)]);
        body.push(0);
        let error = DataTableIndex::parse(&body, &package).unwrap_err();
        assert!(
            matches!(error, DataTableError::TrailingBytes { remaining: 1 }),
            "unexpected error: {error}"
        );
    }
}
