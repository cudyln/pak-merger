//! Reader and header rewriter for cooked Unreal Engine 4 legacy packages.
//!
//! Scope is deliberately narrow: unversioned, uncompressed, single-export
//! `LegacyFileVersion -7` packages, which is what OCTOPATH TRAVELER II ships its
//! `UDataTable` databases as. Anything else fails closed rather than being
//! parsed on a guess.
//!
//! Two jobs:
//!
//! * read the summary well enough to locate the name table, the export record
//!   and every offset field that a header rewrite has to move;
//! * rebuild the header after names are appended, without re-encoding anything
//!   that was already there. Existing name entries, the import table, the export
//!   table and the trailing sections are copied byte-for-byte; only the offset
//!   fields that must move are recomputed.
//!
//! Appended names always go on the end, so every pre-existing name index stays
//! valid and the tables that reference names by index need no rewriting.

use std::ops::Range;
use thiserror::Error;

/// `LegacyFileVersion` of the UE4 cooked packages handled here.
pub const UE4_LEGACY_FILE_VERSION: i32 = -7;
/// Package tag every legacy Unreal package starts with.
pub const PACKAGE_MAGIC: [u8; 4] = [0xC1, 0x83, 0x2A, 0x9E];
/// `PKG_FilterEditorOnly`; set on every cooked package.
pub const PKG_FILTER_EDITOR_ONLY: u32 = 0x8000_0000;

const MAX_NAME_COUNT: usize = 1_000_000;
const MAX_IMPORT_COUNT: usize = 1_000_000;
const MAX_GENERATIONS: usize = 1_000;
const MAX_CHUNK_IDS: usize = 1_000;
/// Longest name a cooked package is expected to carry, in bytes on disk.
const MAX_NAME_BYTES: usize = 4 * 1024;

pub const IMPORT_ENTRY_SIZE: usize = 28;
pub const EXPORT_ENTRY_SIZE: usize = 104;
const EXPORT_CLASS_INDEX_FIELD: usize = 0x00;
const EXPORT_OBJECT_NAME_FIELD: usize = 0x10;
const EXPORT_SERIAL_SIZE_FIELD: usize = 0x1C;
const EXPORT_SERIAL_OFFSET_FIELD: usize = 0x24;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum UePackageError {
    #[error("not an Unreal package: missing the C1 83 2A 9E tag")]
    NotAPackage,
    #[error("unsupported LegacyFileVersion {found}; expected {UE4_LEGACY_FILE_VERSION}")]
    UnsupportedLegacyVersion { found: i32 },
    #[error("package is versioned or carries custom versions, which is not supported")]
    NotUnversioned,
    #[error("TotalHeaderSize {declared} does not equal the .uasset length {actual}")]
    HeaderSizeMismatch { declared: u64, actual: usize },
    #[error("{field} is outside the package header")]
    OutOfRange { field: &'static str },
    #[error("{field} count {count} exceeds the supported maximum {limit}")]
    TooMany {
        field: &'static str,
        count: u64,
        limit: usize,
    },
    #[error("the name table does not end where the following section begins")]
    NameTableNotContiguous,
    #[error("package has {found} exports; exactly one is required")]
    ExportCount { found: u64 },
    #[error("{field} is not valid UTF-8")]
    InvalidText { field: &'static str },
    #[error("the rewritten header overflowed a 32-bit offset field")]
    Overflow,
}

type Result<T> = std::result::Result<T, UePackageError>;

/// One serialised `FNameEntry`: its decoded text plus the exact bytes it
/// occupies, so it can be copied into another package without re-encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameEntry {
    pub text: String,
    pub raw: Range<usize>,
}

/// Byte positions of the summary fields a header rewrite has to update.
///
/// The tail of an unversioned UE4 summary is variable length — `Generations` is
/// a counted array and both engine-version records end in an `FString` — so
/// these are discovered by walking rather than by fixed offsets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SummaryFieldOffsets {
    total_header_size: usize,
    name_count: usize,
    name_offset: usize,
    gatherable_text_data_offset: usize,
    export_offset: usize,
    import_offset: usize,
    depends_offset: usize,
    soft_package_references_offset: usize,
    searchable_names_offset: usize,
    thumbnail_table_offset: usize,
    asset_registry_data_offset: usize,
    bulk_data_start_offset: usize,
    world_tile_info_data_offset: usize,
    preload_dependency_offset: usize,
}

/// One `FObjectImport`, with its `FName` fields resolved to text.
///
/// Row data can carry an `FPackageIndex`, which is an index into this table (or
/// the export table). Splicing such a field across packages is only safe when
/// the index resolves to the same identity on both sides, so the identity has
/// to be readable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportEntry {
    pub class_package: String,
    pub class_name: String,
    pub outer_index: i32,
    pub object_name: String,
}

#[derive(Debug, Clone)]
pub struct Ue4Package {
    pub package_flags: u32,
    pub folder_name: String,
    pub name_offset: usize,
    pub names: Vec<NameEntry>,
    pub imports: Vec<ImportEntry>,
    /// Class of the single export, resolved through the import table.
    pub export_class: String,
    pub export_object_name: String,
    /// End of the last name entry. Must equal the start of the next section.
    pub name_table_end: usize,
    pub import_count: usize,
    pub import_offset: usize,
    pub export_offset: usize,
    pub total_header_size: usize,
    pub serial_size: u64,
    pub serial_offset: u64,
    pub bulk_data_start_offset: u64,
    /// Byte range of everything after the name table, up to `TotalHeaderSize`.
    pub tail: Range<usize>,
    fields: SummaryFieldOffsets,
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8], offset: usize) -> Self {
        Self { bytes, offset }
    }

    fn i32(&mut self, field: &'static str) -> Result<i32> {
        let value = read_i32(self.bytes, self.offset, field)?;
        self.offset += 4;
        Ok(value)
    }

    fn u32(&mut self, field: &'static str) -> Result<u32> {
        Ok(self.i32(field)? as u32)
    }

    fn i64(&mut self, field: &'static str) -> Result<i64> {
        let raw = self
            .bytes
            .get(self.offset..self.offset + 8)
            .ok_or(UePackageError::OutOfRange { field })?;
        self.offset += 8;
        Ok(i64::from_le_bytes(raw.try_into().expect("fixed range")))
    }

    fn skip(&mut self, amount: usize, field: &'static str) -> Result<()> {
        self.offset = self
            .offset
            .checked_add(amount)
            .filter(|end| *end <= self.bytes.len())
            .ok_or(UePackageError::OutOfRange { field })?;
        Ok(())
    }

    /// Reads an `FString`. Negative lengths are UTF-16; cooked packages use
    /// ASCII, so only the byte span is needed for the ones this reader skips.
    fn fstring(&mut self, field: &'static str) -> Result<String> {
        let length = self.i32(field)?;
        if length == 0 {
            return Ok(String::new());
        }
        if length > 0 {
            let count =
                usize::try_from(length).map_err(|_| UePackageError::OutOfRange { field })?;
            let raw = self
                .bytes
                .get(self.offset..self.offset + count)
                .ok_or(UePackageError::OutOfRange { field })?;
            self.offset += count;
            let text = std::str::from_utf8(raw.strip_suffix(b"\0").unwrap_or(raw))
                .map_err(|_| UePackageError::InvalidText { field })?;
            return Ok(text.to_owned());
        }
        let units = length
            .checked_neg()
            .and_then(|value| usize::try_from(value).ok())
            .ok_or(UePackageError::OutOfRange { field })?;
        let bytes = units
            .checked_mul(2)
            .ok_or(UePackageError::OutOfRange { field })?;
        let raw = self
            .bytes
            .get(self.offset..self.offset + bytes)
            .ok_or(UePackageError::OutOfRange { field })?;
        self.offset += bytes;
        let utf16: Vec<u16> = raw
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        let text = String::from_utf16(&utf16).map_err(|_| UePackageError::InvalidText { field })?;
        Ok(text.trim_end_matches('\0').to_owned())
    }

    /// `FEngineVersion`: major/minor/patch (u16), changelist (u32), branch.
    fn engine_version(&mut self) -> Result<()> {
        self.skip(6 + 4, "engine version")?;
        self.fstring("engine version branch")?;
        Ok(())
    }
}

impl Ue4Package {
    /// Parses the header of a cooked UE4 package.
    ///
    /// `bytes` must be the complete `.uasset`; the reader requires
    /// `TotalHeaderSize` to equal its length, which is what makes every offset
    /// in the summary checkable against a known end.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.get(..PACKAGE_MAGIC.len()) != Some(PACKAGE_MAGIC.as_slice()) {
            return Err(UePackageError::NotAPackage);
        }
        let legacy = read_i32(bytes, 4, "LegacyFileVersion")?;
        if legacy != UE4_LEGACY_FILE_VERSION {
            return Err(UePackageError::UnsupportedLegacyVersion { found: legacy });
        }
        // LegacyUE3Version, FileVersionUE4, FileVersionLicenseeUE4 and the
        // custom-version count must all be zero for an unversioned cook.
        if bytes.get(8..0x18) != Some(&[0; 16]) {
            return Err(UePackageError::NotUnversioned);
        }

        let mut cursor = Cursor::new(bytes, 0x18);
        let total_header_size_field = cursor.offset;
        let total_header_size = cursor.u32("TotalHeaderSize")?;
        if u64::from(total_header_size) != bytes.len() as u64 {
            return Err(UePackageError::HeaderSizeMismatch {
                declared: u64::from(total_header_size),
                actual: bytes.len(),
            });
        }
        let folder_name = cursor.fstring("FolderName")?;
        let package_flags = cursor.u32("PackageFlags")?;

        let name_count_field = cursor.offset;
        let name_count = counted(cursor.i32("NameCount")?, "NameCount", MAX_NAME_COUNT)?;
        let name_offset_field = cursor.offset;
        let name_offset = offset_within(cursor.i32("NameOffset")?, "NameOffset", bytes.len())?;

        // Cooked packages set PKG_FilterEditorOnly, which omits LocalizationId.
        if package_flags & PKG_FILTER_EDITOR_ONLY == 0 {
            cursor.fstring("LocalizationId")?;
        }

        cursor.i32("GatherableTextDataCount")?;
        let gatherable_text_data_offset_field = cursor.offset;
        cursor.i32("GatherableTextDataOffset")?;

        let export_count = cursor.i32("ExportCount")?;
        if export_count != 1 {
            return Err(UePackageError::ExportCount {
                found: export_count.max(0) as u64,
            });
        }
        let export_offset_field = cursor.offset;
        let export_offset =
            offset_within(cursor.i32("ExportOffset")?, "ExportOffset", bytes.len())?;
        let import_count = counted(cursor.i32("ImportCount")?, "ImportCount", MAX_IMPORT_COUNT)?;
        let import_offset_field = cursor.offset;
        let import_offset =
            offset_within(cursor.i32("ImportOffset")?, "ImportOffset", bytes.len())?;
        let depends_offset_field = cursor.offset;
        cursor.i32("DependsOffset")?;

        cursor.i32("SoftPackageReferencesCount")?;
        let soft_package_references_offset_field = cursor.offset;
        cursor.i32("SoftPackageReferencesOffset")?;
        let searchable_names_offset_field = cursor.offset;
        cursor.i32("SearchableNamesOffset")?;
        let thumbnail_table_offset_field = cursor.offset;
        cursor.i32("ThumbnailTableOffset")?;

        cursor.skip(16, "Guid")?;
        let generations = counted(cursor.i32("Generations")?, "Generations", MAX_GENERATIONS)?;
        cursor.skip(generations * 8, "Generations")?;
        cursor.engine_version()?;
        cursor.engine_version()?;
        cursor.u32("CompressionFlags")?;
        let compressed_chunks = cursor.i32("CompressedChunks")?;
        if compressed_chunks != 0 {
            return Err(UePackageError::TooMany {
                field: "CompressedChunks",
                count: compressed_chunks.max(0) as u64,
                limit: 0,
            });
        }
        cursor.u32("PackageSource")?;
        let additional_packages = cursor.i32("AdditionalPackagesToCook")?;
        if additional_packages != 0 {
            return Err(UePackageError::TooMany {
                field: "AdditionalPackagesToCook",
                count: additional_packages.max(0) as u64,
                limit: 0,
            });
        }
        let asset_registry_data_offset_field = cursor.offset;
        cursor.i32("AssetRegistryDataOffset")?;
        let bulk_data_start_offset_field = cursor.offset;
        let bulk_data_start_offset = cursor.i64("BulkDataStartOffset")?;
        let world_tile_info_data_offset_field = cursor.offset;
        cursor.i32("WorldTileInfoDataOffset")?;
        let chunk_ids = counted(cursor.i32("ChunkIDs")?, "ChunkIDs", MAX_CHUNK_IDS)?;
        cursor.skip(chunk_ids * 4, "ChunkIDs")?;
        cursor.i32("PreloadDependencyCount")?;
        let preload_dependency_offset_field = cursor.offset;
        cursor.i32("PreloadDependencyOffset")?;

        // The name table is expected to start immediately after the summary.
        // Anything else means an unrecognised layout, so fail rather than guess.
        if cursor.offset != name_offset {
            return Err(UePackageError::NameTableNotContiguous);
        }

        let (names, name_table_end) = parse_names(bytes, name_offset, name_count)?;
        let tail_start = import_offset.min(export_offset);
        if name_table_end != tail_start {
            return Err(UePackageError::NameTableNotContiguous);
        }

        let export_end = export_offset
            .checked_add(EXPORT_ENTRY_SIZE)
            .filter(|end| *end <= bytes.len())
            .ok_or(UePackageError::OutOfRange {
                field: "export table",
            })?;
        let _ = export_end;
        let serial_size = read_u64(
            bytes,
            export_offset + EXPORT_SERIAL_SIZE_FIELD,
            "export SerialSize",
        )?;
        let serial_offset = read_u64(
            bytes,
            export_offset + EXPORT_SERIAL_OFFSET_FIELD,
            "export SerialOffset",
        )?;

        let imports = parse_imports(bytes, import_offset, import_count, &names)?;
        let class_index = read_i32(
            bytes,
            export_offset + EXPORT_CLASS_INDEX_FIELD,
            "export class",
        )?;
        let export_class = resolve_package_index(class_index, &imports)
            .ok_or(UePackageError::OutOfRange {
                field: "export class index",
            })?
            .to_owned();
        let export_object_name =
            read_fname(bytes, export_offset + EXPORT_OBJECT_NAME_FIELD, &names)?;

        Ok(Self {
            package_flags,
            folder_name,
            name_offset,
            names,
            imports,
            export_class,
            export_object_name,
            name_table_end,
            import_count,
            import_offset,
            export_offset,
            total_header_size: total_header_size as usize,
            serial_size,
            serial_offset,
            bulk_data_start_offset: bulk_data_start_offset.max(0) as u64,
            tail: tail_start..bytes.len(),
            fields: SummaryFieldOffsets {
                total_header_size: total_header_size_field,
                name_count: name_count_field,
                name_offset: name_offset_field,
                gatherable_text_data_offset: gatherable_text_data_offset_field,
                export_offset: export_offset_field,
                import_offset: import_offset_field,
                depends_offset: depends_offset_field,
                soft_package_references_offset: soft_package_references_offset_field,
                searchable_names_offset: searchable_names_offset_field,
                thumbnail_table_offset: thumbnail_table_offset_field,
                asset_registry_data_offset: asset_registry_data_offset_field,
                bulk_data_start_offset: bulk_data_start_offset_field,
                world_tile_info_data_offset: world_tile_info_data_offset_field,
                preload_dependency_offset: preload_dependency_offset_field,
            },
        })
    }

    /// Resolves a name-table index the way export data references it.
    pub fn name(&self, index: usize) -> Option<&str> {
        self.names.get(index).map(|entry| entry.text.as_str())
    }

    /// Rebuilds the header with `appended_names` added to the end of the name
    /// table and the export record pointed at a `.uexp` of `new_serial_size`
    /// bytes.
    ///
    /// Every byte that is not an offset field is copied verbatim: existing name
    /// entries keep their exact encoding and stored hashes, and the import,
    /// export, depends, asset-registry and preload-dependency blocks move as one
    /// opaque block. Appended entries must already be in serialised
    /// `FNameEntry` form, which lets a donor package's bytes be reused instead
    /// of recomputing Unreal's name hashes.
    pub fn rewrite_header(
        &self,
        original: &[u8],
        appended_names: &[Vec<u8>],
        new_serial_size: u64,
    ) -> Result<Vec<u8>> {
        let delta: usize = appended_names.iter().map(Vec::len).sum();
        let new_total = self
            .total_header_size
            .checked_add(delta)
            .ok_or(UePackageError::Overflow)?;
        u32::try_from(new_total).map_err(|_| UePackageError::Overflow)?;

        let mut output = Vec::with_capacity(new_total);
        output.extend_from_slice(&original[..self.name_table_end]);
        for entry in appended_names {
            output.extend_from_slice(entry);
        }
        output.extend_from_slice(&original[self.tail.clone()]);
        debug_assert_eq!(output.len(), new_total);

        let new_name_count = self
            .names
            .len()
            .checked_add(appended_names.len())
            .ok_or(UePackageError::Overflow)?;
        put_u32(&mut output, self.fields.name_count, new_name_count)?;
        put_u32(&mut output, self.fields.total_header_size, new_total)?;

        // NameOffset does not move: the name table directly follows the summary.
        for field in [
            self.fields.gatherable_text_data_offset,
            self.fields.export_offset,
            self.fields.import_offset,
            self.fields.depends_offset,
            self.fields.soft_package_references_offset,
            self.fields.searchable_names_offset,
            self.fields.thumbnail_table_offset,
            self.fields.asset_registry_data_offset,
            self.fields.world_tile_info_data_offset,
            self.fields.preload_dependency_offset,
        ] {
            shift_optional_offset(&mut output, field, delta)?;
        }

        let new_export_offset = self
            .export_offset
            .checked_add(delta)
            .ok_or(UePackageError::Overflow)?;
        put_u64(
            &mut output,
            new_export_offset + EXPORT_SERIAL_SIZE_FIELD,
            new_serial_size,
        )?;
        put_u64(
            &mut output,
            new_export_offset + EXPORT_SERIAL_OFFSET_FIELD,
            new_total as u64,
        )?;
        put_u64(
            &mut output,
            self.fields.bulk_data_start_offset,
            (new_total as u64)
                .checked_add(new_serial_size)
                .ok_or(UePackageError::Overflow)?,
        )?;

        Ok(output)
    }

    /// Serialised bytes of one existing name entry, for copying into another
    /// package's name table.
    pub fn name_entry_bytes<'a>(&self, original: &'a [u8], index: usize) -> Option<&'a [u8]> {
        self.names
            .get(index)
            .and_then(|entry| original.get(entry.raw.clone()))
    }

    /// Builds a package carrying only a name table.
    ///
    /// Export-body readers need nothing else from the package, so this lets
    /// their tests describe a name table directly instead of assembling a full
    /// cooked header.
    #[cfg(test)]
    pub(crate) fn from_name_table_for_tests(names: &[String]) -> Self {
        let mut offset = 0;
        let names = names
            .iter()
            .map(|text| {
                let encoded = encode_name_entry(text, [0; 4]).expect("ascii test name");
                let raw = offset..offset + encoded.len();
                offset = raw.end;
                NameEntry {
                    text: text.clone(),
                    raw,
                }
            })
            .collect();
        Self {
            package_flags: PKG_FILTER_EDITOR_ONLY,
            folder_name: "None".to_owned(),
            name_offset: 0,
            names,
            imports: Vec::new(),
            export_class: "DataTable".to_owned(),
            export_object_name: "TestTable".to_owned(),
            name_table_end: offset,
            import_count: 0,
            import_offset: offset,
            export_offset: offset,
            total_header_size: offset,
            serial_size: 0,
            serial_offset: offset as u64,
            bulk_data_start_offset: offset as u64,
            tail: offset..offset,
            fields: SummaryFieldOffsets {
                total_header_size: 0,
                name_count: 0,
                name_offset: 0,
                gatherable_text_data_offset: 0,
                export_offset: 0,
                import_offset: 0,
                depends_offset: 0,
                soft_package_references_offset: 0,
                searchable_names_offset: 0,
                thumbnail_table_offset: 0,
                asset_registry_data_offset: 0,
                bulk_data_start_offset: 0,
                world_tile_info_data_offset: 0,
                preload_dependency_offset: 0,
            },
        }
    }
}

/// Resolves an `FPackageIndex` to a readable identity. Negative values index
/// the import table, `0` is null, and positive values index exports.
pub fn resolve_package_index(index: i32, imports: &[ImportEntry]) -> Option<&str> {
    if index >= 0 {
        return None;
    }
    let position = index.checked_neg()?.checked_sub(1)?;
    let position = usize::try_from(position).ok()?;
    imports
        .get(position)
        .map(|entry| entry.object_name.as_str())
}

fn read_fname(bytes: &[u8], offset: usize, names: &[NameEntry]) -> Result<String> {
    let index = read_i32(bytes, offset, "FName index")?;
    let number = read_i32(bytes, offset + 4, "FName number")?;
    let entry = usize::try_from(index)
        .ok()
        .and_then(|index| names.get(index))
        .ok_or(UePackageError::OutOfRange {
            field: "FName index",
        })?;
    Ok(if number <= 0 {
        entry.text.clone()
    } else {
        format!("{}_{}", entry.text, number - 1)
    })
}

fn parse_imports(
    bytes: &[u8],
    offset: usize,
    count: usize,
    names: &[NameEntry],
) -> Result<Vec<ImportEntry>> {
    let span = count
        .checked_mul(IMPORT_ENTRY_SIZE)
        .and_then(|span| offset.checked_add(span))
        .filter(|end| *end <= bytes.len())
        .ok_or(UePackageError::OutOfRange {
            field: "import table",
        })?;
    let _ = span;
    let mut imports = Vec::new();
    imports
        .try_reserve_exact(count)
        .map_err(|_| UePackageError::TooMany {
            field: "ImportCount",
            count: count as u64,
            limit: MAX_IMPORT_COUNT,
        })?;
    for index in 0..count {
        let base = offset + index * IMPORT_ENTRY_SIZE;
        imports.push(ImportEntry {
            class_package: read_fname(bytes, base, names)?,
            class_name: read_fname(bytes, base + 8, names)?,
            outer_index: read_i32(bytes, base + 16, "import outer")?,
            object_name: read_fname(bytes, base + 20, names)?,
        });
    }
    Ok(imports)
}

fn parse_names(bytes: &[u8], offset: usize, count: usize) -> Result<(Vec<NameEntry>, usize)> {
    let mut names = Vec::new();
    names
        .try_reserve_exact(count)
        .map_err(|_| UePackageError::TooMany {
            field: "NameCount",
            count: count as u64,
            limit: MAX_NAME_COUNT,
        })?;
    let mut cursor = Cursor::new(bytes, offset);
    for _ in 0..count {
        let start = cursor.offset;
        let text = cursor.fstring("name entry")?;
        if cursor.offset - start > MAX_NAME_BYTES {
            return Err(UePackageError::TooMany {
                field: "name entry",
                count: (cursor.offset - start) as u64,
                limit: MAX_NAME_BYTES,
            });
        }
        // Serialised FNameEntry carries the case-preserving and
        // non-case-preserving hashes; they are copied, never recomputed.
        cursor.skip(4, "name entry hashes")?;
        names.push(NameEntry {
            text,
            raw: start..cursor.offset,
        });
    }
    Ok((names, cursor.offset))
}

fn counted(value: i32, field: &'static str, limit: usize) -> Result<usize> {
    let count = usize::try_from(value).map_err(|_| UePackageError::OutOfRange { field })?;
    if count > limit {
        return Err(UePackageError::TooMany {
            field,
            count: count as u64,
            limit,
        });
    }
    Ok(count)
}

fn offset_within(value: i32, field: &'static str, limit: usize) -> Result<usize> {
    let offset = usize::try_from(value).map_err(|_| UePackageError::OutOfRange { field })?;
    if offset > limit {
        return Err(UePackageError::OutOfRange { field });
    }
    Ok(offset)
}

fn read_i32(bytes: &[u8], offset: usize, field: &'static str) -> Result<i32> {
    bytes
        .get(offset..offset + 4)
        .map(|raw| i32::from_le_bytes(raw.try_into().expect("fixed range")))
        .ok_or(UePackageError::OutOfRange { field })
}

fn read_u64(bytes: &[u8], offset: usize, field: &'static str) -> Result<u64> {
    bytes
        .get(offset..offset + 8)
        .map(|raw| u64::from_le_bytes(raw.try_into().expect("fixed range")))
        .ok_or(UePackageError::OutOfRange { field })
}

/// Shifts an offset field, leaving `0` alone: Unreal writes 0 for a section
/// that is not present, and 0 is not a position that can move.
fn shift_optional_offset(bytes: &mut [u8], field_offset: usize, delta: usize) -> Result<()> {
    let current = read_i32(bytes, field_offset, "summary offset")?;
    if current == 0 {
        return Ok(());
    }
    let shifted = usize::try_from(current)
        .ok()
        .and_then(|value| value.checked_add(delta))
        .ok_or(UePackageError::Overflow)?;
    put_u32(bytes, field_offset, shifted)
}

fn put_u32(bytes: &mut [u8], offset: usize, value: usize) -> Result<()> {
    let value = u32::try_from(value).map_err(|_| UePackageError::Overflow)?;
    bytes
        .get_mut(offset..offset + 4)
        .ok_or(UePackageError::OutOfRange {
            field: "summary field",
        })?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) -> Result<()> {
    bytes
        .get_mut(offset..offset + 8)
        .ok_or(UePackageError::OutOfRange {
            field: "summary field",
        })?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

/// Serialises one `FNameEntry` the way a cooked package stores it: an ASCII
/// `FString` including its NUL terminator, then the two stored hashes.
///
/// Only used for names that no donor package can supply verbatim.
pub fn encode_name_entry(text: &str, hashes: [u8; 4]) -> Option<Vec<u8>> {
    if !text.is_ascii() || text.contains('\0') {
        return None;
    }
    let length = i32::try_from(text.len() + 1).ok()?;
    let mut out = Vec::with_capacity(4 + text.len() + 1 + 4);
    out.extend_from_slice(&length.to_le_bytes());
    out.extend_from_slice(text.as_bytes());
    out.push(0);
    out.extend_from_slice(&hashes);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Names every synthetic package needs so its single export can resolve a
    /// class through the import table, exactly as a real cooked package does.
    const SUPPORT_NAMES: [&str; 3] = ["/Script/CoreUObject", "Class", "DataTable"];

    /// Builds a minimal but structurally faithful UE4 cooked package header.
    ///
    /// Caller names keep indices `0..names.len()`; the import-support names are
    /// appended after them.
    fn synthetic_package(names: &[&str], serial_size: u64) -> Vec<u8> {
        let mut all_names: Vec<&str> = names.to_vec();
        for support in SUPPORT_NAMES {
            if !all_names.contains(&support) {
                all_names.push(support);
            }
        }
        let names = all_names.as_slice();
        let name_index = |text: &str| {
            names
                .iter()
                .position(|name| *name == text)
                .expect("support name") as i32
        };
        let mut summary = Vec::new();
        summary.extend_from_slice(&PACKAGE_MAGIC);
        summary.extend_from_slice(&UE4_LEGACY_FILE_VERSION.to_le_bytes());
        summary.extend_from_slice(&[0; 16]); // unversioned
        summary.extend_from_slice(&0_u32.to_le_bytes()); // TotalHeaderSize, patched below
        summary.extend_from_slice(&5_i32.to_le_bytes()); // FolderName "None\0"
        summary.extend_from_slice(b"None\0");
        summary.extend_from_slice(&PKG_FILTER_EDITOR_ONLY.to_le_bytes());

        let name_count_at = summary.len();
        summary.extend_from_slice(&(names.len() as i32).to_le_bytes());
        let name_offset_at = summary.len();
        summary.extend_from_slice(&0_i32.to_le_bytes()); // NameOffset, patched below
        summary.extend_from_slice(&0_i32.to_le_bytes()); // GatherableTextDataCount
        summary.extend_from_slice(&0_i32.to_le_bytes()); // GatherableTextDataOffset
        summary.extend_from_slice(&1_i32.to_le_bytes()); // ExportCount
        let export_offset_at = summary.len();
        summary.extend_from_slice(&0_i32.to_le_bytes()); // ExportOffset
        summary.extend_from_slice(&1_i32.to_le_bytes()); // ImportCount
        let import_offset_at = summary.len();
        summary.extend_from_slice(&0_i32.to_le_bytes()); // ImportOffset
        let depends_offset_at = summary.len();
        summary.extend_from_slice(&0_i32.to_le_bytes()); // DependsOffset
        summary.extend_from_slice(&0_i32.to_le_bytes()); // SoftPackageReferencesCount
        summary.extend_from_slice(&0_i32.to_le_bytes()); // SoftPackageReferencesOffset
        summary.extend_from_slice(&0_i32.to_le_bytes()); // SearchableNamesOffset
        summary.extend_from_slice(&0_i32.to_le_bytes()); // ThumbnailTableOffset
        summary.extend_from_slice(&[0; 16]); // Guid
        summary.extend_from_slice(&1_i32.to_le_bytes()); // Generations
        summary.extend_from_slice(&[0; 8]); // one generation
        for _ in 0..2 {
            summary.extend_from_slice(&[0; 6]); // major/minor/patch
            summary.extend_from_slice(&0_u32.to_le_bytes()); // changelist
            summary.extend_from_slice(&0_i32.to_le_bytes()); // empty branch
        }
        summary.extend_from_slice(&0_u32.to_le_bytes()); // CompressionFlags
        summary.extend_from_slice(&0_i32.to_le_bytes()); // CompressedChunks
        summary.extend_from_slice(&0_u32.to_le_bytes()); // PackageSource
        summary.extend_from_slice(&0_i32.to_le_bytes()); // AdditionalPackagesToCook
        let asset_registry_at = summary.len();
        summary.extend_from_slice(&0_i32.to_le_bytes()); // AssetRegistryDataOffset
        let bulk_at = summary.len();
        summary.extend_from_slice(&0_u64.to_le_bytes()); // BulkDataStartOffset
        summary.extend_from_slice(&0_i32.to_le_bytes()); // WorldTileInfoDataOffset
        summary.extend_from_slice(&0_i32.to_le_bytes()); // ChunkIDs
        summary.extend_from_slice(&0_i32.to_le_bytes()); // PreloadDependencyCount
        let preload_at = summary.len();
        summary.extend_from_slice(&0_i32.to_le_bytes()); // PreloadDependencyOffset

        let name_offset = summary.len();
        let mut package = summary;
        for (index, name) in names.iter().enumerate() {
            package.extend_from_slice(&encode_name_entry(name, [index as u8, 0, 0, 0]).unwrap());
        }
        // One import: Class'/Script/CoreUObject.DataTable', which the export's
        // ClassIndex -1 resolves to.
        let import_offset = package.len();
        let fname = |bytes: &mut Vec<u8>, text: &str| {
            bytes.extend_from_slice(&name_index(text).to_le_bytes());
            bytes.extend_from_slice(&0_i32.to_le_bytes());
        };
        fname(&mut package, "/Script/CoreUObject");
        fname(&mut package, "Class");
        package.extend_from_slice(&0_i32.to_le_bytes()); // OuterIndex
        fname(&mut package, "DataTable");

        let export_offset = package.len();
        package.extend_from_slice(&[0; EXPORT_ENTRY_SIZE]);
        package[export_offset..export_offset + 4].copy_from_slice(&(-1_i32).to_le_bytes());
        package[export_offset + EXPORT_OBJECT_NAME_FIELD
            ..export_offset + EXPORT_OBJECT_NAME_FIELD + 4]
            .copy_from_slice(&0_i32.to_le_bytes());
        let depends_offset = package.len();
        package.extend_from_slice(&0_i32.to_le_bytes());
        let asset_registry_offset = package.len();
        package.extend_from_slice(&0_i32.to_le_bytes());
        let preload_offset = package.len();
        package.extend_from_slice(&0_i32.to_le_bytes());
        let total = package.len();

        let put32 = |bytes: &mut Vec<u8>, at: usize, value: usize| {
            bytes[at..at + 4].copy_from_slice(&(value as u32).to_le_bytes());
        };
        put32(&mut package, 0x18, total);
        put32(&mut package, name_offset_at, name_offset);
        put32(&mut package, export_offset_at, export_offset);
        put32(&mut package, import_offset_at, import_offset);
        put32(&mut package, depends_offset_at, depends_offset);
        put32(&mut package, asset_registry_at, asset_registry_offset);
        put32(&mut package, preload_at, preload_offset);
        package[bulk_at..bulk_at + 8].copy_from_slice(&(total as u64 + serial_size).to_le_bytes());
        package[export_offset + EXPORT_SERIAL_SIZE_FIELD
            ..export_offset + EXPORT_SERIAL_SIZE_FIELD + 8]
            .copy_from_slice(&serial_size.to_le_bytes());
        package[export_offset + EXPORT_SERIAL_OFFSET_FIELD
            ..export_offset + EXPORT_SERIAL_OFFSET_FIELD + 8]
            .copy_from_slice(&(total as u64).to_le_bytes());
        let _ = name_count_at;
        package
    }

    #[test]
    fn parses_a_cooked_ue4_header_and_locates_every_section() {
        let package = synthetic_package(&["None", "RowStruct", "EnemyGroup"], 4096);
        let parsed = Ue4Package::parse(&package).unwrap();

        assert_eq!(parsed.folder_name, "None");
        assert_eq!(parsed.package_flags, PKG_FILTER_EDITOR_ONLY);
        assert_eq!(parsed.names.len(), 3 + SUPPORT_NAMES.len());
        assert_eq!(parsed.name(1), Some("RowStruct"));
        assert_eq!(parsed.export_class, "DataTable");
        assert_eq!(parsed.imports.len(), 1);
        assert_eq!(parsed.imports[0].class_name, "Class");
        assert_eq!(parsed.total_header_size, package.len());
        assert_eq!(parsed.serial_size, 4096);
        assert_eq!(parsed.serial_offset, package.len() as u64);
        assert_eq!(
            parsed.bulk_data_start_offset,
            package.len() as u64 + parsed.serial_size
        );
        // 193 is the summary size of a real OT2 cooked DataTable header
        // (FolderName "None", one generation, empty engine-version branches,
        // no chunk ids). Matching it exactly is what proves this reader walks
        // the same variable-length tail the shipped packages use.
        assert_eq!(parsed.name_offset, 193);
        assert_eq!(parsed.import_count, 1);
        // The name table must run from the end of the summary to the next section.
        assert_eq!(parsed.name_table_end, parsed.tail.start);
    }

    #[test]
    fn rewriting_with_no_new_names_reproduces_the_input_bytes() {
        let package = synthetic_package(&["None", "RowStruct"], 512);
        let parsed = Ue4Package::parse(&package).unwrap();
        let rewritten = parsed
            .rewrite_header(&package, &[], parsed.serial_size)
            .unwrap();
        assert_eq!(rewritten, package);
    }

    #[test]
    fn appending_names_shifts_every_section_offset_and_keeps_old_indices() {
        let package = synthetic_package(&["None", "RowStruct"], 512);
        let parsed = Ue4Package::parse(&package).unwrap();
        let appended = vec![encode_name_entry("ENE_BOS_EXT_LOW_010", [1, 2, 3, 4]).unwrap()];
        let delta = appended[0].len();
        let new_serial = 777;

        let rewritten = parsed
            .rewrite_header(&package, &appended, new_serial)
            .unwrap();
        let reparsed = Ue4Package::parse(&rewritten).unwrap();

        assert_eq!(rewritten.len(), package.len() + delta);
        assert_eq!(reparsed.total_header_size, rewritten.len());
        assert_eq!(reparsed.names.len(), 2 + SUPPORT_NAMES.len() + 1);
        // Pre-existing indices are unchanged, which is what lets the import and
        // export tables move as opaque bytes.
        assert_eq!(reparsed.name(0), Some("None"));
        assert_eq!(reparsed.name(1), Some("RowStruct"));
        assert_eq!(
            reparsed.name(2 + SUPPORT_NAMES.len()),
            Some("ENE_BOS_EXT_LOW_010")
        );
        assert_eq!(reparsed.export_offset, parsed.export_offset + delta);
        assert_eq!(reparsed.serial_size, new_serial);
        assert_eq!(reparsed.serial_offset, rewritten.len() as u64);
        assert_eq!(
            reparsed.bulk_data_start_offset,
            rewritten.len() as u64 + new_serial
        );
        // The appended entry keeps the exact bytes it was given.
        assert_eq!(
            reparsed.name_entry_bytes(&rewritten, 2 + SUPPORT_NAMES.len()),
            Some(appended[0].as_slice())
        );
    }

    /// Validates the reader against real cooked packages instead of synthetic
    /// ones. Ignored by default because the game files are not redistributable
    /// and are not present in CI.
    ///
    /// Point `PAK_MERGER_UE4_PACKAGE_DIR` at a directory of cooked `.uasset`
    /// files and run:
    ///
    /// ```text
    /// cargo test --lib ue_package -- --ignored --nocapture
    /// ```
    #[test]
    #[ignore = "requires a local cooked UE4 package tree"]
    fn reads_real_cooked_packages_and_round_trips_their_headers() {
        let Ok(root) = std::env::var("PAK_MERGER_UE4_PACKAGE_DIR") else {
            panic!("set PAK_MERGER_UE4_PACKAGE_DIR to a directory of cooked .uasset files");
        };
        let mut checked = 0_usize;
        let mut rejected: std::collections::BTreeMap<String, usize> =
            std::collections::BTreeMap::new();
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
                let bytes = std::fs::read(&path).expect("readable .uasset");
                let parsed = match Ue4Package::parse(&bytes) {
                    Ok(parsed) => parsed,
                    Err(error) => {
                        // Rejections must be the reader's declared scope limits,
                        // not accidental parse failures, so they are tallied by
                        // kind rather than silently skipped.
                        let kind = match error {
                            UePackageError::ExportCount { .. } => "multi-export package",
                            UePackageError::NotAPackage => "not a package",
                            UePackageError::UnsupportedLegacyVersion { .. } => "not UE4 legacy -7",
                            UePackageError::NotUnversioned => "versioned package",
                            other => Box::leak(other.to_string().into_boxed_str()),
                        };
                        *rejected.entry(kind.to_owned()).or_default() += 1;
                        continue;
                    }
                };
                assert_eq!(parsed.total_header_size, bytes.len(), "{}", path.display());
                assert_eq!(
                    parsed.serial_offset,
                    bytes.len() as u64,
                    "{}",
                    path.display()
                );
                assert_eq!(
                    parsed.bulk_data_start_offset,
                    parsed.serial_offset + parsed.serial_size,
                    "{}",
                    path.display()
                );
                assert_eq!(
                    parsed.name_table_end,
                    parsed.tail.start,
                    "{}",
                    path.display()
                );
                // Rewriting without changes must reproduce the input exactly.
                let rewritten = parsed
                    .rewrite_header(&bytes, &[], parsed.serial_size)
                    .expect("rewrite");
                assert_eq!(rewritten, bytes, "{}", path.display());
                checked += 1;
            }
        }
        assert!(checked > 0, "no cooked UE4 packages were found");
        println!("validated {checked} cooked UE4 packages");
        for (kind, count) in &rejected {
            println!("  rejected {count} as: {kind}");
        }
        // Every rejection must be one of the reader's declared scope limits.
        // Anything else means the walk went wrong on a real shipped package.
        let unexpected: Vec<_> = rejected
            .keys()
            .filter(|kind| {
                !matches!(
                    kind.as_str(),
                    "multi-export package"
                        | "not a package"
                        | "not UE4 legacy -7"
                        | "versioned package"
                )
            })
            .collect();
        assert!(
            unexpected.is_empty(),
            "unexpected rejections: {unexpected:?}"
        );
    }

    #[test]
    fn rejects_packages_outside_the_supported_cook() {
        let package = synthetic_package(&["None"], 16);

        let mut not_a_package = package.clone();
        not_a_package[0] = 0;
        assert_eq!(
            Ue4Package::parse(&not_a_package).unwrap_err(),
            UePackageError::NotAPackage
        );

        let mut ue5 = package.clone();
        ue5[4..8].copy_from_slice(&(-8_i32).to_le_bytes());
        assert!(matches!(
            Ue4Package::parse(&ue5),
            Err(UePackageError::UnsupportedLegacyVersion { found: -8 })
        ));

        let mut versioned = package.clone();
        versioned[12..16].copy_from_slice(&522_i32.to_le_bytes());
        assert_eq!(
            Ue4Package::parse(&versioned).unwrap_err(),
            UePackageError::NotUnversioned
        );

        let mut truncated = package.clone();
        truncated.pop();
        assert!(matches!(
            Ue4Package::parse(&truncated),
            Err(UePackageError::HeaderSizeMismatch { .. })
        ));

        let mut two_exports = package;
        // ExportCount sits 12 bytes after NameOffset in this layout.
        let export_count_at = 0x18 + 4 + 4 + 5 + 4 + 4 + 4 + 8;
        two_exports[export_count_at..export_count_at + 4].copy_from_slice(&2_i32.to_le_bytes());
        assert!(matches!(
            Ue4Package::parse(&two_exports),
            Err(UePackageError::ExportCount { found: 2 })
        ));
    }
}
