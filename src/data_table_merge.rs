//! Lossless merge of cooked UE4 `UDataTable` packages.
//!
//! The carrier package supplies every byte that is not explicitly replaced.
//! Selected donor fields and donor-only rows are copied as raw bytes, with only
//! their `FName` indices and `FPackageIndex` values retargeted at the merged
//! package's tables. Nothing is re-encoded.
//!
//! Two structural facts keep this simple, both measured on the real game data:
//!
//! * a row has **no length field** and `NumRows` is a count, not a byte size, so
//!   replacing a whole top-level property changes no enclosing size. The cascade
//!   that element-level splicing would need stops before it starts.
//! * `FName` (8 bytes) and `FPackageIndex` (4 bytes) are fixed width, so
//!   retargeting never changes a length either.
//!
//! The merged name table keeps the carrier's entries at their original indices
//! and appends only what a donor needs, copying the donor's exact serialised
//! entry — including its stored hashes — rather than recomputing anything.

use crate::data_table::{DataTableError, DataTableIndex, RowField, RowLayout};
use crate::profiles::AssetProfile;
use crate::types::AtomicGroup;
use crate::ue_package::{ImportEntry, Ue4Package, UePackageError};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DataTableMergeError {
    #[error(transparent)]
    Package(#[from] UePackageError),
    #[error(transparent)]
    Table(#[from] DataTableError),
    #[error("donor {donor} does not contain row {row}")]
    MissingDonorRow { donor: usize, row: String },
    #[error("donor {donor} row {row} does not contain field {field}")]
    MissingDonorField {
        donor: usize,
        row: String,
        field: String,
    },
    #[error(
        "the base Pak's row {row} does not contain field {field}, so there is nothing to replace"
    )]
    MissingCarrierField { row: String, field: String },
    #[error(
        "{row}.{field} cannot be taken from donor {donor}: it references {identity}, which the base Pak's package does not import"
    )]
    UnresolvableReference {
        donor: usize,
        row: String,
        field: String,
        identity: String,
    },
    #[error("donor index {donor} is out of range")]
    InvalidDonor { donor: usize },
    #[error("row {row} has no field {field}")]
    UnknownField { row: String, field: String },
    #[error("profile group {group} is only partly present in row {row} ({missing})")]
    PartialGroup {
        group: String,
        row: String,
        missing: String,
    },
    #[error("the merged package would exceed the 32-bit size the format allows")]
    Overflow,
}

type Result<T> = std::result::Result<T, DataTableMergeError>;

/// One parsed `.uasset` + `.uexp` pair.
pub struct DataTableImage {
    pub uasset: Vec<u8>,
    pub uexp: Vec<u8>,
    pub package: Ue4Package,
    pub index: DataTableIndex,
}

impl DataTableImage {
    pub fn parse(uasset: Vec<u8>, uexp: Vec<u8>) -> Result<Self> {
        let package = Ue4Package::parse(&uasset)?;
        let serial =
            usize::try_from(package.serial_size).map_err(|_| DataTableMergeError::Overflow)?;
        let body = uexp.get(..serial).ok_or(UePackageError::OutOfRange {
            field: ".uexp body",
        })?;
        let index = DataTableIndex::parse(body, &package)?;
        Ok(Self {
            uasset,
            uexp,
            package,
            index,
        })
    }

    /// Export payload, excluding the trailing package tag.
    pub fn body(&self) -> &[u8] {
        &self.uexp[..self.index.body_len]
    }

    /// The 4-byte package tag the `.uexp` ends with.
    fn package_tag(&self) -> &[u8] {
        &self.uexp[self.index.body_len..]
    }

    pub fn row_layout(&self, row_index: usize) -> Result<RowLayout> {
        Ok(self
            .index
            .row_layout(self.body(), &self.package, row_index)?)
    }

    /// Digest of one unit's value that ignores name-table layout.
    ///
    /// Two Paks built from the same original can hold identical values at
    /// different `FName` indices, so hashing raw bytes would report a conflict
    /// where none exists. Every `FName` is therefore replaced by the text it
    /// resolves to, and every `FPackageIndex` by the import identity it names,
    /// before hashing.
    pub fn unit_semantic_digest(&self, layout: &RowLayout, fields: &[String]) -> Result<String> {
        let mut digest = Sha256::new();
        digest.update(b"PAK-MERGER-DATATABLE-UNIT-V1");
        for name in fields {
            let field = layout
                .field(name)
                .ok_or_else(|| DataTableMergeError::UnknownField {
                    row: String::new(),
                    field: name.clone(),
                })?;
            digest.update((name.len() as u64).to_le_bytes());
            digest.update(name.as_bytes());
            let normalized = self.normalized_field_bytes(field)?;
            digest.update((normalized.len() as u64).to_le_bytes());
            digest.update(&normalized);
        }
        Ok(hex::encode(digest.finalize()))
    }

    /// Field bytes with every reference replaced by the text it resolves to.
    fn normalized_field_bytes(&self, field: &RowField) -> Result<Vec<u8>> {
        let body = self.body();
        let mut out = Vec::with_capacity(field.range.len());
        let mut cursor = field.range.start;
        let mut markers: Vec<(usize, bool)> = field
            .fname_sites
            .iter()
            .map(|site| (*site, true))
            .chain(field.package_index_sites.iter().map(|site| (*site, false)))
            .collect();
        markers.sort_unstable();
        for (site, is_name) in markers {
            out.extend_from_slice(&body[cursor..site]);
            if is_name {
                let index = read_i32(body, site);
                let text = self
                    .package
                    .name(usize::try_from(index).unwrap_or(usize::MAX))
                    .unwrap_or("<unknown>");
                out.extend_from_slice(text.as_bytes());
                // The instance number stays significant.
                out.extend_from_slice(&body[site + 4..site + 8]);
                cursor = site + 8;
            } else {
                let index = read_i32(body, site);
                match package_index_import(index, &self.package.imports) {
                    Some(entry) => out.extend_from_slice(describe_import(entry).as_bytes()),
                    None => out.extend_from_slice(&index.to_le_bytes()),
                }
                cursor = site + 4;
            }
        }
        out.extend_from_slice(&body[cursor..field.range.end]);
        Ok(out)
    }

    /// Short human-readable summary of a unit, for the conflict picker.
    pub fn unit_preview(&self, layout: &RowLayout, fields: &[String]) -> String {
        const MAX_PREVIEW: usize = 96;
        let mut preview = String::new();
        for name in fields {
            let Some(field) = layout.field(name) else {
                continue;
            };
            if !preview.is_empty() {
                preview.push_str(", ");
            }
            let short = name.split('_').next().unwrap_or(name);
            let bytes = self.normalized_field_bytes(field).unwrap_or_default();
            preview.push_str(short);
            preview.push('=');
            preview.push_str(&hex::encode(&bytes[..bytes.len().min(8)]));
            if preview.len() >= MAX_PREVIEW {
                preview.truncate(MAX_PREVIEW);
                preview.push('…');
                break;
            }
        }
        preview
    }
}

/// Builds field-selection units for one DataTable row from a profile.
///
/// This mirrors the MessagePack planner but works on field *names* alone: a
/// DataTable value is never decoded, so there is nothing to inspect. A group
/// that is only partly present is an error, exactly as it is for an audited
/// MessagePack profile — a half-applied group is how linked values get split.
pub fn atomic_units_for_row(
    profile: &AssetProfile,
    row_name: &str,
    field_names: &[String],
) -> Result<Vec<AtomicGroup>> {
    let present: BTreeSet<&str> = field_names.iter().map(String::as_str).collect();
    let mut consumed: BTreeSet<&str> = BTreeSet::new();
    let mut units = Vec::new();

    for rule in &profile.groups {
        let found: Vec<&String> = rule
            .fields
            .iter()
            .filter(|field| present.contains(field.as_str()))
            .collect();
        if found.is_empty() {
            continue;
        }
        if found.len() != rule.fields.len() {
            let missing = rule
                .fields
                .iter()
                .filter(|field| !present.contains(field.as_str()))
                .cloned()
                .collect::<Vec<_>>()
                .join(", ");
            return Err(DataTableMergeError::PartialGroup {
                group: rule.id.clone(),
                row: row_name.to_owned(),
                missing,
            });
        }
        for field in &found {
            consumed.insert(field.as_str());
        }
        units.push(AtomicGroup {
            id: format!("group:{}", rule.id),
            fields: found.into_iter().cloned().collect(),
            compound: true,
            array_index: None,
            expected_array_len: None,
        });
    }

    for name in field_names {
        if consumed.contains(name.as_str()) {
            continue;
        }
        units.push(AtomicGroup {
            id: format!("field:{name}"),
            fields: vec![name.clone()],
            compound: false,
            array_index: None,
            expected_array_len: None,
        });
    }
    Ok(units)
}

/// What the merged table takes from where.
#[derive(Debug, Default, Clone)]
pub struct DataTableSelections {
    /// `(row name, field name) -> donor index`. Absent means keep the carrier's.
    pub fields: BTreeMap<(String, String), usize>,
    /// Rows absent from the carrier, appended in order: `(row name, donor)`.
    pub appended_rows: Vec<(String, usize)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergedDataTable {
    pub uasset: Vec<u8>,
    pub uexp: Vec<u8>,
    /// Names appended to the carrier's table to satisfy donor references.
    pub appended_name_count: usize,
}

/// Builds the merged name table lazily, keeping carrier indices stable.
struct NameTableBuilder<'a> {
    carrier: &'a Ue4Package,
    lookup: BTreeMap<String, usize>,
    appended: Vec<Vec<u8>>,
}

impl<'a> NameTableBuilder<'a> {
    fn new(carrier: &'a Ue4Package) -> Self {
        let lookup = carrier
            .names
            .iter()
            .enumerate()
            // First occurrence wins so an accidental duplicate never moves an
            // index that existing carrier bytes already reference.
            .rev()
            .map(|(index, entry)| (entry.text.clone(), index))
            .collect();
        Self {
            carrier,
            lookup,
            appended: Vec::new(),
        }
    }

    /// Index of `text` in the merged table, appending the donor's exact entry
    /// bytes if the carrier does not already have it.
    fn intern(
        &mut self,
        text: &str,
        donor: &Ue4Package,
        donor_uasset: &[u8],
        donor_index: usize,
    ) -> usize {
        if let Some(index) = self.lookup.get(text) {
            return *index;
        }
        let entry = donor
            .name_entry_bytes(donor_uasset, donor_index)
            .expect("donor name index came from the donor's own table")
            .to_vec();
        let merged_index = self.carrier.names.len() + self.appended.len();
        self.appended.push(entry);
        self.lookup.insert(text.to_owned(), merged_index);
        merged_index
    }
}

/// Same import identity, in the sense that matters for a reference: the object,
/// its class, and the package the class comes from.
fn import_identity(entry: &ImportEntry) -> (&str, &str, &str) {
    (
        entry.class_package.as_str(),
        entry.class_name.as_str(),
        entry.object_name.as_str(),
    )
}

fn describe_import(entry: &ImportEntry) -> String {
    format!(
        "{}'{}.{}'",
        entry.class_name, entry.class_package, entry.object_name
    )
}

/// Copies donor bytes and retargets every reference in them.
///
/// `sites` are absolute offsets into the donor body; `range` is the donor byte
/// range being copied.
struct Retargeter<'a, 'b> {
    names: &'a mut NameTableBuilder<'b>,
    carrier_imports: &'a [ImportEntry],
}

impl Retargeter<'_, '_> {
    #[allow(clippy::too_many_arguments)]
    fn copy(
        &mut self,
        donor_number: usize,
        donor: &Ue4Package,
        donor_uasset: &[u8],
        donor_body: &[u8],
        range: std::ops::Range<usize>,
        fname_sites: &[usize],
        package_index_sites: &[usize],
        context: impl Fn() -> (String, String),
    ) -> Result<Vec<u8>> {
        let mut bytes = donor_body[range.clone()].to_vec();

        for site in fname_sites {
            let local = site - range.start;
            let donor_index = read_i32(&bytes, local);
            let text = donor
                .names
                .get(usize::try_from(donor_index).unwrap_or(usize::MAX))
                .map(|entry| entry.text.clone())
                .ok_or(UePackageError::OutOfRange {
                    field: "donor FName index",
                })?;
            let merged = self.names.intern(
                &text,
                donor,
                donor_uasset,
                usize::try_from(donor_index).unwrap_or(0),
            );
            let merged = i32::try_from(merged).map_err(|_| DataTableMergeError::Overflow)?;
            bytes[local..local + 4].copy_from_slice(&merged.to_le_bytes());
        }

        for site in package_index_sites {
            let local = site - range.start;
            let donor_index = read_i32(&bytes, local);
            // Null references need no work; only imports are retargetable.
            if donor_index == 0 {
                continue;
            }
            let donor_import = package_index_import(donor_index, &donor.imports);
            let (row, field) = context();
            let donor_import =
                donor_import.ok_or_else(|| DataTableMergeError::UnresolvableReference {
                    donor: donor_number,
                    row: row.clone(),
                    field: field.clone(),
                    identity: format!("export index {donor_index}"),
                })?;
            let carrier_position = self
                .carrier_imports
                .iter()
                .position(|entry| import_identity(entry) == import_identity(donor_import))
                .ok_or_else(|| DataTableMergeError::UnresolvableReference {
                    donor: donor_number,
                    row,
                    field,
                    identity: describe_import(donor_import),
                })?;
            let retargeted =
                -(i32::try_from(carrier_position).map_err(|_| DataTableMergeError::Overflow)? + 1);
            bytes[local..local + 4].copy_from_slice(&retargeted.to_le_bytes());
        }

        Ok(bytes)
    }
}

fn package_index_import(index: i32, imports: &[ImportEntry]) -> Option<&ImportEntry> {
    if index >= 0 {
        return None;
    }
    let position = usize::try_from(index.checked_neg()?.checked_sub(1)?).ok()?;
    imports.get(position)
}

fn read_i32(bytes: &[u8], offset: usize) -> i32 {
    i32::from_le_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("caller bounds-checked the site"),
    )
}

/// Merges donor selections into the carrier and returns the new package pair.
pub fn merge_data_table(
    carrier: &DataTableImage,
    donors: &[&DataTableImage],
    selections: &DataTableSelections,
) -> Result<MergedDataTable> {
    let carrier_body = carrier.body();
    let mut names = NameTableBuilder::new(&carrier.package);

    // Header: the object property block, the zero trailer and NumRows are
    // carrier bytes. Only NumRows changes.
    let mut body = carrier_body[..carrier.index.row_count_field].to_vec();
    let row_count = carrier
        .index
        .rows
        .len()
        .checked_add(selections.appended_rows.len())
        .ok_or(DataTableMergeError::Overflow)?;
    body.extend_from_slice(
        &i32::try_from(row_count)
            .map_err(|_| DataTableMergeError::Overflow)?
            .to_le_bytes(),
    );

    for (row_index, span) in carrier.index.rows.iter().enumerate() {
        let row_name = span.name.as_ref();
        let selected: Vec<(&String, &usize)> = selections
            .fields
            .iter()
            .filter(|((row, _), _)| row.as_str() == row_name)
            .map(|((_, field), donor)| (field, donor))
            .collect();
        if selected.is_empty() {
            // Untouched rows are copied byte-for-byte, exactly like the OT0
            // reader preserves rows it does not need to change.
            body.extend_from_slice(&carrier_body[span.range.clone()]);
            continue;
        }

        let layout = carrier
            .index
            .row_layout(carrier_body, &carrier.package, row_index)?;
        let mut replacements: BTreeMap<usize, Vec<u8>> = BTreeMap::new();
        for (field_name, donor_number) in selected {
            let carrier_field = layout.field(field_name).ok_or_else(|| {
                DataTableMergeError::MissingCarrierField {
                    row: row_name.to_owned(),
                    field: field_name.clone(),
                }
            })?;
            let donor = *donors
                .get(*donor_number)
                .ok_or(DataTableMergeError::InvalidDonor {
                    donor: *donor_number,
                })?;
            let donor_field = donor_row_field(donor, row_name, field_name, *donor_number)?;
            let bytes = Retargeter {
                names: &mut names,
                carrier_imports: &carrier.package.imports,
            }
            .copy(
                *donor_number,
                &donor.package,
                &donor.uasset,
                donor.body(),
                donor_field.range.clone(),
                &donor_field.fname_sites,
                &donor_field.package_index_sites,
                || (row_name.to_owned(), field_name.clone()),
            )?;
            replacements.insert(carrier_field.range.start, bytes);
        }

        // Splice the row: carrier bytes with the selected field ranges swapped.
        let mut cursor = span.range.start;
        for field in &layout.fields {
            if let Some(bytes) = replacements.remove(&field.range.start) {
                body.extend_from_slice(&carrier_body[cursor..field.range.start]);
                body.extend_from_slice(&bytes);
                cursor = field.range.end;
            }
        }
        body.extend_from_slice(&carrier_body[cursor..span.range.end]);
    }

    for (row_name, donor_number) in &selections.appended_rows {
        let donor = *donors
            .get(*donor_number)
            .ok_or(DataTableMergeError::InvalidDonor {
                donor: *donor_number,
            })?;
        let donor_index = donor.index.row_index(row_name).ok_or_else(|| {
            DataTableMergeError::MissingDonorRow {
                donor: *donor_number,
                row: row_name.clone(),
            }
        })?;
        let span = &donor.index.rows[donor_index];
        let fname_sites = donor
            .index
            .row_fname_sites(donor.body(), &donor.package, donor_index)?;
        let layout = donor
            .index
            .row_layout(donor.body(), &donor.package, donor_index)?;
        let package_index_sites: Vec<usize> = layout
            .fields
            .iter()
            .flat_map(|field| field.package_index_sites.iter().copied())
            .collect();
        let bytes = Retargeter {
            names: &mut names,
            carrier_imports: &carrier.package.imports,
        }
        .copy(
            *donor_number,
            &donor.package,
            &donor.uasset,
            donor.body(),
            span.range.clone(),
            &fname_sites,
            &package_index_sites,
            || (row_name.clone(), "<whole row>".to_owned()),
        )?;
        body.extend_from_slice(&bytes);
    }

    let mut uexp = body;
    let serial_size = u64::try_from(uexp.len()).map_err(|_| DataTableMergeError::Overflow)?;
    uexp.extend_from_slice(carrier.package_tag());

    let appended_name_count = names.appended.len();
    let uasset = carrier
        .package
        .rewrite_header(&carrier.uasset, &names.appended, serial_size)?;

    Ok(MergedDataTable {
        uasset,
        uexp,
        appended_name_count,
    })
}

fn donor_row_field(
    donor: &DataTableImage,
    row_name: &str,
    field_name: &str,
    donor_number: usize,
) -> Result<RowField> {
    let donor_row =
        donor
            .index
            .row_index(row_name)
            .ok_or_else(|| DataTableMergeError::MissingDonorRow {
                donor: donor_number,
                row: row_name.to_owned(),
            })?;
    let layout = donor
        .index
        .row_layout(donor.body(), &donor.package, donor_row)?;
    layout
        .field(field_name)
        .cloned()
        .ok_or_else(|| DataTableMergeError::MissingDonorField {
            donor: donor_number,
            row: row_name.to_owned(),
            field: field_name.to_owned(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::datatable::{TableSpec, build_table};

    fn image(spec: &TableSpec) -> DataTableImage {
        let (uasset, uexp) = build_table(spec);
        DataTableImage::parse(uasset, uexp).expect("synthetic table parses")
    }

    fn base() -> TableSpec {
        TableSpec::new(&[("ROW_A", 1, "Alpha"), ("ROW_B", 2, "Beta")])
    }

    #[test]
    fn merging_a_table_with_an_unchanged_copy_reproduces_the_input_bytes() {
        let carrier = image(&base());
        let donor = image(&base());
        let merged =
            merge_data_table(&carrier, &[&donor], &DataTableSelections::default()).unwrap();

        assert_eq!(merged.uasset, carrier.uasset);
        assert_eq!(merged.uexp, carrier.uexp);
        assert_eq!(merged.appended_name_count, 0);
    }

    #[test]
    fn a_numeric_field_is_taken_from_the_donor_without_touching_the_name_table() {
        let carrier = image(&base());
        let mut changed = base();
        changed.rows[1].1 = 99;
        let donor = image(&changed);

        let mut selections = DataTableSelections::default();
        selections
            .fields
            .insert(("ROW_B".to_owned(), "Amount".to_owned()), 0);
        let merged = merge_data_table(&carrier, &[&donor], &selections).unwrap();

        // Value-only edits need no new names, so the header is untouched.
        assert_eq!(merged.appended_name_count, 0);
        assert_eq!(merged.uasset, carrier.uasset);
        assert_eq!(merged.uexp.len(), carrier.uexp.len());

        let result = DataTableImage::parse(merged.uasset.clone(), merged.uexp.clone()).unwrap();
        assert_eq!(result.index.rows.len(), 2);
        let layout = result
            .index
            .row_layout(result.body(), &result.package, 1)
            .unwrap();
        let amount = layout.field("Amount").unwrap();
        let value = read_i32(result.body(), amount.range.end - 4);
        assert_eq!(value, 99);
        // The row the user did not choose keeps the carrier's bytes.
        assert_eq!(
            &merged.uexp[result.index.rows[0].range.clone()],
            &carrier.uexp[carrier.index.rows[0].range.clone()]
        );
    }

    #[test]
    fn a_donor_name_missing_from_the_carrier_is_appended_and_retargeted() {
        let carrier = image(&base());
        let mut changed = base();
        changed.rows[0].2 = "GammaOnlyInDonor";
        let donor = image(&changed);

        let mut selections = DataTableSelections::default();
        selections
            .fields
            .insert(("ROW_A".to_owned(), "Label".to_owned()), 0);
        let merged = merge_data_table(&carrier, &[&donor], &selections).unwrap();

        assert_eq!(merged.appended_name_count, 1);
        assert!(merged.uasset.len() > carrier.uasset.len());

        let result = DataTableImage::parse(merged.uasset.clone(), merged.uexp.clone()).unwrap();
        // Carrier indices are untouched; the new name lands at the end.
        for (index, entry) in carrier.package.names.iter().enumerate() {
            assert_eq!(result.package.name(index), Some(entry.text.as_str()));
        }
        assert_eq!(
            result.package.name(carrier.package.names.len()),
            Some("GammaOnlyInDonor")
        );
        let layout = result
            .index
            .row_layout(result.body(), &result.package, 0)
            .unwrap();
        let label = layout.field("Label").unwrap();
        let name_index = read_i32(result.body(), label.range.end - 8);
        assert_eq!(
            result.package.name(name_index as usize),
            Some("GammaOnlyInDonor")
        );
    }

    #[test]
    fn a_donor_only_row_is_appended_whole() {
        let carrier = image(&base());
        let mut extended = base();
        extended.rows.push(("ROW_C", 7, "OnlyInDonor"));
        let donor = image(&extended);

        let mut selections = DataTableSelections::default();
        selections.appended_rows.push(("ROW_C".to_owned(), 0));
        let merged = merge_data_table(&carrier, &[&donor], &selections).unwrap();

        let result = DataTableImage::parse(merged.uasset.clone(), merged.uexp.clone()).unwrap();
        assert_eq!(result.index.rows.len(), 3);
        assert_eq!(result.index.rows[2].name.as_ref(), "ROW_C");
        assert!(result.index.row_index("ROW_C").is_some());
        // Both the row name and its label were new, so two names were appended.
        assert_eq!(merged.appended_name_count, 2);
    }

    #[test]
    fn two_donors_can_contribute_different_fields_of_the_same_row() {
        let carrier = image(&base());
        let mut first = base();
        first.rows[0].1 = 50;
        let mut second = base();
        second.rows[0].2 = "FromSecondDonor";
        let donor_a = image(&first);
        let donor_b = image(&second);

        let mut selections = DataTableSelections::default();
        selections
            .fields
            .insert(("ROW_A".to_owned(), "Amount".to_owned()), 0);
        selections
            .fields
            .insert(("ROW_A".to_owned(), "Label".to_owned()), 1);
        let merged = merge_data_table(&carrier, &[&donor_a, &donor_b], &selections).unwrap();

        let result = DataTableImage::parse(merged.uasset.clone(), merged.uexp.clone()).unwrap();
        let layout = result
            .index
            .row_layout(result.body(), &result.package, 0)
            .unwrap();
        assert_eq!(
            read_i32(result.body(), layout.field("Amount").unwrap().range.end - 4),
            50
        );
        let label = layout.field("Label").unwrap();
        let name_index = read_i32(result.body(), label.range.end - 8);
        assert_eq!(
            result.package.name(name_index as usize),
            Some("FromSecondDonor")
        );
    }

    #[test]
    fn a_reference_the_carrier_cannot_resolve_is_refused() {
        // Both sides have the field, but the donor's reference points at an
        // import the carrier's package does not have, so it cannot be
        // retargeted and the splice must be refused rather than guessed.
        let mut carrier_spec = base();
        carrier_spec.reference_import = Some("SharedTarget");
        let carrier = image(&carrier_spec);
        let mut with_reference = base();
        with_reference.reference_import = Some("SomethingTheCarrierLacks");
        let donor = image(&with_reference);

        let mut selections = DataTableSelections::default();
        selections
            .fields
            .insert(("ROW_A".to_owned(), "Ref".to_owned()), 0);
        let error = merge_data_table(&carrier, &[&donor], &selections).unwrap_err();
        assert!(
            matches!(error, DataTableMergeError::UnresolvableReference { .. }),
            "unexpected error: {error}"
        );
        assert!(error.to_string().contains("SomethingTheCarrierLacks"));

        // The same reference resolves when both packages import it, and the
        // index is retargeted rather than copied blindly.
        let matching = image(&carrier_spec);
        let merged = merge_data_table(&carrier, &[&matching], &selections).unwrap();
        assert_eq!(merged.uexp, carrier.uexp);
    }

    #[test]
    fn replacing_a_field_the_base_pak_does_not_have_is_refused() {
        let carrier = image(&base());
        let mut with_reference = base();
        with_reference.reference_import = Some("SomethingNew");
        let donor = image(&with_reference);

        let mut selections = DataTableSelections::default();
        selections
            .fields
            .insert(("ROW_A".to_owned(), "Ref".to_owned()), 0);
        let error = merge_data_table(&carrier, &[&donor], &selections).unwrap_err();
        assert!(
            matches!(error, DataTableMergeError::MissingCarrierField { .. }),
            "unexpected error: {error}"
        );
    }
}
