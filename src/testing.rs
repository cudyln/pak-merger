//! Test-only builders for synthetic game data.
//!
//! Merging cooked UE4 `UDataTable` packages has to be exercised against real
//! package structure — a header whose offsets all agree, a name table the export
//! data indexes into, and an import the export resolves its class through.
//! Hand-writing that in each test would bury the behaviour under byte plumbing,
//! so it lives here.

#![cfg(test)]

pub mod datatable {
    use crate::ue_package::{
        EXPORT_ENTRY_SIZE, IMPORT_ENTRY_SIZE, PACKAGE_MAGIC, PKG_FILTER_EDITOR_ONLY,
        UE4_LEGACY_FILE_VERSION, encode_name_entry,
    };

    /// One synthetic table: rows of `(RowName, Amount: int, Label: FName)`, and
    /// optionally a `Ref` `ObjectProperty` on the first row pointing at an
    /// import the carrier may or may not have.
    #[derive(Debug, Clone)]
    pub struct TableSpec {
        pub rows: Vec<(&'static str, i32, &'static str)>,
        pub reference_import: Option<&'static str>,
        /// When set, every row also carries a `Detail` `TextProperty` holding
        /// this source string. Text is the shape most localisation mods edit.
        pub text: Option<&'static str>,
    }

    impl TableSpec {
        pub fn new(rows: &[(&'static str, i32, &'static str)]) -> Self {
            Self {
                rows: rows.to_vec(),
                reference_import: None,
                text: None,
            }
        }

        pub fn with_text(mut self, text: &'static str) -> Self {
            self.text = Some(text);
            self
        }
    }

    /// Serialises an `FString` the way cooked data stores ASCII: length
    /// including the NUL terminator, then the bytes.
    fn fstring(text: &str) -> Vec<u8> {
        let mut out = ((text.len() + 1) as i32).to_le_bytes().to_vec();
        out.extend_from_slice(text.as_bytes());
        out.push(0);
        out
    }

    /// `FText` with a Base history: flags, history type 0, namespace, key,
    /// source string.
    fn ftext(source: &str) -> Vec<u8> {
        let mut out = 0_u32.to_le_bytes().to_vec();
        out.push(0);
        out.extend_from_slice(&fstring(""));
        out.extend_from_slice(&fstring("KEY"));
        out.extend_from_slice(&fstring(source));
        out
    }

    #[derive(Default)]
    struct Names(Vec<String>);

    impl Names {
        fn index(&mut self, text: &str) -> i32 {
            if let Some(index) = self.0.iter().position(|name| name == text) {
                return index as i32;
            }
            self.0.push(text.to_owned());
            (self.0.len() - 1) as i32
        }
    }

    struct Body {
        bytes: Vec<u8>,
    }

    impl Body {
        fn fname(&mut self, names: &mut Names, text: &str) {
            let index = names.index(text);
            self.bytes.extend_from_slice(&index.to_le_bytes());
            self.bytes.extend_from_slice(&0_i32.to_le_bytes());
        }

        fn i32(&mut self, value: i32) {
            self.bytes.extend_from_slice(&value.to_le_bytes());
        }

        /// Emits a property tag plus its value.
        fn tag(&mut self, names: &mut Names, name: &str, kind: &str, value: &[u8]) {
            self.fname(names, name);
            self.fname(names, kind);
            self.i32(value.len() as i32);
            self.i32(0);
            self.bytes.push(0); // no property guid
            self.bytes.extend_from_slice(value);
        }
    }

    /// Builds a `.uasset` / `.uexp` pair for one synthetic `UDataTable`.
    pub fn build_table(spec: &TableSpec) -> (Vec<u8>, Vec<u8>) {
        let mut names = Names::default();
        // "None" must exist: it terminates every tagged-property block.
        names.index("None");

        let mut body = Body { bytes: Vec::new() };
        // Object block: RowStruct -> the row-struct import at package index -2.
        body.tag(
            &mut names,
            "RowStruct",
            "ObjectProperty",
            &(-2_i32).to_le_bytes(),
        );
        body.fname(&mut names, "None");
        body.i32(0); // zero trailer
        body.i32(spec.rows.len() as i32);

        for (position, (row, amount, label)) in spec.rows.iter().enumerate() {
            body.fname(&mut names, row);
            body.tag(&mut names, "Amount", "IntProperty", &amount.to_le_bytes());
            let label_index = names.index(label);
            let mut label_value = label_index.to_le_bytes().to_vec();
            label_value.extend_from_slice(&0_i32.to_le_bytes());
            body.tag(&mut names, "Label", "NameProperty", &label_value);
            if let Some(text) = spec.text {
                body.tag(&mut names, "Detail", "TextProperty", &ftext(text));
            }
            if position == 0 && spec.reference_import.is_some() {
                // Package index -3: the optional third import.
                body.tag(&mut names, "Ref", "ObjectProperty", &(-3_i32).to_le_bytes());
            }
            body.fname(&mut names, "None");
        }
        let serial_size = body.bytes.len() as u64;

        // Imports the export and the row struct resolve through.
        let mut imports: Vec<(String, String, String)> = vec![
            (
                "/Script/CoreUObject".to_owned(),
                "Class".to_owned(),
                "DataTable".to_owned(),
            ),
            (
                "/Script/Engine".to_owned(),
                "UserDefinedStruct".to_owned(),
                "TestRow".to_owned(),
            ),
        ];
        if let Some(target) = spec.reference_import {
            imports.push((
                "/Script/Engine".to_owned(),
                "Texture2D".to_owned(),
                target.to_owned(),
            ));
        }
        let export_object_name = names.index("SyntheticTable");
        let import_names: Vec<[i32; 3]> = imports
            .iter()
            .map(|(package, class, object)| {
                [
                    names.index(package),
                    names.index(class),
                    names.index(object),
                ]
            })
            .collect();

        // --- summary -------------------------------------------------------
        let mut summary = Vec::new();
        summary.extend_from_slice(&PACKAGE_MAGIC);
        summary.extend_from_slice(&UE4_LEGACY_FILE_VERSION.to_le_bytes());
        summary.extend_from_slice(&[0; 16]); // unversioned
        summary.extend_from_slice(&0_u32.to_le_bytes()); // TotalHeaderSize
        summary.extend_from_slice(&5_i32.to_le_bytes());
        summary.extend_from_slice(b"None\0"); // FolderName
        summary.extend_from_slice(&PKG_FILTER_EDITOR_ONLY.to_le_bytes());
        let name_count_at = summary.len();
        summary.extend_from_slice(&0_i32.to_le_bytes()); // NameCount
        let name_offset_at = summary.len();
        summary.extend_from_slice(&0_i32.to_le_bytes()); // NameOffset
        summary.extend_from_slice(&0_i32.to_le_bytes()); // GatherableTextDataCount
        summary.extend_from_slice(&0_i32.to_le_bytes()); // GatherableTextDataOffset
        summary.extend_from_slice(&1_i32.to_le_bytes()); // ExportCount
        let export_offset_at = summary.len();
        summary.extend_from_slice(&0_i32.to_le_bytes());
        summary.extend_from_slice(&(imports.len() as i32).to_le_bytes()); // ImportCount
        let import_offset_at = summary.len();
        summary.extend_from_slice(&0_i32.to_le_bytes());
        let depends_offset_at = summary.len();
        summary.extend_from_slice(&0_i32.to_le_bytes());
        summary.extend_from_slice(&0_i32.to_le_bytes()); // SoftPackageReferencesCount
        summary.extend_from_slice(&0_i32.to_le_bytes()); // SoftPackageReferencesOffset
        summary.extend_from_slice(&0_i32.to_le_bytes()); // SearchableNamesOffset
        summary.extend_from_slice(&0_i32.to_le_bytes()); // ThumbnailTableOffset
        summary.extend_from_slice(&[0; 16]); // Guid
        summary.extend_from_slice(&1_i32.to_le_bytes()); // Generations
        summary.extend_from_slice(&[0; 8]);
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
        summary.extend_from_slice(&0_i32.to_le_bytes());
        let bulk_at = summary.len();
        summary.extend_from_slice(&0_u64.to_le_bytes());
        summary.extend_from_slice(&0_i32.to_le_bytes()); // WorldTileInfoDataOffset
        summary.extend_from_slice(&0_i32.to_le_bytes()); // ChunkIDs
        summary.extend_from_slice(&0_i32.to_le_bytes()); // PreloadDependencyCount
        let preload_at = summary.len();
        summary.extend_from_slice(&0_i32.to_le_bytes());

        // --- name table, imports, exports, trailing sections ---------------
        let name_offset = summary.len();
        let mut uasset = summary;
        for (index, name) in names.0.iter().enumerate() {
            uasset.extend_from_slice(
                &encode_name_entry(name, [index as u8, 0, 0, 0]).expect("ascii test name"),
            );
        }
        let import_offset = uasset.len();
        for entry in &import_names {
            for value in entry.iter().take(2) {
                uasset.extend_from_slice(&value.to_le_bytes());
                uasset.extend_from_slice(&0_i32.to_le_bytes());
            }
            uasset.extend_from_slice(&0_i32.to_le_bytes()); // OuterIndex
            uasset.extend_from_slice(&entry[2].to_le_bytes());
            uasset.extend_from_slice(&0_i32.to_le_bytes());
        }
        debug_assert_eq!(
            uasset.len() - import_offset,
            imports.len() * IMPORT_ENTRY_SIZE
        );

        let export_offset = uasset.len();
        uasset.extend_from_slice(&[0; EXPORT_ENTRY_SIZE]);
        uasset[export_offset..export_offset + 4].copy_from_slice(&(-1_i32).to_le_bytes());
        uasset[export_offset + 0x10..export_offset + 0x14]
            .copy_from_slice(&export_object_name.to_le_bytes());

        let depends_offset = uasset.len();
        uasset.extend_from_slice(&0_i32.to_le_bytes());
        let asset_registry_offset = uasset.len();
        uasset.extend_from_slice(&0_i32.to_le_bytes());
        let preload_offset = uasset.len();
        uasset.extend_from_slice(&0_i32.to_le_bytes());
        let total = uasset.len();

        let put32 = |bytes: &mut Vec<u8>, at: usize, value: usize| {
            bytes[at..at + 4].copy_from_slice(&(value as u32).to_le_bytes());
        };
        put32(&mut uasset, 0x18, total);
        put32(&mut uasset, name_count_at, names.0.len());
        put32(&mut uasset, name_offset_at, name_offset);
        put32(&mut uasset, export_offset_at, export_offset);
        put32(&mut uasset, import_offset_at, import_offset);
        put32(&mut uasset, depends_offset_at, depends_offset);
        put32(&mut uasset, asset_registry_at, asset_registry_offset);
        put32(&mut uasset, preload_at, preload_offset);
        uasset[bulk_at..bulk_at + 8].copy_from_slice(&(total as u64 + serial_size).to_le_bytes());
        uasset[export_offset + 0x1C..export_offset + 0x24]
            .copy_from_slice(&serial_size.to_le_bytes());
        uasset[export_offset + 0x24..export_offset + 0x2C]
            .copy_from_slice(&(total as u64).to_le_bytes());

        let mut uexp = body.bytes;
        uexp.extend_from_slice(&PACKAGE_MAGIC);
        (uasset, uexp)
    }
}
