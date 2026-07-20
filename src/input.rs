//! Read-only inspection for a user-supplied Pak input.

use crate::pak::{PakError, PakInventory, inspect_pak};
use crate::types::PakInput;
use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum InspectError {
    #[error("could not inspect {path}: {source}")]
    Pak {
        path: PathBuf,
        #[source]
        source: PakError,
    },
}

pub fn inspect(PakInput { path }: PakInput) -> Result<PakInventory, InspectError> {
    inspect_pak(&path).map_err(|source| InspectError::Pak { path, source })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pak::{PakWriteEntry, write_pak_v11_to};
    use std::io::Cursor;

    #[test]
    fn inspects_strict_pak() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("input.pak");
        let bytes = write_pak_v11_to(
            Cursor::new(Vec::new()),
            "../../../Game/Content/",
            [PakWriteEntry::new("A/One.uasset", b"one".to_vec())],
        )
        .unwrap()
        .into_inner();
        std::fs::write(&path, bytes).unwrap();

        let inventory = inspect(PakInput { path }).unwrap();
        assert_eq!(inventory.footer.version, 11);
        assert_eq!(inventory.entries.len(), 1);
    }

    #[test]
    fn preserves_pak_error_context() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("broken.pak");
        std::fs::write(&path, b"broken").unwrap();
        assert!(matches!(
            inspect(PakInput { path }),
            Err(InspectError::Pak { .. })
        ));
    }
}
