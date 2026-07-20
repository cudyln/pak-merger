use crate::types::{MergePlan, MergeReport, ResolutionSet};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::Path;

pub fn sha256_file(path: &Path) -> io::Result<String> {
    let mut reader = BufReader::new(File::open(path)?);
    let mut digest = Sha256::new();
    // Keep the 1 MiB buffer off the Windows main-thread stack.
    let mut buffer = vec![0_u8; 1024 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(hex::encode(digest.finalize()))
}

pub fn write_json<T: serde::Serialize>(path: &Path, value: &T) -> anyhow::Result<()> {
    let file = OpenOptions::new().write(true).create_new(true).open(path)?;
    let mut writer = BufWriter::new(file);
    serde_json::to_writer_pretty(&mut writer, value)?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    writer.get_ref().sync_all()?;
    Ok(())
}

pub fn read_plan(path: &Path) -> anyhow::Result<MergePlan> {
    Ok(serde_json::from_reader(BufReader::new(File::open(path)?))?)
}

pub fn read_resolutions(path: &Path) -> anyhow::Result<ResolutionSet> {
    Ok(serde_json::from_reader(BufReader::new(File::open(path)?))?)
}

pub fn read_report(path: &Path) -> anyhow::Result<MergeReport> {
    Ok(serde_json::from_reader(BufReader::new(File::open(path)?))?)
}

pub fn stable_json_hash<T: serde::Serialize>(value: &T) -> anyhow::Result<String> {
    let bytes = serde_json::to_vec(value)?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn sha256_file_uses_heap_buffer_on_a_small_stack() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("payload.bin");
        let payload = vec![0xA5; 2 * 1024 * 1024 + 17];
        fs::write(&path, &payload).unwrap();
        let expected = hex::encode(Sha256::digest(&payload));

        let actual = std::thread::Builder::new()
            .name("small-stack-sha256".to_owned())
            .stack_size(128 * 1024)
            .spawn(move || sha256_file(&path).unwrap())
            .unwrap()
            .join()
            .unwrap();

        assert_eq!(actual, expected);
    }
}
