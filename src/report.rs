use crate::types::{MERGE_PLAN_SCHEMA_VERSION, MergePlan, ResolutionSet};
use anyhow::{Context, bail};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

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
    let mut plan: MergePlan = serde_json::from_reader(BufReader::new(File::open(path)?))?;
    if plan.schema_version != MERGE_PLAN_SCHEMA_VERSION {
        bail!(
            "unsupported comparison schema version {}; expected {}",
            plan.schema_version,
            MERGE_PLAN_SCHEMA_VERSION
        );
    }

    let plan_path = std::fs::canonicalize(path)
        .with_context(|| format!("couldn't resolve the comparison file: {}", path.display()))?;
    let plan_directory = plan_path
        .parent()
        .context("the comparison file has no parent directory")?;
    rebase_legacy_plan_paths(&mut plan, plan_directory);
    Ok(plan)
}

pub fn read_resolutions(path: &Path) -> anyhow::Result<ResolutionSet> {
    Ok(serde_json::from_reader(BufReader::new(File::open(path)?))?)
}

pub fn stable_json_hash<T: serde::Serialize>(value: &T) -> anyhow::Result<String> {
    let bytes = serde_json::to_vec(value)?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

fn rebase_legacy_plan_paths(plan: &mut MergePlan, plan_directory: &Path) {
    for path in &mut plan.request.pak_paths {
        rebase_legacy_path(path, plan_directory);
    }
    rebase_legacy_path(&mut plan.request.carrier_path, plan_directory);
    for input in &mut plan.inputs {
        rebase_legacy_path(&mut input.path, plan_directory);
    }
    for conflict in &mut plan.conflicts {
        for variant in &mut conflict.variants {
            rebase_legacy_path(&mut variant.provenance.input_path, plan_directory);
        }
    }
}

fn rebase_legacy_path(path: &mut PathBuf, plan_directory: &Path) {
    if path.is_absolute() {
        return;
    }
    let rebased = plan_directory.join(&*path);
    *path = std::fs::canonicalize(&rebased).unwrap_or(rebased);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{AnalysisRequest, InputDescriptor};
    use std::fs;

    fn sample_plan(input_path: PathBuf) -> MergePlan {
        MergePlan {
            schema_version: MERGE_PLAN_SCHEMA_VERSION,
            plan_id: "plan".to_owned(),
            request: AnalysisRequest {
                pak_paths: vec![input_path.clone()],
                carrier_path: input_path.clone(),
            },
            inputs: vec![InputDescriptor {
                id: "pak-a".to_owned(),
                path: input_path,
                display_name: "A.pak".to_owned(),
                sha256: "00".repeat(32),
                size: 1,
                pak_version: Some(11),
                mount_point: Some("../../../".to_owned()),
                entry_count: Some(1),
            }],
            carrier_input_id: "pak-a".to_owned(),
            assets: Vec::new(),
            conflicts: Vec::new(),
            warnings: Vec::new(),
            selected_profile_id: None,
            profile_detection_status: None,
            encoding_drift_count: 0,
            full_reencode_forbidden: true,
        }
    }

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

    #[test]
    fn read_plan_rebases_legacy_relative_paths_from_the_plan_directory() {
        let directory = tempfile::tempdir().unwrap();
        let input_directory = directory.path().join("inputs");
        fs::create_dir(&input_directory).unwrap();
        let input_path = input_directory.join("A_P.pak");
        fs::write(&input_path, b"pak").unwrap();
        let plan_path = directory.path().join("comparison.json");
        let plan = sample_plan(PathBuf::from("inputs/A_P.pak"));
        fs::write(&plan_path, serde_json::to_vec_pretty(&plan).unwrap()).unwrap();

        let loaded = read_plan(&plan_path).unwrap();
        let expected = fs::canonicalize(input_path).unwrap();
        assert_eq!(loaded.request.pak_paths, vec![expected.clone()]);
        assert_eq!(loaded.request.carrier_path, expected);
        assert!(loaded.inputs[0].path.is_absolute());
    }

    #[test]
    fn read_plan_rejects_unsupported_schema_versions() {
        let directory = tempfile::tempdir().unwrap();
        let plan_path = directory.path().join("comparison.json");
        let mut plan = sample_plan(PathBuf::from("A_P.pak"));
        plan.schema_version = MERGE_PLAN_SCHEMA_VERSION + 1;
        fs::write(&plan_path, serde_json::to_vec_pretty(&plan).unwrap()).unwrap();

        let error = read_plan(&plan_path).unwrap_err();
        assert!(error.to_string().contains("unsupported comparison schema"));
        assert!(error.to_string().contains(&plan.schema_version.to_string()));
    }
}
