//! Memory, worker, and temporary-storage limits for Pak operations.

use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

pub const GIB: u64 = 1024 * 1024 * 1024;
const FALLBACK_MEMORY_BUDGET: u64 = 8 * GIB;
const MAX_MEMORY_BUDGET: u64 = 32 * GIB;
const SYSTEM_RESERVE: u64 = GIB;
const MAX_WORKER_THREADS: usize = 32;
const STALE_TEMP_AGE: Duration = Duration::from_secs(7 * 24 * 60 * 60);
const JOB_OWNERSHIP_FILE: &str = ".pak-merger-owner.lock";
const INSTALL_JOURNAL_PREFIX: &str = "pak-merger-install-journal-";
const INSTALL_JOURNAL_MAGIC: &str = "PAK_MERGER_INSTALL_SIDECAR_V1\n";
const MAX_INSTALL_JOURNAL_BYTES: u64 = 64 * 1024;

static MEMORY_BUDGET: OnceLock<u64> = OnceLock::new();
static DECODED_CACHE_BYTES: AtomicU64 = AtomicU64::new(0);
static PENDING_TEMPORARY_DISK_BYTES: AtomicU64 = AtomicU64::new(0);
static TEMP_CLEANUP_DONE: OnceLock<()> = OnceLock::new();

/// Returns the work directory beside the executable when possible. Installed
/// copies in a read-only folder fall back to the current user's local data
/// directory (or the operating-system temporary directory).
pub(crate) fn runtime_temp_directory() -> io::Result<PathBuf> {
    let executable = env::current_exe().map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("could not locate the running Pak Merger executable: {error}"),
        )
    })?;
    let directory = runtime_temp_directory_for_executable(&executable).or_else(|_| {
        let fallback_root = env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(env::temp_dir)
            .join("PakMerger");
        runtime_temp_directory_at(&fallback_root.join("tmp"), true)
    })?;
    TEMP_CLEANUP_DONE.get_or_init(|| {
        let _ = cleanup_stale_runtime_artifacts(&directory, SystemTime::now());
    });
    Ok(directory)
}

fn runtime_temp_directory_for_executable(executable: &Path) -> io::Result<PathBuf> {
    let executable_directory = executable.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "the Pak Merger executable has no parent folder",
        )
    })?;
    runtime_temp_directory_at(&executable_directory.join("tmp"), false)
}

fn runtime_temp_directory_at(temp_directory: &Path, create_parents: bool) -> io::Result<PathBuf> {
    if create_parents && let Some(parent) = temp_directory.parent() {
        fs::create_dir_all(parent).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "could not create the temporary work folder {}: {error}",
                    temp_directory.display()
                ),
            )
        })?;
    }

    match fs::symlink_metadata(temp_directory) {
        Ok(metadata) => validate_runtime_temp_directory(temp_directory, &metadata)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            match fs::create_dir(temp_directory) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => {
                    return Err(io::Error::new(
                        error.kind(),
                        format!(
                            "could not create the temporary work folder {}: {error}",
                            temp_directory.display()
                        ),
                    ));
                }
            }
            let metadata = fs::symlink_metadata(temp_directory).map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!(
                        "could not inspect the temporary work folder {}: {error}",
                        temp_directory.display()
                    ),
                )
            })?;
            validate_runtime_temp_directory(temp_directory, &metadata)?;
        }
        Err(error) => {
            return Err(io::Error::new(
                error.kind(),
                format!(
                    "could not inspect the temporary work folder {}: {error}",
                    temp_directory.display()
                ),
            ));
        }
    }

    Ok(temp_directory.to_path_buf())
}

fn cleanup_stale_runtime_artifacts(directory: &Path, now: SystemTime) -> io::Result<()> {
    for entry in fs::read_dir(directory)? {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => continue,
        };
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let owned_name = name.starts_with("pak-merger-");
        if !owned_name {
            continue;
        }
        if name.starts_with(INSTALL_JOURNAL_PREFIX) {
            cleanup_abandoned_install_journal(&entry.path());
            continue;
        }
        let metadata = match entry.metadata() {
            Ok(metadata) => metadata,
            Err(_) => continue,
        };
        if metadata.is_dir() && entry.path().join(JOB_OWNERSHIP_FILE).is_file() {
            cleanup_abandoned_job_directory(&entry.path());
            continue;
        }
        let old_enough = metadata
            .modified()
            .ok()
            .and_then(|modified| now.duration_since(modified).ok())
            .is_some_and(|age| age >= STALE_TEMP_AGE);
        if !old_enough {
            continue;
        }
        if metadata.is_dir() {
            let _ = fs::remove_dir_all(entry.path());
        } else if metadata.is_file() {
            cleanup_stale_owned_file(&entry.path());
        }
    }
    Ok(())
}

fn cleanup_stale_owned_file(path: &Path) {
    use fs2::FileExt;

    let Ok(file) = OpenOptions::new().read(true).write(true).open(path) else {
        return;
    };
    if file.try_lock_exclusive().is_err() {
        return;
    }
    let _ = FileExt::unlock(&file);
    drop(file);
    let _ = fs::remove_file(path);
}

/// Marks one temporary job directory as owned by a live process. The open,
/// exclusively locked marker lets a later launch distinguish an abandoned
/// directory from a merge that is still running in another process.
pub(crate) fn lock_runtime_job_directory(directory: &Path) -> io::Result<File> {
    use fs2::FileExt;

    let marker_path = directory.join(JOB_OWNERSHIP_FILE);
    let mut marker = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&marker_path)?;
    marker.lock_exclusive()?;
    marker.write_all(b"Pak Merger temporary job\n")?;
    marker.sync_all()?;
    Ok(marker)
}

fn cleanup_abandoned_job_directory(directory: &Path) {
    use fs2::FileExt;

    let marker_path = directory.join(JOB_OWNERSHIP_FILE);
    let Ok(marker) = OpenOptions::new().read(true).write(true).open(marker_path) else {
        return;
    };
    if marker.try_lock_exclusive().is_err() {
        return;
    }
    let _ = FileExt::unlock(&marker);
    drop(marker);
    let _ = fs::remove_dir_all(directory);
}

/// Keeps a recovery record for a cross-volume output copy. Normal completion
/// removes the record through `NamedTempFile`; after a process kill, the next
/// launch can remove only the exact app-created `.partial` file it names.
pub(crate) struct InstallSidecarJournal {
    _journal: tempfile::NamedTempFile,
}

pub(crate) fn register_install_sidecar(sidecar: &Path) -> io::Result<InstallSidecarJournal> {
    use fs2::FileExt;

    let sidecar = fs::canonicalize(sidecar)?;
    let file_name = sidecar.file_name().and_then(|name| name.to_str());
    if !file_name.is_some_and(is_install_sidecar_name) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the install recovery record was given an unexpected file name",
        ));
    }
    let directory = runtime_temp_directory()?;
    let mut journal = tempfile::Builder::new()
        .prefix(INSTALL_JOURNAL_PREFIX)
        .suffix(".txt")
        .tempfile_in(directory)?;
    journal.as_file().lock_exclusive()?;
    journal.write_all(INSTALL_JOURNAL_MAGIC.as_bytes())?;
    journal.write_all(sidecar.to_string_lossy().as_bytes())?;
    journal.write_all(b"\n")?;
    journal.as_file_mut().sync_all()?;
    Ok(InstallSidecarJournal { _journal: journal })
}

fn cleanup_abandoned_install_journal(journal_path: &Path) {
    use fs2::FileExt;

    let Ok(mut journal) = OpenOptions::new().read(true).write(true).open(journal_path) else {
        return;
    };
    if journal.try_lock_exclusive().is_err() {
        return;
    }
    let size = journal.metadata().map(|metadata| metadata.len());
    if !matches!(size, Ok(size) if size <= MAX_INSTALL_JOURNAL_BYTES) {
        return;
    }
    let mut text = String::new();
    if journal.read_to_string(&mut text).is_err() {
        return;
    }
    let Some(path_text) = text.strip_prefix(INSTALL_JOURNAL_MAGIC) else {
        return;
    };
    let sidecar = PathBuf::from(path_text.trim_end_matches(['\r', '\n']));
    let valid_name = sidecar
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(is_install_sidecar_name);
    let recovery_complete = if !valid_name {
        true
    } else {
        match fs::symlink_metadata(&sidecar) {
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
                match fs::remove_file(&sidecar) {
                    Ok(()) => true,
                    Err(error) if error.kind() == io::ErrorKind::NotFound => true,
                    Err(_) => false,
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => true,
            Ok(_) | Err(_) => false,
        }
    };
    let _ = FileExt::unlock(&journal);
    drop(journal);
    if recovery_complete {
        let _ = fs::remove_file(journal_path);
    }
}

fn is_install_sidecar_name(name: &str) -> bool {
    name.starts_with(".pak-merger-install-") && name.ends_with(".partial")
}

/// Stable comparison key for a host path. Existing paths are canonicalized;
/// for a not-yet-created output, its existing parent is canonicalized instead.
pub fn path_identity_key(path: &Path) -> String {
    let resolved = fs::canonicalize(path).or_else(|_| {
        let absolute = if path.is_absolute() {
            path.to_path_buf()
        } else {
            env::current_dir()?.join(path)
        };
        let Some(name) = absolute.file_name() else {
            return Ok(absolute);
        };
        let parent = absolute.parent().unwrap_or_else(|| Path::new("."));
        Ok::<_, io::Error>(fs::canonicalize(parent)?.join(name))
    });
    resolved
        .unwrap_or_else(|_| path.to_path_buf())
        .to_string_lossy()
        .replace('\\', "/")
        .to_lowercase()
}

/// Compares existing files by filesystem identity on Windows, with a
/// canonical-path fallback for paths that cannot be opened.
pub fn same_file_path(left: &Path, right: &Path) -> bool {
    #[cfg(windows)]
    if let (Ok(left), Ok(right)) = (windows_file_identity(left), windows_file_identity(right)) {
        return left == right;
    }
    path_identity_key(left) == path_identity_key(right)
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn windows_file_identity(path: &Path) -> io::Result<(u32, u64)> {
    use std::fs::File;
    use std::mem::zeroed;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };

    let file = File::open(path)?;
    // SAFETY: `information` is initialized to zero and the live File handle and
    // correctly-sized output structure remain valid for the entire call.
    let mut information: BY_HANDLE_FILE_INFORMATION = unsafe { zeroed() };
    let succeeded = unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut information) };
    if succeeded == 0 {
        return Err(io::Error::last_os_error());
    }
    let index =
        (u64::from(information.nFileIndexHigh) << 32) | u64::from(information.nFileIndexLow);
    Ok((information.dwVolumeSerialNumber, index))
}

fn validate_runtime_temp_directory(path: &Path, metadata: &fs::Metadata) -> io::Result<()> {
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!(
                "the temporary work path is not a regular folder: {}",
                path.display()
            ),
        ));
    }
    Ok(())
}

/// RAM budget for bounded working buffers. Database groups are streamed separately.
pub fn memory_budget_bytes() -> u64 {
    *MEMORY_BUDGET.get_or_init(|| {
        detected_memory()
            .map(|(available, total)| budget_from_memory(available, total))
            .unwrap_or(FALLBACK_MEMORY_BUDGET)
    })
}

/// Process-wide RAM cache limit for decoded entries.
pub fn decoded_memory_cache_limit_bytes() -> u64 {
    decoded_memory_cache_limit_from_budget(memory_budget_bytes())
}

/// RAM still available to the decoded-entry cache at this instant. Disk-space
/// preflight uses this only as a best-case reservation; the decode path keeps
/// its own atomic enforcement if concurrent work changes the value later.
pub(crate) fn decoded_memory_cache_available_bytes() -> u64 {
    decoded_memory_cache_limit_bytes().saturating_sub(DECODED_CACHE_BYTES.load(Ordering::Acquire))
}

fn decoded_memory_cache_limit_from_budget(memory_budget: u64) -> u64 {
    // Larger entries spill to read-only temporary mappings.
    (memory_budget / 16).clamp(64 * 1024 * 1024, 512 * 1024 * 1024)
}

/// Reserves decoded-entry RAM, or returns `None` so the caller can use disk.
pub fn try_reserve_decoded_memory(bytes: u64) -> Option<DecodedMemoryReservation> {
    try_reserve_decoded_memory_from(
        &DECODED_CACHE_BYTES,
        bytes,
        decoded_memory_cache_limit_bytes(),
    )
    .map(|reservation| DecodedMemoryReservation {
        _reservation: reservation,
    })
}

fn try_reserve_decoded_memory_from<'a>(
    counter: &'a AtomicU64,
    bytes: u64,
    limit: u64,
) -> Option<ByteReservation<'a>> {
    let mut current = counter.load(Ordering::Acquire);
    loop {
        let next = current.checked_add(bytes)?;
        if next > limit {
            return None;
        }
        match counter.compare_exchange_weak(current, next, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => {
                return Some(ByteReservation {
                    counter,
                    remaining: bytes,
                });
            }
            Err(actual) => current = actual,
        }
    }
}

#[derive(Debug)]
pub struct DecodedMemoryReservation {
    _reservation: ByteReservation<'static>,
}

/// Disk shortage after accounting for this process's pending temporary files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TemporaryDiskShortage {
    pub(crate) required: u64,
    pub(crate) available: u64,
}

/// Capacity held until a decoded temporary file reaches the filesystem.
#[derive(Debug)]
pub(crate) struct TemporaryDiskReservation {
    reservation: ByteReservation<'static>,
}

impl TemporaryDiskReservation {
    pub(crate) fn record_materialized(&mut self, bytes: u64) {
        self.reservation.release(bytes);
    }
}

/// Reserves temporary-disk capacity across parallel workers.
pub(crate) fn reserve_temporary_disk(
    cache_directory: &Path,
    bytes: u64,
    headroom: u64,
) -> io::Result<std::result::Result<TemporaryDiskReservation, TemporaryDiskShortage>> {
    let available = fs2::available_space(cache_directory)?;
    Ok(
        reserve_temporary_disk_from(&PENDING_TEMPORARY_DISK_BYTES, available, bytes, headroom)
            .map(|reservation| TemporaryDiskReservation { reservation }),
    )
}

fn reserve_temporary_disk_from<'a>(
    counter: &'a AtomicU64,
    available: u64,
    bytes: u64,
    headroom: u64,
) -> std::result::Result<ByteReservation<'a>, TemporaryDiskShortage> {
    let required = bytes.saturating_add(headroom);
    let mut current = counter.load(Ordering::Acquire);
    loop {
        let effective_available = available.saturating_sub(current);
        if effective_available < required {
            return Err(TemporaryDiskShortage {
                required,
                available: effective_available,
            });
        }
        let Some(next) = current.checked_add(bytes) else {
            return Err(TemporaryDiskShortage {
                required,
                available: effective_available,
            });
        };
        match counter.compare_exchange_weak(current, next, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => {
                return Ok(ByteReservation {
                    counter,
                    remaining: bytes,
                });
            }
            Err(actual) => current = actual,
        }
    }
}

#[derive(Debug)]
struct ByteReservation<'a> {
    counter: &'a AtomicU64,
    remaining: u64,
}

impl ByteReservation<'_> {
    fn release(&mut self, bytes: u64) {
        let released = bytes.min(self.remaining);
        if released != 0 {
            self.counter.fetch_sub(released, Ordering::AcqRel);
            self.remaining -= released;
        }
    }
}

impl Drop for ByteReservation<'_> {
    fn drop(&mut self) {
        self.release(self.remaining);
    }
}

/// Worker count for scans, comparisons, decoding, and compression.
pub fn worker_threads() -> usize {
    std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(4)
        .clamp(1, MAX_WORKER_THREADS)
}

fn budget_from_memory(available: u64, total: u64) -> u64 {
    if available == 0 || total == 0 {
        return FALLBACK_MEMORY_BUDGET;
    }
    let after_reserve = available.saturating_sub(SYSTEM_RESERVE);
    let total_share = total.saturating_mul(3) / 4;
    let generous = after_reserve.min(total_share).min(MAX_MEMORY_BUDGET);
    if generous >= 2 * GIB {
        generous
    } else {
        available.saturating_mul(3) / 4
    }
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn detected_memory() -> Option<(u64, u64)> {
    use std::mem::{size_of, zeroed};
    use windows_sys::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};

    // SAFETY: MEMORYSTATUSEX is initialized to zero, dwLength is set to the
    // exact structure size required by GlobalMemoryStatusEx, and the pointer
    // remains valid for the duration of the call.
    let mut status: MEMORYSTATUSEX = unsafe { zeroed() };
    status.dwLength = size_of::<MEMORYSTATUSEX>() as u32;
    let succeeded = unsafe { GlobalMemoryStatusEx(&mut status) };
    (succeeded != 0).then_some((status.ullAvailPhys, status.ullTotalPhys))
}

#[cfg(not(windows))]
fn detected_memory() -> Option<(u64, u64)> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_work_folder_is_created_beside_the_executable() {
        let root = tempfile::tempdir().unwrap();
        let executable = root.path().join("pak-merger.exe");

        let work_folder = runtime_temp_directory_for_executable(&executable).unwrap();

        assert_eq!(work_folder, root.path().join("tmp"));
        assert!(work_folder.is_dir());
        assert_eq!(
            runtime_temp_directory_for_executable(&executable).unwrap(),
            work_folder
        );
    }

    #[test]
    fn runtime_work_folder_rejects_an_existing_file() {
        let root = tempfile::tempdir().unwrap();
        let executable = root.path().join("pak-merger.exe");
        let work_path = root.path().join("tmp");
        fs::write(&work_path, b"not a folder").unwrap();

        let error = runtime_temp_directory_for_executable(&executable).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(work_path).unwrap(), b"not a folder");
    }

    #[test]
    fn fallback_work_folder_creates_missing_parents() {
        let root = tempfile::tempdir().unwrap();
        let work_path = root.path().join("PakMerger").join("tmp");

        let created = runtime_temp_directory_at(&work_path, true).unwrap();

        assert_eq!(created, work_path);
        assert!(created.is_dir());
    }

    #[test]
    fn stale_cleanup_removes_only_owned_artifacts() {
        let root = tempfile::tempdir().unwrap();
        let stale_job = root.path().join("pak-merger-stale");
        let unrelated = root.path().join("notes.txt");
        fs::create_dir(&stale_job).unwrap();
        fs::write(&unrelated, b"keep").unwrap();
        let future = SystemTime::now() + STALE_TEMP_AGE + Duration::from_secs(1);

        cleanup_stale_runtime_artifacts(root.path(), future).unwrap();

        assert!(!stale_job.exists());
        assert_eq!(fs::read(unrelated).unwrap(), b"keep");
    }

    #[test]
    fn stale_cleanup_preserves_current_jobs() {
        let root = tempfile::tempdir().unwrap();
        let current_job = root.path().join("pak-merger-current");
        fs::create_dir(&current_job).unwrap();

        cleanup_stale_runtime_artifacts(root.path(), SystemTime::now()).unwrap();

        assert!(current_job.is_dir());
    }

    #[test]
    fn ownership_lock_preserves_live_job_and_reclaims_abandoned_job() {
        let root = tempfile::tempdir().unwrap();
        let job = root.path().join("pak-merger-owned-job");
        fs::create_dir(&job).unwrap();
        let ownership = lock_runtime_job_directory(&job).unwrap();

        cleanup_stale_runtime_artifacts(root.path(), SystemTime::now()).unwrap();
        assert!(job.is_dir());

        drop(ownership);
        cleanup_stale_runtime_artifacts(root.path(), SystemTime::now()).unwrap();
        assert!(!job.exists());
    }

    #[test]
    fn abandoned_install_journal_removes_only_named_partial() {
        let root = tempfile::tempdir().unwrap();
        let partial = root.path().join(".pak-merger-install-test.partial");
        let journal = root.path().join("pak-merger-install-journal-stale.txt");
        fs::write(&partial, b"partial").unwrap();
        fs::write(
            &journal,
            format!(
                "{INSTALL_JOURNAL_MAGIC}{}\n",
                fs::canonicalize(&partial).unwrap().display()
            ),
        )
        .unwrap();

        cleanup_stale_runtime_artifacts(root.path(), SystemTime::now()).unwrap();

        assert!(!partial.exists());
        assert!(!journal.exists());
    }

    #[test]
    fn install_journal_lock_preserves_a_live_cross_volume_copy() {
        use fs2::FileExt;

        let root = tempfile::tempdir().unwrap();
        let partial = root.path().join(".pak-merger-install-live.partial");
        let journal_path = root.path().join("pak-merger-install-journal-live.txt");
        fs::write(&partial, b"partial").unwrap();
        let mut journal = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&journal_path)
            .unwrap();
        writeln!(
            journal,
            "{INSTALL_JOURNAL_MAGIC}{}",
            fs::canonicalize(&partial).unwrap().display()
        )
        .unwrap();
        journal.flush().unwrap();
        journal.lock_exclusive().unwrap();

        cleanup_stale_runtime_artifacts(root.path(), SystemTime::now()).unwrap();
        assert!(partial.exists());
        assert!(journal_path.exists());

        drop(journal);
        cleanup_stale_runtime_artifacts(root.path(), SystemTime::now()).unwrap();
        assert!(!partial.exists());
        assert!(!journal_path.exists());
    }

    #[test]
    fn install_journal_never_removes_an_unrelated_file() {
        let root = tempfile::tempdir().unwrap();
        let unrelated = root.path().join("keep.txt");
        let journal = root.path().join("pak-merger-install-journal-invalid.txt");
        fs::write(&unrelated, b"keep").unwrap();
        fs::write(
            &journal,
            format!(
                "{INSTALL_JOURNAL_MAGIC}{}\n",
                fs::canonicalize(&unrelated).unwrap().display()
            ),
        )
        .unwrap();

        cleanup_stale_runtime_artifacts(root.path(), SystemTime::now()).unwrap();

        assert_eq!(fs::read(unrelated).unwrap(), b"keep");
        assert!(!journal.exists());
    }

    #[cfg(windows)]
    #[test]
    fn install_journal_survives_a_transient_sidecar_delete_failure() {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{FILE_SHARE_READ, FILE_SHARE_WRITE};

        let root = tempfile::tempdir().unwrap();
        let partial = root.path().join(".pak-merger-install-retry.partial");
        let journal = root.path().join("pak-merger-install-journal-retry.txt");
        fs::write(&partial, b"partial").unwrap();
        fs::write(
            &journal,
            format!(
                "{INSTALL_JOURNAL_MAGIC}{}\n",
                fs::canonicalize(&partial).unwrap().display()
            ),
        )
        .unwrap();
        let blocking_handle = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .open(&partial)
            .unwrap();

        cleanup_stale_runtime_artifacts(root.path(), SystemTime::now()).unwrap();
        assert!(partial.exists());
        assert!(journal.exists());

        drop(blocking_handle);
        cleanup_stale_runtime_artifacts(root.path(), SystemTime::now()).unwrap();
        assert!(!partial.exists());
        assert!(!journal.exists());
    }

    #[test]
    fn path_identity_handles_relative_and_hard_link_aliases() {
        let root = tempfile::tempdir().unwrap();
        let original = root.path().join("Original.pak");
        let alias = root.path().join("Alias.pak");
        fs::write(&original, b"pak").unwrap();
        fs::hard_link(&original, &alias).unwrap();

        assert!(same_file_path(&original, &alias));
        assert!(!same_file_path(&original, &root.path().join("Other.pak")));
    }

    #[test]
    fn memory_policy_uses_large_machines_without_consuming_all_ram() {
        assert_eq!(budget_from_memory(48 * GIB, 64 * GIB), 32 * GIB);
        assert_eq!(budget_from_memory(12 * GIB, 16 * GIB), 11 * GIB);
    }

    #[test]
    fn memory_policy_remains_possible_on_small_machines() {
        assert_eq!(budget_from_memory(GIB, 2 * GIB), 768 * 1024 * 1024);
        assert_eq!(budget_from_memory(0, 0), FALLBACK_MEMORY_BUDGET);
    }

    #[test]
    fn decoded_cache_is_a_small_adaptive_working_set() {
        assert_eq!(
            decoded_memory_cache_limit_from_budget(GIB),
            64 * 1024 * 1024
        );
        assert_eq!(
            decoded_memory_cache_limit_from_budget(8 * GIB),
            512 * 1024 * 1024
        );
        assert_eq!(
            decoded_memory_cache_limit_from_budget(64 * GIB),
            512 * 1024 * 1024
        );
    }

    #[test]
    fn decoded_memory_reservation_spills_instead_of_exceeding_policy() {
        let counter = AtomicU64::new(0);
        let first = try_reserve_decoded_memory_from(&counter, 40, 64).unwrap();
        assert!(try_reserve_decoded_memory_from(&counter, 30, 64).is_none());
        drop(first);
        assert_eq!(counter.load(Ordering::Acquire), 0);
        assert!(try_reserve_decoded_memory_from(&counter, 30, 64).is_some());
    }

    #[test]
    fn temporary_disk_reservation_prevents_parallel_free_space_race() {
        let counter = AtomicU64::new(0);
        let mut first = reserve_temporary_disk_from(&counter, 150, 60, 64).unwrap();
        assert_eq!(first.remaining, 60);
        assert_eq!(counter.load(Ordering::Acquire), 60);

        let shortage = reserve_temporary_disk_from(&counter, 150, 60, 64).unwrap_err();
        assert_eq!(shortage.required, 124);
        assert_eq!(shortage.available, 90);

        first.release(20);
        assert_eq!(first.remaining, 40);
        assert_eq!(counter.load(Ordering::Acquire), 40);
        drop(first);
        assert_eq!(counter.load(Ordering::Acquire), 0);
        assert!(reserve_temporary_disk_from(&counter, 150, 60, 64).is_ok());
    }

    #[test]
    fn simultaneous_disk_reservations_cannot_both_claim_the_same_space() {
        use std::sync::{Arc, Barrier, mpsc};

        let counter = Arc::new(AtomicU64::new(0));
        let start = Arc::new(Barrier::new(3));
        let finish = Arc::new(Barrier::new(3));
        let (sender, receiver) = mpsc::channel();
        let mut workers = Vec::new();
        for _ in 0..2 {
            let counter = Arc::clone(&counter);
            let start = Arc::clone(&start);
            let finish = Arc::clone(&finish);
            let sender = sender.clone();
            workers.push(std::thread::spawn(move || {
                start.wait();
                let reservation = reserve_temporary_disk_from(&counter, 150, 60, 64);
                sender.send(reservation.is_ok()).unwrap();
                finish.wait();
                drop(reservation);
            }));
        }
        drop(sender);
        start.wait();
        let outcomes = [receiver.recv().unwrap(), receiver.recv().unwrap()];
        assert_eq!(outcomes.into_iter().filter(|accepted| *accepted).count(), 1);
        finish.wait();
        for worker in workers {
            worker.join().unwrap();
        }
        assert_eq!(counter.load(Ordering::Acquire), 0);
    }
}
