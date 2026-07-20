//! Memory, worker, and temporary-storage limits for Pak operations.

use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

pub const GIB: u64 = 1024 * 1024 * 1024;
const FALLBACK_MEMORY_BUDGET: u64 = 8 * GIB;
const MAX_MEMORY_BUDGET: u64 = 32 * GIB;
const SYSTEM_RESERVE: u64 = GIB;
const MAX_WORKER_THREADS: usize = 32;

static MEMORY_BUDGET: OnceLock<u64> = OnceLock::new();
static DECODED_CACHE_BYTES: AtomicU64 = AtomicU64::new(0);
static PENDING_TEMPORARY_DISK_BYTES: AtomicU64 = AtomicU64::new(0);

/// Returns the real `tmp` directory beside the executable.
pub(crate) fn runtime_temp_directory() -> io::Result<PathBuf> {
    let executable = env::current_exe().map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("could not locate the running Pak Merger executable: {error}"),
        )
    })?;
    runtime_temp_directory_for_executable(&executable)
}

fn runtime_temp_directory_for_executable(executable: &Path) -> io::Result<PathBuf> {
    let executable_directory = executable.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "the Pak Merger executable has no parent folder",
        )
    })?;
    let temp_directory = executable_directory.join("tmp");

    match fs::symlink_metadata(&temp_directory) {
        Ok(metadata) => validate_runtime_temp_directory(&temp_directory, &metadata)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            match fs::create_dir(&temp_directory) {
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
            let metadata = fs::symlink_metadata(&temp_directory).map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!(
                        "could not inspect the temporary work folder {}: {error}",
                        temp_directory.display()
                    ),
                )
            })?;
            validate_runtime_temp_directory(&temp_directory, &metadata)?;
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

    Ok(temp_directory)
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
