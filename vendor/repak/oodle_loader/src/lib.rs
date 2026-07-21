use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock, TryLockError};
use std::time::{Duration, SystemTime};

type Result<T, E = Error> = std::result::Result<T, E>;

pub use oodle_lz::{CompressionLevel, Compressor};

mod oodle_lz {
    #[derive(Debug, Clone, Copy)]
    #[repr(i32)]
    pub enum Compressor {
        /// None = memcpy, pass through uncompressed bytes
        None = 3,

        /// Fast decompression and high compression ratios, amazing!
        Kraken = 8,
        /// Leviathan = Kraken's big brother with higher compression, slightly slower decompression.
        Leviathan = 13,
        /// Mermaid is between Kraken & Selkie - crazy fast, still decent compression.
        Mermaid = 9,
        /// Selkie is a super-fast relative of Mermaid. For maximum decode speed.
        Selkie = 11,
        /// Hydra selects among the Oodle LZ codecs.
        Hydra = 12,
    }

    #[derive(Debug, Clone, Copy)]
    #[repr(i32)]
    pub enum CompressionLevel {
        None = 0,
        SuperFast = 1,
        VeryFast = 2,
        Fast = 3,
        Normal = 4,
        Optimal1 = 5,
        Optimal2 = 6,
        Optimal3 = 7,
        Optimal4 = 8,
        Optimal5 = 9,
        HyperFast1 = -1,
        HyperFast2 = -2,
        HyperFast3 = -3,
        HyperFast4 = -4,
    }

    #[allow(non_snake_case)]
    pub type Compress = unsafe extern "system" fn(
        compressor: Compressor,
        rawBuf: *const u8,
        rawLen: usize,
        compBuf: *mut u8,
        level: CompressionLevel,
        pOptions: *const (),
        dictionaryBase: *const (),
        lrm: *const (),
        scratchMem: *mut u8,
        scratchSize: usize,
    ) -> isize;

    #[allow(non_snake_case)]
    pub type Decompress = unsafe extern "system" fn(
        compBuf: *const u8,
        compBufSize: usize,
        rawBuf: *mut u8,
        rawLen: usize,
        fuzzSafe: u32,
        checkCRC: u32,
        verbosity: u32,
        decBufBase: u64,
        decBufSize: usize,
        fpCallback: u64,
        callbackUserData: u64,
        decoderMemory: *mut u8,
        decoderMemorySize: usize,
        threadPhase: u32,
    ) -> isize;

    #[allow(non_snake_case)]
    pub type GetCompressedBufferSizeNeeded =
        unsafe extern "system" fn(compressor: Compressor, rawSize: usize) -> usize;

    pub type SetPrintf = unsafe extern "system" fn(printf: *const ());
}

const OODLE_VERSION: &str = "2.9.10";
const OODLE_BASE_URL: &str = "https://github.com/WorkingRobot/OodleUE/raw/refs/heads/main/Engine/Source/Programs/Shared/EpicGames.Oodle/Sdk/";
const MAX_OODLE_RUNTIME_BYTES: u64 = 64 * 1024 * 1024;
const DOWNLOAD_CHUNK_BYTES: usize = 64 * 1024;
const DOWNLOAD_GLOBAL_TIMEOUT: Duration = Duration::from_secs(120);
const DOWNLOAD_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const DOWNLOAD_RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);
const DOWNLOAD_BODY_TIMEOUT: Duration = Duration::from_secs(10);
const STALE_DOWNLOAD_PARTIAL_AGE: Duration = Duration::from_secs(10 * 60);

struct OodlePlatform {
    path: &'static str,
    name: &'static str,
    hash: &'static str,
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
static OODLE_PLATFORM: OodlePlatform = OodlePlatform {
    path: "linux/lib",
    name: "liboo2corelinux64.so.9",
    hash: "ed7e98f70be1254a80644efd3ae442ff61f854a2fe9debb0b978b95289884e9c",
};

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
static OODLE_PLATFORM: OodlePlatform = OodlePlatform {
    path: "linuxarm/lib",
    name: "liboo2corelinuxarm64.so.9",
    hash: "161a8ecca8cc2d4ea6469779c2cc529ed5bb2765d99466273c29fdbef4657374",
};

#[cfg(all(target_os = "linux", target_arch = "arm"))]
static OODLE_PLATFORM: OodlePlatform = OodlePlatform {
    path: "linuxarm/lib",
    name: "liboo2corelinuxarm32.so.9",
    hash: "83cda016c033844fe650e49fac4cc19ff0a0fb4a3c9a7576a320ea39a9e4626b",
};

#[cfg(target_os = "macos")]
static OODLE_PLATFORM: OodlePlatform = OodlePlatform {
    path: "mac/lib",
    name: "liboo2coremac64.2.9.10.dylib",
    hash: "b09af35f6b84a61e2b6488495c7927e1cef789b969128fa1c845e51a475ec501",
};

#[cfg(windows)]
static OODLE_PLATFORM: OodlePlatform = OodlePlatform {
    path: "win/redist",
    name: "oo2core_9_win64.dll",
    hash: "6f5d41a7892ea6b2db420f2458dad2f84a63901c9a93ce9497337b16c195f457",
};

fn url() -> String {
    format!(
        "{OODLE_BASE_URL}/{}/{}/{}",
        OODLE_VERSION, OODLE_PLATFORM.path, OODLE_PLATFORM.name
    )
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Oodle support file hash mismatch (expected {expected}, found {found})")]
    HashMismatch { expected: String, found: String },
    #[error("Oodle compression failed")]
    CompressionFailed,
    #[error("Oodle support preparation was cancelled")]
    Cancelled,
    #[error("Oodle support download exceeds the {limit}-byte safety limit")]
    DownloadTooLarge { limit: u64 },
    #[error("Oodle support path is not a regular file: {0}")]
    InvalidRuntimeFile(PathBuf),
    #[error("Oodle initialization lock is unavailable")]
    InitializationLock,
    #[error("IO error {0:?}")]
    Io(#[from] io::Error),
    #[error("ureq error {0:?}")]
    Ureq(Box<ureq::Error>),
    #[error("Oodle libloading error {0:?}")]
    LibLoading(#[from] libloading::Error),
}

impl From<ureq::Error> for Error {
    fn from(value: ureq::Error) -> Self {
        Self::Ureq(value.into())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DownloadWriteFailure {
    Cancelled,
    TooLarge,
}

struct CheckedDownloadWriter<'a> {
    file: &'a mut File,
    hasher: Sha256,
    written: u64,
    max_bytes: u64,
    cancelled: &'a dyn Fn() -> bool,
    failure: Option<DownloadWriteFailure>,
}

impl<'a> CheckedDownloadWriter<'a> {
    fn new(file: &'a mut File, max_bytes: u64, cancelled: &'a dyn Fn() -> bool) -> Self {
        Self {
            file,
            hasher: Sha256::new(),
            written: 0,
            max_bytes,
            cancelled,
            failure: None,
        }
    }

    fn finish(self) -> (u64, String) {
        (self.written, hex::encode(self.hasher.finalize()))
    }
}

impl Write for CheckedDownloadWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if (self.cancelled)() {
            self.failure = Some(DownloadWriteFailure::Cancelled);
            return Err(io::Error::other(
                // `Write::write_all` retries `Interrupted` forever. Use a
                // terminal error and translate it back to `Cancelled` below.
                "Oodle support download cancelled",
            ));
        }
        let next = self
            .written
            .checked_add(buf.len() as u64)
            .ok_or_else(|| io::Error::other("Oodle support download size overflow"))?;
        if next > self.max_bytes {
            self.failure = Some(DownloadWriteFailure::TooLarge);
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Oodle support download exceeds its safety limit",
            ));
        }
        let count = self.file.write(buf)?;
        self.hasher.update(&buf[..count]);
        self.written += count as u64;
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

static PARTIAL_COUNTER: AtomicU64 = AtomicU64::new(0);

fn create_unique_partial(destination: &Path) -> Result<(PathBuf, File)> {
    let parent = destination
        .parent()
        .ok_or_else(|| io::Error::other("Oodle support path has no parent directory"))?;
    let name = destination
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("oodle-runtime");
    for _ in 0..128 {
        let serial = PARTIAL_COUNTER.fetch_add(1, Ordering::Relaxed);
        let partial = parent.join(format!(".{name}.{}.{}.partial", std::process::id(), serial));
        match OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&partial)
        {
            Ok(file) => {
                fs2::FileExt::lock_exclusive(&file)?;
                return Ok((partial, file));
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not create a unique Oodle download file",
    )
    .into())
}

fn cleanup_stale_download_partials(destination: &Path, now: SystemTime) {
    let Some(parent) = destination.parent() else {
        return;
    };
    let Some(runtime_name) = destination.file_name().and_then(|name| name.to_str()) else {
        return;
    };
    let prefix = format!(".{runtime_name}.");
    let Ok(entries) = fs::read_dir(parent) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let Some(identity) = name
            .strip_prefix(&prefix)
            .and_then(|name| name.strip_suffix(".partial"))
        else {
            continue;
        };
        let mut identity_parts = identity.split('.');
        let exact_identity =
            identity_parts.next().is_some_and(|part| {
                !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit())
            }) && identity_parts.next().is_some_and(|part| {
                !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit())
            }) && identity_parts.next().is_none();
        if !exact_identity {
            continue;
        }
        let path = entry.path();
        let Ok(metadata) = fs::symlink_metadata(&path) else {
            continue;
        };
        if !metadata.file_type().is_file()
            || metadata
                .modified()
                .ok()
                .and_then(|modified| now.duration_since(modified).ok())
                .is_none_or(|age| age < STALE_DOWNLOAD_PARTIAL_AGE)
        {
            continue;
        }
        let Ok(file) = OpenOptions::new().read(true).write(true).open(&path) else {
            continue;
        };
        if fs2::FileExt::try_lock_exclusive(&file).is_err() {
            continue;
        }
        let _ = fs2::FileExt::unlock(&file);
        drop(file);
        let _ = fs::remove_file(path);
    }
}

fn hash_open_file(file: &mut File, max_bytes: u64, cancelled: &dyn Fn() -> bool) -> Result<String> {
    let size = file.metadata()?.len();
    if size > max_bytes {
        return Err(Error::DownloadTooLarge { limit: max_bytes });
    }
    file.seek(SeekFrom::Start(0))?;
    let mut hasher = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; DOWNLOAD_CHUNK_BYTES];
    loop {
        if cancelled() {
            return Err(Error::Cancelled);
        }
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(count as u64)
            .ok_or(Error::DownloadTooLarge { limit: max_bytes })?;
        if total > max_bytes {
            return Err(Error::DownloadTooLarge { limit: max_bytes });
        }
        hasher.update(&buffer[..count]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn validate_open_file(
    file: &mut File,
    expected_hash: &str,
    max_bytes: u64,
    cancelled: &dyn Fn() -> bool,
) -> Result<()> {
    let found = hash_open_file(file, max_bytes, cancelled)?;
    if found != expected_hash {
        return Err(Error::HashMismatch {
            expected: expected_hash.to_owned(),
            found,
        });
    }
    Ok(())
}

fn validate_runtime_path(
    path: &Path,
    expected_hash: &str,
    max_bytes: u64,
    cancelled: &dyn Fn() -> bool,
) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() {
        return Err(Error::InvalidRuntimeFile(path.to_path_buf()));
    }
    let mut file = File::open(path)?;
    validate_open_file(&mut file, expected_hash, max_bytes, cancelled)
}

fn remove_invalid_runtime(path: &Path, error: Error) -> Result<()> {
    match error {
        Error::HashMismatch { .. } | Error::DownloadTooLarge { .. } => {
            fs::remove_file(path)?;
            Ok(())
        }
        Error::InvalidRuntimeFile(_) => {
            let metadata = fs::symlink_metadata(path)?;
            if metadata.file_type().is_symlink() {
                fs::remove_file(path)?;
                Ok(())
            } else {
                Err(Error::InvalidRuntimeFile(path.to_path_buf()))
            }
        }
        error => Err(error),
    }
}

fn publish_partial(
    partial: &Path,
    destination: &Path,
    expected_hash: &str,
    max_bytes: u64,
    cancelled: &dyn Fn() -> bool,
) -> Result<()> {
    match fs::rename(partial, destination) {
        Ok(()) => {}
        Err(rename_error) => {
            match validate_runtime_path(destination, expected_hash, max_bytes, cancelled) {
                Ok(()) => {
                    fs::remove_file(partial)?;
                    return Ok(());
                }
                Err(Error::HashMismatch { .. } | Error::DownloadTooLarge { .. }) => {
                    fs::remove_file(destination)?;
                    fs::rename(partial, destination)?;
                }
                Err(Error::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
                    return Err(rename_error.into());
                }
                Err(error) => return Err(error),
            }
        }
    }
    validate_runtime_path(destination, expected_hash, max_bytes, cancelled)
}

fn ensure_runtime_with_download<F>(
    destination: &Path,
    expected_hash: &str,
    max_bytes: u64,
    cancelled: &dyn Fn() -> bool,
    download: F,
) -> Result<PathBuf>
where
    F: FnOnce(&mut dyn Write) -> Result<()>,
{
    cleanup_stale_download_partials(destination, SystemTime::now());
    match validate_runtime_path(destination, expected_hash, max_bytes, cancelled) {
        Ok(()) => return Ok(destination.to_path_buf()),
        Err(Error::Io(error)) if error.kind() == io::ErrorKind::NotFound => {}
        Err(Error::Cancelled) => return Err(Error::Cancelled),
        Err(error) => remove_invalid_runtime(destination, error)?,
    }
    if cancelled() {
        return Err(Error::Cancelled);
    }

    let (partial, mut file) = create_unique_partial(destination)?;
    let result = (|| {
        let mut writer = CheckedDownloadWriter::new(&mut file, max_bytes, cancelled);
        let download_result = download(&mut writer);
        if cancelled() {
            return Err(Error::Cancelled);
        }
        if let Some(failure) = writer.failure {
            return Err(match failure {
                DownloadWriteFailure::Cancelled => Error::Cancelled,
                DownloadWriteFailure::TooLarge => Error::DownloadTooLarge { limit: max_bytes },
            });
        }
        download_result?;
        writer.flush()?;
        let (_, found) = writer.finish();
        if found != expected_hash {
            return Err(Error::HashMismatch {
                expected: expected_hash.to_owned(),
                found,
            });
        }
        file.sync_all()?;
        drop(file);
        if cancelled() {
            return Err(Error::Cancelled);
        }
        publish_partial(&partial, destination, expected_hash, max_bytes, cancelled)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&partial);
    }
    result.map(|()| destination.to_path_buf())
}

fn download_oodle(output: &mut dyn Write) -> Result<()> {
    let config = ureq::Agent::config_builder()
        .timeout_global(Some(DOWNLOAD_GLOBAL_TIMEOUT))
        .timeout_connect(Some(DOWNLOAD_CONNECT_TIMEOUT))
        .timeout_recv_response(Some(DOWNLOAD_RESPONSE_TIMEOUT))
        .timeout_recv_body(Some(DOWNLOAD_BODY_TIMEOUT))
        .build();
    let agent: ureq::Agent = config.into();
    let mut response = agent.get(url()).call()?;
    let mut reader = response.body_mut().as_reader();
    let mut buffer = [0_u8; DOWNLOAD_CHUNK_BYTES];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        output.write_all(&buffer[..count])?;
    }
    Ok(())
}

fn fetch_oodle(cancelled: &dyn Fn() -> bool) -> Result<PathBuf> {
    let destination = std::env::current_exe()?.with_file_name(OODLE_PLATFORM.name);
    ensure_runtime_with_download(
        &destination,
        OODLE_PLATFORM.hash,
        MAX_OODLE_RUNTIME_BYTES,
        cancelled,
        download_oodle,
    )
}

fn open_runtime_locked(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // The verified handle allows readers only. Replacement, deletion, and
        // writes remain blocked until the dynamic loader has opened the file.
        options.share_mode(0x0000_0001); // FILE_SHARE_READ
    }
    options.open(path)
}

fn with_verified_runtime_lock<T>(
    path: &Path,
    expected_hash: &str,
    max_bytes: u64,
    cancelled: &dyn Fn() -> bool,
    action: impl FnOnce() -> Result<T>,
) -> Result<T> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() {
        return Err(Error::InvalidRuntimeFile(path.to_path_buf()));
    }
    let mut locked = open_runtime_locked(path)?;
    validate_open_file(&mut locked, expected_hash, max_bytes, cancelled)?;
    let result = action();
    drop(locked);
    result
}

pub struct Oodle {
    _library: libloading::Library,
    compress: oodle_lz::Compress,
    decompress: oodle_lz::Decompress,
    get_compressed_buffer_size_needed: oodle_lz::GetCompressedBufferSizeNeeded,
    set_printf: oodle_lz::SetPrintf,
}

impl Oodle {
    fn new(lib: libloading::Library) -> Result<Self> {
        unsafe {
            let result = Oodle {
                compress: *lib.get(b"OodleLZ_Compress")?,
                decompress: *lib.get(b"OodleLZ_Decompress")?,
                get_compressed_buffer_size_needed: *lib
                    .get(b"OodleLZ_GetCompressedBufferSizeNeeded")?,
                set_printf: *lib.get(b"OodleCore_Plugins_SetPrintf")?,
                _library: lib,
            };
            (result.set_printf)(std::ptr::null());
            Ok(result)
        }
    }

    pub fn compress(
        &self,
        input: &[u8],
        compressor: Compressor,
        compression_level: CompressionLevel,
    ) -> Result<Vec<u8>> {
        unsafe {
            let buffer_size = self.compressed_buffer_size_needed(compressor, input.len());
            let mut buffer = Vec::new();
            buffer
                .try_reserve_exact(buffer_size)
                .map_err(|_| Error::CompressionFailed)?;
            buffer.resize(buffer_size, 0);

            let len = (self.compress)(
                compressor,
                input.as_ptr(),
                input.len(),
                buffer.as_mut_ptr(),
                compression_level,
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null_mut(),
                0,
            );
            let len = checked_compressed_len(len, buffer.len())?;
            buffer.truncate(len);
            Ok(buffer)
        }
    }

    pub fn decompress(&self, input: &[u8], output: &mut [u8]) -> isize {
        unsafe {
            (self.decompress)(
                input.as_ptr(),
                input.len(),
                output.as_mut_ptr(),
                output.len(),
                1,
                1,
                0,
                0,
                0,
                0,
                0,
                std::ptr::null_mut(),
                0,
                3,
            )
        }
    }

    pub fn compressed_buffer_size_needed(
        &self,
        compressor: oodle_lz::Compressor,
        raw_buffer: usize,
    ) -> usize {
        unsafe { (self.get_compressed_buffer_size_needed)(compressor, raw_buffer) }
    }
}

fn checked_compressed_len(len: isize, capacity: usize) -> Result<usize> {
    let len = usize::try_from(len).map_err(|_| Error::CompressionFailed)?;
    if len == 0 || len > capacity {
        return Err(Error::CompressionFailed);
    }
    Ok(len)
}

static OODLE: OnceLock<Oodle> = OnceLock::new();
static OODLE_INIT: Mutex<()> = Mutex::new(());

fn get_or_try_init<'a, T>(
    cell: &'a OnceLock<T>,
    lock: &Mutex<()>,
    cancelled: &dyn Fn() -> bool,
    initialize: impl FnOnce() -> Result<T>,
) -> Result<&'a T> {
    if let Some(value) = cell.get() {
        return Ok(value);
    }
    let guard = loop {
        if cancelled() {
            return Err(Error::Cancelled);
        }
        match lock.try_lock() {
            Ok(guard) => break guard,
            Err(TryLockError::WouldBlock) => std::thread::sleep(Duration::from_millis(20)),
            Err(TryLockError::Poisoned(_)) => return Err(Error::InitializationLock),
        }
    };
    if let Some(value) = cell.get() {
        drop(guard);
        return Ok(value);
    }
    let value = initialize()?;
    let _ = cell.set(value);
    drop(guard);
    cell.get().ok_or(Error::InitializationLock)
}

fn load_oodle(cancelled: &dyn Fn() -> bool) -> Result<Oodle> {
    let path = fetch_oodle(cancelled)?;
    with_verified_runtime_lock(
        &path,
        OODLE_PLATFORM.hash,
        MAX_OODLE_RUNTIME_BYTES,
        cancelled,
        || unsafe {
            let library = libloading::Library::new(&path)?;
            Oodle::new(library)
        },
    )
}

pub fn oodle_with_cancel(cancelled: impl Fn() -> bool) -> Result<&'static Oodle> {
    get_or_try_init(&OODLE, &OODLE_INIT, &cancelled, || load_oodle(&cancelled))
}

pub fn oodle() -> Result<&'static Oodle> {
    oodle_with_cancel(|| false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn digest(bytes: &[u8]) -> String {
        hex::encode(Sha256::digest(bytes))
    }

    #[test]
    fn valid_existing_runtime_skips_download() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("runtime.bin");
        let expected = b"known runtime";
        fs::write(&path, expected).unwrap();
        let downloads = AtomicUsize::new(0);

        ensure_runtime_with_download(&path, &digest(expected), 1024, &|| false, |_| {
            downloads.fetch_add(1, Ordering::Relaxed);
            Ok(())
        })
        .unwrap();
        assert_eq!(downloads.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn corrupt_existing_runtime_is_repaired_atomically() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("runtime.bin");
        let expected = b"known runtime";
        fs::write(&path, b"corrupt").unwrap();

        ensure_runtime_with_download(&path, &digest(expected), 1024, &|| false, |output| {
            output.write_all(expected)?;
            Ok(())
        })
        .unwrap();
        assert_eq!(fs::read(path).unwrap(), expected);
    }

    #[test]
    fn failed_download_leaves_no_destination_or_partial_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("runtime.bin");
        let error =
            ensure_runtime_with_download(&path, &digest(b"complete"), 1024, &|| false, |output| {
                output.write_all(b"part")?;
                Err(io::Error::other("network stopped").into())
            })
            .unwrap_err();
        assert!(matches!(error, Error::Io(_)));
        assert!(!path.exists());
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 0);
    }

    #[test]
    fn oversized_download_is_rejected_and_cleaned_up() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("runtime.bin");
        let error =
            ensure_runtime_with_download(&path, &digest(b"12345"), 4, &|| false, |output| {
                output.write_all(b"12345")?;
                Ok(())
            })
            .unwrap_err();
        assert!(matches!(error, Error::DownloadTooLarge { limit: 4 }));
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 0);
    }

    #[test]
    fn cancelled_download_is_retryable_and_cleaned_up() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("runtime.bin");
        let cancelled = AtomicUsize::new(0);
        let error = ensure_runtime_with_download(
            &path,
            &digest(b"payload"),
            1024,
            &|| cancelled.load(Ordering::Relaxed) != 0,
            |output| {
                cancelled.store(1, Ordering::Relaxed);
                output.write_all(b"payload")?;
                Ok(())
            },
        )
        .unwrap_err();
        assert!(matches!(error, Error::Cancelled));
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 0);
    }

    #[test]
    fn cancellation_takes_precedence_over_a_late_download_error() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("runtime.bin");
        let cancelled = AtomicUsize::new(0);
        let error = ensure_runtime_with_download(
            &path,
            &digest(b"payload"),
            1024,
            &|| cancelled.load(Ordering::Relaxed) != 0,
            |_| {
                cancelled.store(1, Ordering::Relaxed);
                Err(Error::Io(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "download timed out after cancellation",
                )))
            },
        )
        .unwrap_err();

        assert!(matches!(error, Error::Cancelled));
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 0);
    }

    #[test]
    fn stale_download_cleanup_is_exact_and_skips_live_or_recent_files() {
        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("runtime.bin");
        let stale = directory.path().join(".runtime.bin.10.1.partial");
        let locked = directory.path().join(".runtime.bin.10.2.partial");
        let recent = directory.path().join(".runtime.bin.10.3.partial");
        let unrelated = directory.path().join(".other.bin.10.1.partial");
        fs::write(&stale, b"stale").unwrap();
        fs::write(&locked, b"locked").unwrap();
        fs::write(&recent, b"recent").unwrap();
        fs::write(&unrelated, b"keep").unwrap();
        let old = SystemTime::now() - STALE_DOWNLOAD_PARTIAL_AGE - Duration::from_secs(1);
        for path in [&stale, &locked, &unrelated] {
            File::options()
                .write(true)
                .open(path)
                .unwrap()
                .set_times(std::fs::FileTimes::new().set_modified(old))
                .unwrap();
        }
        let lock = File::options()
            .read(true)
            .write(true)
            .open(&locked)
            .unwrap();
        fs2::FileExt::lock_exclusive(&lock).unwrap();

        cleanup_stale_download_partials(&destination, SystemTime::now());

        assert!(!stale.exists());
        assert!(locked.exists());
        assert!(recent.exists());
        assert!(unrelated.exists());

        drop(lock);
        cleanup_stale_download_partials(&destination, SystemTime::now());
        assert!(!locked.exists());
    }

    #[test]
    fn failed_initialization_is_not_cached() {
        let cell = OnceLock::new();
        let lock = Mutex::new(());
        assert!(matches!(
            get_or_try_init(&cell, &lock, &|| false, || Err(Error::CompressionFailed)),
            Err(Error::CompressionFailed)
        ));
        assert_eq!(
            *get_or_try_init(&cell, &lock, &|| false, || Ok(7)).unwrap(),
            7
        );
    }

    #[test]
    fn invalid_compressor_lengths_are_rejected() {
        for len in [isize::MIN, -1, 0, 9] {
            assert!(checked_compressed_len(len, 8).is_err());
        }
        assert_eq!(checked_compressed_len(8, 8).unwrap(), 8);
    }

    #[cfg(windows)]
    #[test]
    fn verified_runtime_cannot_be_replaced_before_load() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("runtime.bin");
        let bytes = b"locked runtime";
        fs::write(&path, bytes).unwrap();
        with_verified_runtime_lock(&path, &digest(bytes), 1024, &|| false, || {
            assert!(OpenOptions::new().write(true).open(&path).is_err());
            assert!(fs::remove_file(&path).is_err());
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn external_oodle_runtime_round_trip() {
        if std::env::var_os("PAK_MERGER_TEST_OODLE_OUTPUT").is_none() {
            return;
        }
        let oodle = oodle().unwrap();
        let data = b"Oodle runtime integration test payload";
        let buffer = oodle
            .compress(data, Compressor::Mermaid, CompressionLevel::Optimal5)
            .unwrap();
        let mut uncompressed = vec![0; data.len()];
        assert_eq!(
            oodle.decompress(&buffer, &mut uncompressed),
            data.len() as isize
        );
        assert_eq!(data[..], uncompressed[..]);
    }
}
