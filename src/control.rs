use std::sync::Arc;
#[cfg(windows)]
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};

#[cfg(windows)]
static CONSOLE_CANCELLATION: OnceLock<CancellationToken> = OnceLock::new();
#[cfg(windows)]
static CONSOLE_HANDLER_RESULT: OnceLock<Result<(), i32>> = OnceLock::new();

/// Cancellation flag shared by the interface and merge engine.
#[derive(Debug, Clone, Default)]
pub struct CancellationToken {
    cancelled: Arc<AtomicBool>,
}

impl CancellationToken {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
}

/// Installs the process-wide Windows console handler used by CLI commands.
/// Pressing Ctrl+C or Ctrl+Break requests cooperative cancellation instead of
/// terminating the process before temporary files can be removed.
#[cfg(windows)]
#[allow(unsafe_code)]
pub fn install_console_cancellation_handler() -> std::io::Result<CancellationToken> {
    use windows_sys::Win32::System::Console::SetConsoleCtrlHandler;

    let token = CONSOLE_CANCELLATION.get_or_init(CancellationToken::new);
    let handler_result = CONSOLE_HANDLER_RESULT.get_or_init(|| {
        // SAFETY: the callback has the required ABI and lives for the process
        // lifetime. It only performs a lock-free atomic store and never unwinds.
        let installed = unsafe { SetConsoleCtrlHandler(Some(console_control_handler), 1) };
        if installed == 0 {
            Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(1))
        } else {
            Ok(())
        }
    });
    if let Err(code) = handler_result {
        return Err(std::io::Error::from_raw_os_error(*code));
    }
    Ok(token.clone())
}

#[cfg(windows)]
#[allow(unsafe_code)]
unsafe extern "system" fn console_control_handler(control_type: u32) -> i32 {
    use windows_sys::Win32::System::Console::{CTRL_BREAK_EVENT, CTRL_C_EVENT};

    if control_type != CTRL_C_EVENT && control_type != CTRL_BREAK_EVENT {
        return 0;
    }
    if let Some(token) = CONSOLE_CANCELLATION.get() {
        token.cancel();
        1
    } else {
        0
    }
}

#[cfg(not(windows))]
pub fn install_console_cancellation_handler() -> std::io::Result<CancellationToken> {
    Ok(CancellationToken::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clones_observe_cancellation() {
        let first = CancellationToken::new();
        let second = first.clone();
        assert!(!second.is_cancelled());
        first.cancel();
        assert!(second.is_cancelled());
    }
}
