#![deny(unsafe_code)]

pub mod binary_asset;
pub mod control;
pub mod eula;
pub mod input;
pub mod merge;
pub mod pak;
pub mod profiles;
pub mod report;
pub mod resources;
pub mod types;

pub use control::CancellationToken;
pub use input::{InspectError, inspect};
pub use merge::{
    MergeAnalysisSession, analyze, analyze_with_archives, analyze_with_archives_and_cancel,
    analyze_with_archives_progress_and_cancel, analyze_with_archives_progress_cancel_and_threads,
    resolve, verify, write, write_session_with_options_and_progress,
    write_session_with_options_progress_and_cancel, write_with_options,
    write_with_options_and_progress,
};
pub use types::*;
