use anyhow::{Context, Result, bail};
use clap::{ArgAction, Args, Parser, Subcommand, ValueEnum};
use pak_merger::eula::{
    self, EULA_EN, EULA_JA, EULA_KO, EULA_VERSION, EulaConfirmations, EulaLocale, PRODUCT_NAME,
};
use pak_merger::report;
use pak_merger::{
    AnalysisRequest, OutputCompression, PakInput, ResolutionSet, WriteOptions, analyze, inspect,
    resolve, verify, write_with_options,
};
use serde::Serialize;
use std::fs::{self, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};

#[derive(Debug, Parser)]
#[command(
    name = "pak-merger",
    bin_name = "pak-merger",
    version,
    about = "Compare compatible mod Pak files and combine them into one Pak"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// View or manage the Terms of Use.
    Eula(EulaArgs),
    /// Check whether a Pak can be read and print its file list.
    Inspect(InspectArgs),
    /// Compare Pak files and save the conflicts that need a choice.
    Analyze(AnalyzeArgs),
    /// Apply saved choices and write one merged Pak.
    Merge(MergeArgs),
    /// Check a Pak and print the verification result.
    Verify(VerifyArgs),
}

#[derive(Debug, Args)]
#[command(args_conflicts_with_subcommands = true)]
struct EulaArgs {
    /// Accept the current Terms of Use.
    #[arg(long = "true", action = ArgAction::SetTrue)]
    accept: bool,

    /// Language used to review the terms. Requires --true.
    #[arg(long, value_enum, requires = "accept")]
    locale: Option<AcceptLocale>,

    #[command(subcommand)]
    command: Option<EulaCommand>,
}

#[derive(Debug, Subcommand)]
enum EulaCommand {
    /// Display the Terms of Use.
    Show(EulaShowArgs),
    /// Show the current acceptance status.
    Status(EulaStatusArgs),
    /// Withdraw acceptance.
    Revoke,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum DisplayLocale {
    #[value(name = "ko")]
    Korean,
    #[value(name = "en")]
    English,
    #[value(name = "ja")]
    Japanese,
    #[value(name = "all", alias = "both")]
    All,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum AcceptLocale {
    #[value(name = "ko")]
    Korean,
    #[value(name = "en")]
    English,
    #[value(name = "ja")]
    Japanese,
}

#[derive(Debug, Args)]
struct EulaShowArgs {
    /// Language to display.
    #[arg(long, value_enum, default_value = "all")]
    locale: DisplayLocale,
}

#[derive(Debug, Args)]
struct EulaStatusArgs {
    /// Emit a machine-readable JSON status.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct InspectArgs {
    /// Pak file to check.
    input: PathBuf,
    /// Write JSON to this new file instead of standard output.
    #[arg(short, long)]
    output: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct AnalyzeArgs {
    /// Pak file to compare. Repeat --pak for each file (maximum 64).
    #[arg(long = "pak", required = true, action = ArgAction::Append)]
    pak_paths: Vec<PathBuf>,
    /// Base Pak that sets the default format where no choice is needed. Defaults to the first --pak input.
    #[arg(long = "base-pak", alias = "carrier")]
    base_pak: Option<PathBuf>,
    /// New JSON file that records the comparison results.
    #[arg(short, long)]
    output: PathBuf,
}

#[derive(Debug, Args)]
struct MergeArgs {
    /// Comparison JSON produced by `pak-merger analyze`.
    #[arg(long)]
    plan: PathBuf,
    /// Optional JSON file containing saved choices for this comparison.
    #[arg(long)]
    resolutions: Option<PathBuf>,
    /// Choose which Pak value to use as CONFLICT_ID=PAK_OPTION_ID. Repeat for each conflict.
    #[arg(long = "choose", action = ArgAction::Append, value_name = "CONFLICT_ID=PAK_OPTION_ID")]
    choices: Vec<String>,
    /// Output compression. Oodle support is downloaded on first use if needed.
    #[arg(long, value_enum, default_value = "oodle")]
    compression: CompressionChoice,
    /// New output path. It must end in `_P.pak`.
    #[arg(short, long)]
    output: PathBuf,
    /// Replace the output if it already exists. Without this flag, existing files are never changed.
    #[arg(long, action = ArgAction::SetTrue)]
    overwrite: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CompressionChoice {
    None,
    Oodle,
}

impl From<CompressionChoice> for OutputCompression {
    fn from(value: CompressionChoice) -> Self {
        match value {
            CompressionChoice::None => Self::None,
            CompressionChoice::Oodle => Self::Oodle,
        }
    }
}

#[derive(Debug, Args)]
struct VerifyArgs {
    /// Pak file to check.
    pak: PathBuf,
    /// Write the verification result to this new JSON file.
    #[arg(short, long)]
    output: Option<PathBuf>,
}

#[derive(Debug, Serialize)]
struct EulaStatus<'a> {
    product: &'static str,
    current_eula_version: &'static str,
    current_text_sha256: String,
    consent_path: Option<PathBuf>,
    accepted: bool,
    current: bool,
    record: Option<&'a eula::EulaConsentRecord>,
}

pub fn run() -> Result<()> {
    let cli = Cli::parse();
    if !matches!(&cli.command, Command::Eula(_)) {
        require_current_eula_consent()?;
    }

    match cli.command {
        Command::Eula(args) => run_eula(args),
        Command::Inspect(args) => run_inspect(args),
        Command::Analyze(args) => run_analyze(args),
        Command::Merge(args) => run_merge(args),
        Command::Verify(args) => run_verify(args),
    }
}

fn run_eula(args: EulaArgs) -> Result<()> {
    if args.accept {
        return accept_eula(args.locale.unwrap_or(AcceptLocale::English));
    }

    match args.command {
        None => show_eula(DisplayLocale::All),
        Some(EulaCommand::Show(args)) => show_eula(args.locale),
        Some(EulaCommand::Status(args)) => show_eula_status(args.json),
        Some(EulaCommand::Revoke) => {
            eula::revoke().context("could not withdraw acceptance")?;
            println!("Terms acceptance withdrawn.");
            Ok(())
        }
    }
}

fn show_eula(locale: DisplayLocale) -> Result<()> {
    match locale {
        DisplayLocale::Korean => print_eula_section(EULA_KO)?,
        DisplayLocale::English => print_eula_section(EULA_EN)?,
        DisplayLocale::Japanese => print_eula_section(EULA_JA)?,
        DisplayLocale::All => {
            print_eula_section(EULA_KO)?;
            println!("\n{}\n", "=".repeat(78));
            print_eula_section(EULA_EN)?;
            println!("\n{}\n", "=".repeat(78));
            print_eula_section(EULA_JA)?;
        }
    }
    eprintln!("\nTo accept these terms, run `pak-merger eula --true`.");
    Ok(())
}

fn print_eula_section(text: &str) -> Result<()> {
    let mut stdout = io::stdout().lock();
    stdout.write_all(text.as_bytes())?;
    if !text.ends_with('\n') {
        writeln!(stdout)?;
    }
    Ok(())
}

fn show_eula_status(json: bool) -> Result<()> {
    let record = eula::load_consent().context("could not read the Terms acceptance")?;
    let current = record.as_ref().is_some_and(eula::is_valid_record);
    let status = EulaStatus {
        product: PRODUCT_NAME,
        current_eula_version: EULA_VERSION,
        current_text_sha256: eula::combined_text_sha256(),
        consent_path: eula::stored_consent_path().ok(),
        accepted: record.is_some(),
        current,
        record: record.as_ref(),
    };
    if json {
        print_json(&status)?;
    } else {
        println!("{PRODUCT_NAME} Terms version: {EULA_VERSION}");
        println!(
            "Consent status: {}",
            if current {
                "accepted and current"
            } else if record.is_some() {
                "saved, but it no longer matches this version; accept the terms again"
            } else {
                "not accepted"
            }
        );
    }
    Ok(())
}

fn accept_eula(locale: AcceptLocale) -> Result<()> {
    let confirmations = EulaConfirmations {
        non_commercial_use: true,
        original_eula_and_law: true,
        end_user_responsibility: true,
    };
    let locale = match locale {
        AcceptLocale::Korean => EulaLocale::Korean,
        AcceptLocale::English => EulaLocale::English,
        AcceptLocale::Japanese => EulaLocale::Japanese,
    };
    let record =
        eula::accept(locale, confirmations).context("could not save the Terms acceptance")?;
    println!("{PRODUCT_NAME} Terms v{} accepted.", record.eula_version);
    Ok(())
}

fn require_current_eula_consent() -> Result<()> {
    match eula::load_consent().context("could not read the Terms acceptance")? {
        Some(record) if eula::is_valid_record(&record) => Ok(()),
        Some(_) => {
            bail!("The Terms have changed. Run `pak-merger eula`, then `pak-merger eula --true`.")
        }
        None => {
            bail!("Accept the Terms first: run `pak-merger eula`, then `pak-merger eula --true`.")
        }
    }
}

fn run_inspect(args: InspectArgs) -> Result<()> {
    let inventory = inspect(PakInput { path: args.input })?;
    emit_json(args.output.as_deref(), &inventory)
}

fn run_analyze(args: AnalyzeArgs) -> Result<()> {
    let base_pak = args
        .base_pak
        .or_else(|| args.pak_paths.first().cloned())
        .context("at least one --pak input is required")?;
    let plan = analyze(AnalysisRequest {
        pak_paths: args.pak_paths,
        carrier_path: base_pak,
    })
    .context("Pak comparison failed")?;
    write_json_new(&args.output, &plan)?;
    println!("Comparison saved: {}", args.output.display());
    println!(
        "Choices required: {}",
        plan.conflicts.iter().filter(|item| item.blocking).count()
    );
    Ok(())
}

fn run_merge(args: MergeArgs) -> Result<()> {
    let plan = report::read_plan(&args.plan)
        .with_context(|| format!("couldn't open the comparison file: {}", args.plan.display()))?;
    let mut resolutions = match args.resolutions {
        Some(path) => report::read_resolutions(&path)
            .with_context(|| format!("couldn't open the saved choices: {}", path.display()))?,
        None => ResolutionSet {
            plan_id: plan.plan_id.clone(),
            ..ResolutionSet::default()
        },
    };
    merge_inline_choices(&mut resolutions, &args.choices)?;
    let resolved = resolve(plan, resolutions).context("some conflicts still need a choice")?;
    let report = write_with_options(
        resolved,
        &args.output,
        WriteOptions {
            compression: args.compression.into(),
            multithreaded: true,
            overwrite_existing: args.overwrite,
        },
    )
    .context("merged Pak creation failed")?;
    println!("Merged Pak: {}", args.output.display());
    println!("SHA-256: {}", report.output_sha256);
    println!("Files in merged Pak: {}", report.output_entry_count);
    println!(
        "Storage method: {}",
        if report.output_compression == "Oodle" {
            "Oodle compression"
        } else {
            "Uncompressed"
        }
    );
    Ok(())
}

fn merge_inline_choices(resolutions: &mut ResolutionSet, choices: &[String]) -> Result<()> {
    for choice in choices {
        let (conflict_id, variant_id) = choice.split_once('=').with_context(|| {
            format!("--choose must be CONFLICT_ID=PAK_OPTION_ID; received `{choice}`")
        })?;
        if conflict_id.is_empty() || variant_id.is_empty() || variant_id.contains('=') {
            bail!("--choose must be CONFLICT_ID=PAK_OPTION_ID; received `{choice}`");
        }
        if let Some(existing) = resolutions.choices.get(conflict_id) {
            if existing != variant_id {
                bail!(
                    "--choose assigns conflict {conflict_id} more than once ({existing} and {variant_id})"
                );
            }
        } else {
            resolutions
                .choices
                .insert(conflict_id.to_owned(), variant_id.to_owned());
        }
    }
    Ok(())
}

fn run_verify(args: VerifyArgs) -> Result<()> {
    let result = verify(&args.pak, None).context("the Pak check could not be completed")?;
    emit_json(args.output.as_deref(), &result)?;
    if !result.valid {
        bail!("the Pak did not pass verification");
    }
    Ok(())
}

fn emit_json<T: Serialize>(output: Option<&Path>, value: &T) -> Result<()> {
    match output {
        Some(path) => write_json_new(path, value),
        None => print_json(value),
    }
}

fn print_json<T: Serialize>(value: &T) -> Result<()> {
    let stdout = io::stdout().lock();
    let mut writer = BufWriter::new(stdout);
    serde_json::to_writer_pretty(&mut writer, value)?;
    writeln!(writer)?;
    Ok(())
}

fn write_json_new<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| {
            format!(
                "output file already exists; choose a new path: {}",
                path.display()
            )
        })?;
    let mut writer = BufWriter::new(file);
    if let Err(error) = serde_json::to_writer_pretty(&mut writer, value)
        .and_then(|()| writer.write_all(b"\n").map_err(serde_json::Error::io))
        .and_then(|()| writer.flush().map_err(serde_json::Error::io))
    {
        drop(writer);
        let _ = fs::remove_file(path);
        return Err(error)
            .with_context(|| format!("couldn't write the output file: {}", path.display()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parser_exposes_only_pak_workflow_commands() {
        for command in ["inspect", "analyze", "merge", "verify"] {
            assert!(Cli::try_parse_from(["pak-merger", command]).is_err());
        }

        let cli = Cli::try_parse_from(["pak-merger", "eula"]).unwrap();
        let Command::Eula(args) = cli.command else {
            panic!("expected EULA command");
        };
        assert!(!args.accept);
        assert!(args.command.is_none());
    }

    #[test]
    fn eula_true_is_the_short_acceptance_form() {
        let cli = Cli::try_parse_from(["pak-merger", "eula", "--true"]).unwrap();
        let Command::Eula(args) = cli.command else {
            panic!("expected EULA command");
        };
        assert!(args.accept);
        assert!(args.locale.is_none());
        assert!(args.command.is_none());

        let cli = Cli::try_parse_from(["pak-merger", "eula", "--true", "--locale", "ko"]).unwrap();
        let Command::Eula(args) = cli.command else {
            panic!("expected EULA command");
        };
        assert!(args.accept);
        assert!(matches!(args.locale, Some(AcceptLocale::Korean)));

        assert!(Cli::try_parse_from(["pak-merger", "eula", "--locale", "ko"]).is_err());
        assert!(Cli::try_parse_from(["pak-merger", "eula", "--true", "status"]).is_err());
        assert!(Cli::try_parse_from(["pak-merger", "eula", "accept"]).is_err());

        for command in ["show", "status", "revoke"] {
            let cli = Cli::try_parse_from(["pak-merger", "eula", command]).unwrap();
            let Command::Eula(args) = cli.command else {
                panic!("expected EULA command");
            };
            assert!(!args.accept);
            assert!(args.command.is_some());
        }
    }

    #[test]
    fn analyze_uses_readable_base_pak_option_and_keeps_old_alias() {
        for option in ["--base-pak", "--carrier"] {
            let cli = Cli::try_parse_from([
                "pak-merger",
                "analyze",
                "--pak",
                "A.pak",
                "--pak",
                "B.pak",
                option,
                "A.pak",
                "--output",
                "plan.json",
            ])
            .unwrap();
            let Command::Analyze(args) = cli.command else {
                panic!("expected analyze command");
            };
            assert_eq!(args.base_pak, Some(PathBuf::from("A.pak")));
        }
    }

    #[test]
    fn merge_defaults_to_oodle_and_accepts_uncompressed() {
        for (arguments, expected) in [
            (Vec::<&str>::new(), CompressionChoice::Oodle),
            (vec!["--compression", "none"], CompressionChoice::None),
        ] {
            let mut command = vec![
                "pak-merger",
                "merge",
                "--plan",
                "plan.json",
                "--output",
                "Merged_P.pak",
            ];
            command.extend(arguments);
            let cli = Cli::try_parse_from(command).unwrap();
            let Command::Merge(args) = cli.command else {
                panic!("expected merge command");
            };
            assert!(matches!(
                (args.compression, expected),
                (CompressionChoice::None, CompressionChoice::None)
                    | (CompressionChoice::Oodle, CompressionChoice::Oodle)
            ));
        }
    }

    #[test]
    fn merge_requires_an_explicit_overwrite_flag() {
        let base = [
            "pak-merger",
            "merge",
            "--plan",
            "plan.json",
            "--output",
            "Merged_P.pak",
        ];
        let cli = Cli::try_parse_from(base).unwrap();
        let Command::Merge(args) = cli.command else {
            panic!("expected merge command");
        };
        assert!(!args.overwrite);

        let cli =
            Cli::try_parse_from(base.into_iter().chain(std::iter::once("--overwrite"))).unwrap();
        let Command::Merge(args) = cli.command else {
            panic!("expected merge command");
        };
        assert!(args.overwrite);
    }

    #[test]
    fn inline_choices_reject_conflicting_duplicates() {
        let mut resolutions = ResolutionSet::default();
        let error = merge_inline_choices(
            &mut resolutions,
            &["conflict=left".to_owned(), "conflict=right".to_owned()],
        )
        .unwrap_err();
        assert!(error.to_string().contains("more than once"));
    }
}
