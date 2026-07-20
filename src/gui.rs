use eframe::egui;
use pak_merger::eula::{self, EulaConfirmations, EulaLocale, PRODUCT_NAME};
use pak_merger::types::{
    AnalysisRequest, Conflict, ConflictKind, MergePlan, MergeProgress, MergeProgressStage,
    MergeReport, OutputCompression, ResolutionSet, Variant, WriteOptions,
};
use std::collections::{BTreeMap, BTreeSet};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};

const DEFAULT_MERGED_PAK_FILE_NAME: &str = "ZZMerge_P.pak";

enum WorkerResult {
    Analyzed(Box<pak_merger::merge::MergeAnalysisSession>),
    Merged(Box<MergeReport>),
}

enum WorkerMessage {
    Progress(MergeProgress),
    Finished(Result<WorkerResult, String>),
}

#[derive(Debug, Clone)]
struct PendingBulkSelection {
    input_id: String,
    display_name: String,
    filter: String,
    count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ResolutionUndoChange {
    conflict_id: String,
    previous_variant_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ResolutionUndo {
    Single(ResolutionUndoChange),
    Batch(Vec<ResolutionUndoChange>),
}

impl ResolutionUndo {
    #[cfg(test)]
    fn change_count(&self) -> usize {
        match self {
            Self::Single(_) => 1,
            Self::Batch(changes) => changes.len(),
        }
    }

    fn restore(self, resolutions: &mut ResolutionSet) {
        let restore_change = |change: ResolutionUndoChange, resolutions: &mut ResolutionSet| {
            if let Some(previous_variant_id) = change.previous_variant_id {
                resolutions
                    .choices
                    .insert(change.conflict_id, previous_variant_id);
            } else {
                resolutions.choices.remove(&change.conflict_id);
            }
        };
        match self {
            Self::Single(change) => restore_change(change, resolutions),
            Self::Batch(changes) => {
                for change in changes.into_iter().rev() {
                    restore_change(change, resolutions);
                }
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PakInspection {
    sha256: String,
    size: u64,
    mount_point: String,
    version: u32,
    entry_count: usize,
    stale_payload_hashes: Vec<StalePayloadHash>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StalePayloadHash {
    path: String,
    stored_sha1: String,
    actual_sha1: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PakInspectionStatus {
    Pending,
    Supported(PakInspection),
    Failed(String),
}

#[derive(Debug)]
struct CachedPakInspection {
    generation: u64,
    status: PakInspectionStatus,
    archive: Option<Arc<pak_merger::pak::PakArchive>>,
    progress: Option<(u64, u64)>,
    cancellation: pak_merger::CancellationToken,
}

struct PakInspectionJob {
    key: String,
    generation: u64,
    path: PathBuf,
    cancellation: pak_merger::CancellationToken,
    multithreaded: bool,
}

struct PakInspectionResult {
    key: String,
    generation: u64,
    result: Result<(PakInspection, Arc<pak_merger::pak::PakArchive>), String>,
}

enum PakInspectionMessage {
    Progress {
        key: String,
        generation: u64,
        completed_bytes: u64,
        total_bytes: u64,
    },
    Finished(PakInspectionResult),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ConflictHierarchy {
    asset: String,
    row: String,
    group: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UiLocale {
    Korean,
    English,
    Japanese,
}

impl UiLocale {
    fn from_system() -> Self {
        let locale = sys_locale::get_locale()
            .unwrap_or_default()
            .to_ascii_lowercase();
        if locale.starts_with("ko") {
            Self::Korean
        } else if locale.starts_with("ja") {
            Self::Japanese
        } else {
            Self::English
        }
    }

    fn tr<'a>(self, ko: &'a str, en: &'a str) -> &'a str {
        match self {
            Self::Korean => ko,
            Self::English => en,
            Self::Japanese => japanese_ui_text(en).unwrap_or(en),
        }
    }

    const fn eula_locale(self) -> EulaLocale {
        match self {
            Self::Korean => EulaLocale::Korean,
            Self::English => EulaLocale::English,
            Self::Japanese => EulaLocale::Japanese,
        }
    }
}

fn japanese_ui_text(english: &str) -> Option<&'static str> {
    Some(match english {
        "<file group>" => "<ファイル一式>",
        "<whole file group>" => "<ファイル一式全体>",
        "⚠ Items to review" => "⚠ 確認事項",
        "A compressed file inside the Pak could not be decoded and may be damaged." => {
            "Pak 内の圧縮ファイルを展開できませんでした。ファイルが破損している可能性があります。"
        }
        "A file in this Pak failed its integrity check." => {
            "Pak 内のファイルが整合性チェックに失敗しました。"
        }
        "A file could not be read again while checking linked data." => {
            "関連データの確認中にファイルを再度読み込めませんでした。"
        }
        "A file path inside the Pak is not valid, so the Pak cannot be read safely." => {
            "Pak 内のファイルパスが無効なため、安全に読み込めません。"
        }
        "A file with that name already exists. Choose a different name." => {
            "同じ名前のファイルが既にあります。別の名前を選択してください。"
        }
        "The temporary work folder beside Pak Merger could not be used. Check write access to the executable folder." => {
            "Pak Merger の隣にある一時作業フォルダーを使用できません。実行ファイルのフォルダーへの書き込み権限を確認してください。"
        }
        "This file already exists. Replace it?" => {
            "同じ名前のファイルが既にあります。上書きしますか？"
        }
        "A problem was found while checking the merged Pak." => {
            "統合 Pak の検査中に問題が見つかりました。"
        }
        "Accept all and continue" => "すべてに同意して続行",
        "Add at least one Pak file." => "Pak ファイルを1つ以上追加してください。",
        "Add at least two Pak files." => "Pak ファイルを2つ以上追加してください。",
        "Add Pak" => "Pak を追加",
        "An input Pak changed after analysis. Analyze the Paks again." => {
            "解析後に入力 Pak が変更されました。もう一度解析してください。"
        }
        "Analyze" => "解析",
        "Analyzing…" => "解析中…",
        "Apply" => "適用",
        "Base Pak" => "基準 Pak",
        "Build merged Pak" => "統合 Pak を作成",
        "Building database" => "データベースを統合",
        "Indexing database" => "データベースを確認",
        "Building and checking the merged Pak…" => "統合 Pak を作成して検査しています…",
        "Cancel" => "キャンセル",
        "Cancel operation" => "処理をキャンセル",
        "Cancelling..." => "キャンセルしています…",
        "Category code" => "分類コード",
        "Checked Paks" => "確認済み Pak",
        "Checking data links" => "データ参照を確認",
        "Checking the Pak file…" => "Pak ファイルを確認しています…",
        "Choose a Pak" => "Pak を選択",
        "Choose conflicting values" => "異なる値を選択",
        "Apply one Pak to all visible unresolved items:" => {
            "表示中の未選択項目に1つの Pak を一括適用："
        }
        "Compare changes from several mod Paks, choose which values to keep, and combine them into one Pak." => {
            "複数の Mod Pak の変更を比較し、使用する値を選んで1つの Pak に統合します。"
        }
        "Comparing changes" => "変更内容を比較",
        "Comparison" => "比較内容",
        "Conflict ID" => "競合 ID",
        "Conflict list" => "競合一覧",
        "The base Pak sets the default format where no choice is needed. You still choose every conflicting value." => {
            "基準 Pak は、選択が不要な項目の既定形式を決めます。競合する値は個別に選択します。"
        }
        "Creates a larger file, but finishes fastest." => {
            "ファイルは大きくなりますが、最も速く作成できます。"
        }
        "Data ID (m_id)" => "データ ID (m_id)",
        "Decline and exit" => "同意せず終了",
        "Details" => "詳細情報",
        "Different file structures" => "ファイル構造が異なる",
        "Different NPCs or interactions may overlap at the same location. Merging can continue, but check the result in game." => {
            "同じ場所に異なる NPC や会話が重なる可能性があります。統合は続行できますが、ゲーム内で確認してください。"
        }
        "Encrypted Paks cannot be read." => "暗号化された Pak は読み込めません。",
        "Error details" => "エラーの詳細",
        "Fields that must change together differ between Paks. Choose one Pak." => {
            "同時に変更する必要がある値が Pak ごとに異なります。1つの Pak を選択してください。"
        }
        "File in Pak" => "Pak 内のファイル",
        "File-group conflict" => "ファイル一式の競合",
        "Files" => "ファイル数",
        "Finalizing" => "仕上げ",
        "Fix the problem, then add the Pak again." => {
            "問題を解決してから Pak を追加し直してください。"
        }
        "Folder in Pak" => "Pak 内フォルダー",
        "For information only · no choice needed" => "案内のみ・選択不要",
        "Input Paks and base Pak" => "統合する Pak と基準 Pak",
        "Inspection has not started" => "検査待ち",
        "Internal storage code" => "内部保存コード",
        "Item being compared" => "比較項目",
        "Linked values conflict" => "連動する値の競合",
        "Merge" => "統合",
        "Missing linked item" => "必要な参照データがない",
        "No items match this search." => "検索条件に一致する項目はありません。",
        "Oodle compression" => "Oodle 圧縮",
        "Options" => "オプション",
        "Pak ID" => "Pak ID",
        "Terms of Use" => "利用規約",
        "Pak storage method" => "Pak の保存方式",
        "Pak version" => "Pak バージョン",
        "Performance" => "パフォーマンス",
        "Possible placement overlap" => "NPC 配置重複の可能性",
        "Preparing files" => "統合ファイルを準備",
        "Read and accept the terms to continue." => {
            "続行するには、利用規約を読み、同意してください。"
        }
        "Ready" => "使用可能",
        "Ready to merge." => "統合できます。",
        "Recalculated SHA-1:" => "再計算した SHA-1：",
        "Rechecking input Paks" => "入力 Pak を再確認",
        "Recorded SHA-1:" => "Pak に記録された SHA-1：",
        "Reduces Pak size. The required support file is downloaded automatically on first use." => {
            "Pak のサイズを小さくします。初回使用時に必要なサポートファイルを自動でダウンロードします。"
        }
        "Remove" => "削除",
        "Replace" => "上書き",
        "Replace existing file" => "既存ファイルを上書き",
        "Resolved" => "解決済み",
        "Rows with the same m_id differ. Choose the Pak to use for the whole row." => {
            "同じ m_id のデータ内容が異なります。行全体に使用する Pak を選択してください。"
        }
        "Runs all work sequentially on one thread." => {
            "すべての処理を1つのスレッドで順番に実行します。"
        }
        "Runs analysis, decompression, and compression across multiple CPU cores." => {
            "解析・展開・圧縮を複数の CPU コアで同時に処理します。"
        }
        "Same data ID, different contents" => "同じデータ ID で内容が異なる",
        "Same value, stored differently" => "同じ値で保存形式だけが異なる",
        "Search list" => "一覧を検索",
        "Select an item to compare what each Pak contains." => {
            "項目を選ぶと、各 Pak の内容を右側または下側で比較できます。"
        }
        "Selected" => "選択",
        "Show storage-format examples" => "同じ値の保存形式の違いを表示",
        "Size" => "サイズ",
        "Some game data could not be compared or merged safely." => {
            "一部のゲームデータを安全に比較または統合できませんでした。"
        }
        "Some items still need a choice. Choose a Pak for every conflict." => {
            "未選択の項目があります。すべての競合で使用する Pak を選択してください。"
        }
        "Some linked data could not be checked. Review the input Paks." => {
            "一部の関連データを確認できませんでした。入力 Pak を確認してください。"
        }
        "Required linked data is missing. Choose another Pak or review the inputs." => {
            "必要な関連データがありません。別の Pak を選択するか、入力を確認してください。"
        }
        "Stored-data check" => "保存データ検査値",
        "Terms" => "利用規約",
        "The base Pak changed, so the previous analysis and choices were cleared. Analyze again." => {
            "基準 Pak が変更されたため、以前の解析結果と選択を消去しました。もう一度解析してください。"
        }
        "The base Pak has no value here, so the first available Pak is used." => {
            "基準 Pak にこの値がないため、最初に利用できる Pak の値を使用します。"
        }
        "The compression method used by this Pak cannot be read by this version of the tool." => {
            "この Pak の圧縮方式は、現在のツールでは読み込めません。"
        }
        "The contents match but are stored differently. The base Pak format is kept." => {
            "内容は同じですが保存形式が異なります。基準 Pak 側の形式を維持します。"
        }
        "The contents match, so the base Pak storage format is kept." => {
            "内容が同じため、基準 Pak 側の保存形式を維持します。"
        }
        "The contents match; the base Pak storage format is kept." => {
            "内容は同じで、基準 Pak 側の保存形式を維持します。"
        }
        "The file list in this Pak cannot be read." => "この Pak のファイル一覧を読み込めません。",
        "The file structures differ, so they cannot be partly merged. Choose one Pak for the whole group." => {
            "ファイル構造が異なるため部分統合できません。一式全体に使用する Pak を選択してください。"
        }
        "Oodle support couldn't be prepared. Check your internet connection and write access to the Pak Merger folder." => {
            "Oodle サポートを準備できませんでした。インターネット接続と Pak Merger フォルダーへの書き込み権限を確認してください。"
        }
        "The operation couldn't be completed. Check the input Paks and your choices." => {
            "処理を完了できませんでした。入力 Pak と選択内容を確認してください。"
        }
        "The operation stopped unexpectedly." => "処理が予期せず停止しました。",
        "The operation was cancelled. The unfinished temporary Pak was removed." => {
            "処理をキャンセルしました。未完成の一時 Pak は削除しました。"
        }
        "The Pak check could not start. Try again." => {
            "Pak の確認を開始できませんでした。もう一度お試しください。"
        }
        "The Pak check stopped unexpectedly. Try again." => {
            "Pak の確認が予期せず停止しました。もう一度お試しください。"
        }
        "The Paks point to different game folders. Check that they are for the same game." => {
            "Pak が異なるゲームフォルダーを指しています。同じゲーム用の Pak か確認してください。"
        }
        "The same Pak was added twice. Remove one copy." => {
            "同じ Pak が2回追加されています。片方を削除してください。"
        }
        "This item couldn't be merged automatically. Check the details." => {
            "この項目は自動で統合できませんでした。詳細を確認してください。"
        }
        "There is no Pak to choose from." => "選択できる Pak がありません。",
        "There is not enough disk space or memory for this operation." => {
            "処理に必要なディスク容量またはメモリが不足しています。"
        }
        "This file cannot be partly merged. Choose the Pak you want to use." => {
            "このファイルは部分統合できません。使用する Pak を選択してください。"
        }
        "This file group cannot be compared item by item. Choose one Pak for the whole group." => {
            "このファイル一式は項目単位で比較できません。一式全体に使用する Pak を選択してください。"
        }
        "This Pak can't be read" => "この Pak を読み込めません",
        "This Pak couldn't be read. It may be damaged or use an unsupported format." => {
            "この Pak を読み込めませんでした。破損しているか、未対応の形式である可能性があります。"
        }
        "This Pak version cannot be read by this version of the tool." => {
            "この Pak バージョンは、現在のツールでは読み込めません。"
        }
        "This value differs between Paks. Choose the Pak whose value you want to use." => {
            "この値が Pak ごとに異なります。使用する値を含む Pak を選択してください。"
        }
        "Troubleshooting details" => "問題解決用の詳細",
        "Uncompressed" => "無圧縮",
        "Undo" => "元に戻す",
        "Unresolved" => "選択が必要",
        "Unsupported file" => "未対応のファイル",
        "Use multiple CPU threads" => "複数の CPU スレッドを使用",
        "Disable the source mod Paks before using the merged Pak." => {
            "統合 Pak を使用する前に、元の Mod Pak を無効にしてください。"
        }
        "Value comparison check" => "値比較用の検査値",
        "Value conflict" => "値の競合",
        "Value in this Pak" => "この Pak に含まれる値",
        "Verifying Pak" => "作成した Pak を検査",
        "Wait for the Pak check to finish, then analyze again." => {
            "Pak の確認が終わってから、もう一度解析してください。"
        }
        "Warning · merging can continue" => "注意・統合を続行可能",
        "Writing Pak" => "Pak を保存",
        "You can also drop files onto this window." => {
            "このウィンドウにファイルをドラッグ＆ドロップすることもできます。"
        }
        "You can change these settings after the current operation finishes." => {
            "現在の処理が完了した後に設定を変更できます。"
        }
        _ => return None,
    })
}

struct MergerApp {
    locale: UiLocale,
    cjk_font_available: bool,
    consent_valid: bool,
    eula_confirmations: EulaConfirmations,
    show_terms: bool,
    pak_paths: Vec<PathBuf>,
    carrier_index: usize,
    plan: Option<Arc<MergePlan>>,
    analysis_session: Option<Arc<pak_merger::merge::MergeAnalysisSession>>,
    resolutions: ResolutionSet,
    undo: Vec<ResolutionUndo>,
    filter: String,
    show_storage_format_details: bool,
    selected_conflict_id: Option<String>,
    pending_bulk: Option<PendingBulkSelection>,
    output_compression: OutputCompression,
    multithreaded: bool,
    show_options: bool,
    status: String,
    status_detail: Option<String>,
    completed_output: Option<PathBuf>,
    pending_overwrite: Option<PathBuf>,
    worker: Option<Receiver<WorkerMessage>>,
    cancel_signal: Option<pak_merger::CancellationToken>,
    merge_progress: Option<MergeProgress>,
    operation_started_at: Option<std::time::Instant>,
    inspection_requests: Sender<PakInspectionJob>,
    inspection_results: Receiver<PakInspectionMessage>,
    inspections: BTreeMap<String, CachedPakInspection>,
    next_inspection_generation: u64,
    last_consent_check: std::time::Instant,
}

impl Default for MergerApp {
    fn default() -> Self {
        let (inspection_requests, inspection_results) = inspection_worker();
        Self {
            locale: UiLocale::from_system(),
            cjk_font_available: true,
            consent_valid: eula::has_valid_consent(),
            eula_confirmations: EulaConfirmations::default(),
            show_terms: false,
            pak_paths: Vec::new(),
            carrier_index: 0,
            plan: None,
            analysis_session: None,
            resolutions: ResolutionSet::default(),
            undo: Vec::new(),
            filter: String::new(),
            show_storage_format_details: false,
            selected_conflict_id: None,
            pending_bulk: None,
            output_compression: OutputCompression::Oodle,
            multithreaded: true,
            show_options: false,
            status: String::new(),
            status_detail: None,
            completed_output: None,
            pending_overwrite: None,
            worker: None,
            cancel_signal: None,
            merge_progress: None,
            operation_started_at: None,
            inspection_requests,
            inspection_results,
            inspections: BTreeMap::new(),
            next_inspection_generation: 1,
            last_consent_check: std::time::Instant::now(),
        }
    }
}

impl MergerApp {
    fn tr<'a>(&self, ko: &'a str, en: &'a str) -> &'a str {
        self.locale.tr(ko, en)
    }

    fn progress_stage_label(&self, stage: MergeProgressStage) -> &'static str {
        match stage {
            MergeProgressStage::CheckingInputs => {
                self.tr("입력 Pak 다시 확인", "Rechecking input Paks")
            }
            MergeProgressStage::ComparingChanges => self.tr("변경 내용 비교", "Comparing changes"),
            MergeProgressStage::PreparingFiles => self.tr("합칠 파일 준비", "Preparing files"),
            MergeProgressStage::IndexingDatabase => {
                self.tr("데이터베이스 확인", "Indexing database")
            }
            MergeProgressStage::BuildingDatabase => {
                self.tr("데이터베이스 병합", "Building database")
            }
            MergeProgressStage::WritingPak => self.tr("Pak 저장", "Writing Pak"),
            MergeProgressStage::VerifyingPak => self.tr("만든 Pak 검사", "Verifying Pak"),
            MergeProgressStage::CheckingReferences => {
                self.tr("데이터 연결 검사", "Checking data links")
            }
            MergeProgressStage::Finalizing => self.tr("마무리", "Finalizing"),
        }
    }

    fn draw_options(&mut self, ui: &mut egui::Ui) {
        ui.heading(self.tr("옵션", "Options"));
        ui.add_space(8.0);
        let busy = self.is_busy() || self.has_pending_inspections();
        let storage_heading = self.tr("Pak 저장 방식", "Pak storage method").to_owned();
        let oodle_label = self.tr("Oodle 압축", "Oodle compression").to_owned();
        let oodle_help = self
            .tr(
                "Pak 크기를 줄입니다. 처음 사용할 때 필요한 지원 파일을 자동으로 내려받습니다.",
                "Reduces Pak size. The required support file is downloaded automatically on first use.",
            )
            .to_owned();
        let uncompressed_label = self.tr("무압축", "Uncompressed").to_owned();
        let uncompressed_help = self
            .tr(
                "파일은 더 커지지만 가장 빠르게 만들 수 있습니다.",
                "Creates a larger file, but finishes fastest.",
            )
            .to_owned();
        let performance_heading = self.tr("성능", "Performance").to_owned();
        let multithread_label = self
            .tr("멀티스레드 사용", "Use multiple CPU threads")
            .to_owned();
        let multithread_on_help = self
            .tr(
                "분석, 압축 해제, 압축 작업을 여러 CPU 코어에서 동시에 처리합니다.",
                "Runs analysis, decompression, and compression across multiple CPU cores.",
            )
            .to_owned();
        let multithread_off_help = self
            .tr(
                "모든 작업을 한 스레드에서 순서대로 처리합니다.",
                "Runs all work sequentially on one thread.",
            )
            .to_owned();
        ui.add_enabled_ui(!busy, |ui| {
            ui.group(|ui| {
                ui.label(egui::RichText::new(storage_heading).strong());
                ui.radio_value(
                    &mut self.output_compression,
                    OutputCompression::Oodle,
                    oodle_label,
                );
                ui.small(oodle_help);
                ui.radio_value(
                    &mut self.output_compression,
                    OutputCompression::None,
                    uncompressed_label,
                );
                ui.small(uncompressed_help);
            });
            ui.add_space(8.0);
            ui.group(|ui| {
                ui.label(egui::RichText::new(performance_heading).strong());
                ui.checkbox(&mut self.multithreaded, multithread_label);
                ui.small(if self.multithreaded {
                    multithread_on_help
                } else {
                    multithread_off_help
                });
            });
        });
        if busy {
            ui.add_space(8.0);
            ui.colored_label(
                egui::Color32::YELLOW,
                self.tr(
                    "현재 작업에 사용 중인 설정은 작업이 끝난 뒤 변경할 수 있습니다.",
                    "You can change these settings after the current operation finishes.",
                ),
            );
        }
    }

    fn draw_locale_picker(&mut self, ui: &mut egui::Ui, id: &str) {
        egui::ComboBox::from_id_salt(id)
            .selected_text(match self.locale {
                UiLocale::Korean => "한국어",
                UiLocale::English => "English",
                UiLocale::Japanese => "日本語",
            })
            .show_ui(ui, |ui| {
                ui.add_enabled_ui(self.cjk_font_available, |ui| {
                    ui.selectable_value(&mut self.locale, UiLocale::Korean, "한국어");
                    ui.selectable_value(&mut self.locale, UiLocale::Japanese, "日本語");
                });
                ui.selectable_value(&mut self.locale, UiLocale::English, "English");
                if !self.cjk_font_available {
                    ui.small("Only English is available because no Windows CJK font was found.");
                }
            });
    }

    fn is_busy(&self) -> bool {
        self.worker.is_some()
    }

    fn invalidate_analysis(&mut self) {
        self.plan = None;
        self.analysis_session = None;
        self.resolutions = ResolutionSet::default();
        self.undo.clear();
        self.selected_conflict_id = None;
        self.pending_bulk = None;
        self.completed_output = None;
        self.pending_overwrite = None;
        self.status.clear();
        self.status_detail = None;
    }

    fn add_path(&mut self, path: PathBuf) {
        let extension = path
            .extension()
            .and_then(|value| value.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        if extension != "pak" {
            return;
        }
        if self
            .pak_paths
            .iter()
            .any(|existing| same_path(existing, &path))
        {
            return;
        }
        self.pak_paths.push(path.clone());
        self.queue_pak_inspection(path);
        if self.carrier_index >= self.pak_paths.len() {
            self.carrier_index = 0;
        }
        self.invalidate_analysis();
    }

    fn remove_pak(&mut self, index: usize) {
        if index >= self.pak_paths.len() {
            return;
        }
        let old_carrier = self.carrier_index;
        let removed = self.pak_paths.remove(index);
        if let Some(cached) = self.inspections.remove(&path_key(&removed)) {
            cached.cancellation.cancel();
        }
        self.carrier_index = if self.pak_paths.is_empty() {
            0
        } else if index < old_carrier {
            old_carrier - 1
        } else {
            old_carrier.min(self.pak_paths.len() - 1)
        };
        self.invalidate_analysis();
    }

    fn set_carrier(&mut self, index: usize) {
        if index < self.pak_paths.len() && index != self.carrier_index {
            self.carrier_index = index;
            // A different base invalidates the analysis and every saved choice.
            self.invalidate_analysis();
            self.status = self
                .tr(
                    "기준 Pak이 변경되어 기존 분석과 선택을 지웠습니다. 다시 분석하세요.",
                    "The base Pak changed, so the previous analysis and choices were cleared. Analyze again.",
                )
                .to_owned();
            self.status_detail = None;
        }
    }

    fn queue_pak_inspection(&mut self, path: PathBuf) {
        let key = path_key(&path);
        let generation = self.next_inspection_generation;
        self.next_inspection_generation = self.next_inspection_generation.wrapping_add(1).max(1);
        let cancellation = pak_merger::CancellationToken::new();
        self.inspections.insert(
            key.clone(),
            CachedPakInspection {
                generation,
                status: PakInspectionStatus::Pending,
                archive: None,
                progress: None,
                cancellation: cancellation.clone(),
            },
        );
        if self
            .inspection_requests
            .send(PakInspectionJob {
                key: key.clone(),
                generation,
                path,
                cancellation,
                multithreaded: self.multithreaded,
            })
            .is_err()
            && let Some(cached) = self.inspections.get_mut(&key)
        {
            cached.status =
                PakInspectionStatus::Failed("Pak inspection could not start.".to_owned());
        }
    }

    fn apply_inspection_result(&mut self, message: PakInspectionMessage) {
        match message {
            PakInspectionMessage::Progress {
                key,
                generation,
                completed_bytes,
                total_bytes,
            } => {
                let Some(cached) = self.inspections.get_mut(&key) else {
                    return;
                };
                if cached.generation == generation {
                    cached.progress = Some((completed_bytes, total_bytes));
                }
            }
            PakInspectionMessage::Finished(message) => {
                let Some(cached) = self.inspections.get_mut(&message.key) else {
                    return;
                };
                if cached.generation != message.generation {
                    return;
                }
                cached.progress = None;
                match message.result {
                    Ok((inspection, archive)) => {
                        cached.status = PakInspectionStatus::Supported(inspection);
                        cached.archive = Some(archive);
                    }
                    Err(error) => {
                        cached.status = PakInspectionStatus::Failed(error);
                        cached.archive = None;
                    }
                }
            }
        }
    }

    fn poll_inspections(&mut self) {
        loop {
            match self.inspection_results.try_recv() {
                Ok(message) => self.apply_inspection_result(message),
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => {
                    for cached in self.inspections.values_mut() {
                        if cached.status == PakInspectionStatus::Pending {
                            cached.status = PakInspectionStatus::Failed(
                                "Pak inspection stopped unexpectedly.".to_owned(),
                            );
                        }
                    }
                    break;
                }
            }
        }
    }

    fn has_pending_inspections(&self) -> bool {
        self.inspections
            .values()
            .any(|cached| cached.status == PakInspectionStatus::Pending)
    }

    fn request(&self) -> Option<AnalysisRequest> {
        let carrier_path = self.pak_paths.get(self.carrier_index)?.clone();
        Some(AnalysisRequest {
            pak_paths: self.pak_paths.clone(),
            carrier_path,
        })
    }

    fn start_analysis(&mut self) {
        if !self.require_current_consent() {
            return;
        }
        let Some(request) = self.request() else {
            self.status = self
                .tr("Pak 파일을 추가하세요.", "Add at least one Pak file.")
                .to_owned();
            return;
        };
        if request.pak_paths.len() < 2 {
            self.status = self
                .tr(
                    "Pak 두 개 이상을 추가하세요.",
                    "Add at least two Pak files.",
                )
                .to_owned();
            return;
        }
        let mut archives = Vec::with_capacity(request.pak_paths.len());
        for path in &request.pak_paths {
            let archive = self
                .inspections
                .get(&path_key(path))
                .and_then(|cached| cached.archive.as_ref())
                .cloned();
            let Some(archive) = archive else {
                self.status = self
                    .tr(
                        "Pak 확인이 끝난 뒤 다시 분석해 주세요.",
                        "Wait for the Pak check to finish, then analyze again.",
                    )
                    .to_owned();
                return;
            };
            archives.push(archive);
        }
        self.invalidate_analysis();
        let (sender, receiver) = mpsc::channel();
        let multithreaded = self.multithreaded;
        let cancellation = pak_merger::CancellationToken::new();
        let worker_cancellation = cancellation.clone();
        std::thread::spawn(move || {
            let progress_sender = sender.clone();
            let result = catch_unwind(AssertUnwindSafe(|| {
                pak_merger::merge::analyze_with_archives_progress_cancel_and_threads(
                    request,
                    archives,
                    &worker_cancellation,
                    multithreaded,
                    |completed, total, current_item| {
                        let _ = progress_sender.send(WorkerMessage::Progress(MergeProgress {
                            stage: MergeProgressStage::ComparingChanges,
                            completed: completed as u64,
                            total: total as u64,
                            current_item,
                        }));
                    },
                )
            }))
            .map_err(worker_panic_message)
            .and_then(|result| result.map_err(|error| error.to_string()))
            .map(|session| WorkerResult::Analyzed(Box::new(session)));
            let _ = sender.send(WorkerMessage::Finished(result));
        });
        self.worker = Some(receiver);
        self.cancel_signal = Some(cancellation);
        self.merge_progress = None;
        self.operation_started_at = Some(std::time::Instant::now());
        self.status = self.tr("분석 중…", "Analyzing…").to_owned();
        self.status_detail = None;
    }

    fn start_merge(&mut self, output: PathBuf, overwrite_existing: bool) {
        if !self.require_current_consent() {
            return;
        }
        let Some(session) = self.analysis_session.clone() else {
            return;
        };
        let resolutions = self.resolutions.clone();
        let compression = self.output_compression;
        let multithreaded = self.multithreaded;
        let (sender, receiver) = mpsc::channel();
        let cancellation = pak_merger::CancellationToken::new();
        let worker_cancellation = cancellation.clone();
        std::thread::spawn(move || {
            let progress_sender = sender.clone();
            let result = catch_unwind(AssertUnwindSafe(|| {
                pak_merger::merge::write_session_with_options_progress_and_cancel(
                    &session,
                    resolutions,
                    &output,
                    WriteOptions {
                        compression,
                        multithreaded,
                        overwrite_existing,
                    },
                    &worker_cancellation,
                    |progress| {
                        let _ = progress_sender.send(WorkerMessage::Progress(progress));
                    },
                )
            }))
            .map_err(worker_panic_message)
            .and_then(|result| result.map_err(|error| error.to_string()))
            .map(|report| WorkerResult::Merged(Box::new(report)));
            let _ = sender.send(WorkerMessage::Finished(result));
        });
        self.worker = Some(receiver);
        self.cancel_signal = Some(cancellation);
        self.merge_progress = None;
        self.operation_started_at = Some(std::time::Instant::now());
        self.completed_output = None;
        self.status = self
            .tr(
                "병합 Pak을 만들고 확인하는 중…",
                "Building and checking the merged Pak…",
            )
            .to_owned();
        self.status_detail = None;
    }

    fn request_merge_output(&mut self, output: PathBuf) {
        if output.exists() {
            self.pending_overwrite = Some(output);
        } else {
            self.start_merge(output, false);
        }
    }

    fn poll_worker(&mut self) {
        let Some(receiver) = &self.worker else {
            return;
        };
        let mut messages = Vec::new();
        let mut disconnected = false;
        loop {
            match receiver.try_recv() {
                Ok(message) => messages.push(message),
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => {
                    disconnected = true;
                    break;
                }
            }
        }

        let mut finished = false;
        for message in messages {
            match message {
                WorkerMessage::Progress(progress) => {
                    self.merge_progress = Some(progress);
                }
                WorkerMessage::Finished(Ok(WorkerResult::Analyzed(session))) => {
                    let session = Arc::new(*session);
                    let plan = session.shared_plan();
                    self.resolutions = ResolutionSet {
                        plan_id: plan.plan_id.clone(),
                        ..ResolutionSet::default()
                    };
                    let count = plan.conflicts.iter().filter(|item| item.blocking).count();
                    let warning_count = plan
                        .conflicts
                        .iter()
                        .filter(|item| is_placement_warning(item))
                        .count();
                    self.status = match self.locale {
                        UiLocale::Korean => format!(
                            "분석 완료: 직접 선택이 필요한 충돌 {count}개 · 위치 겹침 주의 {warning_count}개"
                        ),
                        UiLocale::English => format!(
                            "Analysis complete: {count} conflicts require your choice · {warning_count} possible placement overlaps"
                        ),
                        UiLocale::Japanese => format!(
                            "解析完了：選択が必要な競合 {count} 件・配置重複の可能性 {warning_count} 件"
                        ),
                    };
                    self.status_detail = None;
                    self.selected_conflict_id = plan
                        .conflicts
                        .iter()
                        .find(|item| item.blocking)
                        .or_else(|| plan.conflicts.first())
                        .map(|item| item.id.clone());
                    self.plan = Some(plan);
                    self.analysis_session = Some(session);
                    self.undo.clear();
                    self.pending_bulk = None;
                    finished = true;
                }
                WorkerMessage::Finished(Ok(WorkerResult::Merged(report))) => {
                    self.completed_output = Some(report.output_path.clone());
                    self.status.clear();
                    self.status_detail = None;
                    finished = true;
                }
                WorkerMessage::Finished(Err(error)) => {
                    self.status = friendly_operation_error(&error, self.locale).to_owned();
                    self.status_detail = Some(error);
                    finished = true;
                }
            }
            if finished {
                break;
            }
        }

        if disconnected && !finished {
            self.status = self
                .tr(
                    "작업이 예기치 않게 중단되었습니다.",
                    "The operation stopped unexpectedly.",
                )
                .to_owned();
            self.status_detail = None;
            finished = true;
        }

        if finished {
            self.worker = None;
            self.cancel_signal = None;
            self.merge_progress = None;
            self.operation_started_at = None;
        }
    }

    fn choose_variant(&mut self, conflict_id: &str, variant_id: &str) {
        if self
            .resolutions
            .choices
            .get(conflict_id)
            .is_some_and(|current| current == variant_id)
        {
            return;
        }

        let previous_variant_id = self
            .resolutions
            .choices
            .insert(conflict_id.to_owned(), variant_id.to_owned());
        self.undo.push(ResolutionUndo::Single(ResolutionUndoChange {
            conflict_id: conflict_id.to_owned(),
            previous_variant_id,
        }));
    }

    fn apply_bulk_updates(&mut self, updates: Vec<(String, String)>) {
        let updates = updates.into_iter().collect::<BTreeMap<_, _>>();
        let mut changes = Vec::with_capacity(updates.len());
        for (conflict_id, variant_id) in updates {
            if self
                .resolutions
                .choices
                .get(&conflict_id)
                .is_some_and(|current| current == &variant_id)
            {
                continue;
            }
            let previous_variant_id = self
                .resolutions
                .choices
                .insert(conflict_id.clone(), variant_id);
            changes.push(ResolutionUndoChange {
                conflict_id,
                previous_variant_id,
            });
        }
        if !changes.is_empty() {
            self.undo.push(ResolutionUndo::Batch(changes));
        }
    }

    fn undo_last_resolution(&mut self) {
        if let Some(command) = self.undo.pop() {
            command.restore(&mut self.resolutions);
        }
    }

    fn unresolved(&self) -> usize {
        self.plan
            .as_ref()
            .map(|plan| {
                plan.conflicts
                    .iter()
                    .filter(|conflict| {
                        conflict.blocking && !self.resolutions.choices.contains_key(&conflict.id)
                    })
                    .count()
            })
            .unwrap_or(0)
    }

    fn require_current_consent(&mut self) -> bool {
        if eula::has_valid_consent() {
            self.consent_valid = true;
            return true;
        }
        self.consent_valid = false;
        self.eula_confirmations = EulaConfirmations::default();
        self.status = match self.locale {
            UiLocale::Korean => {
                "이용약관 동의 기록을 확인할 수 없습니다. 약관을 다시 읽고 동의해 주세요."
                    .to_owned()
            }
            UiLocale::English => {
                "The saved terms acceptance cannot be used. Please review and accept the terms again."
                    .to_owned()
            }
            UiLocale::Japanese => {
                "保存された利用規約への同意を確認できません。規約を確認して、もう一度同意してください。"
                    .to_owned()
            }
        };
        self.status_detail = None;
        false
    }

    fn draw_eula_gate(&mut self, context: &egui::Context) {
        egui::CentralPanel::default().show(context, |ui| {
            egui::ScrollArea::vertical()
                .id_salt("eula-page-scroll")
                .auto_shrink([false, false])
                .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.heading(self.tr(
                    "이용약관",
                    "Terms of Use",
                ));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    self.draw_locale_picker(ui, "eula-locale");
                });
            });
            ui.colored_label(
                egui::Color32::YELLOW,
                self.tr(
                    "계속하려면 약관을 읽고 동의하세요.",
                    "Read and accept the terms to continue.",
                ),
            );
            ui.separator();
            egui::ScrollArea::vertical()
                .id_salt("eula-scroll")
                .max_height(460.0)
                .show(ui, |ui| {
                    ui.label(match self.locale {
                        UiLocale::Korean => eula::EULA_KO,
                        UiLocale::English => eula::EULA_EN,
                        UiLocale::Japanese => eula::EULA_JA,
                    });
                });
            ui.separator();
            ui.checkbox(
                &mut self.eula_confirmations.non_commercial_use,
                match self.locale {
                    UiLocale::Korean => "개인적·비상업적 목적으로만 사용합니다.",
                    UiLocale::English => {
                        "I will use Pak Merger only for personal, non-commercial purposes."
                    }
                    UiLocale::Japanese => {
                        "本ツールを個人的かつ非商用の目的に限って使用します。"
                    }
                },
            );
            ui.checkbox(
                &mut self.eula_confirmations.original_eula_and_law,
                match self.locale {
                    UiLocale::Korean => {
                        "해당 게임·소프트웨어의 EULA와 관련 법령을 확인하고 준수합니다."
                    }
                    UiLocale::English => {
                        "I will follow the applicable game or software EULA and law."
                    }
                    UiLocale::Japanese => {
                        "対象となるゲームまたはソフトウェアの EULA と適用法令を確認し、遵守します。"
                    }
                },
            );
            ui.checkbox(
                &mut self.eula_confirmations.end_user_responsibility,
                match self.locale {
                    UiLocale::Korean => {
                        "입력 파일, 선택, 결과 사용과 재배포에 대한 책임을 집니다."
                    }
                    UiLocale::English => {
                        "I am responsible for input files, choices, output use, and redistribution."
                    }
                    UiLocale::Japanese => {
                        "入力ファイル、選択、出力の利用、および再配布について責任を負います。"
                    }
                },
            );
            ui.horizontal(|ui| {
                let ready = self.eula_confirmations.all_confirmed();
                if ui
                    .add_enabled(
                        ready,
                        egui::Button::new(self.tr(
                            "모두 동의하고 계속",
                            "Accept all and continue",
                        )),
                    )
                    .clicked()
                {
                    let locale = self.locale.eula_locale();
                    match eula::accept(locale, self.eula_confirmations.clone()) {
                        Ok(_) => {
                            self.consent_valid = true;
                            self.last_consent_check = std::time::Instant::now();
                            self.status.clear();
                            self.status_detail = None;
                        }
                        Err(error) => {
                            self.status = match self.locale {
                                UiLocale::Korean => "이용약관 동의를 저장하지 못했습니다. 저장 폴더의 쓰기 권한을 확인한 뒤 다시 시도하세요.".to_owned(),
                                UiLocale::English => "The terms acceptance could not be saved. Check access to the settings folder and try again.".to_owned(),
                                UiLocale::Japanese => "利用規約への同意を保存できませんでした。設定フォルダーへの書き込み権限を確認して、もう一度お試しください。".to_owned(),
                            };
                            self.status_detail = Some(error.to_string());
                        }
                    }
                }
                if ui
                    .button(self.tr("동의하지 않고 종료", "Decline and exit"))
                    .clicked()
                {
                    context.send_viewport_cmd(egui::ViewportCommand::Close);
                }
            });
            if !self.status.is_empty() {
                ui.colored_label(egui::Color32::RED, &self.status);
            }
            if let Some(detail) = &self.status_detail {
                egui::CollapsingHeader::new(self.tr(
                    "자세한 오류 내용",
                    "Error details",
                ))
                .id_salt("eula-status-error-details")
                .default_open(false)
                .show(ui, |ui| {
                    ui.monospace(detail);
                });
            }
                });
        });
    }

    fn draw_analyzed_inputs(&self, ui: &mut egui::Ui, plan: &MergePlan) {
        ui.heading(self.tr("확인한 Pak", "Checked Paks"));
        for input in &plan.inputs {
            let version = input
                .pak_version
                .map(|value| format!("v{value}"))
                .unwrap_or_else(|| "?".to_owned());
            let mount = input.mount_point.as_deref().unwrap_or("?");
            ui.group(|ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.strong(format!("{} [Pak]", input.display_name));
                    ui.label(format!("{}: {version}", self.tr("Pak 버전", "Pak version")));
                    ui.label(format!(
                        "{}: {mount}",
                        self.tr("Pak 내부 폴더", "Folder in Pak")
                    ));
                    ui.label(format!(
                        "{}: {}",
                        self.tr("크기", "Size"),
                        format_bytes(input.size)
                    ));
                });
                ui.colored_label(
                    egui::Color32::LIGHT_GREEN,
                    self.tr("병합할 수 있습니다.", "Ready to merge."),
                );
                egui::CollapsingHeader::new(self.tr("자세한 정보", "Details"))
                    .id_salt(("analyzed-input-details", &input.id))
                    .default_open(false)
                    .show(ui, |ui| {
                        ui.horizontal_wrapped(|ui| {
                            ui.label("SHA-256:");
                            ui.monospace(&input.sha256);
                        });
                    });
            });
        }
    }

    fn draw_plan_warnings(&self, ui: &mut egui::Ui, plan: &MergePlan) {
        let encoding_drift_count = plan.encoding_drift_count;
        let visible_warnings = plan
            .warnings
            .iter()
            .filter(|warning| {
                let normalized = warning.to_ascii_lowercase();
                !normalized.starts_with("encoding drift retained")
                    && !normalized
                        .starts_with("the value is the same but its storage format differs.")
                    && !is_placement_plan_warning(warning)
                    && !is_routine_plan_notice(warning)
            })
            .collect::<Vec<_>>();
        if visible_warnings.is_empty() && encoding_drift_count == 0 {
            return;
        }
        egui::Frame::group(ui.style())
            .fill(egui::Color32::from_rgb(70, 53, 12))
            .show(ui, |ui| {
                ui.colored_label(
                    egui::Color32::YELLOW,
                    egui::RichText::new(self.tr("⚠ 확인할 내용", "⚠ Items to review"))
                        .strong(),
                );
                if encoding_drift_count != 0 {
                    ui.label(match self.locale {
                        UiLocale::Korean => format!(
                            "내용은 같지만 파일에 저장된 방식이 다른 항목 {encoding_drift_count}개는 기준 Pak 쪽을 유지합니다."
                        ),
                        UiLocale::English => format!(
                            "For {encoding_drift_count} items whose contents match but are stored differently, the base Pak format is kept."
                        ),
                        UiLocale::Japanese => format!(
                            "内容は同じでも保存形式が異なる {encoding_drift_count} 件は、基準 Pak 側の形式を維持します。"
                        ),
                    });
                }
                egui::ScrollArea::vertical()
                    .id_salt("plan-warnings")
                    .max_height(140.0)
                    .show(ui, |ui| {
                        for warning in visible_warnings {
                            if let Some((pak, path)) = stale_hash_warning_subject(warning) {
                                ui.colored_label(
                                    egui::Color32::YELLOW,
                                    match self.locale {
                                        UiLocale::Korean => format!(
                                            "• {pak}의 파일이 무결성 검사에 실패했습니다: {path}"
                                        ),
                                        UiLocale::English => format!(
                                            "• A file in {pak} failed its integrity check: {path}"
                                        ),
                                        UiLocale::Japanese => format!(
                                            "• {pak} のファイルが整合性チェックに失敗しました：{path}"
                                        ),
                                    },
                                );
                                egui::CollapsingHeader::new(self.tr(
                                    "문제 해결용 정보",
                                    "Troubleshooting details",
                                ))
                                .id_salt(("stale-plan-warning", warning))
                                .default_open(false)
                                .show(ui, |ui| {
                                    ui.monospace(warning);
                                });
                            } else {
                                let friendly = friendly_plan_warning(warning, self.locale);
                                ui.label(format!("• {friendly}"));
                                if friendly != warning.as_str() {
                                    egui::CollapsingHeader::new(self.tr(
                                        "자세한 오류 내용",
                                        "Error details",
                                    ))
                                        .id_salt(("plan-warning-details", warning))
                                        .default_open(false)
                                        .show(ui, |ui| {
                                            ui.monospace(warning);
                                        });
                                }
                            }
                        }
                    });
            });
    }

    fn draw_input_inspection(&self, ui: &mut egui::Ui, path: &Path) {
        let Some(cached) = self.inspections.get(&path_key(path)) else {
            ui.colored_label(
                egui::Color32::YELLOW,
                self.tr("검사 대기 중", "Inspection has not started"),
            );
            return;
        };
        match &cached.status {
            PakInspectionStatus::Pending => {
                ui.horizontal(|ui| {
                    ui.add(egui::Spinner::new().size(14.0));
                    ui.label(self.tr("Pak 파일을 확인하는 중입니다…", "Checking the Pak file…"));
                });
                if let Some((completed, total)) = cached.progress {
                    let fraction = if total == 0 {
                        0.0
                    } else {
                        (completed.min(total) as f32 / total as f32).clamp(0.0, 1.0)
                    };
                    ui.add(
                        egui::ProgressBar::new(fraction)
                            .desired_width(ui.available_width())
                            .text(match self.locale {
                                UiLocale::Korean => format!(
                                    "파일 읽기 {:.0}% ({}/{})",
                                    fraction * 100.0,
                                    format_bytes(completed),
                                    format_bytes(total)
                                ),
                                UiLocale::English => format!(
                                    "Reading {:.0}% ({}/{})",
                                    fraction * 100.0,
                                    format_bytes(completed),
                                    format_bytes(total)
                                ),
                                UiLocale::Japanese => format!(
                                    "読み込み {:.0}% ({}/{})",
                                    fraction * 100.0,
                                    format_bytes(completed),
                                    format_bytes(total)
                                ),
                            }),
                    );
                }
            }
            PakInspectionStatus::Supported(inspection) => {
                ui.horizontal_wrapped(|ui| {
                    ui.colored_label(egui::Color32::LIGHT_GREEN, self.tr("사용 가능", "Ready"));
                    ui.label(format!("Pak v{}", inspection.version));
                    ui.label(format!(
                        "{}: {}",
                        self.tr("파일", "Files"),
                        inspection.entry_count
                    ));
                    ui.label(format_bytes(inspection.size));
                });
                ui.small(format!(
                    "{}: {}",
                    self.tr("Pak 내부 폴더", "Folder in Pak"),
                    inspection.mount_point
                ));
                if !inspection.stale_payload_hashes.is_empty() {
                    let paths = inspection
                        .stale_payload_hashes
                        .iter()
                        .map(|item| item.path.as_str())
                        .collect::<Vec<_>>()
                        .join(", ");
                    let warning = match self.locale {
                        UiLocale::Korean => {
                            format!("이 Pak의 일부 파일이 무결성 검사에 실패했습니다: {paths}")
                        }
                        UiLocale::English => {
                            format!("Some files in this Pak failed the integrity check: {paths}")
                        }
                        UiLocale::Japanese => format!(
                            "この Pak の一部のファイルが整合性チェックに失敗しました：{paths}"
                        ),
                    };
                    ui.add(
                        egui::Label::new(
                            egui::RichText::new(truncate(&warning, 360))
                                .color(egui::Color32::YELLOW),
                        )
                        .wrap(),
                    )
                    .on_hover_text(warning);
                }
                egui::CollapsingHeader::new(self.tr("자세한 정보", "Details"))
                    .id_salt(("input-inspection-details", path_key(path)))
                    .default_open(false)
                    .show(ui, |ui| {
                        ui.horizontal_wrapped(|ui| {
                            ui.label("Pak SHA-256:");
                            ui.monospace(&inspection.sha256);
                        });
                        for item in &inspection.stale_payload_hashes {
                            ui.separator();
                            ui.monospace(&item.path);
                            ui.horizontal_wrapped(|ui| {
                                ui.label(self.tr("Pak에 기록된 SHA-1:", "Recorded SHA-1:"));
                                ui.monospace(&item.stored_sha1);
                            });
                            ui.horizontal_wrapped(|ui| {
                                ui.label(self.tr("다시 계산한 SHA-1:", "Recalculated SHA-1:"));
                                ui.monospace(&item.actual_sha1);
                            });
                        }
                    });
            }
            PakInspectionStatus::Failed(error) => {
                ui.colored_label(
                    egui::Color32::LIGHT_RED,
                    self.tr("이 Pak을 읽을 수 없습니다", "This Pak can't be read"),
                );
                ui.label(friendly_inspection_error(error, self.locale));
                egui::CollapsingHeader::new(self.tr("자세한 오류 내용", "Error details"))
                    .id_salt(("input-inspection-error-details", path_key(path)))
                    .default_open(false)
                    .show(ui, |ui| {
                        ui.monospace(error);
                    });
                ui.small(self.tr(
                    "문제를 해결한 뒤 Pak을 다시 추가하세요.",
                    "Fix the problem, then add the Pak again.",
                ));
            }
        }
    }
}

impl eframe::App for MergerApp {
    fn update(&mut self, context: &egui::Context, _frame: &mut eframe::Frame) {
        if self.consent_valid
            && self.last_consent_check.elapsed() >= std::time::Duration::from_secs(1)
        {
            self.last_consent_check = std::time::Instant::now();
            self.require_current_consent();
        }
        if !self.consent_valid {
            self.draw_eula_gate(context);
            return;
        }
        self.poll_inspections();
        self.poll_worker();
        if self.is_busy() || self.has_pending_inspections() {
            context.request_repaint_after(std::time::Duration::from_millis(100));
        }

        if !self.is_busy() {
            for file in context.input(|input| input.raw.dropped_files.clone()) {
                if let Some(path) = file.path {
                    self.add_path(path);
                }
            }
        }

        egui::TopBottomPanel::top("header").show(context, |ui| {
            ui.horizontal(|ui| {
                ui.heading(PRODUCT_NAME);
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    self.draw_locale_picker(ui, "locale");
                    if ui.button(self.tr("이용약관", "Terms")).clicked() {
                        self.show_terms = true;
                    }
                });
            });
            ui.label(self.tr(
                "여러 모드 Pak이 바꾼 내용을 비교해 하나로 합칩니다. 값이 겹치면 사용할 Pak을 직접 고를 수 있습니다.",
                "Compare changes from several mod Paks, choose which values to keep, and combine them into one Pak.",
            ));
            let merge_tab = self.tr("병합", "Merge").to_owned();
            let options_tab = self.tr("옵션", "Options").to_owned();
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.show_options, false, merge_tab);
                ui.selectable_value(&mut self.show_options, true, options_tab);
            });
        });

        egui::CentralPanel::default().show(context, |ui| {
            if self.show_options {
                self.draw_options(ui);
                return;
            }
            egui::ScrollArea::vertical()
                .id_salt("main-page-scroll")
                .auto_shrink([false, false])
                .show(ui, |ui| {
            ui.horizontal(|ui| {
                if ui
                    .add_enabled(
                        !self.is_busy(),
                        egui::Button::new(self.tr("Pak 추가", "Add Pak")),
                    )
                    .clicked()
                    && let Some(paths) = rfd::FileDialog::new()
                        .add_filter("Unreal Pak", &["pak"])
                        .pick_files()
                {
                    for path in paths {
                        self.add_path(path);
                    }
                }
                ui.label(self.tr(
                    "파일을 이 창에 끌어놓아도 됩니다.",
                    "You can also drop files onto this window.",
                ));
            });

            ui.separator();
            ui.heading(self.tr("합칠 Pak과 기준 Pak", "Input Paks and base Pak"));
            ui.small(self.tr(
                "기준 Pak은 별도 선택이 필요 없는 항목의 기본 형식을 정합니다. 충돌한 값은 직접 선택합니다.",
                "The base Pak sets the default format where no choice is needed. You still choose every conflicting value.",
            ));
            let busy = self.is_busy();
            let mut next_carrier = self.carrier_index;
            let mut remove_pak = None;
            for (index, path) in self.pak_paths.iter().enumerate() {
                ui.horizontal(|ui| {
                    ui.add_enabled_ui(!busy, |ui| {
                        ui.radio_value(
                            &mut next_carrier,
                            index,
                            self.tr("기준 Pak", "Base Pak"),
                        );
                    });
                    ui.monospace(path.display().to_string());
                    if ui
                        .add_enabled(
                            !busy,
                            egui::Button::new(self.tr("제거", "Remove")),
                        )
                        .clicked()
                    {
                        remove_pak = Some(index);
                    }
                });
                ui.indent(("pak-inspection", index), |ui| {
                    self.draw_input_inspection(ui, path);
                });
            }
            if let Some(index) = remove_pak {
                self.remove_pak(index);
            } else if next_carrier != self.carrier_index {
                self.set_carrier(next_carrier);
            }

            if ui
                .add_enabled(
                    !busy && !self.pak_paths.is_empty(),
                    egui::Button::new(self.tr("분석", "Analyze")),
                )
                .clicked()
            {
                self.start_analysis();
            }

            if self.plan.is_some() {
                ui.separator();
                if let Some(plan) = self.plan.as_ref() {
                    self.draw_analyzed_inputs(ui, plan);
                    self.draw_plan_warnings(ui, plan);
                }

                ui.separator();
                ui.horizontal(|ui| {
                    ui.heading(self.tr("서로 다른 값 선택", "Choose conflicting values"));
                    ui.label(match self.locale {
                        UiLocale::Korean => format!("선택 필요: {}", self.unresolved()),
                        UiLocale::English => format!("Choices left: {}", self.unresolved()),
                        UiLocale::Japanese => format!("残りの選択: {}", self.unresolved()),
                    });
                    if let Some(plan) = self.plan.as_ref() {
                        let warning_count = plan
                            .conflicts
                            .iter()
                            .filter(|conflict| is_placement_warning(conflict))
                            .count();
                        if warning_count != 0 {
                            ui.colored_label(
                                egui::Color32::YELLOW,
                                match self.locale {
                                    UiLocale::Korean => {
                                        format!("NPC 위치 겹침 주의: {warning_count}")
                                    }
                                    UiLocale::English => {
                                        format!("Possible placement overlaps: {warning_count}")
                                    }
                                    UiLocale::Japanese => {
                                        format!("NPC 配置重複の可能性: {warning_count}")
                                    }
                                },
                            );
                        }
                    }
                    if ui
                        .add_enabled(
                            !self.undo.is_empty(),
                            egui::Button::new(self.tr("실행 취소", "Undo")),
                        )
                        .clicked()
                    {
                        self.undo_last_resolution();
                    }
                });
                ui.horizontal(|ui| {
                    ui.label(self.tr("목록 검색", "Search list"));
                    if ui.text_edit_singleline(&mut self.filter).changed() {
                        self.pending_bulk = None;
                    }
                    let storage_examples_label = self
                        .tr(
                            "같은 값의 저장 방식 차이 예시 보기",
                            "Show storage-format examples",
                        )
                        .to_owned();
                    if ui
                        .checkbox(
                            &mut self.show_storage_format_details,
                            storage_examples_label,
                        )
                        .changed()
                    {
                        self.pending_bulk = None;
                        self.selected_conflict_id = None;
                    }
                });

                let needle = self.filter.trim().to_ascii_lowercase();
                let show_storage_format_details = self.show_storage_format_details;
                let visible_indices = self
                    .plan
                    .as_ref()
                    .map(|plan| {
                        plan.conflicts
                            .iter()
                            .enumerate()
                            .filter_map(|(index, conflict)| {
                                conflict_is_visible(
                                    conflict,
                                    &needle,
                                    show_storage_format_details,
                                )
                                .then_some(index)
                            })
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();

                let mut counts = BTreeMap::<String, usize>::new();
                if let Some(plan) = self.plan.as_ref() {
                    for input in &plan.inputs {
                        counts.insert(input.id.clone(), 0);
                    }
                    for &index in &visible_indices {
                        let conflict = &plan.conflicts[index];
                        if !is_user_selectable_conflict(conflict)
                            || self.resolutions.choices.contains_key(&conflict.id)
                        {
                            continue;
                        }
                        let mut counted = BTreeSet::new();
                        for variant in &conflict.variants {
                            if counted.insert(&variant.input_id)
                                && let Some(count) = counts.get_mut(&variant.input_id)
                            {
                                *count += 1;
                            }
                        }
                    }
                }

                let mut requested_bulk = None;
                ui.horizontal_wrapped(|ui| {
                    ui.label(self.tr(
                        "보이는 미선택 항목에 한 Pak 일괄 적용:",
                        "Apply one Pak to all visible unresolved items:",
                    ));
                    if let Some(plan) = self.plan.as_ref() {
                        for input in &plan.inputs {
                            let count = counts.get(&input.id).copied().unwrap_or(0);
                            let text = format!("{} ({count})", input.display_name);
                            if ui.add_enabled(count > 0, egui::Button::new(text)).clicked() {
                                requested_bulk = Some(PendingBulkSelection {
                                    input_id: input.id.clone(),
                                    display_name: input.display_name.clone(),
                                    filter: needle.clone(),
                                    count,
                                });
                            }
                        }
                    }
                });
                if let Some(requested_bulk) = requested_bulk {
                    self.pending_bulk = Some(requested_bulk);
                }

                let mut confirm_bulk = false;
                let mut cancel_bulk = false;
                if let Some(pending) = &self.pending_bulk {
                    egui::Frame::group(ui.style())
                        .fill(egui::Color32::from_rgb(43, 56, 76))
                        .show(ui, |ui| {
                            ui.label(match self.locale {
                                UiLocale::Korean => format!(
                                    "현재 보이는 미선택 항목 {}개에 '{}' Pak을 적용할까요? 한 번에 되돌릴 수 있습니다.",
                                    pending.count, pending.display_name
                                ),
                                UiLocale::English => format!(
                                    "Apply Pak '{}' to the {} unselected items shown here? You can undo the whole batch at once.",
                                    pending.display_name, pending.count,
                                ),
                                UiLocale::Japanese => format!(
                                    "表示中の未選択項目 {} 件に Pak '{}' を適用しますか？一括で元に戻せます。",
                                    pending.count, pending.display_name,
                                ),
                            });
                            ui.horizontal(|ui| {
                                if ui.button(self.tr("적용", "Apply")).clicked() {
                                    confirm_bulk = true;
                                }
                                if ui.button(self.tr("취소", "Cancel")).clicked() {
                                    cancel_bulk = true;
                                }
                            });
                        });
                }
                if confirm_bulk {
                    let updates = match (self.plan.as_ref(), self.pending_bulk.as_ref()) {
                        (Some(plan), Some(pending)) => collect_bulk_updates(
                            plan,
                            &self.resolutions,
                            &pending.input_id,
                            &pending.filter,
                        ),
                        _ => Vec::new(),
                    };
                    if !updates.is_empty() {
                        self.apply_bulk_updates(updates);
                    }
                    self.pending_bulk = None;
                } else if cancel_bulk {
                    self.pending_bulk = None;
                }

                let mut pending_choices = Vec::<(String, String)>::new();
                let mut requested_conflict_selection = None;
                if let Some(plan) = self.plan.as_ref() {
                    if visible_indices.is_empty() {
                        ui.weak(self.tr(
                            "검색어와 일치하는 항목이 없습니다.",
                            "No items match this search.",
                        ));
                    } else {
                        ui.label(match self.locale {
                            UiLocale::Korean => format!("보이는 항목: {}개", visible_indices.len()),
                            UiLocale::English => format!("Showing: {}", visible_indices.len()),
                            UiLocale::Japanese => format!("表示中: {} 件", visible_indices.len()),
                        });
                    }
                    let active_conflict_index = selected_visible_conflict_index(
                        plan,
                        &visible_indices,
                        self.selected_conflict_id.as_deref(),
                    );
                    let active_conflict_id = active_conflict_index
                        .map(|index| plan.conflicts[index].id.clone());
                    if self.selected_conflict_id.as_deref() != active_conflict_id.as_deref() {
                        requested_conflict_selection = active_conflict_id.clone();
                    }

                    if ui.available_width() >= 820.0 {
                        let total_width = ui.available_width();
                        let list_width = (total_width * 0.34).clamp(280.0, 390.0);
                        let detail_width = (total_width - list_width - 18.0).max(380.0);
                        ui.horizontal_top(|ui| {
                            ui.allocate_ui_with_layout(
                                egui::vec2(list_width, 470.0),
                                egui::Layout::top_down(egui::Align::Min),
                                |ui| {
                                    if let Some(id) = draw_compact_conflict_list(
                                        ui,
                                        plan,
                                        &visible_indices,
                                        &self.resolutions,
                                        active_conflict_id.as_deref(),
                                        self.locale,
                                        445.0,
                                    ) {
                                        requested_conflict_selection = Some(id);
                                    }
                                },
                            );
                            ui.separator();
                            ui.allocate_ui_with_layout(
                                egui::vec2(detail_width, 470.0),
                                egui::Layout::top_down(egui::Align::Min),
                                |ui| {
                                    egui::ScrollArea::vertical()
                                        .id_salt("selected-conflict-detail")
                                        .max_height(465.0)
                                        .auto_shrink([false, false])
                                        .show(ui, |ui| {
                                            if let Some(index) = active_conflict_index {
                                                draw_conflict_detail(
                                                    ui,
                                                    &plan.conflicts[index],
                                                    &plan.carrier_input_id,
                                                    &self.resolutions,
                                                    self.locale,
                                                    &mut pending_choices,
                                                );
                                            }
                                        });
                                },
                            );
                        });
                    } else {
                        if let Some(id) = draw_compact_conflict_list(
                            ui,
                            plan,
                            &visible_indices,
                            &self.resolutions,
                            active_conflict_id.as_deref(),
                            self.locale,
                            220.0,
                        ) {
                            requested_conflict_selection = Some(id);
                        }
                        ui.separator();
                        if let Some(index) = active_conflict_index {
                            draw_conflict_detail(
                                ui,
                                &plan.conflicts[index],
                                &plan.carrier_input_id,
                                &self.resolutions,
                                self.locale,
                                &mut pending_choices,
                            );
                        }
                    }
                }
                if let Some(conflict_id) = requested_conflict_selection {
                    self.selected_conflict_id = Some(conflict_id);
                }
                for (conflict_id, variant_id) in pending_choices {
                    self.choose_variant(&conflict_id, &variant_id);
                }
                let can_merge = !self.is_busy() && self.unresolved() == 0;
                if ui
                    .add_enabled(
                        can_merge,
                        egui::Button::new(self.tr("병합 Pak 생성", "Build merged Pak")),
                    )
                    .clicked()
                    && let Some(path) = rfd::FileDialog::new()
                        .set_file_name(DEFAULT_MERGED_PAK_FILE_NAME)
                        .add_filter("Unreal Pak", &["pak"])
                        .save_file()
                {
                    self.request_merge_output(path);
                }
            }

            if let Some(output) = &self.completed_output {
                ui.separator();
                egui::Frame::group(ui.style())
                    .fill(egui::Color32::from_rgb(24, 65, 44))
                    .show(ui, |ui| {
                        ui.colored_label(
                            egui::Color32::LIGHT_GREEN,
                            egui::RichText::new(match self.locale {
                                UiLocale::Korean => {
                                    format!("병합 Pak 생성 완료: {}", output.display())
                                }
                                UiLocale::English => {
                                    format!("Merged Pak created: {}", output.display())
                                }
                                UiLocale::Japanese => {
                                    format!("統合 Pak の作成完了：{}", output.display())
                                }
                            })
                            .strong(),
                        );
                        ui.colored_label(
                            egui::Color32::YELLOW,
                            self.tr(
                                "병합 Pak을 사용하기 전에 원본 모드 Pak을 비활성화하세요.",
                                "Disable the source mod Paks before using the merged Pak.",
                            ),
                        );
                    });
            }

            ui.separator();
            if self.is_busy() {
                ui.horizontal(|ui| {
                    ui.add(egui::Spinner::new());
                    let cancelling = self
                        .cancel_signal
                        .as_ref()
                        .is_some_and(pak_merger::CancellationToken::is_cancelled);
                    if ui
                        .add_enabled(
                            !cancelling,
                            egui::Button::new(self.tr("작업 취소", "Cancel operation")),
                        )
                        .clicked()
                    {
                        if let Some(token) = &self.cancel_signal {
                            token.cancel();
                        }
                        self.status = self
                            .tr("취소하는 중...", "Cancelling...")
                            .to_owned();
                        self.status_detail = None;
                    }
                });
                if let Some(progress) = &self.merge_progress {
                    let stage = self.progress_stage_label(progress.stage);
                    let fraction = if progress.total == 0 {
                        0.0
                    } else {
                        (progress.completed.min(progress.total) as f32 / progress.total as f32)
                            .clamp(0.0, 1.0)
                    };
                    let displayed_percent = if progress.completed < progress.total {
                        (fraction * 100.0).min(99.9)
                    } else {
                        100.0
                    };
                    let text = if progress.total == 0 {
                        stage.to_owned()
                    } else {
                        let completed = progress.completed.min(progress.total);
                        match progress.stage {
                            MergeProgressStage::ComparingChanges
                                if progress.total
                                    >= pak_merger::ANALYSIS_PROGRESS_STEPS_PER_ITEM as u64
                                    && progress.total
                                        % pak_merger::ANALYSIS_PROGRESS_STEPS_PER_ITEM as u64
                                        == 0 =>
                            {
                                format!(
                                    "{stage} · {}/{} ({displayed_percent:.1}%)",
                                    completed
                                        / pak_merger::ANALYSIS_PROGRESS_STEPS_PER_ITEM as u64,
                                    progress.total
                                        / pak_merger::ANALYSIS_PROGRESS_STEPS_PER_ITEM as u64,
                                )
                            }
                            MergeProgressStage::IndexingDatabase
                            | MergeProgressStage::WritingPak
                            | MergeProgressStage::VerifyingPak
                            | MergeProgressStage::Finalizing
                                if progress.total > 1 =>
                            {
                                format!(
                                    "{stage} · {} / {} ({displayed_percent:.1}%)",
                                    format_bytes(completed),
                                    format_bytes(progress.total),
                                )
                            }
                            MergeProgressStage::CheckingReferences => {
                                format!("{stage} · {displayed_percent:.1}%")
                            }
                            _ => format!(
                                "{stage} · {completed}/{} ({displayed_percent:.1}%)",
                                progress.total
                            ),
                        }
                    };
                    ui.add(
                        egui::ProgressBar::new(fraction)
                            .desired_width(ui.available_width())
                            .text(text),
                    );
                    if let Some(item) = &progress.current_item {
                        ui.small(egui::RichText::new(item).monospace());
                    }
                }
                if let Some(started_at) = self.operation_started_at {
                    let elapsed = started_at.elapsed().as_secs();
                    let minutes = elapsed / 60;
                    let seconds = elapsed % 60;
                    ui.small(match self.locale {
                        UiLocale::Korean => format!("경과 {minutes:02}:{seconds:02}"),
                        UiLocale::English => format!("Elapsed {minutes:02}:{seconds:02}"),
                        UiLocale::Japanese => format!("経過時間 {minutes:02}:{seconds:02}"),
                    });
                }
            }
            ui.label(&self.status);
            if let Some(detail) = &self.status_detail {
                egui::CollapsingHeader::new(self.tr(
                    "자세한 오류 내용",
                    "Error details",
                ))
                .id_salt("main-status-error-details")
                .default_open(false)
                .show(ui, |ui| {
                    ui.monospace(detail);
                });
            }
                });
        });

        if self.show_terms {
            let locale = self.locale;
            let mut show_terms = self.show_terms;
            egui::Window::new(match locale {
                UiLocale::Korean => "이용약관",
                UiLocale::English => "Terms of Use",
                UiLocale::Japanese => "利用規約",
            })
            .open(&mut show_terms)
            .default_width(760.0)
            .default_height(600.0)
            .show(context, |ui| {
                egui::ScrollArea::vertical().show(ui, |ui| {
                    ui.label(match locale {
                        UiLocale::Korean => eula::EULA_KO,
                        UiLocale::English => eula::EULA_EN,
                        UiLocale::Japanese => eula::EULA_JA,
                    });
                });
            });
            self.show_terms = show_terms;
        }

        if let Some(path) = self.pending_overwrite.clone() {
            let mut replace = false;
            let mut cancel = false;
            egui::Modal::new(egui::Id::new("confirm-output-overwrite")).show(context, |ui| {
                ui.heading(self.tr("기존 파일 덮어쓰기", "Replace existing file"));
                ui.label(self.tr(
                    "같은 이름의 파일이 있습니다. 덮어쓸까요?",
                    "This file already exists. Replace it?",
                ));
                ui.add_space(6.0);
                ui.monospace(path.display().to_string());
                ui.add_space(10.0);
                ui.horizontal(|ui| {
                    replace = ui.button(self.tr("덮어쓰기", "Replace")).clicked();
                    cancel = ui.button(self.tr("취소", "Cancel")).clicked();
                });
            });
            if replace {
                self.pending_overwrite = None;
                self.start_merge(path, true);
            } else if cancel {
                self.pending_overwrite = None;
            }
        }
    }
}

fn inspection_worker() -> (Sender<PakInspectionJob>, Receiver<PakInspectionMessage>) {
    let (request_sender, request_receiver) = mpsc::channel::<PakInspectionJob>();
    let (result_sender, result_receiver) = mpsc::channel::<PakInspectionMessage>();
    let request_receiver = Arc::new(Mutex::new(request_receiver));
    // Scan a few Paks at once without overwhelming slower disks.
    let worker_count = pak_merger::resources::worker_threads().clamp(1, 4);
    for _ in 0..worker_count {
        let request_receiver = Arc::clone(&request_receiver);
        let result_sender = result_sender.clone();
        std::thread::spawn(move || {
            loop {
                let job = {
                    let Ok(receiver) = request_receiver.lock() else {
                        break;
                    };
                    receiver.recv()
                };
                let Ok(job) = job else {
                    break;
                };
                let progress_sender = result_sender.clone();
                let progress_key = job.key.clone();
                let result =
                    pak_merger::pak::PakArchive::open_fast_with_progress_cancel_and_threads(
                        &job.path,
                        &job.cancellation,
                        job.multithreaded,
                        |progress| match progress {
                            pak_merger::pak::PakOpenProgress::Scanning {
                                completed_bytes,
                                total_bytes,
                            } => {
                                let _ = progress_sender.send(PakInspectionMessage::Progress {
                                    key: progress_key.clone(),
                                    generation: job.generation,
                                    completed_bytes,
                                    total_bytes,
                                });
                            }
                            pak_merger::pak::PakOpenProgress::Decoding { .. } => {}
                        },
                    )
                    .map(|archive| {
                        let archive = Arc::new(archive);
                        let inventory = archive.inventory();
                        let stale_payload_hashes = inventory
                            .entries
                            .iter()
                            .filter(|entry| !entry.payload_sha1_matches)
                            .map(|entry| StalePayloadHash {
                                path: entry.path.clone(),
                                stored_sha1: entry.stored_payload_sha1.clone(),
                                actual_sha1: entry.payload_sha1.clone(),
                            })
                            .collect();
                        let inspection = PakInspection {
                            sha256: inventory.archive_sha256.clone(),
                            size: inventory.archive_size,
                            mount_point: inventory.mount_point.clone(),
                            version: inventory.footer.version,
                            entry_count: inventory.entries.len(),
                            stale_payload_hashes,
                        };
                        (inspection, archive)
                    })
                    .map_err(|error| error.to_string());
                if result_sender
                    .send(PakInspectionMessage::Finished(PakInspectionResult {
                        key: job.key,
                        generation: job.generation,
                        result,
                    }))
                    .is_err()
                {
                    break;
                }
            }
        });
    }
    (request_sender, result_receiver)
}

fn worker_panic_message(payload: Box<dyn std::any::Any + Send>) -> String {
    let detail = payload
        .downcast_ref::<&str>()
        .map(|value| (*value).to_owned())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "unknown worker error".to_owned());
    format!("The background operation stopped unexpectedly: {detail}")
}

fn path_key(path: &Path) -> String {
    path.to_string_lossy().to_ascii_lowercase()
}

fn friendly_inspection_error(error: &str, locale: UiLocale) -> String {
    let lower = error.to_ascii_lowercase();
    if lower.contains("worker") || lower.contains("inspection stopped") {
        return locale
            .tr(
                "Pak 확인이 예기치 않게 중단되었습니다. 다시 시도하세요.",
                "The Pak check stopped unexpectedly. Try again.",
            )
            .to_owned();
    }
    if lower.contains("inspection could not start") {
        return locale
            .tr(
                "Pak 확인을 시작하지 못했습니다. 다시 시도하세요.",
                "The Pak check could not start. Try again.",
            )
            .to_owned();
    }
    if lower.contains("version") {
        return locale
            .tr(
                "이 Pak 버전은 현재 도구에서 읽을 수 없습니다.",
                "This Pak version cannot be read by this version of the tool.",
            )
            .to_owned();
    }
    if lower.contains("encrypted") {
        return locale
            .tr(
                "암호화된 Pak은 읽을 수 없습니다.",
                "Encrypted Paks cannot be read.",
            )
            .to_owned();
    }
    if lower.contains("oodle support could not be prepared") || lower.contains("oodle loader error")
    {
        return locale.tr(
            "Oodle 지원 파일을 준비하지 못했습니다. 인터넷 연결과 Pak Merger 폴더의 쓰기 권한을 확인하세요.",
            "Oodle support couldn't be prepared. Check your internet connection and write access to the Pak Merger folder.",
        ).to_owned();
    }
    if lower.contains("unsupported compression") {
        return locale.tr(
            "이 Pak에 사용된 압축 방식은 현재 도구에서 읽을 수 없습니다.",
            "The compression method used by this Pak cannot be read by this version of the tool.",
        ).to_owned();
    }
    if lower.contains("could not be decoded") || lower.contains("decoded file") {
        return locale.tr(
            "Pak 안의 압축 파일을 푸는 중 오류가 발견되었습니다. 파일이 손상되었을 수 있습니다.",
            "A compressed file inside the Pak could not be decoded and may be damaged.",
        ).to_owned();
    }
    if lower.contains("integrity check failed") {
        return locale
            .tr(
                "Pak 안의 파일이 무결성 검사에 실패했습니다.",
                "A file in this Pak failed its integrity check.",
            )
            .to_owned();
    }
    if lower.contains("root path") || lower.contains("internal file path") {
        return locale
            .tr(
                "Pak 안의 파일 경로가 올바르지 않아 안전하게 읽을 수 없습니다.",
                "A file path inside the Pak is not valid, so the Pak cannot be read safely.",
            )
            .to_owned();
    }
    if lower.contains("file-list format") {
        return locale
            .tr(
                "이 Pak의 파일 목록을 읽을 수 없습니다.",
                "The file list in this Pak cannot be read.",
            )
            .to_owned();
    }
    locale
        .tr(
            "이 Pak을 읽지 못했습니다. 파일이 손상되었거나 지원하지 않는 형식일 수 있습니다.",
            "This Pak couldn't be read. It may be damaged or use an unsupported format.",
        )
        .to_owned()
}

fn friendly_operation_error(error: &str, locale: UiLocale) -> &'static str {
    let lower = error.to_ascii_lowercase();
    if lower.contains("operation cancelled")
        || (lower.contains("interrupted") && lower.contains("cancel"))
    {
        locale.tr(
            "작업을 취소했습니다. 완성되지 않은 임시 Pak은 삭제했습니다.",
            "The operation was cancelled. The unfinished temporary Pak was removed.",
        )
    } else if lower.contains("oodle support could not be prepared")
        || lower.contains("oodle loader error")
    {
        locale.tr(
            "Oodle 지원 파일을 준비하지 못했습니다. 인터넷 연결과 Pak Merger 폴더의 쓰기 권한을 확인하세요.",
            "Oodle support couldn't be prepared. Check your internet connection and write access to the Pak Merger folder.",
        )
    } else if lower.contains("conflict")
        && (lower.contains("choice") || lower.contains("unresolved"))
    {
        locale.tr(
            "아직 고르지 않은 항목이 있습니다. 모든 충돌에서 사용할 Pak을 선택하세요.",
            "Some items still need a choice. Choose a Pak for every conflict.",
        )
    } else if lower.contains("temporary work folder") || lower.contains("temporary work path") {
        locale.tr(
            "Pak Merger 실행 파일 옆의 임시 작업 폴더를 사용할 수 없습니다. 실행 파일 폴더의 쓰기 권한을 확인하세요.",
            "The temporary work folder beside Pak Merger could not be used. Check write access to the executable folder.",
        )
    } else if lower.contains("already exists") {
        locale.tr(
            "같은 이름의 파일이 이미 있습니다. 다른 이름으로 저장하세요.",
            "A file with that name already exists. Choose a different name.",
        )
    } else if lower.contains("identical") {
        locale.tr(
            "내용이 같은 Pak이 두 번 추가되었습니다. 하나를 제거하세요.",
            "The same Pak was added twice. Remove one copy.",
        )
    } else if lower.contains("root path") || lower.contains("game folder") {
        locale.tr(
            "Pak들이 서로 다른 게임 폴더를 가리킵니다. 같은 게임용 Pak인지 확인하세요.",
            "The Paks point to different game folders. Check that they are for the same game.",
        )
    } else if lower.contains("input pak changed") || lower.contains("input changed") {
        locale.tr(
            "분석한 뒤 입력 Pak이 바뀌었습니다. 다시 분석하세요.",
            "An input Pak changed after analysis. Analyze the Paks again.",
        )
    } else if lower.contains("space") || lower.contains("memory") {
        locale.tr(
            "작업에 필요한 디스크 공간이나 메모리가 부족합니다.",
            "There is not enough disk space or memory for this operation.",
        )
    } else if lower.contains("final checks") || lower.contains("integrity") {
        locale.tr(
            "만든 Pak을 다시 확인하는 과정에서 오류가 발견되었습니다.",
            "A problem was found while checking the merged Pak.",
        )
    } else if lower.contains("database") {
        locale.tr(
            "일부 게임 데이터를 안전하게 비교하거나 합칠 수 없습니다.",
            "Some game data could not be compared or merged safely.",
        )
    } else {
        locale.tr(
            "작업을 완료하지 못했습니다. 입력 Pak과 선택 내용을 확인하세요.",
            "The operation couldn't be completed. Check the input Paks and your choices.",
        )
    }
}

fn value_preview(preview: &str) -> String {
    // Value notation stays the same in every interface language.
    preview.replace("array[", "list[")
}

fn stale_hash_warning_subject(warning: &str) -> Option<(&str, &str)> {
    let (pak, rest) = warning.split_once(" contains ")?;
    let (path, _) = rest.split_once(", whose integrity value is outdated.")?;
    (!pak.is_empty() && !path.is_empty()).then_some((pak, path))
}

fn is_placement_plan_warning(warning: &str) -> bool {
    warning.starts_with("POTENTIAL_PLACEMENT_COLLISION") || warning.starts_with("NpcSet location ")
}

fn is_routine_plan_notice(warning: &str) -> bool {
    warning.starts_with("Known-reference validation checked ")
        || warning.starts_with("Only bundled, field-qualified reference rules were checked")
}

fn friendly_plan_warning(warning: &str, locale: UiLocale) -> String {
    if let Some((asset, _)) = warning.split_once(" cannot be compared row by row") {
        return match locale {
            UiLocale::Korean => format!(
                "{asset}: Pak마다 데이터 구성이 달라 항목별로 나눠 합칠 수 없습니다. 이 파일 묶음에 사용할 Pak을 선택하세요."
            ),
            UiLocale::English => format!(
                "{asset}: The Paks organize this data differently, so it cannot be merged item by item. Choose one Pak for this file group."
            ),
            UiLocale::Japanese => format!(
                "{asset}: Pak ごとにデータ構成が異なるため、項目単位では統合できません。このファイル一式に使用する Pak を選択してください。"
            ),
        };
    }
    if let Some((asset, _)) = warning.split_once(" could not be compared field by field") {
        return match locale {
            UiLocale::Korean => format!(
                "{asset}: 세부 내용을 안전하게 비교할 수 없어 관련 파일을 한 Pak에서 함께 가져와야 합니다."
            ),
            UiLocale::English => format!(
                "{asset}: The contents cannot be compared safely item by item, so choose one Pak for the related files."
            ),
            UiLocale::Japanese => format!(
                "{asset}: 内容を項目単位で安全に比較できないため、関連ファイルに使用する Pak を一つ選択してください。"
            ),
        };
    }
    if let Some((asset, _)) = warning.split_once(": the related .uasset file differs between Paks")
    {
        return match locale {
            UiLocale::Korean => format!(
                "{asset}: 함께 쓰이는 파일의 구성이 Pak마다 다릅니다. 기준 Pak 쪽 파일을 사용하므로 병합 뒤 게임에서 확인하세요."
            ),
            UiLocale::English => format!(
                "{asset}: The related files differ between Paks. The base Pak file is kept, so check this content in the game after merging."
            ),
            UiLocale::Japanese => format!(
                "{asset}: 関連ファイルが Pak ごとに異なります。基準 Pak 側を維持するため、統合後にゲーム内で確認してください。"
            ),
        };
    }
    if warning.starts_with("Known-reference table ") {
        return locale
            .tr(
                "서로 연결된 데이터 일부를 확인하지 못했습니다. 입력 Pak을 확인하세요.",
                "Some linked data could not be checked. Review the input Paks.",
            )
            .to_owned();
    }
    if warning.starts_with("Reference rule ") {
        return locale
            .tr(
                "필요한 연결 데이터가 없습니다. 다른 Pak을 선택하거나 입력을 확인하세요.",
                "Required linked data is missing. Choose another Pak or review the inputs.",
            )
            .to_owned();
    }
    if warning.starts_with("Reference source ") {
        return locale
            .tr(
                "서로 연결된 데이터를 확인하는 중 일부 파일을 다시 읽지 못했습니다.",
                "A file could not be read again while checking linked data.",
            )
            .to_owned();
    }
    locale
        .tr(
            "이 항목은 자동으로 병합할 수 없습니다. 자세한 내용을 확인하세요.",
            "This item couldn't be merged automatically. Check the details.",
        )
        .to_owned()
}

fn conflict_hierarchy(conflict: &Conflict, locale: UiLocale) -> ConflictHierarchy {
    ConflictHierarchy {
        asset: conflict.asset_path.clone(),
        row: conflict
            .row_id
            .clone()
            .unwrap_or_else(|| locale.tr("<파일 묶음>", "<file group>").to_owned()),
        group: conflict.group_id.clone().unwrap_or_else(|| {
            locale
                .tr("<파일 묶음 전체>", "<whole file group>")
                .to_owned()
        }),
    }
}

fn conflict_kind_label(kind: &ConflictKind, locale: UiLocale) -> &'static str {
    match kind {
        ConflictKind::FieldValue => locale.tr("값 충돌", "Value conflict"),
        ConflictKind::AtomicGroup => locale.tr("함께 바뀌는 값 충돌", "Linked values conflict"),
        ConflictKind::RowIdCollision => locale.tr(
            "같은 데이터 ID의 내용이 다름",
            "Same data ID, different contents",
        ),
        ConflictKind::PotentialPlacementCollision => {
            locale.tr("NPC 위치 겹침 주의", "Possible placement overlap")
        }
        ConflictKind::OpaquePackage => locale.tr("파일 전체 선택 필요", "File-group conflict"),
        ConflictKind::StructureMismatch => {
            locale.tr("파일 구조가 다름", "Different file structures")
        }
        ConflictKind::EncodingDrift => locale.tr(
            "값은 같고 저장 방식만 다름",
            "Same value, stored differently",
        ),
        ConflictKind::ReferenceBreak => {
            locale.tr("필요한 연결 데이터가 없음", "Missing linked item")
        }
        ConflictKind::UnsupportedAsset => locale.tr("지원하지 않는 파일", "Unsupported file"),
    }
}

fn conflict_kind_help(kind: &ConflictKind, locale: UiLocale) -> &'static str {
    match kind {
        ConflictKind::FieldValue => locale.tr(
            "같은 값이 Pak마다 다릅니다. 사용할 값을 가진 Pak을 선택하세요.",
            "This value differs between Paks. Choose the Pak whose value you want to use.",
        ),
        ConflictKind::AtomicGroup => locale.tr(
            "함께 바뀌어야 하는 값이 Pak마다 다릅니다. 한 Pak의 내용을 통째로 선택하세요.",
            "Fields that must change together differ between Paks. Choose one Pak.",
        ),
        ConflictKind::RowIdCollision => locale.tr(
            "같은 데이터 ID(m_id)에 서로 다른 내용이 들어 있습니다. 이 데이터 전체를 가져올 Pak을 선택하세요.",
            "Rows with the same m_id differ. Choose the Pak to use for the whole row.",
        ),
        ConflictKind::PotentialPlacementCollision => locale.tr(
            "같은 위치에 서로 다른 NPC나 대화가 겹칠 수 있습니다. 병합은 계속할 수 있지만 게임에서 확인하세요.",
            "Different NPCs or interactions may overlap at the same location. Merging can continue, but check the result in game.",
        ),
        ConflictKind::OpaquePackage => locale.tr(
            "이 파일들은 내용을 나눠 비교할 수 없습니다. 관련 파일 전체를 가져올 Pak을 선택하세요.",
            "This file group cannot be compared item by item. Choose one Pak for the whole group.",
        ),
        ConflictKind::StructureMismatch => locale.tr(
            "파일 구조가 달라 부분 병합할 수 없습니다. 묶음 전체를 가져올 Pak을 선택하세요.",
            "The file structures differ, so they cannot be partly merged. Choose one Pak for the whole group.",
        ),
        ConflictKind::EncodingDrift => locale.tr(
            "내용은 같지만 파일에 저장된 방식이 다릅니다. 기준 Pak 쪽을 유지합니다.",
            "The contents match but are stored differently. The base Pak format is kept.",
        ),
        ConflictKind::ReferenceBreak => locale.tr(
            "필요한 연결 데이터가 없습니다. 다른 Pak을 선택하거나 입력을 확인하세요.",
            "Required linked data is missing. Choose another Pak or review the inputs.",
        ),
        ConflictKind::UnsupportedAsset => locale.tr(
            "이 파일은 부분 병합을 지원하지 않습니다. 사용할 Pak을 선택하세요.",
            "This file cannot be partly merged. Choose the Pak you want to use.",
        ),
    }
}

fn is_encoding_drift(conflict: &Conflict) -> bool {
    conflict.kind == ConflictKind::EncodingDrift
}

fn is_placement_warning(conflict: &Conflict) -> bool {
    conflict.kind == ConflictKind::PotentialPlacementCollision
}

fn is_user_selectable_conflict(conflict: &Conflict) -> bool {
    conflict.blocking && !is_encoding_drift(conflict)
}

fn fixed_encoding_drift_variant<'a>(
    conflict: &'a Conflict,
    carrier_input_id: &str,
) -> Option<&'a Variant> {
    if !is_encoding_drift(conflict) {
        return None;
    }
    conflict
        .variants
        .iter()
        .find(|variant| variant.input_id == carrier_input_id)
        .or_else(|| conflict.variants.first())
}

fn selected_visible_conflict_index(
    plan: &MergePlan,
    visible_indices: &[usize],
    selected_conflict_id: Option<&str>,
) -> Option<usize> {
    selected_conflict_id
        .and_then(|selected| {
            visible_indices
                .iter()
                .copied()
                .find(|&index| plan.conflicts[index].id == selected)
        })
        .or_else(|| visible_indices.first().copied())
}

fn conflict_is_resolved(conflict: &Conflict, resolutions: &ResolutionSet) -> bool {
    if !conflict.blocking {
        return true;
    }
    resolutions.choices.contains_key(&conflict.id)
}

fn draw_compact_conflict_list(
    ui: &mut egui::Ui,
    plan: &MergePlan,
    visible_indices: &[usize],
    resolutions: &ResolutionSet,
    active_conflict_id: Option<&str>,
    locale: UiLocale,
    max_height: f32,
) -> Option<String> {
    let mut requested = None;
    ui.with_layout(egui::Layout::top_down(egui::Align::Min), |ui| {
        ui.strong(locale.tr("충돌 목록", "Conflict list"));
        ui.small(locale.tr(
            "항목을 고르면 오른쪽이나 아래에서 Pak별 내용을 비교할 수 있습니다.",
            "Select an item to compare what each Pak contains.",
        ));
        egui::ScrollArea::vertical()
            .id_salt("compact-conflict-list")
            .max_height(max_height)
            .auto_shrink([false, false])
            .show_rows(ui, 30.0, visible_indices.len(), |ui, row_range| {
                for visible_row in row_range {
                    let conflict = &plan.conflicts[visible_indices[visible_row]];
                    let hierarchy = conflict_hierarchy(conflict, locale);
                    let resolved = conflict_is_resolved(conflict, resolutions);
                    let active = active_conflict_id == Some(conflict.id.as_str());
                    let asset_name = path_leaf(&hierarchy.asset);
                    let status = if is_placement_warning(conflict) {
                        "⚠"
                    } else if resolved {
                        "✓"
                    } else {
                        "!"
                    };
                    let label = format!(
                        "{status} {asset_name} · {} · {}",
                        hierarchy.row, hierarchy.group
                    );
                    let color = if is_placement_warning(conflict) {
                        egui::Color32::YELLOW
                    } else if resolved {
                        egui::Color32::LIGHT_GREEN
                    } else {
                        egui::Color32::LIGHT_RED
                    };
                    let width = ui.available_width();
                    let response = ui
                        .add_sized(
                            [width, 28.0],
                            egui::Button::selectable(
                                active,
                                egui::RichText::new(label).color(color),
                            )
                            .wrap_mode(egui::TextWrapMode::Truncate),
                        )
                        .on_hover_ui(|ui| {
                            ui.strong(&hierarchy.asset);
                            ui.monospace(format!("{} · {}", hierarchy.row, hierarchy.group));
                            ui.label(conflict_kind_help(&conflict.kind, locale));
                            if let Some(variant_id) = resolutions.choices.get(&conflict.id)
                                && let Some(variant) = conflict
                                    .variants
                                    .iter()
                                    .find(|variant| &variant.id == variant_id)
                            {
                                ui.label(format!(
                                    "{}: {}",
                                    locale.tr("선택", "Selected"),
                                    provenance_file_name(variant)
                                ));
                            }
                        });
                    if response.clicked() {
                        requested = Some(conflict.id.clone());
                    }
                }
            });
    });
    requested
}

#[allow(clippy::too_many_arguments)]
fn draw_conflict_detail(
    ui: &mut egui::Ui,
    conflict: &Conflict,
    carrier_input_id: &str,
    resolutions: &ResolutionSet,
    locale: UiLocale,
    pending_choices: &mut Vec<(String, String)>,
) {
    let hierarchy = conflict_hierarchy(conflict, locale);
    let selected_id = resolutions.choices.get(&conflict.id).map(String::as_str);
    let resolved = conflict_is_resolved(conflict, resolutions);
    let fixed_drift_id =
        fixed_encoding_drift_variant(conflict, carrier_input_id).map(|variant| variant.id.as_str());

    egui::Frame::group(ui.style()).show(ui, |ui| {
        ui.with_layout(egui::Layout::top_down(egui::Align::Min), |ui| {
            ui.horizontal(|ui| {
                ui.strong(locale.tr("비교 내용", "Comparison"));
                ui.label(conflict_kind_label(&conflict.kind, locale));
                let informational_warning = is_placement_warning(conflict);
                ui.colored_label(
                    if informational_warning {
                        egui::Color32::YELLOW
                    } else if resolved {
                        egui::Color32::LIGHT_GREEN
                    } else {
                        egui::Color32::LIGHT_RED
                    },
                    if informational_warning {
                        locale.tr("주의 · 병합 가능", "Warning · merging can continue")
                    } else if resolved {
                        locale.tr("해결됨", "Resolved")
                    } else {
                        locale.tr("선택 필요", "Unresolved")
                    },
                );
            });
            ui.add(
                egui::Label::new(egui::RichText::new(&hierarchy.asset).monospace())
                    .truncate(),
            )
            .on_hover_text(&hierarchy.asset);
            egui::Grid::new(("conflict-detail-meta", &conflict.id))
                .num_columns(2)
                .spacing([10.0, 3.0])
                .show(ui, |ui| {
                    ui.strong(locale.tr("데이터 ID (m_id)", "Data ID (m_id)"));
                    ui.add(
                        egui::Label::new(egui::RichText::new(&hierarchy.row).monospace())
                            .truncate(),
                    )
                    .on_hover_text(&hierarchy.row);
                    ui.end_row();
                    ui.strong(locale.tr("비교 항목", "Item being compared"));
                    ui.add(
                        egui::Label::new(egui::RichText::new(&hierarchy.group).monospace())
                            .truncate(),
                    )
                    .on_hover_text(&hierarchy.group);
                    ui.end_row();
                });
            ui.add(egui::Label::new(conflict_kind_help(&conflict.kind, locale)).wrap());
            egui::CollapsingHeader::new(locale.tr(
                "문제 해결용 정보",
                "Troubleshooting details",
            ))
            .id_salt(("conflict-troubleshooting-details", &conflict.id))
            .default_open(false)
            .show(ui, |ui| {
                ui.monospace(format!(
                    "{}: {}",
                    locale.tr("충돌 식별값", "Conflict ID"),
                    conflict.id
                ));
                ui.monospace(format!(
                    "{}: {:?}",
                    locale.tr("분류 코드", "Category code"),
                    conflict.kind
                ));
                ui.add(egui::Label::new(&conflict.message).wrap());
            });
            ui.separator();
            ui.strong(locale.tr("선택할 Pak", "Choose a Pak"));
            if conflict.variants.is_empty() {
                ui.weak(locale.tr(
                    "선택할 Pak이 없습니다.",
                    "There is no Pak to choose from.",
                ));
            } else {
                let selection_enabled = is_user_selectable_conflict(conflict);
                egui::ScrollArea::horizontal()
                    .id_salt(("detail-variant-cards", &conflict.id))
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        ui.horizontal_top(|ui| {
                            for variant in &conflict.variants {
                                let fixed = fixed_drift_id == Some(variant.id.as_str());
                                let selected = if is_encoding_drift(conflict) {
                                    fixed
                                } else {
                                    selected_id == Some(variant.id.as_str())
                                };
                                let fixed_reason = if fixed {
                                    if variant.input_id == carrier_input_id {
                                        Some(locale.tr(
                                            "내용이 같아 기준 Pak 쪽 저장 방식을 유지합니다.",
                                            "The contents match, so the base Pak storage format is kept.",
                                        ))
                                    } else {
                                        Some(locale.tr(
                                            "기준 Pak에 이 값이 없어 첫 번째 Pak의 값을 사용합니다.",
                                            "The base Pak has no value here, so the first available Pak is used.",
                                        ))
                                    }
                                } else if is_encoding_drift(conflict) {
                                    Some(locale.tr(
                                        "내용은 같으며 기준 Pak 쪽 저장 방식이 유지됩니다.",
                                        "The contents match; the base Pak storage format is kept.",
                                    ))
                                } else if !conflict.blocking {
                                    Some(locale.tr(
                                        "안내 항목 · 선택할 필요 없음",
                                        "For information only · no choice needed",
                                    ))
                                } else {
                                    None
                                };
                                if draw_variant_card(
                                    ui,
                                    &conflict.id,
                                    variant,
                                    selected,
                                    selection_enabled,
                                    fixed_reason,
                                    locale,
                                ) {
                                    pending_choices
                                        .push((conflict.id.clone(), variant.id.clone()));
                                }
                            }
                        });
                    });
            }
        });
    });
}

fn draw_variant_card(
    ui: &mut egui::Ui,
    conflict_id: &str,
    variant: &Variant,
    selected: bool,
    selection_enabled: bool,
    fixed_reason: Option<&str>,
    locale: UiLocale,
) -> bool {
    let fill = if selected {
        egui::Color32::from_rgb(43, 70, 92)
    } else {
        egui::Color32::from_rgb(31, 34, 40)
    };
    let mut clicked = false;
    egui::Frame::group(ui.style()).fill(fill).show(ui, |ui| {
        ui.set_min_width(340.0);
        ui.set_max_width(340.0);
        ui.with_layout(egui::Layout::top_down(egui::Align::Min), |ui| {
            let full_input_path = variant.provenance.input_path.display().to_string();
            let source_name = provenance_file_name(variant);
            let title = if source_name.eq_ignore_ascii_case(&variant.label) {
                source_name.clone()
            } else {
                format!("{source_name} · {}", variant.label)
            };
            if selection_enabled {
                let button_width = ui.available_width();
                let response = ui
                    .add_sized(
                        [button_width, 28.0],
                        egui::Button::selectable(selected, egui::RichText::new(&title).strong())
                            .wrap_mode(egui::TextWrapMode::Truncate),
                    )
                    .on_hover_text(&full_input_path);
                clicked = response.clicked();
            } else {
                ui.add(egui::Label::new(egui::RichText::new(&title).strong()).truncate())
                    .on_hover_text(&full_input_path);
            }
            if let Some(reason) = fixed_reason {
                ui.add(
                    egui::Label::new(egui::RichText::new(reason).color(egui::Color32::LIGHT_BLUE))
                        .wrap(),
                );
            }
            ui.separator();
            ui.small(locale.tr("들어 있는 값", "Value in this Pak"));
            let preview = value_preview(&variant.preview);
            ui.add(
                egui::Label::new(egui::RichText::new(truncate(&preview, 240)).monospace()).wrap(),
            )
            .on_hover_text(&preview);
            egui::CollapsingHeader::new(locale.tr("문제 해결용 정보", "Troubleshooting details"))
                .id_salt(("variant-troubleshooting-details", conflict_id, &variant.id))
                .default_open(false)
                .show(ui, |ui| {
                    let marker = format!(
                        "{}: {}",
                        locale.tr("내부 저장 코드", "Internal storage code"),
                        variant.marker
                    );
                    ui.add(egui::Label::new(egui::RichText::new(&marker).small()).truncate())
                        .on_hover_text(&marker);
                    ui.small(format!(
                        "{}: {}",
                        locale.tr("저장 데이터 확인값", "Stored-data check"),
                        &variant.raw_sha256[..variant.raw_sha256.len().min(16)]
                    ));
                    ui.small(format!(
                        "{}: {}",
                        locale.tr("값 비교용 확인값", "Value comparison check"),
                        &variant.semantic_sha256[..variant.semantic_sha256.len().min(16)]
                    ));
                    let input_id = format!(
                        "{}: {}",
                        locale.tr("Pak 식별값", "Pak ID"),
                        variant.provenance.input_id
                    );
                    ui.add(egui::Label::new(egui::RichText::new(&input_id).small()).truncate())
                        .on_hover_text(&input_id);
                    if let Some(entry_path) = &variant.provenance.entry_path {
                        let entry_name = path_leaf(entry_path);
                        ui.add(
                            egui::Label::new(
                                egui::RichText::new(format!(
                                    "{}: {entry_name}",
                                    locale.tr("Pak 내부 파일", "File in Pak")
                                ))
                                .small(),
                            )
                            .truncate(),
                        )
                        .on_hover_text(entry_path);
                    }
                });
        });
    });
    clicked
}

fn provenance_file_name(variant: &Variant) -> String {
    let full_path = variant.provenance.input_path.to_string_lossy();
    let file_name = path_leaf(&full_path);
    if file_name.is_empty() {
        variant.label.clone()
    } else {
        file_name.to_owned()
    }
}

fn path_leaf(path: &str) -> &str {
    path.rsplit(['/', '\\']).next().unwrap_or(path)
}

fn same_path(left: &Path, right: &Path) -> bool {
    left.to_string_lossy()
        .eq_ignore_ascii_case(&right.to_string_lossy())
}

fn conflict_matches_filter(conflict: &Conflict, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    let haystack = format!(
        "{} {} {} {}",
        conflict.asset_path,
        conflict.row_id.as_deref().unwrap_or_default(),
        conflict.group_id.as_deref().unwrap_or_default(),
        conflict.message
    )
    .to_ascii_lowercase();
    haystack.contains(needle)
}

fn conflict_is_visible(
    conflict: &Conflict,
    needle: &str,
    show_storage_format_details: bool,
) -> bool {
    conflict_matches_filter(conflict, needle)
        && (show_storage_format_details || !is_encoding_drift(conflict))
}

fn collect_bulk_updates(
    plan: &MergePlan,
    resolutions: &ResolutionSet,
    input_id: &str,
    filter: &str,
) -> Vec<(String, String)> {
    plan.conflicts
        .iter()
        .filter(|conflict| {
            is_user_selectable_conflict(conflict)
                && !resolutions.choices.contains_key(&conflict.id)
                && conflict_matches_filter(conflict, filter)
        })
        .filter_map(|conflict| {
            conflict
                .variants
                .iter()
                .find(|variant| variant.input_id == input_id)
                .map(|variant| (conflict.id.clone(), variant.id.clone()))
        })
        .collect()
}

fn truncate(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.to_owned();
    }
    let mut result = value
        .chars()
        .take(max_chars.saturating_sub(1))
        .collect::<String>();
    result.push('…');
    result
}

fn format_bytes(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = KIB * 1024;
    const GIB: u64 = MIB * 1024;
    if bytes >= GIB {
        format!("{:.2} GiB", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.2} MiB", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.2} KiB", bytes as f64 / KIB as f64)
    } else {
        format!("{bytes} B")
    }
}

pub fn run() -> anyhow::Result<()> {
    let icon = eframe::icon_data::from_png_bytes(include_bytes!("../assets/icon/app-icon.png"))
        .map_err(|error| anyhow::anyhow!("the bundled application icon is invalid: {error}"))?;
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1100.0, 760.0])
            .with_icon(icon),
        ..Default::default()
    };
    eframe::run_native(
        PRODUCT_NAME,
        options,
        Box::new(|context| {
            let cjk_font_available = install_windows_cjk_fonts(&context.egui_ctx);
            let mut app = MergerApp {
                cjk_font_available,
                ..MergerApp::default()
            };
            if !matches!(app.locale, UiLocale::English) && !cjk_font_available {
                app.locale = UiLocale::English;
                app.status = "A Windows CJK font could not be found, so the app is using English."
                    .to_owned();
            }
            Ok(Box::new(app))
        }),
    )
    .map_err(|error| anyhow::anyhow!(error.to_string()))
}

fn install_windows_cjk_fonts(context: &egui::Context) -> bool {
    #[cfg(windows)]
    {
        const MAX_SYSTEM_FONT_BYTES: u64 = 64 * 1024 * 1024;
        let Some(windows_root) = std::env::var_os("WINDIR") else {
            return false;
        };
        let fonts_root = PathBuf::from(windows_root).join("Fonts");
        let mut fonts = egui::FontDefinitions::default();
        let mut loaded = Vec::new();
        for file_name in [
            "malgun.ttf",
            "malgunbd.ttf",
            "YuGothM.ttc",
            "YuGothR.ttc",
            "meiryo.ttc",
            "meiryob.ttc",
            "msgothic.ttc",
        ] {
            let path = fonts_root.join(file_name);
            let Ok(metadata) = std::fs::metadata(&path) else {
                continue;
            };
            if metadata.len() == 0 || metadata.len() > MAX_SYSTEM_FONT_BYTES {
                continue;
            }
            let Ok(bytes) = std::fs::read(path) else {
                continue;
            };
            let name = format!("windows-cjk-{file_name}");
            fonts
                .font_data
                .insert(name.clone(), egui::FontData::from_owned(bytes).into());
            loaded.push(name);
        }
        if loaded.is_empty() {
            return false;
        }
        for family in [egui::FontFamily::Proportional, egui::FontFamily::Monospace] {
            let chain = fonts.families.entry(family).or_default();
            for (index, name) in loaded.iter().enumerate() {
                chain.insert(index, name.clone());
            }
        }
        context.set_fonts(fonts);
        true
    }
    #[cfg(not(windows))]
    {
        let _ = context;
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pak_merger::types::{ConflictKind, Provenance, Variant};
    use std::io::Cursor;

    fn conflict(id: &str, asset: &str, input_id: &str) -> Conflict {
        Conflict {
            id: id.to_owned(),
            kind: ConflictKind::FieldValue,
            asset_path: asset.to_owned(),
            row_id: Some("ROW_1".to_owned()),
            group_id: Some("field:value".to_owned()),
            message: "different value".to_owned(),
            variants: vec![Variant {
                id: format!("variant-{id}"),
                label: input_id.to_owned(),
                input_id: input_id.to_owned(),
                raw_sha256: "00".repeat(32),
                semantic_sha256: "11".repeat(32),
                preview: "1".to_owned(),
                marker: "uint8".to_owned(),
                provenance: Provenance {
                    input_id: input_id.to_owned(),
                    input_path: PathBuf::from(format!("{input_id}.pak")),
                    entry_path: Some(asset.to_owned()),
                    raw_sha256: "00".repeat(32),
                },
            }],
            blocking: true,
        }
    }

    fn plan(conflicts: Vec<Conflict>) -> MergePlan {
        MergePlan {
            schema_version: 1,
            plan_id: "plan".to_owned(),
            request: AnalysisRequest {
                pak_paths: vec![],
                carrier_path: PathBuf::new(),
            },
            inputs: vec![],
            carrier_input_id: "A".to_owned(),
            assets: vec![],
            conflicts,
            warnings: vec![],
            selected_profile_id: None,
            profile_detection_status: None,
            encoding_drift_count: 0,
            full_reencode_forbidden: true,
        }
    }

    fn app_for_logic_tests() -> MergerApp {
        let mut app = MergerApp {
            locale: UiLocale::English,
            consent_valid: false,
            pak_paths: vec![PathBuf::from("A.pak"), PathBuf::from("B.pak")],
            ..MergerApp::default()
        };
        app.invalidate_analysis();
        app.status.clear();
        app
    }

    #[test]
    fn performance_options_default_on_and_survive_reanalysis() {
        let mut app = app_for_logic_tests();
        assert_eq!(app.output_compression, OutputCompression::Oodle);
        assert!(app.multithreaded);
        app.output_compression = OutputCompression::None;
        app.multithreaded = false;
        app.invalidate_analysis();
        assert_eq!(app.output_compression, OutputCompression::None);
        assert!(!app.multithreaded);
    }

    #[test]
    fn japanese_locale_covers_primary_ui_and_error_copy() {
        assert_eq!(UiLocale::Japanese.tr("병합", "Merge"), "統合");
        assert_eq!(UiLocale::Japanese.tr("옵션", "Options"), "オプション");
        assert_eq!(
            UiLocale::Japanese.tr("이용약관", "Terms of Use"),
            "利用規約"
        );
        assert_eq!(
            UiLocale::Japanese.tr(
                "기준 Pak은 별도 선택이 필요 없는 항목의 기본 형식을 정합니다. 충돌한 값은 직접 선택합니다.",
                "The base Pak sets the default format where no choice is needed. You still choose every conflicting value."
            ),
            "基準 Pak は、選択が不要な項目の既定形式を決めます。競合する値は個別に選択します。"
        );
        assert!(friendly_inspection_error("encrypted Pak", UiLocale::Japanese).contains("暗号化"));
        assert!(
            friendly_inspection_error("integrity check failed", UiLocale::Japanese)
                .contains("整合性")
        );
        assert!(
            friendly_operation_error("operation cancelled", UiLocale::Japanese)
                .contains("キャンセル")
        );
    }

    #[test]
    fn database_build_progress_stage_is_localized() {
        let mut app = app_for_logic_tests();
        app.locale = UiLocale::Korean;
        assert_eq!(
            app.progress_stage_label(MergeProgressStage::IndexingDatabase),
            "데이터베이스 확인"
        );
        assert_eq!(
            app.progress_stage_label(MergeProgressStage::BuildingDatabase),
            "데이터베이스 병합"
        );
        app.locale = UiLocale::English;
        assert_eq!(
            app.progress_stage_label(MergeProgressStage::IndexingDatabase),
            "Indexing database"
        );
        assert_eq!(
            app.progress_stage_label(MergeProgressStage::BuildingDatabase),
            "Building database"
        );
        app.locale = UiLocale::Japanese;
        assert_eq!(
            app.progress_stage_label(MergeProgressStage::IndexingDatabase),
            "データベースを確認"
        );
        assert_eq!(
            app.progress_stage_label(MergeProgressStage::BuildingDatabase),
            "データベースを統合"
        );
    }

    #[test]
    fn existing_output_waits_for_explicit_gui_confirmation() {
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join(DEFAULT_MERGED_PAK_FILE_NAME);
        std::fs::write(&output, b"existing").unwrap();
        let mut app = app_for_logic_tests();

        app.request_merge_output(output.clone());

        assert_eq!(app.pending_overwrite, Some(output));
        assert!(app.worker.is_none());
    }

    #[test]
    fn gui_output_name_defaults_to_late_loading_pak_name() {
        assert_eq!(DEFAULT_MERGED_PAK_FILE_NAME, "ZZMerge_P.pak");
    }

    #[test]
    fn filter_matches_asset_row_and_group_text() {
        let item = conflict("c1", "Local/DataBase/Skill/SkillID.uexp", "A");
        assert!(conflict_matches_filter(&item, "skillid"));
        assert!(conflict_matches_filter(&item, "row_1"));
        assert!(conflict_matches_filter(&item, "field:value"));
        assert!(!conflict_matches_filter(&item, "enemygroups"));
    }

    #[test]
    fn storage_format_examples_are_hidden_until_requested() {
        let mut drift = conflict("drift", "Local/DataBase/Enemy/EnemyGroups.uexp", "A");
        drift.kind = ConflictKind::EncodingDrift;
        drift.blocking = false;
        assert!(!conflict_is_visible(&drift, "", false));
        assert!(conflict_is_visible(&drift, "", true));
        assert!(conflict_is_visible(&drift, "enemygroups", true));
        assert!(!conflict_is_visible(&drift, "skillid", true));
    }

    #[test]
    fn bulk_updates_only_unresolved_conflicts_in_filter_scope() {
        let plan = plan(vec![
            conflict("skill", "Local/DataBase/Skill/SkillID.uexp", "A"),
            conflict("enemy", "Local/DataBase/Enemy/EnemyID.uexp", "A"),
            conflict(
                "other-source",
                "Local/DataBase/Skill/SkillAvailID.uexp",
                "B",
            ),
        ]);
        let mut resolutions = ResolutionSet {
            plan_id: "plan".to_owned(),
            ..ResolutionSet::default()
        };
        resolutions
            .choices
            .insert("other-source".to_owned(), "variant-other-source".to_owned());

        let updates = collect_bulk_updates(&plan, &resolutions, "A", "skill");
        assert_eq!(
            updates,
            vec![("skill".to_owned(), "variant-skill".to_owned())]
        );
    }

    #[test]
    fn single_choice_undo_stores_one_change_and_restores_the_previous_value() {
        let mut app = app_for_logic_tests();
        app.resolutions.plan_id = "plan".to_owned();
        for index in 0..10_000 {
            app.resolutions.choices.insert(
                format!("existing-{index}"),
                format!("existing-variant-{index}"),
            );
        }

        app.choose_variant("target", "new-variant");

        assert_eq!(app.undo.len(), 1);
        assert_eq!(app.undo[0].change_count(), 1);
        assert!(matches!(
            &app.undo[0],
            ResolutionUndo::Single(ResolutionUndoChange {
                conflict_id,
                previous_variant_id: None,
            }) if conflict_id == "target"
        ));
        assert_eq!(app.resolutions.choices.len(), 10_001);

        app.choose_variant("target", "new-variant");
        assert_eq!(app.undo.len(), 1, "a repeated choice must be a no-op");

        app.undo_last_resolution();
        assert!(!app.resolutions.choices.contains_key("target"));
        assert_eq!(app.resolutions.choices.len(), 10_000);
        assert_eq!(app.resolutions.plan_id, "plan");

        app.resolutions
            .choices
            .insert("target".to_owned(), "old-variant".to_owned());
        app.choose_variant("target", "replacement-variant");
        assert!(matches!(
            &app.undo[0],
            ResolutionUndo::Single(ResolutionUndoChange {
                conflict_id,
                previous_variant_id: Some(previous),
            }) if conflict_id == "target" && previous == "old-variant"
        ));

        app.undo_last_resolution();
        assert_eq!(
            app.resolutions.choices.get("target").map(String::as_str),
            Some("old-variant")
        );
    }

    #[test]
    fn bulk_choice_undo_stores_only_changed_conflicts_and_restores_as_one_action() {
        let mut app = app_for_logic_tests();
        app.resolutions.plan_id = "plan".to_owned();
        for index in 0..10_000 {
            app.resolutions.choices.insert(
                format!("existing-{index}"),
                format!("existing-variant-{index}"),
            );
        }

        app.apply_bulk_updates(vec![
            ("existing-1".to_owned(), "existing-variant-1".to_owned()),
            ("existing-2".to_owned(), "replacement-2".to_owned()),
            ("new-conflict".to_owned(), "new-variant".to_owned()),
            ("existing-2".to_owned(), "replacement-2".to_owned()),
        ]);

        assert_eq!(app.undo.len(), 1);
        assert_eq!(app.undo[0].change_count(), 2);
        assert!(matches!(&app.undo[0], ResolutionUndo::Batch(changes) if changes.len() == 2));
        assert_eq!(app.resolutions.choices.len(), 10_001);
        assert_eq!(
            app.resolutions
                .choices
                .get("existing-2")
                .map(String::as_str),
            Some("replacement-2")
        );

        app.undo_last_resolution();
        assert_eq!(app.resolutions.choices.len(), 10_000);
        assert_eq!(
            app.resolutions
                .choices
                .get("existing-2")
                .map(String::as_str),
            Some("existing-variant-2")
        );
        assert!(!app.resolutions.choices.contains_key("new-conflict"));
        assert_eq!(app.resolutions.plan_id, "plan");

        app.apply_bulk_updates(Vec::new());
        app.apply_bulk_updates(vec![(
            "existing-1".to_owned(),
            "existing-variant-1".to_owned(),
        )]);
        assert!(
            app.undo.is_empty(),
            "empty and unchanged batches are no-ops"
        );
    }

    #[test]
    fn carrier_change_invalidates_plan_resolutions_and_undo() {
        let mut app = app_for_logic_tests();
        app.plan = Some(Arc::new(plan(vec![conflict("c1", "SkillID.uexp", "A")])));
        app.resolutions.plan_id = "plan".to_owned();
        app.choose_variant("c1", "variant-c1");

        app.set_carrier(1);

        assert_eq!(app.carrier_index, 1);
        assert!(app.plan.is_none());
        assert!(app.resolutions.plan_id.is_empty());
        assert!(app.resolutions.choices.is_empty());
        assert!(app.undo.is_empty());
    }

    #[test]
    fn adding_a_pak_immediately_queues_read_only_inspection() {
        let mut app = app_for_logic_tests();
        let path = PathBuf::from("Queued.pak");

        app.add_path(path.clone());

        let cached = app.inspections.get(&path_key(&path)).unwrap();
        assert_eq!(cached.status, PakInspectionStatus::Pending);
        assert!(cached.generation > 0);
    }

    #[test]
    fn inspection_results_are_generation_bound_and_expose_failures() {
        let mut app = app_for_logic_tests();
        let path = PathBuf::from("Bound.pak");
        let key = path_key(&path);
        app.inspections.insert(
            key.clone(),
            CachedPakInspection {
                generation: 7,
                status: PakInspectionStatus::Pending,
                archive: None,
                progress: None,
                cancellation: pak_merger::CancellationToken::new(),
            },
        );
        let directory = tempfile::tempdir().unwrap();
        let archive_path = directory.path().join("inspection.pak");
        let bytes = pak_merger::pak::write_pak_v11_to(
            Cursor::new(Vec::new()),
            "../../../Game/Content/",
            [pak_merger::pak::PakWriteEntry::new(
                "A/One.bin",
                b"one".to_vec(),
            )],
        )
        .unwrap()
        .into_inner();
        std::fs::write(&archive_path, bytes).unwrap();
        let archive = Arc::new(pak_merger::pak::PakArchive::open(archive_path).unwrap());
        let inspection = PakInspection {
            sha256: "aa".repeat(32),
            size: 10,
            mount_point: "../../../Game/Content/".to_owned(),
            version: 11,
            entry_count: 1,
            stale_payload_hashes: Vec::new(),
        };

        app.apply_inspection_result(PakInspectionMessage::Finished(PakInspectionResult {
            key: key.clone(),
            generation: 6,
            result: Ok((inspection.clone(), archive.clone())),
        }));
        assert_eq!(
            app.inspections.get(&key).unwrap().status,
            PakInspectionStatus::Pending
        );

        app.apply_inspection_result(PakInspectionMessage::Finished(PakInspectionResult {
            key: key.clone(),
            generation: 7,
            result: Ok((inspection.clone(), archive)),
        }));
        assert_eq!(
            app.inspections.get(&key).unwrap().status,
            PakInspectionStatus::Supported(inspection)
        );

        let cached = app.inspections.get_mut(&key).unwrap();
        cached.generation = 8;
        cached.status = PakInspectionStatus::Pending;
        app.apply_inspection_result(PakInspectionMessage::Finished(PakInspectionResult {
            key: key.clone(),
            generation: 8,
            result: Err("unsupported version".to_owned()),
        }));
        assert_eq!(
            app.inspections.get(&key).unwrap().status,
            PakInspectionStatus::Failed("unsupported version".to_owned())
        );
    }

    #[test]
    fn conflict_hierarchy_identifies_asset_row_and_atomic_group() {
        let item = conflict("tree", "Local/DataBase/Enemy/EnemyID.uexp", "A");
        let hierarchy = conflict_hierarchy(&item, UiLocale::English);
        assert_eq!(hierarchy.asset, "Local/DataBase/Enemy/EnemyID.uexp");
        assert_eq!(hierarchy.row, "ROW_1");
        assert_eq!(hierarchy.group, "field:value");
    }

    #[test]
    fn every_conflict_kind_has_user_facing_labels() {
        let kinds = [
            ConflictKind::FieldValue,
            ConflictKind::AtomicGroup,
            ConflictKind::RowIdCollision,
            ConflictKind::PotentialPlacementCollision,
            ConflictKind::OpaquePackage,
            ConflictKind::StructureMismatch,
            ConflictKind::EncodingDrift,
            ConflictKind::ReferenceBreak,
            ConflictKind::UnsupportedAsset,
        ];
        for kind in kinds {
            for locale in [UiLocale::Korean, UiLocale::English, UiLocale::Japanese] {
                assert!(!conflict_kind_label(&kind, locale).is_empty());
                assert!(!conflict_kind_help(&kind, locale).is_empty());
            }
        }
    }

    #[test]
    fn friendly_messages_keep_internal_jargon_out_of_the_main_ui() {
        for locale in [UiLocale::Korean, UiLocale::English, UiLocale::Japanese] {
            let messages = [
                friendly_inspection_error(
                    "opaque entry failed semantic parsing at raw marker in mount point",
                    locale,
                ),
                friendly_operation_error(
                    "database donor carrier raw marker conflict could not be completed",
                    locale,
                )
                .to_owned(),
                friendly_plan_warning(
                    "Local/Test could not be compared field by field: opaque semantic error",
                    locale,
                ),
            ];
            for message in messages {
                let lower = message.to_ascii_lowercase();
                for jargon in [
                    "opaque",
                    "semantic",
                    "entry",
                    "mount",
                    "raw marker",
                    "donor",
                    "carrier",
                ] {
                    assert!(!lower.contains(jargon), "{message:?} contains {jargon:?}");
                }
            }
        }
    }

    #[test]
    fn value_preview_keeps_data_notation_stable_across_ui_languages() {
        let source = "array[2], map[1], binary[4], extension(type=1), x=null";
        let preview = value_preview(source);
        assert_eq!(
            preview,
            "list[2], map[1], binary[4], extension(type=1), x=null"
        );
    }

    #[test]
    fn repeated_details_headers_have_independent_ids() {
        egui::__run_test_ui(|ui| {
            let first = egui::CollapsingHeader::new("문제 해결용 정보")
                .id_salt(("variant-troubleshooting-details", "conflict-a", "variant-a"))
                .show(ui, |_| {})
                .header_response
                .id;
            let second = egui::CollapsingHeader::new("문제 해결용 정보")
                .id_salt(("variant-troubleshooting-details", "conflict-a", "variant-b"))
                .show(ui, |_| {})
                .header_response
                .id;
            assert_ne!(first, second);
        });
    }

    #[test]
    fn bundled_application_icon_is_valid_rgba() {
        let icon = eframe::icon_data::from_png_bytes(include_bytes!("../assets/icon/app-icon.png"))
            .unwrap();
        assert_eq!((icon.width, icon.height), (256, 256));
        assert_eq!(icon.rgba.len(), 256 * 256 * 4);
        assert_eq!(&icon.rgba[..4], &[0, 0, 0, 0]);
    }

    #[test]
    fn oodle_error_gives_brief_recovery_steps() {
        let error = "Oodle support could not be prepared for A/Test.uasset: Oodle loader error";
        let korean = friendly_inspection_error(error, UiLocale::Korean);
        let english = friendly_inspection_error(error, UiLocale::English);
        assert!(korean.contains("Oodle"));
        assert!(korean.contains("인터넷"));
        assert!(korean.contains("쓰기 권한"));
        assert!(!korean.contains("oo2core"));
        assert!(english.contains("Oodle"));
        assert!(english.contains("internet"));
        assert!(english.contains("write access"));
        assert!(!english.contains("oo2core"));

        let korean_output = friendly_operation_error(error, UiLocale::Korean);
        let english_output = friendly_operation_error(error, UiLocale::English);
        assert!(korean_output.contains("Oodle"));
        assert!(korean_output.contains("쓰기 권한"));
        assert!(english_output.contains("Oodle"));
        assert!(english_output.contains("write access"));
    }

    #[test]
    fn work_folder_error_explains_write_access() {
        let unavailable = "could not create the temporary work folder";
        assert!(friendly_operation_error(unavailable, UiLocale::Korean).contains("쓰기 권한"));
        assert!(friendly_operation_error(unavailable, UiLocale::English).contains("write access"));
    }

    #[test]
    fn routine_reference_notices_do_not_appear_as_warnings() {
        assert!(is_routine_plan_notice(
            "Known-reference validation checked 4 rules"
        ));
        assert!(is_routine_plan_notice(
            "Only bundled, field-qualified reference rules were checked"
        ));
    }

    #[test]
    fn compact_browser_keeps_selection_when_visible_and_falls_back_to_first_match() {
        let plan = plan(vec![
            conflict("first", "First.uexp", "A"),
            conflict("second", "Second.uexp", "B"),
            conflict("third", "Third.uexp", "A"),
        ]);

        assert_eq!(
            selected_visible_conflict_index(&plan, &[0, 1, 2], Some("second")),
            Some(1)
        );
        assert_eq!(
            selected_visible_conflict_index(&plan, &[0, 2], Some("second")),
            Some(0)
        );
        assert_eq!(selected_visible_conflict_index(&plan, &[], None), None);
    }

    #[test]
    fn provenance_prefers_file_name_and_path_leaf_handles_pak_separators() {
        let mut item = conflict("source", "Asset.uexp", "A");
        item.variants[0].label = "Friendly source".to_owned();
        item.variants[0].provenance.input_path = PathBuf::from(r"C:\Mods\Readable_Mod_Name_P.pak");

        assert_eq!(
            provenance_file_name(&item.variants[0]),
            "Readable_Mod_Name_P.pak"
        );
        assert_eq!(
            path_leaf("Local/DataBase/Enemy/EnemyID.uexp"),
            "EnemyID.uexp"
        );
        assert_eq!(
            path_leaf(r"Local\DataBase\Enemy\EnemyID.uexp"),
            "EnemyID.uexp"
        );
    }

    #[test]
    fn encoding_drift_is_fixed_to_carrier_and_never_bulk_selectable() {
        let mut drift = conflict("drift", "Local/DataBase/Skill/SkillID.uexp", "A");
        drift.kind = ConflictKind::EncodingDrift;
        drift.blocking = false;
        let mut carrier_variant = drift.variants[0].clone();
        carrier_variant.id = "carrier-variant".to_owned();
        carrier_variant.label = "Carrier B".to_owned();
        carrier_variant.input_id = "B".to_owned();
        carrier_variant.provenance.input_id = "B".to_owned();
        drift.variants.push(carrier_variant);

        assert!(!is_user_selectable_conflict(&drift));
        assert_eq!(
            fixed_encoding_drift_variant(&drift, "B").map(|variant| variant.id.as_str()),
            Some("carrier-variant")
        );

        // Storage-only differences never belong in bulk conflict choices.
        drift.blocking = true;
        let plan = plan(vec![drift]);
        assert!(collect_bulk_updates(&plan, &ResolutionSet::default(), "A", "").is_empty());
    }
}
