use super::{audited_asset, matcher, whole};
use crate::profiles::{AssetProfileRule, PathMatchKind};

pub(super) fn asset_rules() -> Vec<AssetProfileRule> {
    vec![
        audited_asset(
            "game_text_npc",
            vec![
                matcher(PathMatchKind::Contains, "/local/database/gametext/"),
                matcher(PathMatchKind::Suffix, "/gametextnpc"),
            ],
            vec![whole("npc_voice", &["m_PartVoiceID", "m_voiceId"])],
        ),
        audited_asset(
            "game_text",
            vec![
                matcher(PathMatchKind::Contains, "/local/database/gametext/"),
                matcher(PathMatchKind::Suffix, "/gametextskill"),
            ],
            Vec::new(),
        ),
        audited_asset(
            "game_text",
            vec![
                matcher(PathMatchKind::Contains, "/local/database/gametext/"),
                matcher(PathMatchKind::Suffix, "/gametextui"),
            ],
            Vec::new(),
        ),
    ]
}
