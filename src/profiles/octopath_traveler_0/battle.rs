use super::{audited_asset, condition_parameters, indexed, matcher, suffix, whole};
use crate::profiles::{AssetProfileRule, PathMatchKind};

pub(super) fn asset_rules() -> Vec<AssetProfileRule> {
    vec![
        audited_asset(
            "aibattle",
            vec![matcher(
                PathMatchKind::Contains,
                "/local/database/aibattle/",
            )],
            vec![
                whole("tactical_skill_slots", &["m_UseSkills"]),
                whole("tactical_assignments", &["m_Tactics"]),
                whole(
                    "tactical_action_indices",
                    &["m_TacticalList", "m_SkillIndex", "m_FriendlyIndex"],
                ),
                whole("presage_skill", &["m_Presage", "m_PresageSkillID"]),
                whole(
                    "event_flag_pair",
                    &["m_OnEventFlgIndex", "m_OffEventFlgIndex"],
                ),
                condition_parameters(true),
            ],
        ),
        audited_asset(
            "battle_event_command",
            suffix("/local/database/battle/battleeventcommand"),
            vec![
                whole(
                    "event_flag_pair",
                    &["m_OnEventFlgIndex", "m_OffEventFlgIndex"],
                ),
                whole(
                    "texture_change",
                    &[
                        "m_TextureChangeEnemyIdx",
                        "m_ChangeEnemyTextureIdx",
                        "m_TextureChangeTime",
                    ],
                ),
                whole(
                    "narration_presentation",
                    &[
                        "m_NarrationID",
                        "m_IsNextNarrationPage",
                        "m_BlackoutNarration",
                        "m_NarrationColorR",
                        "m_NarrationColorG",
                        "m_NarrationColorB",
                    ],
                ),
                whole(
                    "fade_presentation",
                    &["m_Fade", "m_DisplayFadeTime", "m_FadeTime"],
                ),
            ],
        ),
        audited_asset(
            "battle_event_list",
            suffix("/local/database/battle/battleeventlist"),
            vec![
                indexed(
                    "battle_event_gate",
                    &[
                        "m_EventConditions",
                        "m_EventParams",
                        "m_EventStatusTypes",
                        "m_EventEnemies",
                    ],
                ),
                whole("battle_event_commands", &["m_EventCommand"]),
            ],
        ),
    ]
}
