use super::{ai_condition_parameters, audited_asset, indexed, suffix, whole};
use crate::profiles::AssetProfileRule;

pub(super) fn asset_rules() -> Vec<AssetProfileRule> {
    vec![
        // The four AIBattle tables have disjoint schemas, so they need one rule
        // each. A single `/local/database/aibattle/` rule declaring the union of
        // their groups can never be fully observed by any one table, and the
        // strict profile then rejects the asset as schema drift and demotes it
        // to a whole-file choice.
        audited_asset(
            "aibattle_tactical_action_list",
            suffix("/local/database/aibattle/tacticalactionlist"),
            vec![
                whole(
                    "tactical_action_indices",
                    &["m_TacticalList", "m_SkillIndex", "m_FriendlyIndex"],
                ),
                ai_condition_parameters(true),
            ],
        ),
        audited_asset(
            "aibattle_tactical_assign_list",
            suffix("/local/database/aibattle/tacticalassignlist"),
            vec![whole("tactical_assignments", &["m_Tactics"])],
        ),
        audited_asset(
            "aibattle_tactical_list",
            suffix("/local/database/aibattle/tacticallist"),
            vec![
                whole("presage_skill", &["m_Presage", "m_PresageSkillID"]),
                whole(
                    "event_flag_pair",
                    &["m_OnEventFlgIndex", "m_OffEventFlgIndex"],
                ),
                ai_condition_parameters(true),
            ],
        ),
        audited_asset(
            "aibattle_tactical_skill_list",
            suffix("/local/database/aibattle/tacticalskilllist"),
            vec![whole("tactical_skill_slots", &["m_UseSkills"])],
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
