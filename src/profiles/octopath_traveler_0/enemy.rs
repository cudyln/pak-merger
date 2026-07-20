use super::{audited_asset, indexed, suffix, whole};
use crate::profiles::AssetProfileRule;

pub(super) fn asset_rules() -> Vec<AssetProfileRule> {
    vec![
        audited_asset(
            "enemy_groups",
            suffix("/local/database/enemy/enemygroups"),
            vec![
                indexed("enemy_members", &["m_EnemyID", "m_ImportantFlags"]),
                indexed("battle_event_indices", &["m_EventIndices"]),
                whole(
                    "battle_bgm",
                    &["m_Bgm", "m_NightBgm", "m_DarkBgm", "m_BgmType"],
                ),
                whole(
                    "forced_result_conditions",
                    &[
                        "m_AbortCondition",
                        "m_ForcedWinAbortCondition",
                        "m_IsAllEnemyDeadOnForceWin",
                        "m_ForcedLoseAbortCondition",
                    ],
                ),
            ],
        ),
        audited_asset(
            "enemy_id",
            suffix("/local/database/enemy/enemyid"),
            vec![
                whole(
                    "enemy_type_and_weakness",
                    &[
                        "m_TypeID",
                        "m_WeakID",
                        "m_ResistAilmentID",
                        "m_ResistAilment",
                    ],
                ),
                whole("enemy_skill_ai", &["m_TacticalAssignID", "m_SkillsID"]),
                whole(
                    "enemy_rewards",
                    &[
                        "m_Exp",
                        "m_Money",
                        "m_PetExp",
                        "m_JP",
                        "m_DropReward",
                        "m_StealReward",
                        "m_StealLeafNum",
                        "m_EventDropRewards",
                    ],
                ),
            ],
        ),
        audited_asset(
            "enemy_type_id",
            suffix("/local/database/enemy/enemytypeid"),
            vec![
                whole(
                    "enemy_display_transform",
                    &[
                        "m_ScaleX",
                        "m_ScaleY",
                        "m_HitPosX",
                        "m_HitPosY",
                        "m_HitScaleX",
                        "m_HitScaleY",
                    ],
                ),
                whole(
                    "enemy_animation_sets",
                    &["m_AnimationSetIDs", "m_OverrideOrderIconAnimSetID"],
                ),
            ],
        ),
        audited_asset(
            "enemy_weak_lock_id",
            suffix("/local/database/enemy/enemyweaklockid"),
            vec![
                indexed("weapon_lock_slots", &["m_LockWeapon"]),
                indexed("magic_lock_slots", &["m_LockMagic"]),
                indexed(
                    "weakness_unlock_gate",
                    &["m_RemoveConditions", "m_RemoveParams"],
                ),
            ],
        ),
    ]
}
