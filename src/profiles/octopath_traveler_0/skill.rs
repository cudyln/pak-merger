use super::{audited_asset, condition_parameters, indexed, suffix, whole};
use crate::profiles::AssetProfileRule;

pub(super) fn asset_rules() -> Vec<AssetProfileRule> {
    vec![
        audited_asset(
            "skill_id",
            suffix("/local/database/skill/skillid"),
            vec![
                whole("boost_skill_chain", &["m_BoostSkills", "m_MaxBoostLv"]),
                indexed("avail_effective_slots", &["m_Avails", "m_Effectives"]),
                whole(
                    "effective_boundaries",
                    &["m_BeginEffective", "m_EndEffective"],
                ),
                whole(
                    "replace_skill_pair",
                    &["m_ReplaceCondition", "m_ReplaceSkill"],
                ),
                indexed(
                    "replace_skill_slots",
                    &["m_ReplaceConditionArray", "m_ReplaceSkillArray"],
                ),
                whole(
                    "weapon_replacement",
                    &[
                        "m_IsWeaponSelect",
                        "m_IsReplaceNowSelectedWeapon",
                        "m_IsReplaceMainWeapon",
                        "m_WeaponReplaceSkill",
                    ],
                ),
            ],
        ),
        audited_asset(
            "skill_avail_id",
            suffix("/local/database/skill/skillavailid"),
            vec![
                indexed(
                    "damage_slots",
                    &[
                        "m_HitTypes",
                        "m_Values",
                        "m_FluctuationValues",
                        "m_SkillRatios",
                        "m_Turns",
                        "m_Counts",
                    ],
                ),
                indexed(
                    "add_ailment_slots",
                    &["m_AddAilment", "m_CalcTypeAilment", "m_ValueAilment"],
                ),
                indexed("remove_ailment_slots", &["m_SubAilment"]),
                indexed("resist_ailment_slots", &["m_ResistAilment"]),
                whole("delayed_skill", &["m_DelayedSkill", "m_DelaySkillPriority"]),
                whole(
                    "magnification_pair",
                    &[
                        "m_SkillAvailMagnificationCondition",
                        "m_SkillAvailMagnification",
                    ],
                ),
                indexed(
                    "magnification_slots",
                    &[
                        "m_SkillAvailMagnificationConditionArray",
                        "m_SkillAvailMagnificationArray",
                    ],
                ),
            ],
        ),
        audited_asset(
            "skill_effective_id",
            suffix("/local/database/skill/skilleffectiveid"),
            vec![
                indexed("camera_slots", &["m_Cameras", "m_CameraTimes"]),
                indexed(
                    "animation_slots",
                    &[
                        "m_Animations",
                        "m_PlayTimes",
                        "m_PlayRates",
                        "m_AnimationTarget",
                        "m_AnimStartFrame",
                        "m_AnimEndFrame",
                        "m_AnimNoIdle",
                    ],
                ),
                indexed(
                    "effect_slots",
                    &[
                        "m_Effects",
                        "m_InvokeTimes",
                        "m_EffectLayout",
                        "m_OffsetsH",
                        "m_OffsetsV",
                    ],
                ),
                indexed(
                    "sound_voice_slots",
                    &[
                        "m_Sounds",
                        "m_SoundTimes",
                        "m_SoundToVoice",
                        "m_Voices1",
                        "m_Voices2",
                        "m_Voices3",
                        "m_VoiceTimes",
                    ],
                ),
                indexed("text_slots", &["m_Texts", "m_TextTime"]),
                indexed(
                    "visibility_slots",
                    &[
                        "m_CharaVisibility",
                        "m_VisibilityTarget",
                        "m_VisibilityStartTime",
                    ],
                ),
            ],
        ),
        audited_asset(
            "skill_ailment_type",
            suffix("/local/database/skill/skillailmenttype"),
            vec![
                whole(
                    "ailment_target_status",
                    &["m_TargetStatus", "m_TargetStatusArray", "m_AilmentCalc"],
                ),
                whole(
                    "ailment_removal_gate",
                    &["m_RemoveAilment", "m_RemoveConditions", "m_RemoveParams"],
                ),
                whole(
                    "ailment_presentation",
                    &[
                        "m_TextID",
                        "m_ExplanationTextID",
                        "m_IconTexID",
                        "m_IconSptTexID",
                        "m_AddEffect",
                        "m_CharacterEffect",
                        "m_FieldEffect",
                        "m_InvokeEffect",
                        "m_OnGroundInvoke",
                        "m_AddEffectSound",
                        "m_InvokeSound",
                    ],
                ),
            ],
        ),
        audited_asset(
            "skill_condition_list",
            suffix("/local/database/skill/skillconditionlist"),
            vec![condition_parameters(true)],
        ),
        audited_asset(
            "skill_resist_ailment_id",
            suffix("/local/database/skill/skillresistailmentid"),
            vec![indexed(
                "resist_ailment_rates",
                &["m_ResistAilments", "m_ResistRate"],
            )],
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skill_effective_sound_and_voice_arrays_share_each_slot() {
        let rule = asset_rules()
            .into_iter()
            .find(|rule| rule.profile.id == "skill_effective_id")
            .unwrap();
        let group = rule
            .profile
            .groups
            .iter()
            .find(|group| group.id == "sound_voice_slots")
            .unwrap();

        assert!(group.index_coupled);
        assert_eq!(
            group.fields,
            [
                "m_Sounds",
                "m_SoundTimes",
                "m_SoundToVoice",
                "m_Voices1",
                "m_Voices2",
                "m_Voices3",
                "m_VoiceTimes",
            ]
        );
    }
}
