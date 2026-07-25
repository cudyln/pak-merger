//! Cross-table reference knowledge for OCTOPATH TRAVELER 0.
//!
//! A merged Pak can be structurally perfect and still be broken in game: a row
//! that survived the merge may point at an id another Pak's version of the
//! table no longer contains. These rules let the post-merge check catch that.
//!
//! They are deliberately narrow. A rule only belongs here when the field's
//! values are *always* ids of the named table; a rule that is merely usually
//! right would report breaks on data that is actually fine.

use crate::profiles::{ReferenceRule, ReferenceTable};

pub(super) fn tables() -> Vec<ReferenceTable> {
    [
        ("/local/database/enemy/enemygroups", "EnemyGroups"),
        ("/local/database/enemy/enemyid", "EnemyID"),
        ("/local/database/enemy/enemytypeid", "EnemyTypeID"),
        ("/local/database/enemy/enemyweaklockid", "EnemyWeakLockID"),
        ("/local/database/skill/skillid", "SkillID"),
        ("/local/database/skill/skillavailid", "SkillAvailID"),
        ("/local/database/skill/skilleffectiveid", "SkillEffectiveID"),
        (
            "/local/database/skill/skillresistailmentid",
            "SkillResistAilmentID",
        ),
        ("/local/database/battle/battleeventlist", "BattleEventList"),
        (
            "/local/database/battle/battleeventcommand",
            "BattleEventCommand",
        ),
    ]
    .into_iter()
    .map(|(path_suffix, name)| ReferenceTable { path_suffix, name })
    .collect()
}

pub(super) fn rules() -> Vec<ReferenceRule> {
    [
        ("EnemyGroups", "m_EnemyID", "EnemyID"),
        ("EnemyID", "m_TypeID", "EnemyTypeID"),
        ("EnemyID", "m_WeakID", "EnemyWeakLockID"),
        ("EnemyID", "m_ResistAilmentID", "SkillResistAilmentID"),
        ("EnemyID", "m_SkillsID", "SkillID"),
        ("SkillID", "m_BoostSkills", "SkillID"),
        ("SkillID", "m_ReplaceSkill", "SkillID"),
        ("SkillID", "m_ReplaceSkillArray", "SkillID"),
        ("SkillID", "m_WeaponReplaceSkill", "SkillID"),
        ("SkillID", "m_Avails", "SkillAvailID"),
        ("SkillID", "m_BeginEffective", "SkillEffectiveID"),
        ("SkillID", "m_Effectives", "SkillEffectiveID"),
        ("SkillID", "m_EndEffective", "SkillEffectiveID"),
        ("SkillAvailID", "m_DelayedSkill", "SkillID"),
        ("SkillAvailID", "m_ResistAilmentID", "SkillResistAilmentID"),
        ("BattleEventList", "m_EventCommand", "BattleEventCommand"),
    ]
    .into_iter()
    .map(|(source_table, field, target_table)| ReferenceRule {
        source_table,
        field,
        target_table,
    })
    .collect()
}
