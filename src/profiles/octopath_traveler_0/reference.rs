//! Cross-table reference knowledge for OCTOPATH TRAVELER 0.
//!
//! A merged Pak can be structurally perfect and still be broken in game: a row
//! that survived the merge may point at an id the version of the target table
//! which won the merge no longer contains. These rules let the post-merge check
//! catch that.
//!
//! # How this list was built
//!
//! Every field of all 3,031 cooked databases was measured against the row ids of
//! every other table. A rule is listed only when **every** positive value of
//! that field is a row id of **exactly one** other table, matching how
//! `visit_positive_integer_leaves` reads a field during the check.
//!
//! Integer keys make that criterion insufficient on its own. `EnemyWeakID`
//! holds almost every id from 0 to 6563, so any small stat field is a subset of
//! it by accident — the raw sweep proposed `EnemyID.m_JP` and `EnemyID.m_CrtDef`
//! as references to it, and both are stats. Candidates were therefore also
//! scored on how much of their value span the target actually occupies: when a
//! target holds every integer in the span, containment proves nothing. What
//! survived was confirmed against decoded rows and the disassembly-backed
//! documentation in the OT0 modding workspace.
//!
//! Two rules shipped before this measurement named the wrong table:
//!
//! * `EnemyID.m_WeakID` pointed at `EnemyWeakLockID`, where only 14 of its 656
//!   distinct values exist. `EnemyWeakID` holds all of them. The two tables are
//!   not interchangeable: `EnemyWeakID` rows are an innate weakness profile
//!   (`m_ResistWeapon`/`m_ResistMagic`), `EnemyWeakLockID` rows are an applied
//!   lock effect with removal conditions. `EnemyWeakLockID` is still a real
//!   target — of `SkillAvailID.m_WeakLockID`, now listed below.
//! * `EnemyID.m_SkillsID` pointed at `SkillID`, where only 2 of its 1,050
//!   distinct values exist, and both are dummies. The field names a pool in
//!   `TacticalSkillList`, whose rows hold the actual skill ids; the old rule
//!   collapsed the two-hop chain into one.
//!
//! Together those two reported 2,717 broken references on untouched game data.

use crate::profiles::{ReferenceRule, ReferenceTable};

/// Every reference of the rule resolves in the shipped game data.
const NO_GAPS: &[(i64, u64)] = &[];

pub(super) fn tables() -> Vec<ReferenceTable> {
    [
        (
            "/local/database/activity/activitymainquestprogressparam",
            "ActivityMainQuestProgressParam",
        ),
        ("/local/database/item/alchemyresource", "AlchemyResource"),
        (
            "/local/database/battle/battleabortconditions",
            "BattleAbortConditions",
        ),
        (
            "/local/database/battle/battleeventcommand",
            "BattleEventCommand",
        ),
        ("/local/database/battle/battleeventlist", "BattleEventList"),
        ("/local/database/battle/battleplaybacks", "BattlePlaybacks"),
        (
            "/local/database/charactercreate/charactercreatememoryselect",
            "CharacterCreateMemorySelect",
        ),
        ("/local/database/character/charaguest", "CharaGuest"),
        ("/local/database/character/charaid", "CharaID"),
        ("/local/database/character/charanpclist", "CharaNpcList"),
        ("/local/database/character/charaplayer", "CharaPlayer"),
        (
            "/local/database/character/charaplayerspecialskilllist",
            "CharaPlayerSpecialSkillList",
        ),
        ("/local/database/character/charastatusid", "CharaStatusID"),
        ("/local/database/texture/charatexid", "CharaTexID"),
        ("/local/database/dlcgift/dlcgiftlist", "DLCGiftList"),
        ("/local/database/effect/effectlist", "EffectList"),
        ("/local/database/enemy/encountlist", "EncountList"),
        ("/local/database/enemy/encountvolume", "EncountVolume"),
        (
            "/local/database/endcard/endcardlistparam",
            "EndCardListParam",
        ),
        (
            "/local/database/enemy/enemybattleanimset",
            "EnemyBattleAnimSet",
        ),
        ("/local/database/enemy/enemydropid", "EnemyDropID"),
        ("/local/database/enemy/enemygroups", "EnemyGroups"),
        ("/local/database/enemy/enemyid", "EnemyID"),
        ("/local/database/enemy/enemyparts", "EnemyParts"),
        ("/local/database/texture/enemytexid", "EnemyTexID"),
        ("/local/database/enemy/enemytypeid", "EnemyTypeID"),
        (
            "/local/database/enemy/enemyweakchangeid",
            "EnemyWeakChangeID",
        ),
        ("/local/database/enemy/enemyweakid", "EnemyWeakID"),
        ("/local/database/enemy/enemyweaklockid", "EnemyWeakLockID"),
        (
            "/local/database/gametext/talktext/gametextevent",
            "GameTextEvent",
        ),
        (
            "/local/database/gametext/localize/en-us/talktext/gametextevent",
            "GameTextEvent_EN_US",
        ),
        (
            "/local/database/gametext/localize/ko-kr/talktext/gametextevent",
            "GameTextEvent_KO_KR",
        ),
        (
            "/local/database/gametext/localize/zh-cn/talktext/gametextevent",
            "GameTextEvent_ZH_CN",
        ),
        (
            "/local/database/gametext/localize/zh-tw/talktext/gametextevent",
            "GameTextEvent_ZH_TW",
        ),
        ("/local/database/sound/gramophonelist", "GramophoneList"),
        ("/local/database/item/itemlist", "ItemList"),
        ("/local/database/item/itemlisttabtype", "ItemListTabType"),
        ("/local/database/item/itemtype", "ItemType"),
        ("/local/database/character/jobid", "JobID"),
        (
            "/local/database/quality/landscapelodscale",
            "LandscapeLODScale",
        ),
        ("/local/database/quest/limitconditions", "LimitConditions"),
        ("/local/database/skill/magictype", "MagicType"),
        // MainStoryRingList measured clean but is deliberately absent: it holds
        // a row with the field name `m` twice, which the database reader
        // refuses, so its rules could never run and would only add a permanent
        // "could not be read" warning.
        ("/local/database/map/maplisttable", "MapListTable"),
        (
            "/local/database/object/mapobjectconditionslist",
            "MapObjectConditionsList",
        ),
        ("/local/database/map/mapreplacelist", "MapReplaceList"),
        (
            "/local/database/monsterarena/monsterarenalist",
            "MonsterArenaList",
        ),
        ("/local/database/narration/narrationlist", "NarrationList"),
        ("/local/database/item/notelist", "NoteList"),
        ("/local/database/partychat/partychatlist", "PartyChatList"),
        (
            "/local/database/character/playermemberset",
            "PlayerMemberSet",
        ),
        ("/local/database/quest/questlist", "QuestList"),
        ("/local/database/quest/questtasklist", "QuestTaskList"),
        (
            "/local/database/quest/questtrigcondition",
            "QuestTrigCondition",
        ),
        ("/local/database/sound/replacesoundlist", "ReplaceSoundList"),
        (
            "/local/database/scenarioreplay/scenarioreplaybondsectionparam",
            "ScenarioReplayBondSectionParam",
        ),
        (
            "/local/database/scenarioreplay/scenarioreplaychapterparam",
            "ScenarioReplayChapterParam",
        ),
        (
            "/local/database/scenarioreplay/scenarioreplaysubsectionparam",
            "ScenarioReplaySubSectionParam",
        ),
        ("/local/database/shop/shoplist", "ShopList"),
        (
            "/local/database/skill/skillailmentoffsets",
            "SkillAilmentOffsets",
        ),
        ("/local/database/skill/skillailmenttype", "SkillAilmentType"),
        ("/local/database/skill/skillavailid", "SkillAvailID"),
        (
            "/local/database/skillboard/skillboarddata",
            "SkillBoardData",
        ),
        ("/local/database/skill/skilleffectiveid", "SkillEffectiveID"),
        ("/local/database/skill/skillid", "SkillID"),
        (
            "/local/database/skill/skillresistailmentid",
            "SkillResistAilmentID",
        ),
        (
            "/local/database/skill/skillsupplyitemgroup",
            "SkillSupplyItemGroup",
        ),
        (
            "/local/database/skill/skillsupplyitemlist",
            "SkillSupplyItemList",
        ),
        ("/local/database/sound/soundlist", "SoundList"),
        (
            "/local/database/skill/specialskillgrowthlist",
            "SpecialSkillGrowthList",
        ),
        ("/local/database/skill/specialskillid", "SpecialSkillID"),
        (
            "/local/database/enemy/symbolenemygrouplist",
            "SymbolEnemyGroupList",
        ),
        ("/local/database/enemy/symbolenemylist", "SymbolEnemyList"),
        (
            "/local/database/aibattle/tacticalassignlist",
            "TacticalAssignList",
        ),
        ("/local/database/aibattle/tacticallist", "TacticalList"),
        (
            "/local/database/aibattle/tacticalskilllist",
            "TacticalSkillList",
        ),
        ("/local/database/texture/textureid", "TextureID"),
        (
            "/local/database/village/villagebuildingdata",
            "VillageBuildingData",
        ),
        (
            "/local/database/village/villagebuildinggradebonus",
            "VillageBuildingGradeBonus",
        ),
        (
            "/local/database/village/villagebuildingresourcedestruct",
            "VillageBuildingResourceDestruct",
        ),
        (
            "/local/database/village/villagebuildingresourcerequire",
            "VillageBuildingResourceRequire",
        ),
        (
            "/local/database/village/villagefarmhervestitems",
            "VillageFarmHervestItems",
        ),
        ("/local/database/village/villagefarmitem", "VillageFarmItem"),
        (
            "/local/database/village/villageresidentskill",
            "VillageResidentSkill",
        ),
        (
            "/local/database/village/villagetownlevelcondition",
            "VillageTownLevelCondition",
        ),
        (
            "/local/database/village/villagetradeitem",
            "VillageTradeItem",
        ),
        (
            "/local/database/village/villagetributeitem",
            "VillageTributeItem",
        ),
        (
            "/local/database/map/worldmapillustlist",
            "WorldMapIllustList",
        ),
        ("/local/database/map/worldmaplist", "WorldMapList"),
    ]
    .into_iter()
    .map(|(path_suffix, name)| ReferenceTable { path_suffix, name })
    .collect()
}

pub(super) fn rules() -> Vec<ReferenceRule> {
    [
        ("EnemyGroups", "m_EnemyID", "EnemyID", NO_GAPS),
        ("EnemyID", "m_TypeID", "EnemyTypeID", NO_GAPS),
        ("EnemyID", "m_WeakID", "EnemyWeakID", NO_GAPS),
        (
            "EnemyID",
            "m_ResistAilmentID",
            "SkillResistAilmentID",
            NO_GAPS,
        ),
        ("EnemyID", "m_SkillsID", "TacticalSkillList", NO_GAPS),
        ("SkillID", "m_BoostSkills", "SkillID", NO_GAPS),
        ("SkillID", "m_ReplaceSkill", "SkillID", NO_GAPS),
        ("SkillID", "m_ReplaceSkillArray", "SkillID", NO_GAPS),
        ("SkillID", "m_WeaponReplaceSkill", "SkillID", NO_GAPS),
        // Skill 3414 asks for avail 10178, which the game does not ship (10177
        // and 10179 do). It is dead content, reachable only through a
        // TacticalSkillList row no enemy selects. Exempting that one pair keeps
        // the rule's other 12,412 links checked.
        ("SkillID", "m_Avails", "SkillAvailID", &[(3414, 10178)]),
        ("SkillID", "m_BeginEffective", "SkillEffectiveID", NO_GAPS),
        ("SkillID", "m_Effectives", "SkillEffectiveID", NO_GAPS),
        ("SkillID", "m_EndEffective", "SkillEffectiveID", NO_GAPS),
        ("SkillAvailID", "m_DelayedSkill", "SkillID", NO_GAPS),
        (
            "SkillAvailID",
            "m_ResistAilmentID",
            "SkillResistAilmentID",
            NO_GAPS,
        ),
        (
            "BattleEventList",
            "m_EventCommand",
            "BattleEventCommand",
            NO_GAPS,
        ),
        (
            "ActivityMainQuestProgressParam",
            "m_ClearQuestId",
            "QuestList",
            NO_GAPS,
        ),
        ("AlchemyResource", "m_AlchemyItemId", "ItemList", NO_GAPS),
        ("AlchemyResource", "m_ResourceItemId", "ItemList", NO_GAPS),
        ("BattleAbortConditions", "m_EnemyID", "EnemyID", NO_GAPS),
        ("BattleEventCommand", "m_BgmID", "SoundList", NO_GAPS),
        ("BattleEventCommand", "m_PerformerEnemy", "EnemyID", NO_GAPS),
        ("BattleEventCommand", "m_SkillID", "SkillID", NO_GAPS),
        ("BattleEventCommand", "m_SoundID", "SoundList", NO_GAPS),
        ("BattlePlaybacks", "m_EnemySkillID", "SkillID", NO_GAPS),
        ("CharaGuest", "m_SkillsID", "TacticalSkillList", NO_GAPS),
        (
            "CharaGuest",
            "m_TacticalAssignID",
            "TacticalAssignList",
            NO_GAPS,
        ),
        ("CharaNpcList", "m_CharaID", "CharaID", NO_GAPS),
        ("CharaNpcList", "m_PossessionInfo", "ItemList", NO_GAPS),
        ("CharaPlayer", "m_CharaID", "CharaID", NO_GAPS),
        ("CharaPlayer", "m_EquipDef", "ItemList", NO_GAPS),
        ("CharaPlayer", "m_IllustID", "CharaTexID", NO_GAPS),
        ("CharaPlayer", "m_IllustMaskID", "CharaTexID", NO_GAPS),
        ("CharaPlayer", "m_NameTexID", "CharaTexID", NO_GAPS),
        (
            "CharaPlayerSpecialSkillList",
            "m_PlayerID",
            "CharaPlayer",
            NO_GAPS,
        ),
        ("CharaStatusID", "m_FrameIconID", "TextureID", NO_GAPS),
        ("CharaStatusID", "m_IconID", "TextureID", NO_GAPS),
        (
            "CharacterCreateMemorySelect",
            "m_acquisition_item",
            "ItemList",
            NO_GAPS,
        ),
        ("DLCGiftList", "m_ItemId", "ItemList", NO_GAPS),
        ("EncountList", "m_EncountVolume", "EncountVolume", NO_GAPS),
        ("EncountList", "m_MapId", "MapListTable", NO_GAPS),
        ("EncountVolume", "m_EnemyGroup", "EnemyGroups", NO_GAPS),
        ("EncountVolume", "m_FirstEncount", "EnemyGroups", NO_GAPS),
        ("EndCardListParam", "m_ImageBG", "TextureID", NO_GAPS),
        (
            "EnemyBattleAnimSet",
            "m_EnemyTextureIDs",
            "EnemyTexID",
            NO_GAPS,
        ),
        ("EnemyGroups", "m_Bgm", "SoundList", NO_GAPS),
        ("EnemyID", "m_DropReward", "EnemyDropID", NO_GAPS),
        ("EnemyID", "m_StealReward", "EnemyDropID", NO_GAPS),
        (
            "EnemyID",
            "m_TacticalAssignID",
            "TacticalAssignList",
            NO_GAPS,
        ),
        ("EnemyParts", "m_AnimSetID", "EnemyBattleAnimSet", NO_GAPS),
        (
            "EnemyTypeID",
            "m_AilmentOffset",
            "SkillAilmentOffsets",
            NO_GAPS,
        ),
        (
            "EnemyTypeID",
            "m_AnimationSetIDs",
            "EnemyBattleAnimSet",
            NO_GAPS,
        ),
        ("EnemyTypeID", "m_CallSE", "SoundList", NO_GAPS),
        ("EnemyTypeID", "m_NpcCharaID", "CharaID", NO_GAPS),
        (
            "EnemyTypeID",
            "m_OverrideOrderIconAnimSetID",
            "EnemyBattleAnimSet",
            NO_GAPS,
        ),
        ("GameTextEvent", "m_voiceId", "SoundList", NO_GAPS),
        ("GameTextEvent_EN_US", "m_voiceId", "SoundList", NO_GAPS),
        ("GameTextEvent_KO_KR", "m_voiceId", "SoundList", NO_GAPS),
        ("GameTextEvent_ZH_CN", "m_voiceId", "SoundList", NO_GAPS),
        ("GameTextEvent_ZH_TW", "m_voiceId", "SoundList", NO_GAPS),
        ("GramophoneList", "m_SoundList", "SoundList", NO_GAPS),
        (
            "GramophoneList",
            "m_TrigCondID",
            "QuestTrigCondition",
            NO_GAPS,
        ),
        ("ItemList", "m_SkillID", "SkillID", NO_GAPS),
        ("ItemListTabType", "m_MenuTabIconID", "TextureID", NO_GAPS),
        ("ItemListTabType", "m_TitleIconID", "TextureID", NO_GAPS),
        ("ItemType", "m_DefaultEquipID", "ItemList", NO_GAPS),
        ("ItemType", "m_MenuIconID", "TextureID", NO_GAPS),
        ("ItemType", "m_MenuTabIconID", "TextureID", NO_GAPS),
        ("JobID", "m_BaseAttackSkill", "SkillID", NO_GAPS),
        ("JobID", "m_JobIcon", "TextureID", NO_GAPS),
        ("LandscapeLODScale", "m_TargetMap", "MapListTable", NO_GAPS),
        ("LimitConditions", "m_BgmID", "SoundList", NO_GAPS),
        ("LimitConditions", "m_BootQuestID", "QuestList", NO_GAPS),
        ("LimitConditions", "m_DisableQuestID", "QuestList", NO_GAPS),
        ("LimitConditions", "m_mapID", "MapListTable", NO_GAPS),
        ("LimitConditions", "m_worldMapID", "WorldMapList", NO_GAPS),
        ("MagicType", "m_SkillIconTexID", "TextureID", NO_GAPS),
        ("MagicType", "m_WeakIconTexID", "TextureID", NO_GAPS),
        ("MapListTable", "m_BGM", "SoundList", NO_GAPS),
        ("MapListTable", "m_FootSE", "SoundList", NO_GAPS),
        ("MapListTable", "m_RegionIconTexID", "TextureID", NO_GAPS),
        (
            "MapObjectConditionsList",
            "m_BootQuestID",
            "QuestList",
            NO_GAPS,
        ),
        (
            "MapObjectConditionsList",
            "m_DisableQuestID",
            "QuestList",
            NO_GAPS,
        ),
        ("MapReplaceList", "m_DisableQuestID", "QuestList", NO_GAPS),
        ("MapReplaceList", "m_EnableQuestID", "QuestList", NO_GAPS),
        ("MapReplaceList", "m_MapAfter", "MapListTable", NO_GAPS),
        ("MapReplaceList", "m_MapBefore", "MapListTable", NO_GAPS),
        ("MapReplaceList", "m_WorldMapAfter", "WorldMapList", NO_GAPS),
        (
            "MapReplaceList",
            "m_WorldMapBefore",
            "WorldMapList",
            NO_GAPS,
        ),
        ("MonsterArenaList", "m_MapID", "MapListTable", NO_GAPS),
        ("MonsterArenaList", "m_RewardItemId", "ItemList", NO_GAPS),
        ("NarrationList", "m_VoiceID", "SoundList", NO_GAPS),
        ("NoteList", "m_ItemID", "ItemList", NO_GAPS),
        ("PartyChatList", "m_BootQuestID", "QuestList", NO_GAPS),
        ("PartyChatList", "m_DisableQuestID", "QuestList", NO_GAPS),
        ("PartyChatList", "m_MapID", "MapListTable", NO_GAPS),
        ("PlayerMemberSet", "m_PlayerIDs", "CharaPlayer", NO_GAPS),
        ("QuestTaskList", "m_ClearedQuest", "QuestList", NO_GAPS),
        ("QuestTaskList", "m_ItemID", "ItemList", NO_GAPS),
        (
            "QuestTaskList",
            "m_NextDestination",
            "MapListTable",
            NO_GAPS,
        ),
        ("QuestTaskList", "m_OwnerQuest", "QuestList", NO_GAPS),
        ("QuestTaskList", "m_TaskItemId", "ItemList", NO_GAPS),
        ("QuestTrigCondition", "m_OwnerQuest", "QuestList", NO_GAPS),
        ("ReplaceSoundList", "m_PrevSoundID", "SoundList", NO_GAPS),
        (
            "ScenarioReplayBondSectionParam",
            "m_CharaIds",
            "CharaID",
            NO_GAPS,
        ),
        (
            "ScenarioReplayChapterParam",
            "m_CharaIcons",
            "CharaID",
            NO_GAPS,
        ),
        (
            "ScenarioReplaySubSectionParam",
            "m_QuestId",
            "QuestList",
            NO_GAPS,
        ),
        ("ShopList", "m_ItemID", "ItemList", NO_GAPS),
        ("ShopList", "m_MapID", "MapListTable", NO_GAPS),
        (
            "SkillAilmentType",
            "m_CharacterEffect",
            "EffectList",
            NO_GAPS,
        ),
        (
            "SkillAvailID",
            "m_WeakChangeID",
            "EnemyWeakChangeID",
            NO_GAPS,
        ),
        ("SkillAvailID", "m_WeakLockID", "EnemyWeakLockID", NO_GAPS),
        ("SkillBoardData", "m_PlayerID", "CharaPlayer", NO_GAPS),
        ("SkillBoardData", "m_SkillID", "SkillID", NO_GAPS),
        ("SkillBoardData", "m_SupportSkillID", "SkillID", NO_GAPS),
        ("SkillEffectiveID", "m_Effects", "EffectList", NO_GAPS),
        ("SkillEffectiveID", "m_Sounds", "SoundList", NO_GAPS),
        ("SkillSupplyItemGroup", "m_SkillId", "SkillID", NO_GAPS),
        ("SkillSupplyItemList", "m_ItemId", "ItemList", NO_GAPS),
        ("SpecialSkillGrowthList", "m_SkillID", "SkillID", NO_GAPS),
        (
            "SpecialSkillGrowthList",
            "m_SpecialSkillID",
            "SpecialSkillID",
            NO_GAPS,
        ),
        (
            "SymbolEnemyGroupList",
            "m_StartSymbolEnemyId",
            "SymbolEnemyList",
            NO_GAPS,
        ),
        ("TacticalAssignList", "m_Tactics", "TacticalList", NO_GAPS),
        ("TacticalList", "m_PresageSkillID", "SkillID", NO_GAPS),
        (
            "VillageBuildingData",
            "m_BlueprintItemId",
            "ItemList",
            NO_GAPS,
        ),
        (
            "VillageBuildingData",
            "m_ExchangeItemId",
            "ItemList",
            NO_GAPS,
        ),
        (
            "VillageBuildingData",
            "m_MovableConditions",
            "QuestTrigCondition",
            NO_GAPS,
        ),
        ("VillageBuildingGradeBonus", "m_SkillId", "SkillID", NO_GAPS),
        (
            "VillageBuildingResourceDestruct",
            "m_ItemId",
            "ItemList",
            NO_GAPS,
        ),
        (
            "VillageBuildingResourceRequire",
            "m_ItemId",
            "ItemList",
            NO_GAPS,
        ),
        (
            "VillageFarmHervestItems",
            "m_HarvestItemId",
            "ItemList",
            NO_GAPS,
        ),
        ("VillageFarmItem", "m_ResourceItemId", "ItemList", NO_GAPS),
        ("VillageResidentSkill", "m_SkillId", "SkillID", NO_GAPS),
        (
            "VillageTownLevelCondition",
            "m_Condition",
            "QuestTrigCondition",
            NO_GAPS,
        ),
        ("VillageTradeItem", "m_TradeItemId", "ItemList", NO_GAPS),
        ("VillageTributeItem", "m_ItemId", "ItemList", NO_GAPS),
        ("WorldMapIllustList", "m_TextureID", "TextureID", NO_GAPS),
        ("WorldMapList", "m_BelongingMap", "MapListTable", NO_GAPS),
        ("WorldMapList", "m_FastTravelMap", "MapListTable", NO_GAPS),
        (
            "WorldMapList",
            "m_NpcSetListMapId1",
            "MapListTable",
            NO_GAPS,
        ),
        (
            "WorldMapList",
            "m_SymbolEnemies",
            "SymbolEnemyList",
            NO_GAPS,
        ),
    ]
    .into_iter()
    .map(
        |(source_table, field, target_table, vanilla_gaps)| ReferenceRule {
            source_table,
            field,
            target_table,
            vanilla_gaps,
        },
    )
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};

    #[test]
    fn every_rule_names_a_declared_table() {
        let known: BTreeSet<&str> = tables().into_iter().map(|table| table.name).collect();
        for rule in rules() {
            assert!(
                known.contains(rule.source_table),
                "rule source {} has no table entry",
                rule.source_table
            );
            assert!(
                known.contains(rule.target_table),
                "rule target {} has no table entry",
                rule.target_table
            );
        }
    }

    /// No table path may end with another, or a suffix match would resolve one
    /// asset to two tables and the check would compare the wrong row ids.
    #[test]
    fn table_path_suffixes_are_unambiguous() {
        let paths: Vec<&str> = tables()
            .into_iter()
            .map(|table| table.path_suffix)
            .collect();
        assert_eq!(
            paths.iter().collect::<BTreeSet<_>>().len(),
            paths.len(),
            "a table path is registered twice"
        );
        for path in &paths {
            for other in &paths {
                assert!(
                    path == other || !path.ends_with(other),
                    "{path} also matches {other}"
                );
            }
        }
    }

    /// The corrections this list carries, stated as tests so a future edit that
    /// puts the old targets back fails here rather than in a user's merge.
    #[test]
    fn the_two_retargeted_rules_point_at_the_tables_that_hold_their_values() {
        let rules = rules();
        let find = |source: &str, field: &str| {
            rules
                .iter()
                .find(|rule| rule.source_table == source && rule.field == field)
                .unwrap_or_else(|| panic!("{source}.{field} is missing"))
        };
        // EnemyWeakLockID holds applied lock effects; the innate weakness
        // profile an enemy names lives in EnemyWeakID.
        assert_eq!(find("EnemyID", "m_WeakID").target_table, "EnemyWeakID");
        // m_SkillsID names a pool, and the pool's rows hold the skill ids.
        assert_eq!(
            find("EnemyID", "m_SkillsID").target_table,
            "TacticalSkillList"
        );
        // EnemyWeakLockID is still a real target, of the field that applies one.
        assert_eq!(
            find("SkillAvailID", "m_WeakLockID").target_table,
            "EnemyWeakLockID"
        );
    }

    #[test]
    fn only_the_one_known_vanilla_gap_is_exempt() {
        let exempt: Vec<String> = rules()
            .iter()
            .filter(|rule| !rule.vanilla_gaps.is_empty())
            .map(|rule| {
                format!(
                    "{}.{} {:?}",
                    rule.source_table, rule.field, rule.vanilla_gaps
                )
            })
            .collect();
        assert_eq!(
            exempt,
            vec!["SkillID.m_Avails [(3414, 10178)]".to_owned()],
            "an exemption hides a real break unless it is measured and justified"
        );
    }

    /// Every rule must resolve completely against untouched game data.
    ///
    /// This is what makes the list safe to ship. OT0 rows are keyed by integer,
    /// so a stat field can be a perfect subset of a dense id space by accident;
    /// a rule that is only usually right would report the remainder as broken on
    /// data nobody has modified. Ignored by default because the cooked game
    /// files are not redistributable.
    ///
    /// ```text
    /// PAK_MERGER_OT0_PACKAGE_DIR=<cooked tree> \
    ///   cargo test --lib octopath_traveler_0 -- --ignored --nocapture
    /// ```
    #[test]
    #[ignore = "requires a local cooked OCTOPATH TRAVELER 0 tree"]
    fn every_rule_resolves_against_untouched_game_data() {
        let Ok(root) = std::env::var("PAK_MERGER_OT0_PACKAGE_DIR") else {
            panic!("set PAK_MERGER_OT0_PACKAGE_DIR to a cooked OCTOPATH TRAVELER 0 tree");
        };

        let wanted: Vec<(&str, &str)> = tables()
            .into_iter()
            .map(|table| (table.path_suffix, table.name))
            .collect();
        let mut loaded: BTreeMap<&str, crate::binary_asset::IndexedBinaryAsset> = BTreeMap::new();
        let mut unreadable: Vec<String> = Vec::new();
        let mut stack = vec![std::path::PathBuf::from(root)];
        while let Some(directory) = stack.pop() {
            for entry in std::fs::read_dir(&directory).expect("readable directory") {
                let path = entry.expect("readable entry").path();
                if path.is_dir() {
                    stack.push(path);
                    continue;
                }
                if path.extension().and_then(|value| value.to_str()) != Some("uexp") {
                    continue;
                }
                let stem = path
                    .with_extension("")
                    .to_string_lossy()
                    .replace('\\', "/")
                    .to_lowercase();
                let Some((_, name)) = wanted.iter().find(|(suffix, _)| stem.ends_with(suffix))
                else {
                    continue;
                };
                let bytes = std::fs::read(&path).expect("readable .uexp");
                // A table the merger cannot parse is one the check can never
                // run, so registering it only buys a permanent "could not be
                // read" warning. Collect them all rather than stopping at the
                // first, so the list can be pruned in one pass.
                match crate::binary_asset::IndexedBinaryAsset::parse_backed(bytes) {
                    Ok(asset) => assert!(
                        loaded.insert(name, asset).is_none(),
                        "{name} matched two files"
                    ),
                    Err(error) => unreadable.push(format!("{name}: {error}")),
                }
            }
        }

        let mut missing: Vec<&str> = Vec::new();
        let mut breaks: Vec<String> = Vec::new();
        let mut exempted = 0_usize;
        let mut checked = 0_usize;
        for rule in rules() {
            let (Some(source), Some(target)) =
                (loaded.get(rule.source_table), loaded.get(rule.target_table))
            else {
                missing.push(rule.source_table);
                continue;
            };
            let ids: BTreeSet<i64> = target.row_ids().iter().copied().collect();
            for index in 0..source.row_count() {
                let row = source
                    .row_at(index)
                    .expect("readable row")
                    .expect("row is present");
                let Some(node) = row.node.map_get(rule.field).expect("readable field") else {
                    continue;
                };
                crate::merge::visit_positive_integer_leaves(node, &mut |target_id| {
                    checked += 1;
                    let present = i64::try_from(target_id).is_ok_and(|id| ids.contains(&id));
                    if !present {
                        if rule.vanilla_gaps.contains(&(row.id, target_id)) {
                            exempted += 1;
                        } else {
                            breaks.push(format!(
                                "{}.{} row {} -> {} id {target_id}",
                                rule.source_table, rule.field, row.id, rule.target_table
                            ));
                        }
                    }
                    Ok(())
                })
                .expect("field walks");
            }
        }

        assert!(
            unreadable.is_empty(),
            "the merger cannot parse these registered tables, so their rules would \
             never run: {unreadable:#?}"
        );
        assert!(
            missing.is_empty(),
            "these tables were not found under the tree: {missing:?}"
        );
        assert!(checked > 0, "no references were checked");
        assert!(
            breaks.is_empty(),
            "{} of {checked} references did not resolve, e.g. {:#?}",
            breaks.len(),
            &breaks[..breaks.len().min(20)]
        );
        // The exemptions must still be earned: each one has to be a reference
        // that really is dangling, not a line nobody reaches any more.
        assert_eq!(
            exempted,
            rules()
                .iter()
                .map(|rule| rule.vanilla_gaps.len())
                .sum::<usize>(),
            "an exemption did not correspond to a real dangling reference"
        );
        println!(
            "{checked} references resolved across {} rules, {exempted} known vanilla gap(s)",
            rules().len()
        );
    }
}
