//! Cross-table reference knowledge for OCTOPATH TRAVELER II.
//!
//! `UDataTable` rows are keyed by name, so a reference is a field whose value
//! is a row name of another table. A merged Pak can be structurally perfect and
//! still be broken in game when a surviving row points at a row that the
//! version of the target table which won the merge no longer contains.
//!
//! # How this list was built
//!
//! Every top-level property of all 68 source tables was measured against the row
//! names of every other table in the shipped game data. A rule is listed only
//! when **every** value under that property is a row name of **exactly one**
//! table. Both halves matter:
//!
//! * Anything short of every value would report the remainder as broken on
//!   untouched vanilla data. `EnemyGroupData.EnemyID` looks like an obvious
//!   rule and is deliberately absent for this reason: it resolves against
//!   `EnemyDB` for only 1602 of its 1951 distinct values, because the 349
//!   `ENE_NPC_*` entries are row names of no table in the game.
//!   `BattleEncounterData.Group[].GroupID` is absent for the same reason at
//!   39.7%, as is `EnemyDB.EnemyAbility` at 92.0%.
//! * A single target matters because several tables share a row-name set. The
//!   nine `GameText*` locale tables hold the same 19,062 row names, so a text
//!   label cannot be attributed to one of them, and the whole family is absent.
//!
//! Values are compared the way [`crate::data_table::RowField::referenced_names`]
//! collects them: enum literals, asset paths and `None` are not references.
//!
//! References nest — most of them sit inside array-of-struct elements — so a
//! rule names the top-level property that owns them, and the check reads every
//! value `FName` beneath it.

use crate::profiles::{ReferenceRule, ReferenceTable};

pub(super) fn tables() -> Vec<ReferenceTable> {
    [
        ("/ability/database/abilitydata", "AbilityData"),
        ("/ability/database/abilitysetdata", "AbilitySetData"),
        ("/ability/database/ailmentdata", "AilmentData"),
        ("/ability/database/diseasedata", "DiseaseData"),
        ("/ability/database/dismantlingdata", "DismantlingData"),
        ("/ability/database/invadedata", "InvadeData"),
        ("/ability/database/supportabilitydata", "SupportAbilityData"),
        (
            "/battle/database/battleencounterdata",
            "BattleEncounterData",
        ),
        (
            "/battle/database/battleplacementtype",
            "BattlePlacementType",
        ),
        ("/battle/database/encounttriggerdata", "EncountTriggerData"),
        ("/battle/database/encountvolumedata", "EncountVolumeData"),
        (
            "/battle/database/enemyadditionalweapon",
            "EnemyAdditionalWeapon",
        ),
        ("/battle/database/enemygroupdata", "EnemyGroupData"),
        ("/character/database/battlevoiceset", "BattleVoiceSet"),
        (
            "/character/database/characterresourcedb",
            "CharacterResourceDB",
        ),
        ("/character/database/charactersaction", "CharactersAction"),
        ("/character/database/enemydb", "EnemyDB"),
        ("/character/database/jobdata", "JobData"),
        ("/character/database/myshipflipbookdb", "MyShipFlipbookDB"),
        ("/character/database/npcbattledata", "NPCBattleData"),
        ("/character/database/npcdata", "NPCData"),
        ("/character/database/npcheardata", "NPCHearData"),
        ("/character/database/npcleaddata", "NPCLeadData"),
        (
            "/character/database/playablecharacterdb",
            "PlayableCharacterDB",
        ),
        (
            "/character/database/potentialityactiondb",
            "PotentialityActionDB",
        ),
        (
            "/character/database/spactionmerchantdatadb",
            "SPActionMerchantDataDB",
        ),
        (
            "/character/database/supportcharacterdb",
            "SupportCharacterDB",
        ),
        ("/effect/database/effectdb", "EffectDB"),
        ("/environment/database/objectdata", "ObjectData"),
        ("/event/database/eventlist", "EventList"),
        ("/event/database/eventsounddb", "EventSoundDB"),
        (
            "/extrajobevent/inventorevent/database/inventorinventionquestdb",
            "InventorInventionQuestDB",
        ),
        (
            "/extrajobevent/weaponmasterevent/database/weaponmastereventdb",
            "WeaponMasterEventDB",
        ),
        (
            "/fieldcommand/database/fieldcommanddata",
            "FieldCommandData",
        ),
        (
            "/flipbook/database/missioncustomflipbookdb",
            "MissionCustomFlipbookDB",
        ),
        (
            "/flipbook/database/missioncustomspritedb",
            "MissionCustomSpriteDB",
        ),
        ("/gift/database/giftdata", "GiftData"),
        ("/item/database/equipmenttexture", "EquipmentTexture"),
        ("/item/database/itemdb", "ItemDB"),
        ("/item/database/specialitemdb", "SpecialItemDB"),
        ("/level/database/areainfotable", "AreaInfoTable"),
        ("/level/database/bartalklist", "BarTalkList"),
        ("/level/database/darkareadb", "DarkAreaDB"),
        ("/level/database/footsteptable", "FootStepTable"),
        ("/level/database/leveltable", "LevelTable"),
        ("/level/database/towntable", "TownTable"),
        ("/level/database/worldmapicondb", "WorldMapIconDB"),
        ("/level/database/worldmaptable", "WorldMapTable"),
        ("/placement/database/placementdata", "PlacementData"),
        ("/placement/database/placementlist", "PlacementList"),
        (
            "/reminiscence/database/reminiscencesetting",
            "ReminiscenceSetting",
        ),
        (
            "/render/database/switchlevelresolutiontable",
            "SwitchLevelResolutionTable",
        ),
        (
            "/sequencer/database/sequencerresourcedb",
            "SequencerResourceDB",
        ),
        ("/shop/database/guilddata", "GuildData"),
        ("/shop/database/purchaseitemtable", "PurchaseItemTable"),
        ("/shop/database/shopinfo", "ShopInfo"),
        ("/sound/database/bgmtable", "BGMTable"),
        ("/sound/database/cuesheettable", "CueSheetTable"),
        ("/sound/database/setable", "SETable"),
        ("/sound/database/voicetable_en", "VoiceTable_en"),
        ("/sound/database/voicetable_ja", "VoiceTable_ja"),
        ("/story/database/mainstory", "MainStory"),
        ("/story/database/mainstorytask", "MainStoryTask"),
        ("/story/database/mainstorytasklist", "MainStoryTaskList"),
        ("/story/database/substorytask", "SubStoryTask"),
        ("/story/database/substorytasklist", "SubStoryTaskList"),
        ("/tutorial/database/tutorialflagpart", "TutorialFlagPart"),
        ("/tutorial/database/tutoriallisttable", "TutorialListTable"),
        ("/tutorial/database/tutorialpagetable", "TutorialPageTable"),
        (
            "/userinterface/common/database/pc_db/uiresourcedb_pc",
            "UIResourceDB_pc",
        ),
        (
            "/userinterface/common_pc/database/buttontextdata",
            "ButtonTextData",
        ),
        (
            "/userinterface/common_pc/database/commoncontrollerconfigdatatable",
            "CommonControllerConfigDataTable",
        ),
        (
            "/userinterface/mainmenu/3dworldmap/datatable/worldmapdarkareaeffectdb",
            "WorldMapDarkAreaEffectDB",
        ),
        (
            "/userinterface/narration/database/narrationsettable",
            "NarrationSetTable",
        ),
        (
            "/userinterface/narration/database/narrationtable",
            "NarrationTable",
        ),
        (
            "/userinterface/narration/database/narrationtable_de",
            "NarrationTable_de",
        ),
        (
            "/userinterface/narration/database/narrationtable_en",
            "NarrationTable_en",
        ),
        (
            "/userinterface/narration/database/narrationtable_es",
            "NarrationTable_es",
        ),
        (
            "/userinterface/narration/database/narrationtable_fr",
            "NarrationTable_fr",
        ),
        (
            "/userinterface/narration/database/narrationtable_it",
            "NarrationTable_it",
        ),
        (
            "/userinterface/narration/database/narrationtable_kr",
            "NarrationTable_kr",
        ),
        (
            "/userinterface/narration/database/narrationtable_zh_cn",
            "NarrationTable_zh_cn",
        ),
        (
            "/userinterface/narration/database/narrationtable_zh_tw",
            "NarrationTable_zh_tw",
        ),
        ("/userinterface/partychat/database/partychat", "PartyChat"),
        (
            "/userinterface/staffroll/database/endrollsegmentdb",
            "EndRollSegmentDB",
        ),
        (
            "/userinterface/staffroll/database/staffcreditdb",
            "StaffCreditDB",
        ),
        (
            "/userinterface/staffroll/database/staffcreditstyledb",
            "StaffCreditStyleDB",
        ),
        ("/userinterface/subtitle/database/subtitledb", "SubTitleDB"),
    ]
    .into_iter()
    .map(|(path_suffix, name)| ReferenceTable { path_suffix, name })
    .collect()
}

pub(super) fn rules() -> Vec<ReferenceRule> {
    [
        ("AbilitySetData", "RestrictWeaponLabel", "ItemDB"),
        (
            "AilmentData",
            "AddDisease_105_48D7D93A4B672BF6B0204FA2F9145384",
            "DiseaseData",
        ),
        ("AreaInfoTable", "AreaEmblemID", "UIResourceDB_pc"),
        ("BarTalkList", "ItemEventList", "EventList"),
        ("BarTalkList", "NormalEventList", "EventList"),
        ("BattleVoiceSet", "EnemyGroupID", "EnemyGroupData"),
        ("BattleVoiceSet", "InvadeID", "InvadeData"),
        ("BattleVoiceSet", "SupporterID", "SupportCharacterDB"),
        ("CharactersAction", "ActionFootStep", "SETable"),
        (
            "CommonControllerConfigDataTable",
            "KeyList",
            "ButtonTextData",
        ),
        (
            "DiseaseData",
            "EffectLabel_112_2FB406E143C3E39A01C10993E2678096",
            "EffectDB",
        ),
        (
            "DiseaseData",
            "ResorceLabel_105_9029E3D640BE812B62489D90CE8E3B26",
            "UIResourceDB_pc",
        ),
        ("DismantlingData", "Ailment", "AilmentData"),
        (
            "EncountTriggerData",
            "DarkAreaEncountVolumeName",
            "EncountVolumeData",
        ),
        (
            "EncountTriggerData",
            "LostWayEncountVolumeName",
            "EncountVolumeData",
        ),
        ("EncountVolumeData", "EncounterList", "BattleEncounterData"),
        ("EndRollSegmentDB", "BattleEnemyGroupA", "EnemyGroupData"),
        ("EndRollSegmentDB", "BattleEnemyGroupB", "EnemyGroupData"),
        (
            "EndRollSegmentDB",
            "EventImageLabelPartnerA",
            "UIResourceDB_pc",
        ),
        (
            "EndRollSegmentDB",
            "EventImageLabelPartnerB",
            "UIResourceDB_pc",
        ),
        (
            "EnemyAdditionalWeapon",
            "AdditionalWeapon00_18_1E00388346843B8049199FAE7B14DE52",
            "ItemDB",
        ),
        (
            "EnemyDB",
            "StealItemID_301_CE0FDB3A4138AFC8BFF2ADB1E0E175C6",
            "ItemDB",
        ),
        (
            "EnemyDB",
            "WeaponItemLabel_287_FC3FA16845388B6916B4C3B075BD7FA5",
            "ItemDB",
        ),
        (
            "EnemyGroupData",
            "PlacementType_14_0BECBBB0413FADBA41048FAB127C7CF6",
            "BattlePlacementType",
        ),
        (
            "EventList",
            "ChengeFinishTimeSequencer",
            "SequencerResourceDB",
        ),
        ("EventList", "ChengeTimeSequencer", "SequencerResourceDB"),
        ("EventSoundDB", "BgmLabelOnEnd", "BGMTable"),
        ("EventSoundDB", "BgmLabelOnStart", "BGMTable"),
        ("EventSoundDB", "FixedFieldBgmLabel", "BGMTable"),
        ("FieldCommandData", "BadConnectionEventLabel", "EventList"),
        ("FieldCommandData", "BeforeEventLabel", "EventList"),
        ("FieldCommandData", "FailedEventLabel", "EventList"),
        ("FieldCommandData", "IconLabel", "UIResourceDB_pc"),
        ("FieldCommandData", "IconLabel_Large", "UIResourceDB_pc"),
        ("FieldCommandData", "SELabel", "SETable"),
        ("FieldCommandData", "StatusMenuIconLabel", "UIResourceDB_pc"),
        ("FieldCommandData", "SuccessEventLabel", "EventList"),
        ("FootStepTable", "DashSELabel", "SETable"),
        ("FootStepTable", "WalkSELabel", "SETable"),
        ("GiftData", "ItemDataSets", "ItemDB"),
        ("GuildData", "CompleteEvent", "EventList"),
        ("GuildData", "FirstReconfirm", "EventList"),
        ("GuildData", "FistTaskEvent", "EventList"),
        ("GuildData", "GuildNpcLabel", "PlacementData"),
        ("GuildData", "JobIconLabel", "UIResourceDB_pc"),
        ("GuildData", "LicenseItem", "ItemDB"),
        ("GuildData", "WorldMapLocation", "WorldMapTable"),
        ("InvadeData", "ProcessedItem", "ItemDB"),
        ("InvadeData", "ResourceLabel", "CharacterResourceDB"),
        ("InventorInventionQuestDB", "InventionItemlabel", "ItemDB"),
        (
            "InventorInventionQuestDB",
            "LearnAbilitylabel",
            "AbilitySetData",
        ),
        ("InventorInventionQuestDB", "Materials", "ItemDB"),
        ("ItemDB", "Ailment", "AilmentData"),
        ("ItemDB", "EquipmentTextureLabel", "EquipmentTexture"),
        ("ItemDB", "SpecialItemLabel", "SpecialItemDB"),
        ("JobData", "AbilityJobIcon", "UIResourceDB_pc"),
        ("JobData", "EquipJobItem", "ItemDB"),
        ("JobData", "JobCommandAbility", "AbilitySetData"),
        ("JobData", "JobSupportAbility", "SupportAbilityData"),
        ("JobData", "MenuJobIcon", "UIResourceDB_pc"),
        (
            "LevelTable",
            "BattleMapNameList",
            "SwitchLevelResolutionTable",
        ),
        ("LevelTable", "Bgm2Label", "BGMTable"),
        (
            "LevelTable",
            "DarkAreaEncountVolumeName",
            "EncountVolumeData",
        ),
        (
            "LevelTable",
            "ReplaceTimeZoneSeqLabel",
            "SequencerResourceDB",
        ),
        ("MainStory", "StartWMapLocation", "WorldMapTable"),
        ("MainStoryTask", "AuthorizationFastTravel", "WorldMapTable"),
        ("MainStoryTask", "MainStoryLabel", "MainStory"),
        ("MainStoryTask", "MemoryEventLabel", "EventList"),
        ("MainStoryTaskList", "LabelArray", "MainStoryTask"),
        (
            "MissionCustomFlipbookDB",
            "KeyFrames",
            "MissionCustomSpriteDB",
        ),
        ("MyShipFlipbookDB", "MeshResourceLabel", "UIResourceDB_pc"),
        (
            "MyShipFlipbookDB",
            "OpenSailMeshResourceLabel",
            "UIResourceDB_pc",
        ),
        ("NPCBattleData", "AdditionalTargetNpc", "NPCData"),
        ("NPCBattleData", "DoseItemID", "ItemDB"),
        ("NPCBattleData", "PreBattleEventID", "EventList"),
        ("NPCHearData", "SpecialHearDay_01", "UIResourceDB_pc"),
        ("NPCHearData", "SpecialHearDay_02", "UIResourceDB_pc"),
        ("NPCHearData", "SpecialHearEvening_01", "UIResourceDB_pc"),
        ("NPCHearData", "SpecialHearEvening_02", "UIResourceDB_pc"),
        ("NPCLeadData", "SpActionMerchant", "SPActionMerchantDataDB"),
        ("NarrationTable", "NarrationSet", "NarrationSetTable"),
        ("NarrationTable_de", "NarrationSet", "NarrationSetTable"),
        ("NarrationTable_en", "NarrationSet", "NarrationSetTable"),
        ("NarrationTable_es", "NarrationSet", "NarrationSetTable"),
        ("NarrationTable_fr", "NarrationSet", "NarrationSetTable"),
        ("NarrationTable_it", "NarrationSet", "NarrationSetTable"),
        ("NarrationTable_kr", "NarrationSet", "NarrationSetTable"),
        ("NarrationTable_zh_cn", "NarrationSet", "NarrationSetTable"),
        ("NarrationTable_zh_tw", "NarrationSet", "NarrationSetTable"),
        ("ObjectData", "RandomItemCandidates", "ItemDB"),
        ("PartyChat", "EventLabel", "EventList"),
        ("PartyChat", "MainStoryTaskBegin", "MainStoryTask"),
        ("PartyChat", "MainStoryTaskEnd", "MainStoryTask"),
        ("PartyChat", "RelatedMainStory", "MainStory"),
        ("PlacementData", "EventLabel_C", "EventList"),
        ("PlacementData", "EventLabel_E", "EventList"),
        ("PlacementData", "EventLabel_F", "EventList"),
        ("PlacementData", "EventParam_A_1_ID", "ItemDB"),
        ("PlacementData", "EventParam_E_1", "ItemDB"),
        ("PlacementList", "LabelList", "PlacementData"),
        (
            "PlayableCharacterDB",
            "CharmEnemyLabelForKSBattle",
            "EnemyDB",
        ),
        (
            "PlayableCharacterDB",
            "DayPortraitBgLabel",
            "UIResourceDB_pc",
        ),
        ("PlayableCharacterDB", "DayPortraitLabel", "UIResourceDB_pc"),
        ("PlayableCharacterDB", "FirstEquipment", "ItemDB"),
        (
            "PlayableCharacterDB",
            "NightPortraitBgLabel",
            "UIResourceDB_pc",
        ),
        (
            "PlayableCharacterDB",
            "NightPortraitLabel",
            "UIResourceDB_pc",
        ),
        (
            "PlayableCharacterDB",
            "PortraitNameLabel",
            "UIResourceDB_pc",
        ),
        (
            "PlayableCharacterDB",
            "PotentialityActionLabel",
            "PotentialityActionDB",
        ),
        ("PlayableCharacterDB", "SymbolLabel", "UIResourceDB_pc"),
        ("PlayableCharacterDB", "SymbolWhLabel", "UIResourceDB_pc"),
        ("PlayableCharacterDB", "VoiceCueSheet_ja", "CueSheetTable"),
        ("PotentialityActionDB", "AddAbilityList", "AbilitySetData"),
        ("PotentialityActionDB", "AuraEffectLabel", "EffectDB"),
        (
            "PotentialityActionDB",
            "GageEffectTexLabel",
            "UIResourceDB_pc",
        ),
        ("PotentialityActionDB", "GageIconLabel", "UIResourceDB_pc"),
        ("PurchaseItemTable", "PossibleItemLabel", "ItemDB"),
        ("ReminiscenceSetting", "FirstBackpackItemLabel", "ItemDB"),
        ("ReminiscenceSetting", "ItemOnSkipReminiscence", "ItemDB"),
        ("SETable", "CueSheetName", "CueSheetTable"),
        ("ShopInfo", "InnDiscountItem", "ItemDB"),
        ("SpecialItemDB", "BgmLabel", "BGMTable"),
        ("SpecialItemDB", "RelativeItemLabel", "ItemDB"),
        ("StaffCreditDB", "Style", "StaffCreditStyleDB"),
        ("SubStoryTask", "RelatedMainStoryTask", "MainStoryTask"),
        ("SubStoryTaskList", "LabelArray", "SubStoryTask"),
        ("SubTitleDB", "BeginMainStoryTaskLabel", "MainStoryTask"),
        ("SupportCharacterDB", "SessionAbility", "AbilityData"),
        ("SupportCharacterDB", "WeaponItemLabel", "ItemDB"),
        ("TownTable", "BattleFcAssistItem", "ItemDB"),
        ("TownTable", "HearFcAssistItem", "ItemDB"),
        ("TownTable", "HireFcAssistItem", "ItemDB"),
        ("TownTable", "LeadFcAssistItem", "ItemDB"),
        ("TownTable", "LureFcAssistItem", "ItemDB"),
        ("TownTable", "MonsterFcAssistItem", "ItemDB"),
        ("TownTable", "RobFcAssistItem", "ItemDB"),
        ("TownTable", "StealFcAssistItem", "ItemDB"),
        ("TutorialFlagPart", "PageDataLabel", "TutorialPageTable"),
        ("TutorialListTable", "FlagPartLabel", "TutorialFlagPart"),
        ("VoiceTable_en", "CueSheetName", "CueSheetTable"),
        ("VoiceTable_ja", "CueSheetName", "CueSheetTable"),
        ("WeaponMasterEventDB", "EventLabel", "EventList"),
        ("WorldMapDarkAreaEffectDB", "DarkAreaLabel", "DarkAreaDB"),
        ("WorldMapDarkAreaEffectDB", "WorldMapLabel", "WorldMapTable"),
        ("WorldMapIconDB", "IconTexLabel", "UIResourceDB_pc"),
        ("WorldMapTable", "DarkAreaLabel", "DarkAreaDB"),
        ("WorldMapTable", "EmblemLabel", "UIResourceDB_pc"),
    ]
    .into_iter()
    .map(|(source_table, field, target_table)| ReferenceRule {
        source_table,
        field,
        target_table,
    })
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data_table::DataTableIndex;
    use crate::ue_package::Ue4Package;
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
    /// asset to two tables and the check would compare the wrong row names.
    #[test]
    fn table_path_suffixes_are_unambiguous() {
        let paths: Vec<&str> = tables()
            .into_iter()
            .map(|table| table.path_suffix)
            .collect();
        for path in &paths {
            for other in &paths {
                assert!(
                    path == other || !path.ends_with(other),
                    "{path} also matches {other}"
                );
            }
        }
    }

    /// Every rule must resolve completely against untouched game data.
    ///
    /// This is the guard that makes the rule list safe to ship: a rule that is
    /// only usually right would report the remainder as broken references on
    /// data nobody has modified. Ignored by default because the cooked game
    /// files are not redistributable.
    ///
    /// ```text
    /// PAK_MERGER_OT2_PACKAGE_DIR=<cooked tree> \
    ///   cargo test --lib octopath_traveler_2 -- --ignored --nocapture
    /// ```
    #[test]
    #[ignore = "requires a local cooked OCTOPATH TRAVELER II tree"]
    fn every_rule_resolves_against_untouched_game_data() {
        let Ok(root) = std::env::var("PAK_MERGER_OT2_PACKAGE_DIR") else {
            panic!("set PAK_MERGER_OT2_PACKAGE_DIR to a cooked OCTOPATH TRAVELER II tree");
        };

        let wanted: BTreeMap<&str, &str> = tables()
            .into_iter()
            .map(|table| (table.path_suffix, table.name))
            .collect();
        let mut loaded: BTreeMap<&str, (Vec<u8>, Ue4Package, DataTableIndex)> = BTreeMap::new();
        let mut stack = vec![std::path::PathBuf::from(root)];
        while let Some(directory) = stack.pop() {
            for entry in std::fs::read_dir(&directory).expect("readable directory") {
                let path = entry.expect("readable entry").path();
                if path.is_dir() {
                    stack.push(path);
                    continue;
                }
                if path.extension().and_then(|value| value.to_str()) != Some("uasset") {
                    continue;
                }
                let stem = path
                    .with_extension("")
                    .to_string_lossy()
                    .replace('\\', "/")
                    .to_lowercase();
                let Some((suffix, name)) = wanted
                    .iter()
                    .find(|(suffix, _)| stem.ends_with(**suffix))
                    .map(|(suffix, name)| (*suffix, *name))
                else {
                    continue;
                };
                let uasset = std::fs::read(&path).expect("readable .uasset");
                let package = Ue4Package::parse(&uasset).expect("parsable package");
                let uexp = std::fs::read(path.with_extension("uexp")).expect("readable .uexp");
                let serial = usize::try_from(package.serial_size).expect("serial size");
                let body = uexp[..serial].to_vec();
                let index = DataTableIndex::parse(&body, &package).expect("parsable DataTable");
                assert!(
                    loaded.insert(name, (body, package, index)).is_none(),
                    "{suffix} matched two files"
                );
            }
        }

        let mut missing: Vec<&str> = Vec::new();
        let mut breaks: Vec<String> = Vec::new();
        let mut checked = 0_usize;
        for rule in rules() {
            let (Some(source), Some(target)) =
                (loaded.get(rule.source_table), loaded.get(rule.target_table))
            else {
                missing.push(rule.source_table);
                continue;
            };
            let known: BTreeSet<&str> = target.2.rows.iter().map(|row| row.name.as_ref()).collect();
            for row_index in 0..source.2.rows.len() {
                let layout = source
                    .2
                    .row_layout(&source.0, &source.1, row_index)
                    .expect("row layout");
                let Some(field) = layout.field(rule.field) else {
                    continue;
                };
                for value in field.referenced_names(&source.0, &source.1.names) {
                    checked += 1;
                    if !known.contains(value.as_str()) {
                        breaks.push(format!(
                            "{}.{} row {} -> {} {value}",
                            rule.source_table,
                            rule.field,
                            source.2.rows[row_index].name,
                            rule.target_table
                        ));
                    }
                }
            }
        }

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
        println!(
            "{checked} references resolved across {} rules",
            rules().len()
        );
    }
}
