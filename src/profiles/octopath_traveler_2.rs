//! Built-in OCTOPATH TRAVELER II field-group rules.
//!
//! OT2 stores its databases as cooked UE4 `UDataTable` exports, so this profile
//! declares `Ue4DataTableV1` and its rules name UE4 properties rather than
//! MessagePack fields.
//!
//! Two things make OT2 rules look different from OT0's:
//!
//! * OT2 expresses "N related things" as one `ArrayProperty` of
//!   `StructProperty`, so the coupling is already intrinsic to the encoding.
//!   `parallel_array_items` — which models N *sibling* arrays indexed in
//!   lockstep — is therefore rarely the right tool here, and applying it to a
//!   single struct-array field would silently change the selection granularity.
//!   Groups below are whole-field groups over genuinely separate properties.
//! * `UserDefinedStruct` members are name-mangled as
//!   `<Name>_<index>_<32 hex GUID>`. That token is stable within one shipped
//!   build but is regenerated if the struct is re-saved in the editor, so these
//!   rules are pinned to a game version. Tables backed by a native struct — for
//!   example `AbilityData` — use plain names and are not version-brittle.
//!
//! There is deliberately no blanket "everything else" rule. OT0 can have one
//! because all its databases sit under a single `Local/DataBase/` root; OT2
//! spreads its 201 shipped DataTables across 51 different folders, and a
//! group-less game default behaves identically to the generic rules
//! (`is_strict_profile` is false for both), so enumerating those folders would
//! add maintenance surface for no behavioural gain. An unaudited OT2 table is
//! compared with the generic rules: simple values stay separable, compound
//! values stay whole.
//!
//! Not modelled here, deliberately: selecting *into* a struct or an array
//! element. `EnemyDB.Param` is one `StructProperty` holding HP/ATK/DEF and the
//! resist arrays are index-meaningful, so two mods editing different stats of
//! the same enemy will conflict as one whole-field unit. That is a documented
//! limitation rather than a silent one.

mod reference;

use super::{
    AssetProfile, AssetProfileRule, AtomicGroupRule, GameProfile, PathMatchKind, PathMatcher,
    ProfileFormat, ProfileOrigin, ProfilePrecision,
};

const AUDITED_PRIORITY: u16 = 100;

pub(super) fn game_profile() -> GameProfile {
    GameProfile {
        id: "octopath_traveler_2".to_owned(),
        display_name: "OCTOPATH TRAVELER II".to_owned(),
        format: ProfileFormat::Ue4DataTableV1,
        origin: ProfileOrigin::BuiltIn,
        detection_matchers: vec![
            matcher(
                PathMatchKind::Prefix,
                "/octopath_traveler2/content/battle/database/",
            ),
            matcher(PathMatchKind::Prefix, "/octopath_traveler2/content/"),
        ],
        minimum_detection_matches: 1,
        root_scope_matchers: vec![matcher(
            PathMatchKind::Prefix,
            "/octopath_traveler2/content/",
        )],
        assets: asset_rules(),
        reference_tables: reference::tables(),
        reference_rules: reference::rules(),
    }
}

fn asset_rules() -> Vec<AssetProfileRule> {
    vec![
        audited_asset(
            "enemy_group_data",
            "/battle/database/enemygroupdata",
            vec![
                // Battle music is one decision: which track, and whether the
                // battle, victory and resume behaviours use it.
                whole(
                    "battle_bgm",
                    &[
                        "BGMID_7_B47857404179EE90049AD8A2FCC54983",
                        "UseBattleBGM_44_F63B1CBE40C700E06FCF2AB83B85A37E",
                        "UseVictoryBGM_45_F4B15CC0414BE79A3DCEA6AEE16AE729",
                        "ResumeBGM_51_8AA71C014C38BF84FA39589539D2091A",
                    ],
                ),
                // The placement type describes the layout the enemy slots are
                // arranged into, so it cannot be chosen apart from them.
                whole(
                    "encounter_members",
                    &[
                        "EnemyID_37_DA234CE645A15970D15D82AA5102880C",
                        "PlacementType_14_0BECBBB0413FADBA41048FAB127C7CF6",
                    ],
                ),
                whole(
                    "encounter_voice",
                    &[
                        "VoiceID_8_88ABE9D14C8376A4464354B009EEE27D",
                        "PlayerVoiceID_60_93D85FE44B08FEC5471232A608853FBB",
                        "TalkPlayerID_59_120BD4E7412030C4A7451F94ADA561E6",
                    ],
                ),
            ],
        ),
        audited_asset(
            "enemy_db",
            "/character/database/enemydb",
            vec![
                whole(
                    "enemy_rewards",
                    &[
                        "Exp_46_CDF6F63E46FF9E07F64326AB4F40DF38",
                        "JobPoint_153_D5FBB9B64751E2916C22F098CF1ED0D6",
                        "Money_45_0D1763E0404AA80598B4B69F460861D1",
                    ],
                ),
                whole(
                    "enemy_drop",
                    &[
                        "HaveItemID_141_F51E74424D8CB057EE57E79ABB6535B0",
                        "DropProbability_142_E0E84476427EF904B1835A8E1392E402",
                    ],
                ),
                whole(
                    "enemy_steal",
                    &[
                        "StealItemID_301_CE0FDB3A4138AFC8BFF2ADB1E0E175C6",
                        "StealMoney_238_C35331A14C68B5E174DA5F86BED10FD9",
                        "StealGuard_296_148A86084818F42133C90C9D84C5E707",
                        "StealMoneyGuard_298_E478E53B4DA8F726470B708E9AB69222",
                    ],
                ),
                whole(
                    "enemy_bribe",
                    &[
                        "BribeGuard_312_564F274D4FA6ECBB36424A97AF2604D5",
                        "BribeMoney_314_655670884C00B51408F90F87D9251708",
                    ],
                ),
                // The reveal brain and the shield point it exposes are one
                // gameplay decision.
                whole(
                    "enemy_ai",
                    &[
                        "EnemyAI_321_C934EDCB46C8699CFAB4AD87D320D2DE",
                        "RevealEnemyAI_320_D486C76644E549BF05A58686E82CAA3E",
                        "RevealShieldPoint_318_33A2EAE54825316FAE75DD9F5F13CF15",
                    ],
                ),
                // A UV rectangle and the pixel scale that reads it are a pair.
                whole(
                    "enemy_icon_large",
                    &[
                        "IconL_UV_182_9B6F0DC9467B0EC6E2BF0EA2122480F8",
                        "PixelScaleL_191_5B47FD49499C355412E5208473C5275A",
                    ],
                ),
                whole(
                    "enemy_icon_small",
                    &[
                        "IconS_UV_183_96B9EBF74F9891A8C0235EAB8AB65C69",
                        "PixelScaleS_192_1D2C46134B3AAB93EC7A2496E512F134",
                    ],
                ),
            ],
        ),
        // AbilityData is backed by a native struct, so its property names are
        // plain and stable across builds.
        audited_asset(
            "ability_data",
            "/ability/database/abilitydata",
            vec![
                whole("ability_cost", &["CostType", "CostValue"]),
                whole(
                    "ability_hit_count",
                    &[
                        "BaseCount",
                        "MinimumCount",
                        "RandomCountMin",
                        "RandomCountMax",
                    ],
                ),
                whole("ability_critical", &["CriticalRatio", "CriticalPower"]),
                whole("ability_weapon_gate", &["DependWeapon", "RestrictWeapon"]),
                whole(
                    "ability_order_estimate",
                    &["EstimateOrderType", "EstimateOrderCount"],
                ),
            ],
        ),
        audited_asset(
            "ailment_data",
            "/ability/database/ailmentdata",
            vec![whole(
                "ailment_disease_application",
                &[
                    "DiseaseRatio_116_D9555040467E7BC7EDEA4999BDEB691A",
                    "AddDisease_105_48D7D93A4B672BF6B0204FA2F9145384",
                ],
            )],
        ),
    ]
}

fn matcher(kind: PathMatchKind, value: &str) -> PathMatcher {
    PathMatcher::builtin(kind, value)
}

fn audited_asset(id: &str, suffix: &str, groups: Vec<AtomicGroupRule>) -> AssetProfileRule {
    AssetProfileRule {
        matchers: vec![matcher(PathMatchKind::Suffix, suffix)],
        priority: AUDITED_PRIORITY,
        profile: AssetProfile {
            id: id.to_owned(),
            precision: ProfilePrecision::Audited,
            groups,
        },
    }
}

fn whole(id: &str, fields: &[&str]) -> AtomicGroupRule {
    AtomicGroupRule {
        id: id.to_owned(),
        fields: fields.iter().map(|field| (*field).to_owned()).collect(),
        force_compound: true,
        index_coupled: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profiles::{AssetProfileSelectionKind, ProfileDetectionStatus, ProfileRegistry};

    #[test]
    fn ot2_is_detected_and_scoped_without_colliding_with_ot0() {
        let registry = ProfileRegistry::with_builtins();

        // A real OT2 mod Pak mounts at ../../../Octopath_Traveler2/Content/,
        // so the inventory path carries the leading parent hops.
        let detection = registry.detect_inventory([
            "/../../../Octopath_Traveler2/Content/Battle/Database/EnemyGroupData",
        ]);
        assert_eq!(detection.status, ProfileDetectionStatus::Selected);
        assert_eq!(
            detection.selected_profile_id.as_deref(),
            Some("octopath_traveler_2")
        );

        // The two games' roots cannot claim each other's assets.
        let cross = registry.resolve_asset(
            "/Octopath_Traveler0/Content/Local/DataBase/Skill/SkillID.uasset",
            Some("octopath_traveler_2"),
        );
        assert_eq!(cross.selection, AssetProfileSelectionKind::GenericNoMatch);

        let ot0 = registry.detect_inventory([
            "/../../../Octopath_Traveler0/Content/Local/DataBase/Enemy/EnemyID",
        ]);
        assert_eq!(
            ot0.selected_profile_id.as_deref(),
            Some("octopath_traveler_0")
        );
    }

    #[test]
    fn ot2_declares_the_datatable_format_and_its_ue4_package_layout() {
        let profile = game_profile();
        assert_eq!(profile.format, ProfileFormat::Ue4DataTableV1);
        assert_eq!(profile.format.id(), "ue4_datatable_v1");
        assert_eq!(
            profile.format.row_identity(),
            crate::profiles::RowIdentity::Name
        );

        let shell = profile.format.package_shell();
        assert_eq!(shell.legacy_version, -7);
        assert_eq!(shell.version_zero_run_len, 16);
        assert_eq!(shell.import_entry_size, 28);
        assert_eq!(shell.expected_export_class, "DataTable");
        // Required bits, not equality: 11 shipped tables also set
        // PKG_RequiresLocalizationGather.
        assert_eq!(shell.package_flags_mask, 0x8000_0000);
        assert_eq!(
            0x8004_0000_u32 & shell.package_flags_mask,
            shell.package_flags_value
        );
        assert_eq!(
            shell.package_path_source,
            crate::profiles::PackagePathSource::ExportObjectName
        );
    }

    #[test]
    fn audited_tables_resolve_and_unknown_ones_take_the_game_default() {
        let registry = ProfileRegistry::with_builtins();
        for (path, expected) in [
            ("/Battle/Database/EnemyGroupData.uasset", "enemy_group_data"),
            ("/Character/Database/EnemyDB.uexp", "enemy_db"),
            ("/Ability/Database/AbilityData.uasset", "ability_data"),
            ("/Ability/Database/AilmentData.uasset", "ailment_data"),
        ] {
            let resolved = registry.resolve_asset(path, Some("octopath_traveler_2"));
            assert_eq!(
                resolved.profile.id, expected,
                "{path} resolved to {}",
                resolved.profile.id
            );
            assert_eq!(resolved.selection, AssetProfileSelectionKind::Explicit);
            assert_eq!(resolved.profile.precision, ProfilePrecision::Audited);
        }
    }

    #[test]
    fn an_unaudited_table_falls_back_to_the_generic_rules_on_purpose() {
        // There is no blanket game default for OT2; see the module comment.
        // The fallback must still be the safe one: no groups, non-strict.
        let registry = ProfileRegistry::with_builtins();
        let resolved =
            registry.resolve_asset("/Item/Database/ItemDB.uasset", Some("octopath_traveler_2"));
        assert_eq!(
            resolved.selection,
            AssetProfileSelectionKind::GenericNoMatch
        );
        assert_eq!(resolved.profile.precision, ProfilePrecision::Generic);
        assert!(resolved.profile.groups.is_empty());
    }

    #[test]
    fn every_grouped_field_name_is_a_real_ue4_property_shape() {
        // UserDefinedStruct members are mangled <Name>_<index>_<32 hex>; native
        // struct members are plain. Both must pass validation, and a typo in a
        // GUID is the most likely authoring mistake, so the shape is asserted.
        for rule in asset_rules() {
            for group in &rule.profile.groups {
                for field in &group.fields {
                    assert!(field.len() <= 96, "{field} is too long for a field name");
                    assert!(
                        field
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_'),
                        "{field} is not a UE4 property name"
                    );
                    if let Some((_, suffix)) = field.rsplit_once('_')
                        && suffix.len() == 32
                    {
                        assert!(
                            suffix.bytes().all(|byte| byte.is_ascii_hexdigit()),
                            "{field} has a malformed struct GUID suffix"
                        );
                    }
                }
            }
        }
    }
}
