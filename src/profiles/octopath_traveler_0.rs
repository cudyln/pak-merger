//! Built-in OCTOPATH TRAVELER 0 field-group rules.
//!
//! Only previously reviewed field relationships belong in the domain modules.
//! Other `Local/DataBase` assets use the conservative game-scoped default.

mod battle;
mod default;
mod enemy;
mod event;
mod game_text;
mod skill;

use super::{
    AssetProfile, AssetProfileRule, AtomicGroupRule, GameProfile, PathMatchKind, PathMatcher,
    ProfileFormat, ProfileOrigin, ProfilePrecision,
};

const AUDITED_PRIORITY: u16 = 100;
const DEFAULT_PRIORITY: u16 = 0;

pub(super) fn game_profile() -> GameProfile {
    let mut assets = Vec::new();
    assets.extend(battle::asset_rules());
    assets.extend(enemy::asset_rules());
    assets.extend(skill::asset_rules());
    assets.extend(event::asset_rules());
    assets.extend(game_text::asset_rules());
    assets.push(default::asset_rule());

    GameProfile {
        id: "octopath_traveler_0".to_owned(),
        display_name: "OCTOPATH TRAVELER 0".to_owned(),
        format: ProfileFormat::MessagePackMDataListV1,
        origin: ProfileOrigin::BuiltIn,
        detection_matchers: vec![
            matcher(
                PathMatchKind::Contains,
                "/octopath_traveler0/content/local/database/",
            ),
            matcher(PathMatchKind::Contains, "/octopath_traveler0/content/"),
        ],
        minimum_detection_matches: 1,
        root_scope_matchers: vec![matcher(
            PathMatchKind::Contains,
            "/octopath_traveler0/content/",
        )],
        assets,
    }
}

fn matcher(kind: PathMatchKind, value: &str) -> PathMatcher {
    PathMatcher::builtin(kind, value)
}

fn suffix(value: &str) -> Vec<PathMatcher> {
    vec![matcher(PathMatchKind::Suffix, value)]
}

fn audited_asset(
    id: &str,
    matchers: Vec<PathMatcher>,
    groups: Vec<AtomicGroupRule>,
) -> AssetProfileRule {
    AssetProfileRule {
        matchers,
        priority: AUDITED_PRIORITY,
        profile: AssetProfile {
            id: id.to_owned(),
            precision: ProfilePrecision::Audited,
            groups,
        },
    }
}

fn default_asset(id: &str, matchers: Vec<PathMatcher>) -> AssetProfileRule {
    AssetProfileRule {
        matchers,
        priority: DEFAULT_PRIORITY,
        profile: AssetProfile {
            id: id.to_owned(),
            precision: ProfilePrecision::GameDefault,
            groups: Vec::new(),
        },
    }
}

fn whole(id: &str, fields: &[&str]) -> AtomicGroupRule {
    group(id, fields, false)
}

fn indexed(id: &str, fields: &[&str]) -> AtomicGroupRule {
    group(id, fields, true)
}

fn group(id: &str, fields: &[&str], index_coupled: bool) -> AtomicGroupRule {
    AtomicGroupRule {
        id: id.to_owned(),
        fields: fields.iter().map(|field| (*field).to_owned()).collect(),
        force_compound: true,
        index_coupled,
    }
}

fn condition_parameters(index_coupled: bool) -> AtomicGroupRule {
    group(
        "condition_parameters",
        &[
            "m_Conditions",
            "m_Params",
            "m_AilmentTypes",
            "m_StatusTypes",
            "m_WeaponTypes",
            "m_MagicTypes",
            "m_Equipment",
        ],
        index_coupled,
    )
}
