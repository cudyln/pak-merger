use super::{audited_asset, indexed, matcher, whole};
use crate::profiles::{AssetProfileRule, PathMatchKind};

/// A dialogue row holds five choice slots as *sibling scalars*, not as parallel
/// arrays, so nothing in the generic rules keeps a slot together.
///
/// FAILURE SCENARIO this prevents: two mods each add a choice in slot 3. Without
/// a rule, field-level merging can take `m_ChoiceText3` from one and
/// `m_ConnectTalkNo3` from the other, producing a menu entry that shows one
/// mod's label and launches the other mod's event, with no conflict reported.
pub(super) fn asset_rules() -> Vec<AssetProfileRule> {
    let mut groups = Vec::new();
    for slot in 1..=5 {
        groups.push(whole(
            &format!("talk_choice_slot_{slot}"),
            &[
                &format!("m_ChoiceText{slot}"),
                &format!("m_InfluenceValue{slot}"),
                &format!("m_ConnectTalkNo{slot}"),
            ]
            .map(String::as_str),
        ));
    }
    // A cancel index and a forced destination only mean anything relative to
    // the slot set they point into.
    groups.push(whole(
        "talk_choice_routing",
        &["m_CancelChoice", "m_ForceTalkNo"],
    ));
    groups.push(indexed(
        "talk_condition_slots",
        &["m_TrigConditionID", "m_NoneConditionID"],
    ));

    vec![audited_asset(
        "npc_talk_list",
        vec![matcher(
            PathMatchKind::Contains,
            "/local/database/npc/npctalklist",
        )],
        groups,
    )]
}
