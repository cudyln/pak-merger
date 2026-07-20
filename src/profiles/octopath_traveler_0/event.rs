use super::{audited_asset, suffix, whole};
use crate::profiles::AssetProfileRule;

pub(super) fn asset_rules() -> Vec<AssetProfileRule> {
    vec![audited_asset(
        "event_list",
        suffix("/local/database/event/eventlist"),
        vec![
            whole(
                "return_transition",
                &[
                    "m_ReturnMapID",
                    "m_ReturnPathActorName",
                    "m_ReturnPos",
                    "m_ReturnDir",
                ],
            ),
            whole(
                "map_transition_behavior",
                &[
                    "m_MapID",
                    "m_Kind",
                    "m_PlayBGM",
                    "m_MapLoadWait",
                    "m_Seamless",
                    "m_StartEnvVolumeZero",
                ],
            ),
        ],
    )]
}
