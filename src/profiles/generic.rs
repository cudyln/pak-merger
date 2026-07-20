use super::{AssetProfile, ProfilePrecision};

pub(super) fn asset_profile() -> AssetProfile {
    AssetProfile {
        id: "generic_binary_asset".to_owned(),
        precision: ProfilePrecision::Generic,
        groups: Vec::new(),
    }
}
