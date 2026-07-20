use super::{default_asset, matcher};
use crate::profiles::{AssetProfileRule, PathMatchKind};

pub(super) fn asset_rule() -> AssetProfileRule {
    default_asset(
        "database_default",
        vec![matcher(PathMatchKind::Contains, "/local/database/")],
    )
}
