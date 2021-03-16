use once_cell::sync::Lazy;
use regex::Regex;

use crate::ShopifyApp;

static SHOP_EXP: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[a-zA-Z0-9][a-zA-Z0-9\-]*\.myshopify\.com$").unwrap());

impl ShopifyApp {
    pub fn valid_shop_uri(shop: &str) -> bool {
        SHOP_EXP.is_match(shop)
    }
}
