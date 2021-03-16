use textnonce::TextNonce;

use crate::ShopifyApp;

impl ShopifyApp {
    pub fn new_nonce() -> String {
        // Replaces + with - and / with _ to make it URL safe
        TextNonce::new()
            .into_string()
            .replace("+", "-")
            .replace("/", "_")
    }

    pub fn new_auth_uri(&self, shop: &str, return_uri: &str, nonce: &str) -> String {
        format!(
            "https://{shop}/admin/oauth/authorize?client_id={api_key}&scope={scopes}&redirect_uri={redirect_uri}&state={nonce}&grant_options[]={access_mode}",
            shop = shop,
            api_key = self.credentials.api_key,
            scopes=  self.scopes.join(","),
            redirect_uri = return_uri,
            nonce = nonce,
            access_mode = self.access_mode.as_string()
        )
    }
}
