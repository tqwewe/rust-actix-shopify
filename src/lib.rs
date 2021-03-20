mod auth_uri;
mod valid_hmac;
mod valid_shop_uri;

#[derive(Debug)]
pub enum Error {
    InvalidHmac,
    InvalidShopUri,
    InvalidNonce,
    ShopNotFound,
}

#[derive(Clone)]
pub struct Credentials {
    pub api_key: String,
    pub secret: String,
}

impl Credentials {
    pub fn new(api_key: String, secret: String) -> Self {
        Credentials {
            api_key: api_key,
            secret: secret,
        }
    }
}

#[derive(Clone, Copy)]
pub enum AccessMode {
    Offline,
    Online,
}

impl AccessMode {
    pub fn as_string(&self) -> &'static str {
        match self {
            AccessMode::Offline => "offline",
            AccessMode::Online => "online",
        }
    }
}

#[derive(Clone)]
pub struct ShopifyApp {
    pub access_mode: AccessMode,
    pub auth_callback_uri: String,
    pub credentials: Credentials,
    pub host: String,
    pub scopes: Vec<&'static str>,
}

impl ShopifyApp {
    pub fn validate_auth(
        &self,
        query_params: &Vec<(String, String)>,
        validate_hmac: bool,
    ) -> Result<(String, String), Error> {
        if validate_hmac && !self.valid_hmac(query_params) {
            return Err(Error::InvalidHmac);
        }

        let shop = match query_params
            .into_iter()
            .find(|(key, _)| "shop".to_string() == *key)
            .map(|(_, val)| val)
        {
            Some(shop) => shop,
            None => return Err(Error::ShopNotFound),
        };

        let nonce = ShopifyApp::new_nonce();

        let redirect_uri = self.new_auth_uri(
            &shop,
            &format!(
                "{host}{auth_callback_uri}",
                host = self.host,
                auth_callback_uri = self.auth_callback_uri
            ),
            &nonce,
        );

        Ok((redirect_uri, nonce))
    }

    pub fn validate_auth_callback(
        &self,
        nonce: &str,
        query_params: &Vec<(String, String)>,
    ) -> Result<(), Error> {
        if !self.valid_hmac(query_params) {
            return Err(Error::InvalidHmac);
        }

        let shop = match query_params
            .into_iter()
            .find(|(key, _)| "shop".to_string() == *key)
            .map(|(_, val)| val)
        {
            Some(shop) => shop,
            None => return Err(Error::ShopNotFound),
        };

        if !ShopifyApp::valid_shop_uri(shop) {
            return Err(Error::InvalidShopUri);
        }

        let req_nonce = match query_params
            .into_iter()
            .find(|(key, _)| "state".to_string() == *key)
            .map(|(_, val)| val)
        {
            Some(shop) => shop,
            None => return Err(Error::ShopNotFound),
        };

        if req_nonce != nonce {
            return Err(Error::InvalidNonce);
        }

        Ok(())
    }
}
