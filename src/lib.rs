use act_sdk::prelude::*;
use hmac::{Hmac, KeyInit, Mac};
use md5::Md5;
use sha1::Sha1;
use sha2::{Digest as _, Sha256, Sha512};
use sha3::{Sha3_256, Sha3_512};

/// Hash algorithms supported by `hash`. Serialized as the lowercase name so the
/// tool's JSON Schema constrains `algorithm` to exactly these values.
#[derive(Deserialize, JsonSchema, Clone, Copy)]
#[serde(rename_all = "lowercase")]
enum HashAlgorithm {
    Md5,
    Sha1,
    Sha256,
    Sha512,
    #[serde(rename = "sha3-256", alias = "sha3")]
    Sha3_256,
    #[serde(rename = "sha3-512")]
    Sha3_512,
}

/// Hash algorithms supported by `hmac` (HMAC is defined over a SHA-2 digest).
#[derive(Deserialize, JsonSchema, Clone, Copy)]
#[serde(rename_all = "lowercase")]
enum HmacAlgorithm {
    Sha256,
    Sha512,
}

#[act_component]
mod component {
    use super::*;

    /// Compute a cryptographic hash.
    #[act_tool(description = "Compute a cryptographic hash of a string", read_only)]
    fn hash(
        #[doc = "Input string to hash"] input: String,
        #[doc = "Hash algorithm: md5, sha1, sha256 (default), sha512, sha3-256, sha3-512"]
        algorithm: Option<HashAlgorithm>,
    ) -> ActResult<String> {
        let bytes = input.as_bytes();
        let hex_hash = match algorithm.unwrap_or(HashAlgorithm::Sha256) {
            HashAlgorithm::Md5 => hex::encode(Md5::digest(bytes)),
            HashAlgorithm::Sha1 => hex::encode(Sha1::digest(bytes)),
            HashAlgorithm::Sha256 => hex::encode(Sha256::digest(bytes)),
            HashAlgorithm::Sha512 => hex::encode(Sha512::digest(bytes)),
            HashAlgorithm::Sha3_256 => hex::encode(Sha3_256::digest(bytes)),
            HashAlgorithm::Sha3_512 => hex::encode(Sha3_512::digest(bytes)),
        };
        Ok(hex_hash)
    }

    /// Compute an HMAC signature.
    #[act_tool(
        description = "Compute HMAC signature for message authentication",
        read_only
    )]
    fn hmac(
        #[doc = "Message to sign"] message: String,
        #[doc = "Secret key"] key: String,
        #[doc = "HMAC hash algorithm: sha256 (default), sha512"] algorithm: Option<HmacAlgorithm>,
    ) -> ActResult<String> {
        match algorithm.unwrap_or(HmacAlgorithm::Sha256) {
            HmacAlgorithm::Sha256 => {
                let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes())
                    .map_err(|e| ActError::internal(format!("HMAC error: {e}")))?;
                mac.update(message.as_bytes());
                Ok(hex::encode(mac.finalize().into_bytes()))
            }
            HmacAlgorithm::Sha512 => {
                let mut mac = Hmac::<Sha512>::new_from_slice(key.as_bytes())
                    .map_err(|e| ActError::internal(format!("HMAC error: {e}")))?;
                mac.update(message.as_bytes());
                Ok(hex::encode(mac.finalize().into_bytes()))
            }
        }
    }

    /// Decode a JWT token without verifying the signature.
    #[act_tool(
        description = "Decode a JWT token and return its header and claims (no signature verification)",
        read_only
    )]
    fn jwt_decode(#[doc = "JWT token string"] token: String) -> ActResult<String> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(ActError::invalid_args(
                "Invalid JWT: expected 3 dot-separated parts",
            ));
        }

        let Json(header) = decode_jwt_part(parts[0])?;
        let Json(claims) = decode_jwt_part(parts[1])?;

        Ok(serde_json::json!({
            "header": header,
            "claims": claims,
        })
        .to_string())
    }
}

fn decode_jwt_part(part: &str) -> ActResult<Json<serde_json::Value>> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(part)
        .map_err(|e| ActError::invalid_args(format!("Invalid base64 in JWT: {e}")))?;
    serde_json::from_slice(&bytes)
        .map_err(|e| ActError::invalid_args(format!("Invalid JSON in JWT: {e}")))
        .map(Json)
}
