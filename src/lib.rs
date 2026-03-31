use act_sdk::prelude::*;
use hmac::{Hmac, Mac};
use sha2::{Digest as _, Sha256, Sha512};
use sha3::Sha3_256;

act_sdk::embed_skill!("skill/");

#[act_component]
mod component {
    use super::*;

    /// Compute a cryptographic hash.
    #[act_tool(description = "Compute a cryptographic hash of a string", read_only)]
    fn hash(
        #[doc = "Input string to hash"] input: String,
        #[doc = "Algorithm: 'sha256' (default), 'sha512', 'sha3-256'"] algorithm: Option<String>,
    ) -> ActResult<String> {
        let hex_hash = match algorithm.as_deref().unwrap_or("sha256") {
            "sha256" => hex::encode(Sha256::digest(input.as_bytes())),
            "sha512" => hex::encode(Sha512::digest(input.as_bytes())),
            "sha3-256" | "sha3" => hex::encode(Sha3_256::digest(input.as_bytes())),
            other => {
                return Err(ActError::invalid_args(format!(
                    "Unknown algorithm: {other}. Use: sha256, sha512, sha3-256"
                )));
            }
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
        #[doc = "Algorithm: 'sha256' (default), 'sha512'"] algorithm: Option<String>,
    ) -> ActResult<String> {
        match algorithm.as_deref().unwrap_or("sha256") {
            "sha256" => {
                let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes())
                    .map_err(|e| ActError::internal(format!("HMAC error: {e}")))?;
                mac.update(message.as_bytes());
                Ok(hex::encode(mac.finalize().into_bytes()))
            }
            "sha512" => {
                let mut mac = Hmac::<Sha512>::new_from_slice(key.as_bytes())
                    .map_err(|e| ActError::internal(format!("HMAC error: {e}")))?;
                mac.update(message.as_bytes());
                Ok(hex::encode(mac.finalize().into_bytes()))
            }
            other => Err(ActError::invalid_args(format!(
                "Unknown algorithm: {other}. Use: sha256, sha512"
            ))),
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

        let header = decode_jwt_part(parts[0])?;
        let claims = decode_jwt_part(parts[1])?;

        Ok(serde_json::json!({
            "header": header,
            "claims": claims,
        })
        .to_string())
    }
}

fn decode_jwt_part(part: &str) -> ActResult<serde_json::Value> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(part)
        .map_err(|e| ActError::invalid_args(format!("Invalid base64 in JWT: {e}")))?;
    serde_json::from_slice(&bytes)
        .map_err(|e| ActError::invalid_args(format!("Invalid JSON in JWT: {e}")))
}
