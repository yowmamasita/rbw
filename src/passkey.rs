//! Signing in with a passkey stored in the vault (`WebAuthn` get, ES256 only).
//!
//! Matches what the official Bitwarden clients send for passkeys they store:
//! flags user present + verified + backup eligible + backed up, and a
//! signature counter of 0. A passkey whose stored counter is above 0 is
//! refused: the official clients increment and save that counter, and
//! sending 0 for it would look like a cloned authenticator to the site.

use base64::Engine as _;
use p256::ecdsa::signature::Signer as _;
use p256::pkcs8::DecodePrivateKey as _;
use sha2::Digest as _;

// user present | user verified | backup eligible | backed up
const FLAGS: u8 = 0x1d;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Invalid(String),
}

fn invalid(msg: impl Into<String>) -> Error {
    Error::Invalid(msg.into())
}

// Accepts base64url or standard base64, padded or not.
fn decode_b64(s: &str) -> Result<Vec<u8>, Error> {
    let s: String = s
        .trim_end_matches('=')
        .chars()
        .map(|c| match c {
            '+' => '-',
            '/' => '_',
            c => c,
        })
        .collect();
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|e| invalid(format!("invalid base64: {e}")))
}

/// Official clients give passkeys they create a GUID id, imported ones
/// `b64.` + base64url.
fn credential_id_bytes(id: &str) -> Result<Vec<u8>, Error> {
    if let Some(b64) = id.strip_prefix("b64.") {
        return decode_b64(b64);
    }
    let hex: String = id.chars().filter(|c| *c != '-').collect();
    if hex.len() % 2 != 0 {
        return Err(invalid("invalid credential id"));
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
        .collect::<Result<_, _>>()
        .map_err(|_| invalid("invalid credential id"))
}

/// The host of an https origin (or `http://localhost`), which must be the
/// passkey's rpId or a subdomain of it.
fn check_origin(origin: &str, rp_id: &str) -> Result<(), Error> {
    let (scheme, rest) = origin.split_once("://").ok_or_else(|| {
        invalid("origin must look like https://example.com")
    })?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let host = authority
        .rsplit_once(':')
        .map_or(authority, |(host, _port)| host)
        .to_ascii_lowercase();
    let rp_id = rp_id.to_ascii_lowercase();
    let secure =
        scheme == "https" || (scheme == "http" && host == "localhost");
    if !secure {
        return Err(invalid("origin must be https"));
    }
    if host != rp_id && !host.ends_with(&format!(".{rp_id}")) {
        return Err(invalid(format!(
            "origin {origin} does not belong to the passkey's site {rp_id}"
        )));
    }
    Ok(())
}

pub struct Passkey<'a> {
    pub rp_id: &'a str,
    pub credential_id: &'a str,
    pub key_value: &'a str,
    pub user_handle: Option<&'a str>,
    pub counter: Option<&'a str>,
}

/// Returns the `PublicKeyCredential` JSON a page expects from
/// `navigator.credentials.get()`, binary values as base64url.
pub fn get_assertion(
    passkey: &Passkey,
    origin: &str,
    challenge: &str,
) -> Result<serde_json::Value, Error> {
    let counter = passkey.counter.unwrap_or("0").trim();
    if counter.parse::<u64>().unwrap_or(1) != 0 {
        return Err(invalid(format!(
            "passkey uses a signature counter ({counter}); sign in with an \
             official Bitwarden client so the counter is saved"
        )));
    }
    check_origin(origin, passkey.rp_id)?;
    decode_b64(challenge)
        .map_err(|_| invalid("challenge must be base64url"))?;

    let key = p256::ecdsa::SigningKey::from_pkcs8_der(&decode_b64(
        passkey.key_value,
    )?)
    .map_err(|e| {
        invalid(format!("unsupported passkey key (ES256 only): {e}"))
    })?;

    let mut auth_data =
        sha2::Sha256::digest(passkey.rp_id.as_bytes()).to_vec();
    auth_data.extend_from_slice(&[FLAGS, 0, 0, 0, 0]);
    let client_data = serde_json::json!({
        "type": "webauthn.get",
        "challenge": challenge,
        "origin": origin,
        "crossOrigin": false,
    })
    .to_string();
    let mut signed = auth_data.clone();
    signed.extend_from_slice(&sha2::Sha256::digest(client_data.as_bytes()));
    let signature: p256::ecdsa::Signature = key.sign(&signed);

    let b64u = |bytes: &[u8]| crate::base64::encode_url_safe_no_pad(bytes);
    let id = b64u(&credential_id_bytes(passkey.credential_id)?);
    let user_handle = passkey
        .user_handle
        .map(decode_b64)
        .transpose()?
        .map(|bytes| b64u(&bytes));
    Ok(serde_json::json!({
        "id": id,
        "rawId": id,
        "type": "public-key",
        "authenticatorAttachment": "platform",
        "clientExtensionResults": {},
        "response": {
            "clientDataJSON": b64u(client_data.as_bytes()),
            "authenticatorData": b64u(&auth_data),
            "signature": b64u(signature.to_der().as_bytes()),
            "userHandle": user_handle,
        },
    }))
}

#[cfg(test)]
mod test {
    use super::*;
    use p256::ecdsa::signature::Verifier as _;
    use p256::pkcs8::EncodePrivateKey as _;

    fn passkey_with<'a>(
        key: &'a str,
        counter: Option<&'a str>,
    ) -> Passkey<'a> {
        Passkey {
            rp_id: "webauthn.io",
            credential_id: "0b0a9f3c-7d0e-4a7e-9a35-6a0f1b2c3d4e",
            key_value: key,
            user_handle: Some("dXNlcg"),
            counter,
        }
    }

    #[test]
    fn signs_a_verifiable_assertion() {
        let key = p256::ecdsa::SigningKey::random(&mut rand_8::rngs::OsRng);
        let pkcs8 = crate::base64::encode_url_safe_no_pad(
            key.to_pkcs8_der().unwrap().as_bytes(),
        );
        let out = get_assertion(
            &passkey_with(&pkcs8, Some("0")),
            "https://webauthn.io",
            "Y2hhbGxlbmdl",
        )
        .unwrap();
        let r = &out["response"];
        let get = |k: &str| decode_b64(r[k].as_str().unwrap()).unwrap();
        let (auth, cd, sig) = (
            get("authenticatorData"),
            get("clientDataJSON"),
            get("signature"),
        );

        assert_eq!(
            &auth[..32],
            sha2::Sha256::digest(b"webauthn.io").as_slice()
        );
        assert_eq!(&auth[32..], &[FLAGS, 0, 0, 0, 0]);
        let cd_json: serde_json::Value = serde_json::from_slice(&cd).unwrap();
        assert_eq!(cd_json["type"], "webauthn.get");
        assert_eq!(cd_json["challenge"], "Y2hhbGxlbmdl");
        assert_eq!(cd_json["origin"], "https://webauthn.io");
        assert_eq!(out["id"], "CwqfPH0OSn6aNWoPGyw9Tg");
        assert_eq!(r["userHandle"], "dXNlcg");

        let mut signed = auth;
        signed.extend_from_slice(&sha2::Sha256::digest(&cd));
        let sig = p256::ecdsa::Signature::from_der(&sig).unwrap();
        key.verifying_key().verify(&signed, &sig).unwrap();
    }

    #[test]
    fn refuses_wrong_origin_and_counters() {
        let key = p256::ecdsa::SigningKey::random(&mut rand_8::rngs::OsRng);
        let pkcs8 = crate::base64::encode_url_safe_no_pad(
            key.to_pkcs8_der().unwrap().as_bytes(),
        );
        let ok = passkey_with(&pkcs8, None);
        for origin in [
            "https://evil.com",
            "https://webauthn.io.evil.com",
            "http://webauthn.io",
            "webauthn.io",
        ] {
            assert!(get_assertion(&ok, origin, "YQ").is_err(), "{origin}");
        }
        assert!(
            get_assertion(&ok, "https://www.webauthn.io:443/x", "YQ").is_ok()
        );
        assert!(get_assertion(
            &passkey_with(&pkcs8, Some("5")),
            "https://webauthn.io",
            "YQ"
        )
        .is_err());
    }

    #[test]
    fn credential_ids() {
        assert_eq!(credential_id_bytes("b64.AQID").unwrap(), vec![1, 2, 3]);
        assert_eq!(credential_id_bytes("0102-03").unwrap(), vec![1, 2, 3]);
        assert!(credential_id_bytes("xyz").is_err());
    }
}
