//! Comparison probe for prototype question 5: can an off-the-shelf JOSE crate express
//! the states §10 requires?
//!
//! Three states have to be distinguishable by a caller:
//!   (a) verified
//!   (b) vcrd does not support that algorithm -- and it must say which, by name
//!   (c) the caller's allowlist forbids that algorithm -- a different answer from (b)
//! Plus one property: the algorithm must come from caller policy, never from the
//! attacker-supplied header.
//!
//! Built only with `--features josekit-probe`. Nothing here ships.

use serde_json::Value;

#[derive(Debug, PartialEq, Eq)]
pub enum ProbeOutcome {
    Verified,
    /// josekit could not verify. The interesting question is how much this says.
    Rejected { error_type: &'static str, message: String },
    /// The caller's allowlist stopped us before josekit was reached.
    PolicyRejectedByCallerCode { declared: String },
    /// We had to read the header ourselves before choosing a verifier.
    UnsupportedByCallerCode { declared: String },
}

/// Verify with josekit, under an explicit caller allowlist.
///
/// The shape of this function is the finding: the allowlist check and the
/// unsupported-algorithm check both have to happen in *our* code, before josekit is
/// called, because josekit's verifier is selected per-algorithm by the caller and its
/// error type does not distinguish the two cases.
pub fn verify(token: &str, jwk: &Value, allowed: &[String]) -> ProbeOutcome {
    use josekit::jws::{ES256, ES384, ES512, EdDSA, HS256, JwsVerifier, RS256};

    // Step 1: read `alg` out of the header ourselves. josekit will happily hand us a
    // header-driven verifier via `deserialize_compact_with_selector`, which is the
    // pattern that lets attacker input steer algorithm choice -- so it is not used.
    let header = match josekit::jwt::decode_header(token) {
        Ok(h) => h,
        Err(e) => return ProbeOutcome::Rejected { error_type: "decode_header", message: e.to_string() },
    };
    // FINDING: `decode_header` returns `Box<dyn JoseHeader>`, which has no typed
    // `alg` accessor -- the algorithm comes back as an untyped JSON claim.
    let declared = header
        .claim("alg")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();

    // Step 2: our own allowlist gate. josekit has no concept of one.
    if !allowed.is_empty() && !allowed.iter().any(|a| *a == declared) {
        return ProbeOutcome::PolicyRejectedByCallerCode { declared };
    }

    // Step 3: our own supported-set gate, because a josekit verifier is chosen by
    // naming a concrete algorithm constant -- there is no "look it up" that reports
    // an unknown name distinguishably.
    let jwk_josekit = match josekit::jwk::Jwk::from_bytes(&serde_json::to_vec(jwk).unwrap_or_default()) {
        Ok(k) => k,
        Err(e) => return ProbeOutcome::Rejected { error_type: "jwk", message: e.to_string() },
    };

    let verifier: Box<dyn JwsVerifier> = match declared.as_str() {
        "EdDSA" => match EdDSA.verifier_from_jwk(&jwk_josekit) {
            Ok(v) => Box::new(v),
            Err(e) => return ProbeOutcome::Rejected { error_type: "verifier", message: e.to_string() },
        },
        "ES256" => match ES256.verifier_from_jwk(&jwk_josekit) {
            Ok(v) => Box::new(v),
            Err(e) => return ProbeOutcome::Rejected { error_type: "verifier", message: e.to_string() },
        },
        "ES384" => match ES384.verifier_from_jwk(&jwk_josekit) {
            Ok(v) => Box::new(v),
            Err(e) => return ProbeOutcome::Rejected { error_type: "verifier", message: e.to_string() },
        },
        "ES512" => match ES512.verifier_from_jwk(&jwk_josekit) {
            Ok(v) => Box::new(v),
            Err(e) => return ProbeOutcome::Rejected { error_type: "verifier", message: e.to_string() },
        },
        "RS256" => match RS256.verifier_from_jwk(&jwk_josekit) {
            Ok(v) => Box::new(v),
            Err(e) => return ProbeOutcome::Rejected { error_type: "verifier", message: e.to_string() },
        },
        "HS256" => match HS256.verifier_from_jwk(&jwk_josekit) {
            Ok(v) => Box::new(v),
            Err(e) => return ProbeOutcome::Rejected { error_type: "verifier", message: e.to_string() },
        },
        _ => return ProbeOutcome::UnsupportedByCallerCode { declared },
    };

    match josekit::jwt::decode_with_verifier(token, verifier.as_ref()) {
        Ok(_) => ProbeOutcome::Verified,
        Err(e) => ProbeOutcome::Rejected { error_type: "decode_with_verifier", message: e.to_string() },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn read(name: &str) -> String {
        std::fs::read_to_string(format!("../fixtures/{name}")).unwrap_or_default().trim().to_string()
    }

    /// Does josekit distinguish "unsupported algorithm" from "signature is wrong"?
    #[test]
    fn josekit_error_granularity() {
        let jwk = json!({"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"});

        let unsupported = verify(&read("unsupported-alg.jwt"), &jwk, &[]);
        println!("unsupported-alg -> {unsupported:?}");
        assert!(matches!(unsupported, ProbeOutcome::UnsupportedByCallerCode { .. }));

        let policy = verify(&read("happy-es256.jwt"), &jwk, &["EdDSA".to_string()]);
        println!("allowlist       -> {policy:?}");
        assert!(matches!(policy, ProbeOutcome::PolicyRejectedByCallerCode { .. }));

        let tampered = verify(&read("tampered.jwt"), &jwk, &[]);
        println!("tampered        -> {tampered:?}");

        let none = verify(&read("alg-none.jwt"), &jwk, &[]);
        println!("alg:none        -> {none:?}");
    }

    /// Does josekit reach ES512/P-521 at all -- the EUDI case from §10?
    #[test]
    fn josekit_es512_coverage() {
        let out = verify(&read("happy-es512.jwt"), &json!({"kty":"EC","crv":"P-521","x":"","y":""}), &[]);
        println!("es512 with a bogus key -> {out:?}");
        // The point is only that ES512 is a name josekit knows, not that this verifies.
        assert!(!matches!(out, ProbeOutcome::UnsupportedByCallerCode { .. }));
    }
}
