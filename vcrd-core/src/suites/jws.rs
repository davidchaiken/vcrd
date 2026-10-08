//! The JWS proof suite (RFC 7515): checks the declared algorithm, binds it to the key
//! type, and calls the primitive (ARCHITECTURE §5, §8).
//!
//! Its algorithm table has one row in milestone 1: EdDSA over Ed25519 (RFC 8037 §3.1).

use curve25519_dalek::edwards::CompressedEdwardsY;

use crate::context::Context;
use crate::finding::{Attribution, Finding, FindingDetail};
use crate::keys::PublicKey;
use crate::registry::{ProofInput, ProofSuite, SuiteId};
use crate::report::{Phase, ProofOutcome};

/// The suite.
#[derive(Clone, Copy, Debug, Default)]
pub struct Jws;

const EDDSA: &str = "EdDSA";

/// The JWS extensions the suite implements, which `crit` may list (RFC 7515
/// §4.1.11). None yet.
const EXTENSIONS: &[&str] = &[];

impl ProofSuite for Jws {
    fn id(&self) -> SuiteId {
        super::JWS
    }

    fn algorithms(&self) -> &'static [&'static str] {
        &[EDDSA]
    }

    fn verify(&self, input: &ProofInput<'_>, _ctx: &Context) -> (ProofOutcome, Vec<Finding>) {
        let ProofInput::Jws {
            algorithm,
            signing_input,
            signature,
            critical,
            key,
        } = input;
        let mut findings = Vec::new();
        // The JWS is invalid (RFC 7515 §4.1.11), and the signature is still checked
        // below, for the information. RFC 7797's `b64: false` changes what was signed,
        // but it also leaves the payload unencoded, which parse rejects first.
        let unsupported: Vec<String> = critical
            .iter()
            .filter(|name| !EXTENSIONS.contains(&name.as_str()))
            .cloned()
            .collect();
        if !unsupported.is_empty() {
            findings.push(Finding::error(
                Phase::Verify,
                Attribution::Vcrd,
                FindingDetail::CritUnsupported {
                    extensions: unsupported,
                    supported: EXTENSIONS.to_vec(),
                },
            ));
        }
        // The declared algorithm is checked, never obeyed (ARCHITECTURE §8).
        let rejected = match *algorithm {
            None => Some((Attribution::Input, FindingDetail::AlgorithmMissing)),
            // Always rejected, never a policy question (ARCHITECTURE §8).
            Some("none") => Some((Attribution::Input, FindingDetail::AlgorithmNone)),
            Some(EDDSA) => None,
            Some(declared) => Some((
                Attribution::Vcrd,
                FindingDetail::AlgorithmUnsupported {
                    declared: declared.to_owned(),
                    supported: self.algorithms().to_vec(),
                },
            )),
        };
        if let Some((attribution, detail)) = rejected {
            findings.push(Finding::error(Phase::Verify, attribution, detail));
            return (ProofOutcome::NotAttempted, findings);
        }
        let (outcome, signature_findings) = eddsa(signing_input, signature, *key);
        findings.extend(signature_findings);
        (outcome, findings)
    }
}

fn not_attempted(attribution: Attribution, detail: FindingDetail) -> (ProofOutcome, Vec<Finding>) {
    (
        ProofOutcome::NotAttempted,
        vec![Finding::error(Phase::Verify, attribution, detail)],
    )
}

fn failed(detail: FindingDetail) -> (ProofOutcome, Vec<Finding>) {
    (
        ProofOutcome::Failed,
        vec![Finding::error(Phase::Verify, Attribution::Input, detail)],
    )
}

fn eddsa(
    signing_input: &[u8],
    signature: &[u8],
    key: Option<&PublicKey>,
) -> (ProofOutcome, Vec<Finding>) {
    let key = match key {
        // Key resolution has already reported why there is no key.
        None => return (ProofOutcome::NotAttempted, Vec::new()),
        Some(PublicKey::Ed25519(key)) => key,
    };
    let Ok(bytes) = <&[u8; 64]>::try_from(signature) else {
        return not_attempted(
            Attribution::Input,
            FindingDetail::SignatureLength {
                algorithm: EDDSA,
                expected: 64,
                found: signature.len(),
            },
        );
    };
    // verify_strict rejects a small-order R with the same error as any other
    // failure, so it is checked here first, to be named (ARCHITECTURE §8).
    let small_order = bytes
        .first_chunk::<32>()
        .and_then(|r| CompressedEdwardsY(*r).decompress())
        .is_some_and(|r| r.is_small_order());
    if small_order {
        return failed(FindingDetail::SignatureSmallOrder { algorithm: EDDSA });
    }
    // verify_strict also rejects a weak key, which resolution has already refused.
    match key.verify_strict(signing_input, &ed25519_dalek::Signature::from_bytes(bytes)) {
        Ok(()) => (ProofOutcome::Verified { disclosed: None }, Vec::new()),
        Err(_) => failed(FindingDetail::SignatureInvalid { algorithm: EDDSA }),
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use ed25519_dalek::VerifyingKey;
    use time::OffsetDateTime;

    use super::*;
    use crate::context::FixedClock;

    /// RFC 8037 appendix A.4 and A.5: its public key, signing input and signature.
    const X: &str = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";
    const SIGNING_INPUT: &str = "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc";
    const SIGNATURE: &str =
        "hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg";

    fn verify(algorithm: Option<&str>, signing_input: &[u8]) -> (ProofOutcome, Vec<Finding>) {
        verify_critical(algorithm, signing_input, &[])
    }

    fn verify_critical(
        algorithm: Option<&str>,
        signing_input: &[u8],
        critical: &[String],
    ) -> (ProofOutcome, Vec<Finding>) {
        let key: [u8; 32] = URL_SAFE_NO_PAD.decode(X).unwrap().try_into().unwrap();
        let key = PublicKey::Ed25519(VerifyingKey::from_bytes(&key).unwrap());
        let signature = URL_SAFE_NO_PAD.decode(SIGNATURE).unwrap();
        let input = ProofInput::Jws {
            algorithm,
            signing_input,
            signature: &signature,
            critical,
            key: Some(&key),
        };
        let ctx = Context::builder(FixedClock(OffsetDateTime::UNIX_EPOCH)).build();
        Jws.verify(&input, &ctx)
    }

    #[test]
    fn verifies_rfc8037_a5() {
        let (outcome, findings) = verify(Some("EdDSA"), SIGNING_INPUT.as_bytes());
        assert!(
            matches!(outcome, ProofOutcome::Verified { .. }),
            "{outcome:?} {findings:?}"
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn rejects_rfc8037_a5_with_one_byte_changed() {
        let mut signing_input = SIGNING_INPUT.as_bytes().to_vec();
        *signing_input.last_mut().unwrap() ^= 1;
        let (outcome, findings) = verify(Some("EdDSA"), &signing_input);
        assert!(matches!(outcome, ProofOutcome::Failed));
        assert_eq!(findings[0].code, "verify.signature_invalid");
    }

    #[test]
    fn names_an_unsupported_algorithm_and_what_is_supported() {
        let (outcome, findings) = verify(Some("ES256"), SIGNING_INPUT.as_bytes());
        assert!(matches!(outcome, ProofOutcome::NotAttempted));
        assert_eq!(findings[0].attribution, Attribution::Vcrd);
        let FindingDetail::AlgorithmUnsupported {
            declared,
            supported,
        } = &findings[0].detail
        else {
            panic!("{findings:?}")
        };
        assert_eq!(
            (declared.as_str(), supported.as_slice()),
            ("ES256", &["EdDSA"][..])
        );
    }

    /// RFC 8037 A.5's signature is sound, and is reported as verified beside the
    /// unimplemented critical extension, which alone fails the JWS.
    #[test]
    fn checks_the_signature_beside_an_unimplemented_critical_extension() {
        let critical = ["urn:example:unimplemented".to_owned()];
        let (outcome, findings) =
            verify_critical(Some("EdDSA"), SIGNING_INPUT.as_bytes(), &critical);
        assert!(
            matches!(outcome, ProofOutcome::Verified { .. }),
            "{outcome:?}"
        );
        let [finding] = findings.as_slice() else {
            panic!("{findings:?}")
        };
        assert_eq!(finding.code, "verify.crit_unsupported");
        assert_eq!(finding.attribution, Attribution::Vcrd);
    }

    /// Unsupported and rejected are reported independently (ARCHITECTURE §8).
    #[test]
    fn reports_an_unimplemented_extension_and_alg_none_together() {
        let critical = ["urn:example:unimplemented".to_owned()];
        let (_, findings) = verify_critical(Some("none"), SIGNING_INPUT.as_bytes(), &critical);
        let codes: Vec<_> = findings.iter().map(|f| f.code).collect();
        assert_eq!(codes, ["verify.crit_unsupported", "verify.algorithm_none"]);
    }
}
