//! The JWS proof suite (RFC 7515): checks the declared algorithm, binds it to the key
//! type, and calls the primitive (ARCHITECTURE §5, §8).
//!
//! Its algorithm table has one row in milestone 1, EdDSA over Ed25519, under two names:
//! `Ed25519` (RFC 9864 §2.2) and `EdDSA` with an Ed25519 key (RFC 8037 §3.1).

use curve25519_dalek::Scalar;
use curve25519_dalek::edwards::CompressedEdwardsY;

use crate::context::Context;
use crate::document::DeclaredAlgorithm;
use crate::finding::{Attribution, Finding, FindingDetail, Severity};
use crate::keys::PublicKey;
use crate::registry::{ProofInput, ProofSuite, SuiteId};
use crate::report::{Phase, ProofOutcome};

/// The suite.
#[derive(Clone, Copy, Debug, Default)]
pub struct Jws;

const ED25519: &str = "Ed25519";
const EDDSA: &str = "EdDSA";

/// The JWS extensions the suite implements, which `crit` may list (RFC 7515
/// §4.1.11). None yet.
const EXTENSIONS: &[&str] = &[];

impl ProofSuite for Jws {
    fn id(&self) -> SuiteId {
        super::JWS
    }

    fn algorithms(&self) -> &'static [&'static str] {
        &[ED25519, EDDSA]
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
        let accepted = match algorithm {
            None => Err((Attribution::Input, FindingDetail::AlgorithmMissing)),
            Some(DeclaredAlgorithm::NotAName { found }) => Err((
                Attribution::Input,
                FindingDetail::AlgorithmInvalid { found },
            )),
            Some(DeclaredAlgorithm::Name(name)) => match name.as_str() {
                // Always rejected, never a policy question (ARCHITECTURE §8).
                "none" => Err((Attribution::Input, FindingDetail::AlgorithmNone)),
                ED25519 => Ok(ED25519),
                EDDSA => Ok(EDDSA),
                declared => Err((
                    Attribution::Vcrd,
                    FindingDetail::AlgorithmUnsupported {
                        declared: declared.to_owned(),
                        supported: self.algorithms().to_vec(),
                    },
                )),
            },
        };
        let algorithm = match accepted {
            Ok(algorithm) => algorithm,
            Err((attribution, detail)) => {
                findings.push(Finding::error(Phase::Verify, attribution, detail));
                return (ProofOutcome::NotAttempted, findings);
            }
        };
        if algorithm == EDDSA {
            // RFC 9864 replaces it with the name of the key's curve.
            let replacement = key.map(|PublicKey::Ed25519(_)| ED25519);
            findings.push(Finding::new(
                Phase::Verify,
                Attribution::Input,
                Severity::Info,
                FindingDetail::AlgorithmDeprecated {
                    declared: EDDSA,
                    replacement,
                },
            ));
        }
        let (outcome, signature_findings) = eddsa(algorithm, signing_input, signature, *key);
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

/// EdDSA over Ed25519, which `algorithm` names: `Ed25519` or `EdDSA`. The findings
/// name it as the credential declared it.
fn eddsa(
    algorithm: &'static str,
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
                algorithm,
                expected: 64,
                found: signature.len(),
            },
        );
    };
    // RFC 8032 §5.1.7 step 1. ed25519-dalek rejects such an S only while its
    // `legacy_compatibility` feature is off, which any crate in the same build can turn
    // on, so it is checked here (ARCHITECTURE §8).
    let s_in_range = bytes
        .last_chunk::<32>()
        .is_some_and(|s| bool::from(Scalar::from_canonical_bytes(*s).is_some()));
    if !s_in_range {
        return failed(FindingDetail::SignatureScalarOutOfRange { algorithm });
    }
    // verify_strict rejects a small-order R with the same error as any other
    // failure, so it is checked here first, to be named (ARCHITECTURE §8).
    let small_order = bytes
        .first_chunk::<32>()
        .and_then(|r| CompressedEdwardsY(*r).decompress())
        .is_some_and(|r| r.is_small_order());
    if small_order {
        return failed(FindingDetail::SignatureSmallOrder { algorithm });
    }
    // verify_strict also rejects a weak key, which resolution has already refused.
    match key.verify_strict(signing_input, &ed25519_dalek::Signature::from_bytes(bytes)) {
        Ok(()) => (ProofOutcome::Verified { disclosed: None }, Vec::new()),
        Err(_) => failed(FindingDetail::SignatureInvalid { algorithm }),
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
        let signature = URL_SAFE_NO_PAD.decode(SIGNATURE).unwrap();
        verify_signature(algorithm, signing_input, &signature, critical)
    }

    fn verify_signature(
        algorithm: Option<&str>,
        signing_input: &[u8],
        signature: &[u8],
        critical: &[String],
    ) -> (ProofOutcome, Vec<Finding>) {
        let key: [u8; 32] = URL_SAFE_NO_PAD.decode(X).unwrap().try_into().unwrap();
        let key = PublicKey::Ed25519(VerifyingKey::from_bytes(&key).unwrap());
        let algorithm = algorithm.map(|name| DeclaredAlgorithm::Name(name.to_owned()));
        let input = ProofInput::Jws {
            algorithm: algorithm.as_ref(),
            signing_input,
            signature,
            critical,
            key: Some(&key),
        };
        let ctx = Context::builder(FixedClock(OffsetDateTime::UNIX_EPOCH)).build();
        Jws.verify(&input, &ctx)
    }

    /// The declared algorithm reaches the suite apart from the signing input, so A.4's
    /// header, `{"alg":"EdDSA"}`, does not decide it here.
    #[test]
    fn verifies_rfc8037_a5_under_either_name() {
        let (outcome, findings) = verify(Some("Ed25519"), SIGNING_INPUT.as_bytes());
        assert!(
            matches!(outcome, ProofOutcome::Verified { .. }),
            "{outcome:?} {findings:?}"
        );
        assert!(findings.is_empty(), "{findings:?}");

        let (outcome, findings) = verify(Some("EdDSA"), SIGNING_INPUT.as_bytes());
        assert!(
            matches!(outcome, ProofOutcome::Verified { .. }),
            "{outcome:?} {findings:?}"
        );
        let [finding] = findings.as_slice() else {
            panic!("{findings:?}")
        };
        assert_eq!(
            (finding.code, finding.severity),
            ("verify.algorithm_deprecated", Severity::Info)
        );
    }

    #[test]
    fn rejects_rfc8037_a5_with_one_byte_changed() {
        let mut signing_input = SIGNING_INPUT.as_bytes().to_vec();
        *signing_input.last_mut().unwrap() ^= 1;
        let (outcome, findings) = verify(Some("Ed25519"), &signing_input);
        assert!(matches!(outcome, ProofOutcome::Failed));
        assert_eq!(findings[0].code, "verify.signature_invalid");
    }

    /// RFC 8032 §5.1.7 step 1 splits an Ed25519 signature into two 32-byte halves, so
    /// one of any other length is not checked. The finding names the algorithm as the
    /// header declared it.
    #[test]
    fn names_a_signature_of_the_wrong_length() {
        let mut signature = URL_SAFE_NO_PAD.decode(SIGNATURE).unwrap();
        signature.pop();
        let (outcome, findings) =
            verify_signature(Some("Ed25519"), SIGNING_INPUT.as_bytes(), &signature, &[]);
        assert!(matches!(outcome, ProofOutcome::NotAttempted), "{outcome:?}");
        let [finding] = findings.as_slice() else {
            panic!("{findings:?}")
        };
        assert!(
            matches!(
                finding.detail,
                FindingDetail::SignatureLength {
                    algorithm: "Ed25519",
                    expected: 64,
                    found: 63
                }
            ),
            "{finding:?}"
        );
    }

    /// L, the order of the Ed25519 base point (RFC 8032 §5.1), little-endian.
    const L: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
    ];

    /// RFC 8032 §5.1.7 step 1: S must be less than L. A.5's signature with L added to S
    /// satisfies the group equation, as it did before, so only the range rejects it.
    #[test]
    fn names_an_s_not_less_than_the_group_order() {
        // L is the order: not a reduced scalar, and 0 when reduced.
        assert!(bool::from(Scalar::from_canonical_bytes(L).is_none()));
        assert_eq!(Scalar::from_bytes_mod_order(L), Scalar::ZERO);
        let mut signature = URL_SAFE_NO_PAD.decode(SIGNATURE).unwrap();
        let mut carry = 0;
        for (byte, l) in signature[32..].iter_mut().zip(L) {
            let [low, high] = (u16::from(*byte) + u16::from(l) + carry).to_le_bytes();
            *byte = low;
            carry = u16::from(high);
        }
        assert_eq!(carry, 0);
        let (outcome, findings) =
            verify_signature(Some("Ed25519"), SIGNING_INPUT.as_bytes(), &signature, &[]);
        assert!(matches!(outcome, ProofOutcome::Failed), "{outcome:?}");
        let codes: Vec<_> = findings.iter().map(|f| f.code).collect();
        assert_eq!(codes, ["verify.signature_scalar_out_of_range"]);
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
            ("ES256", &["Ed25519", "EdDSA"][..])
        );
    }

    /// RFC 8037 A.5's signature is sound, and is reported as verified beside the
    /// unimplemented critical extension, which alone fails the JWS.
    #[test]
    fn checks_the_signature_beside_an_unimplemented_critical_extension() {
        let critical = ["urn:example:unimplemented".to_owned()];
        let (outcome, findings) =
            verify_critical(Some("Ed25519"), SIGNING_INPUT.as_bytes(), &critical);
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
