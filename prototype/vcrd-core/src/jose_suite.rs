//! The JOSE proof suite. It receives a detached signing input and signature from the
//! format and knows nothing about credentials -- which is the seam holding.

use crate::context::Context;
use crate::format::{ProofInput, ProofSuite};
use crate::jws::{self, AlgDecision, AlgRejection, SignatureCheck};
use crate::model::*;

#[derive(Debug)]
pub struct JoseSuite;

impl ProofSuite for JoseSuite {
    fn id(&self) -> SuiteId {
        crate::jwt_vc::SUITE_ID
    }

    fn description(&self) -> &'static str {
        "JSON Web Signature (RFC 7515) over the compact serialization"
    }

    fn verify(&self, input: &ProofInput<'_>, ctx: &Context) -> (ProofOutcome, Vec<Finding>) {
        let mut findings = Vec::new();

        // Algorithm first: policy decides, the header is only checked.
        let alg = match jws::select_algorithm(input.declared_alg, &ctx.alg_policy) {
            AlgDecision::Use(a) => a,
            AlgDecision::Rejected(reasons) => {
                for r in reasons {
                    findings.push(match r {
                        AlgRejection::None => Finding::error(
                            "verify.alg_none",
                            Tier::Verify,
                            Blame::Input,
                            FindingDetail::AlgorithmNone,
                        ),
                        AlgRejection::Unsupported { declared, supported } => Finding::error(
                            "verify.alg_unsupported",
                            Tier::Verify,
                            Blame::Vcrd,
                            FindingDetail::AlgorithmUnsupported { declared, supported },
                        ),
                        AlgRejection::PolicyRejected { declared, allowed } => Finding::error(
                            "verify.alg_policy_rejected",
                            Tier::Verify,
                            Blame::Policy,
                            FindingDetail::AlgorithmPolicyRejected { declared, allowed },
                        ),
                    });
                }
                return (ProofOutcome::NotAttempted, findings);
            }
        };

        let Some(key) = input.key else {
            // The key resolver already explained why; do not invent a second reason.
            return (ProofOutcome::NotAttempted, findings);
        };

        match jws::verify_signature(alg, key, input.signing_input, input.signature) {
            SignatureCheck::Valid => (ProofOutcome::Verified { disclosed: None }, findings),
            SignatureCheck::Invalid => {
                findings.push(Finding::error(
                    "verify.signature_invalid",
                    Tier::Verify,
                    Blame::Input,
                    FindingDetail::SignatureInvalid { alg: alg.as_str().to_string() },
                ));
                (ProofOutcome::Failed, findings)
            }
            SignatureCheck::KeyTypeMismatch { key_kind, expects } => {
                findings.push(Finding::error(
                    "verify.alg_key_type_mismatch",
                    Tier::Verify,
                    Blame::Input,
                    FindingDetail::AlgorithmKeyTypeMismatch {
                        declared: alg.as_str().to_string(),
                        key_kind,
                        expects,
                    },
                ));
                (ProofOutcome::Failed, findings)
            }
        }
    }
}
