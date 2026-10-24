# Milestone 1 review

**Scope.** [DEVELOPMENT-PLAN.md], milestone 1: the implementation reviewed against the
normative text of each standard it implements, as its milestone review lists them. The
review runs in rounds, one or two standards at a time, and this record grows with each:

| Round | Texts | State |
|---|---|---|
| 1 | [RFC 7515] (JSON Web Signature, JWS); [RFC 7519] (JSON Web Token, JWT) | below; gaps 1 and 2 fixed, gap 3 deferred |
| 2 | [RFC 8037], [RFC 9864] and [RFC 8032] (EdDSA); key resolution ([did:key], [REQUIREMENTS] §10, [ARCHITECTURE] §8) | below; gaps 4–10 fixed |
| 3 | [VC-JOSE-COSE], the Recommendation of 2026-10-13, which is later than the text milestone 1 was built from (read 2026-09-19) | below; gaps 11–14 fixed |
| 4 | [VCDM 2.0] (the Verifiable Credentials Data Model) | below; gaps 15–17 and 19 fixed, gap 18 recorded as [ARCHITECTURE] §10 [Q7] |
| 5 | the terminology check ([REQUIREMENTS] §15); slices 3–5's red-then-green records | to do |

Each round also completes the entries of [docs/findings.md](../findings.md) whose
standard it reads.

**Where checked.** Branch `milestone-1`: round 1 from `94ff6d0`, round 2 from `46a2ca7`,
round 3 from `30d1f91`, round 4 from `dda3a15`.
Toolchain 1.99.1 (clippy 0.1.99). Locally on macOS 27.0.1, arm64. Line numbers are those
after each round's changes, except in [Gaps found](#gaps-found), which describes the
commit the round started from.

**Texts.** Fetched on 2026-10-22 from rfc-editor.org, as plain text: [RFC 7515] and
[RFC 7519]. Fetched on 2026-10-23: [RFC 8032], [RFC 8037] and [RFC 9864] from
rfc-editor.org, as plain text; [did:key] v0.9, a W3C Credentials Community Group draft
whose page shows no status, date or dated copy; and the [multicodec table]. Fetched on
2026-10-23 from w3.org: [VC-JOSE-COSE], whose status line reads "W3C Recommendation 13
October 2026", §1.1 to §5.4; and [VCDM 2.0], whose status line reads "W3C
Recommendation, 15 May 2025", §1.3, §2, §4.3–4.12, §6.1, §7.1, §7.2 and §11.1. They came
through a fetch tool's extraction, not a direct reading. Each row abridges one sentence,
or one procedural step, and keeps its keyword. For [RFC 8032], round 2 also read the
source of the crates vcrd verifies with, `ed25519-dalek` 3.0.0 and `curve25519-dalek`
5.0.0, as `cargo` downloaded them; `cargo tree -e features` shows `ed25519-dalek` built
with its features `default`, `fast` and `zeroize`.

**Reproduce.** `make ci-ok` and `make test-powerset` run every check named below. A test
is named by its file and function, and runs alone with
`cargo test -p <crate> --test <file> <function>`.

**Status key.** *Met*: implemented, with the check that shows it; "gap N, fixed" when
this review found it missing and it was fixed here. *Deviates*: vcrd departs from the
sentence on purpose, as the cited decision records. *Later*: deferred, to the milestone
or [ARCHITECTURE] §10 item named. *Round N*: a later round reviews it, under its own
standard. *Not applicable*: the sentence binds only producers, or concerns something vcrd
never does; the row says which.

## [RFC 7515], JWS

| Section | Keyword | Sentence (abridged) | Mechanism | Check | Status |
|---|---|---|---|---|---|
| §4 | MUST | Header Parameter names are unique; a recipient rejects a repeated name, or keeps the lexically last. | `Json::parse` keeps the last value and `Json::duplicate_names` lists each repeated name (`vcrd-core/src/json.rs:33`, `:79`); `duplicates` reports each as `inspect.duplicate_name` (`vc_jose.rs:146`). Verify still runs (decided 2026-09-24). | `json.rs` `keeps_duplicate_members_and_returns_the_last`, `lists_each_repeated_name_once_with_its_path_and_count`; `vcrd-core/tests/inspect.rs` `reports_each_duplicate_member_name` | Met |
| §4 | MUST | A Header Parameter that is not understood is ignored, unless `crit` lists it. | `JoseHeader::new` reads `alg`, `kid`, `typ`, `cty` and `jwk` (`vc_jose.rs:63-77`), and `crit` and `iss` are read where they are checked; nothing else is acted on. Every member appears in `format.header`. | By inspection | Met |
| §4.1.1–4.1.10 | — | Each registered Header Parameter's value has the type its section gives: a string, or for `x5c` an array of strings. | `header_members` checks each against `TYPED_HEADER_PARAMETERS` (`vc_jose.rs:159`, `:241`) and reports `inspect.header_member_type`, with the member, the type expected and the type found. `jwk` and `crit` have their own checks. | `vcrd-cli/tests/verify.rs` `a_header_member_of_the_wrong_type_is_reported`; `vcrd-core/tests/inspect.rs` `checks_that_x5c_is_an_array_of_strings` | Met: gap 1, fixed |
| §4.1.1 | MUST | `alg` is present, and a recipient understands and processes it. | The suite rejects an absent `alg` (`verify.algorithm_missing`), one that is not a string (`verify.algorithm_invalid`), `none`, and every name it does not implement (`verify.algorithm_unsupported`) (`suites/jws.rs:65-91`). | `vcrd-core/tests/verify.rs` `a_header_without_alg_is_not_verified` (new; see [checks shown to fail](#the-checks-shown-to-fail)); `vcrd-cli/tests/verify.rs` `a_header_member_of_the_wrong_type_is_reported`, `alg_none_is_rejected`, `an_algorithm_vcrd_does_not_implement_is_rejected_by_name` | Met: gap 1, fixed |
| §4.1.2, §4.1.5 | MUST | A recipient retrieving `jku` or `x5u` uses TLS and validates the server's identity. | vcrd retrieves nothing ([REQUIREMENTS] §10; [ARCHITECTURE] §8). | — | Not applicable: vcrd never retrieves keys |
| §4.1.3 | — | `jwk` is the public key that corresponds to the key that signed. | Parsed into a typed JWK (`check_jwk`, `vc_jose.rs:204`); private members reported; compared by thumbprint with the issuer's key; refused as the key unless the caller opts in ([REQUIREMENTS] §10). | `vcrd-core/tests/verify.rs` `a_jwk_with_private_members_is_an_inspect_error`, `a_malformed_jwk_does_not_stop_verify`, `an_oct_jwk_is_reported_as_symmetric_and_private`; `vcrd-cli/tests/verify.rs` `key_substitution_is_reported`, `a_key_the_credential_asserts_alone_is_refused` | Met |
| §4.1.4 | MUST (producer) | `kid` is a case-sensitive string. | Compared byte for byte (`check_kid`, `vc_jose.rs:534`). A `kid` that is not a string is `inspect.header_member_type`, not `inspect.kid_missing`. | As for §4.1.1–4.1.10 | Met: gap 1, fixed |
| §4.1.6 | MUST | A recipient validates the `x5c` chain, and treats a failure as invalid. | vcrd takes no key from `x5c`. | — | Not applicable: vcrd never uses certificates |
| §4.1.9, §4.1.10 | MUST | A recipient treats a `typ` or `cty` without `/` as if `application/` were prepended. | `media_type` lowercases and prefixes (`vc_jose.rs:229`) before comparing with `application/vc+jwt` and `application/vc`. A value that is not a string is `inspect.header_member_type` alone. | `vcrd-core/tests/inspect.rs` `checks_typ_and_cty` (`application/VC+JWT` passes); `vcrd-cli/tests/verify.rs` `a_header_member_of_the_wrong_type_is_reported` | Met: gap 1, fixed |
| §4.1.11 | MUST NOT (producer) | `crit` lists no name [RFC 7515] defines, no duplicate, no name absent from the header, and is not empty. | `check_crit` (`vc_jose.rs:273`) reports each as `inspect.crit_invalid`. | `vcrd-core/tests/inspect.rs` `checks_the_form_of_crit`; `vcrd-core/tests/verify.rs` `a_registered_name_in_crit_is_not_an_extension` | Met |
| §4.1.11 | MUST | A recipient understands and processes `crit`; an extension it does not support makes the JWS invalid. | `verify.crit_unsupported`, attributed to vcrd; the signature is still checked (`suites/jws.rs:49-63`; decided 2026-10-07). | `vcrd-cli/tests/verify.rs` `a_critical_extension_vcrd_does_not_implement_fails_verify`; `suites/jws.rs` `checks_the_signature_beside_an_unimplemented_critical_extension` | Met |
| §4.1.11 | MUST (producer) | `crit` is integrity protected: it appears only in the protected header. | A compact JWS has no other header (§7.1). | — | Met by construction |
| §5.2 step 1 | — | The compact form has three base64url segments separated by two periods. | `parse_compact` (`vc_jose.rs:628-631`) reports `parse.not_compact_jws`. | `vcrd-core/tests/parse.rs` `two_segments_is_not_a_compact_jws` | Met. A JWE's five segments: Later, gap 3 |
| §2; §5.2 steps 2, 6, 7 | — | Each segment is base64url without padding, line breaks, whitespace or other characters. | `decode` (`vc_jose.rs:794`) reports `parse.base64url_invalid` with the problem. | `vc_jose.rs` property tests `rejects_a_byte_outside_the_alphabet`, `rejects_padding`, `rejects_non_zero_discarded_bits`, `names_each_decoding_problem`; `vcrd-core/tests/parse.rs` `reports_every_bad_segment_and_keeps_the_good_ones` | Met |
| §5.2 step 3 | — | The header is a completely valid JSON object in UTF-8. | `decode_object` (`vc_jose.rs:811`) reports `parse.json_invalid` or `parse.json_not_object`. | `vcrd-core/tests/parse.rs` `reports_every_bad_segment_and_keeps_the_good_ones` | Met |
| §5.2 step 8 | MUST | `alg` is present and accurately describes the algorithm used. | The declared algorithm is checked, never obeyed: `EdDSA` is verified with an Ed25519 key only ([ARCHITECTURE] §8). | As for §4.1.1 | Met |
| §5.2, steps 9–10 | MUST | If no signature validates, the JWS is invalid. | `verify_strict` (`suites/jws.rs:167`); `verify.signature_invalid` fails verify. | `vcrd-cli/tests/verify.rs` `a_claim_changed_after_signing_fails_the_signature`; `suites/jws.rs` `rejects_rfc8037_a5_with_one_byte_changed` | Met |
| §5.2 | SHOULD | A recipient treats a JWS whose algorithm it does not accept as invalid. | `none` is always rejected; every other name vcrd does not implement is rejected by name. | `vcrd-cli/tests/verify.rs` `alg_none_is_rejected` | Met |
| §7.1 | — | A compact JWS is the three segments joined by periods, and nothing else. | Trailing ASCII whitespace is ignored and reported as `parse.trailing_whitespace`, `info`; leading whitespace is not a JWS. | `vcrd-core/tests/parse.rs` `accepts_trailing_whitespace_and_reports_it`, `leading_whitespace_is_not_a_jws`; `vcrd-cli/tests/parse.rs` `a_trailing_newline_is_reported_for_information` | Deviates: trailing whitespace, decided 2026-09-29 |

## [RFC 7519], JWT

| Section | Keyword | Sentence (abridged) | Mechanism | Check | Status |
|---|---|---|---|---|---|
| §4 | MUST | Claim names are unique; a parser rejects a repeated name, or keeps the lexically last. | As [RFC 7515] §4, for the payload. | `vcrd-core/tests/inspect.rs` `reports_each_duplicate_member_name` | Met |
| §4 | MUST | Claims an implementation does not understand are ignored. | No claim is rejected for being unknown; each is listed under `credential.claims` or `credential.metadata`. | By inspection | Met |
| §2 | — | A NumericDate counts seconds from the epoch, and may be fractional. | `proof_times` (`vc_jose.rs:325`) keeps the number as written and its value. | `vcrd-core/tests/verify.rs` `a_fractional_numeric_date_compares_as_written`, `a_numeric_date_beyond_any_calendar_compares` | Met |
| §4.1.1 | OPTIONAL | `iss` is a case-sensitive string or URI; its processing is application-specific. | [VC-JOSE-COSE] §4.1.2 defines it for credentials: round 3's table. | — | Met |
| §4.1.2, §4.1.7 | MUST (producer) | `sub` is unique within its issuer, or globally; `jti` collides with negligible probability. | One credential cannot show uniqueness. Their agreement with `credentialSubject.id` and `id`: round 3's table. | — | Not applicable: producers' rules |
| §4.1.1–4.1.3, §4.1.7 | — | `iss`, `sub` and `jti` are strings; `aud` is a string or an array of strings. Found in round 3. | `inspect.jwt_claim_type`, for these in the payload and `iss` in the header (`vc_jose.rs:430-464`). | `vcrd-core/tests/inspect.rs` `registered_claims_have_their_types` | Met: gap 11, fixed |
| §4.1.3 | MUST | A principal that processes the JWT identifies itself with a value in `aud`; if it does not, the JWT is rejected. | vcrd is not told whom it verifies for. When `aud` is present, `not_evaluated` lists `audience`, `no_parameters_supplied` (`vc_jose.rs:392`). | `vcrd-cli/tests/verify.rs` `an_audience_is_listed_as_not_evaluated`; `vcrd-cli/tests/example.rs` `verify_exits_0_with_one_json_document` (no `aud`, no entry) | Later: the check, milestone 4. Disclosed meanwhile: gap 2, fixed |
| §4.1.4 | MUST | The JWT is not accepted on or after `exp`; a small leeway MAY allow for clock skew. | `proof_validity` (`runner.rs:270`) reports `verify.proof_expired` when `exp` is not later than the clock, less `--clock-skew`. | `vcrd-core/tests/verify.rs` `exp_equal_to_the_clock_has_expired`, `the_skew_applies_to_both_bounds`; `vcrd-cli/tests/verify.rs` `an_expired_signature_fails_verify` | Met |
| §4.1.5 | MUST | The JWT is not accepted before `nbf`; a small leeway MAY allow for clock skew. | `verify.proof_not_yet_valid` when `nbf` is later than the clock, plus the skew. | `vcrd-core/tests/verify.rs` `a_not_before_after_the_clock_fails_verify`, `the_skew_applies_to_both_bounds` | Met |
| §4.1.4–4.1.6 | MUST (producer) | `exp`, `nbf` and `iat` are NumericDates. | `inspect.numeric_date_invalid` (`vc_jose.rs:417-419`); the proof's validity is `unknown`. | `vcrd-core/tests/verify.rs` `a_time_that_is_not_a_number_leaves_the_proof_validity_unknown` | Met |
| §4.1.6 | — | `iat` is when the JWT was issued. No rule for the recipient. | `verify.proof_issued_in_future`, a warning, when it is after the clock plus the skew. | `vcrd-core/tests/verify.rs` `iat_after_the_clock_is_a_warning` | Met |
| §7.2 | MUST | If any step fails, the JWT is rejected. | Each step's failure is an error finding, which fails its phase. | The rows for each step | Met |
| §7.2 steps 1–4 | — | At least one period; the header base64url-decoded strictly; valid UTF-8 JSON. | As [RFC 7515] §5.2 steps 1–3. | As there | Met |
| §7.2 step 5 | — | Every header parameter is understood, or may be ignored. | As [RFC 7515] §4 and §4.1.11. | As there | Met |
| §7.2 step 6 | — | Determine whether the JWT is a JWS or a JWE (JSON Web Encryption). | vcrd reads only a JWS. A compact JWE's five segments are reported as `parse.not_compact_jws`, attributed to the input. | Gap 3's input | Later: [ARCHITECTURE] §10 [F3], gap 3 |
| §7.2 step 8 | — | If `cty` is `JWT`, the message is a nested JWT: start again with it. | Not read. The payload is parsed as JSON, and fails as `parse.json_invalid`, attributed to the input. | Gap 3's input | Later: [ARCHITECTURE] §10 [F3], gap 3 |
| §7.2 steps 9–10 | — | The payload is base64url-decoded strictly, and is a valid UTF-8 JSON object: the claims. | As [RFC 7515] §5.2 steps 2–3. | As there | Met |
| §7.2 | SHOULD | Reject a JWT whose algorithms the application does not accept. | As [RFC 7515] §5.2. | As there | Met |
| §7.3 | MUST | Strings are compared as Unicode code points, after JSON escapes are decoded. Outside the plan's list; read because §7.2 depends on it. | Comparisons use decoded strings: `iss` with `issuer`, `kid`; media types also lowercased, as media types are case-insensitive. | By inspection | Met |
| §5.3 | SHOULD | In a JWT that is a JWE, a recipient checks that claims replicated as Header Parameters are identical to the claims. Outside the plan's list. | vcrd reads no JWE. [VC-JOSE-COSE] §3.1.3 applies the section to credentials secured as a JWS: `inspect.replicated_claim_mismatch` (`vc_jose.rs:512-529`). | `vcrd-core/tests/inspect.rs` `a_claim_replicated_in_the_header_matches_the_claim` | Met: gap 12, fixed |

## [RFC 8037], EdDSA in JOSE

| Section | Keyword | Sentence (abridged) | Mechanism | Check | Status |
|---|---|---|---|---|---|
| §2 | MUST | `kty` is `OKP`; `crv` and `x` are present. | `Jwk::parse` requires each key type's members (`vcrd-core/src/keys.rs:97`); inspect reports a missing one as `inspect.jwk_invalid`. | `keys.rs` `names_what_is_wrong_with_a_jwk` | Met |
| §2 | MUST NOT | `d` is not present in a public key. | `inspect.jwk_private_key` names each private member (`vc_jose.rs:217-223`); the values are masked unless `--unsafe=2`. | `vcrd-core/tests/verify.rs` `a_jwk_with_private_members_is_an_inspect_error`; the redaction tests, on `fixtures/canary.jwt` | Met |
| §2 | MUST (producer) | `x` is the public key, base64url-encoded. | `ed25519_jwk` (`keys.rs:140`) takes strict base64url of 32 bytes that encode a point as [RFC 8032] §5.1.3 requires (`ed25519_key`, `:149`); otherwise `inspect.jwk_invalid`. | `keys.rs` `names_what_is_wrong_with_a_jwk`, `rejects_a_key_not_encoded_as_rfc8032_requires` | Met: gap 7, fixed |
| §3.1 | — | The key's subtype decides the EdDSA variant: Ed25519 for `Ed25519`. | The suite verifies with an Ed25519 key only (`suites/jws.rs:127`), the only kind milestone 1 resolves. | `suites/jws.rs` `verifies_rfc8037_a5_under_either_name` | Met |
| §3.1 | — | The EdDSA signature is the JWS Signature. | `verify_strict` over the signing input (`suites/jws.rs:167`). | `suites/jws.rs` `verifies_rfc8037_a5_under_either_name`, on appendix A.4–A.5's vectors | Met |
| §3.1 | MUST NOT | Ed25519 and Ed448 keys are not used for ECDH-ES. | vcrd does no key agreement. | — | Not applicable |
| §3.2 | MUST NOT | X25519 and X448 keys are not used for signing. | A `did:key` whose codec is `x25519-pub` or `x448-pub` is `verify.did_key_not_for_signing`, attributed to the input (`keys.rs:399`, `:420`). | `keys.rs` `a_key_agreement_key_is_not_for_signing` | Met: gap 9, fixed |
| §4 | REQUIRED, RECOMMENDED | A well-seeded random number generator for key generation or batch verification; 256-bit symmetric encryption with X448. | vcrd generates no key, verifies one signature at a time, and encrypts nothing. | — | Not applicable |

## [RFC 9864], fully specified algorithms

| Section | Keyword | Sentence (abridged) | Mechanism | Check | Status |
|---|---|---|---|---|---|
| §2.2 | — | `Ed25519` is EdDSA with the Ed25519 parameter set of [RFC 8032] §5.1. | Accepted beside `EdDSA` (`suites/jws.rs:65-91`); each signature finding names the algorithm as the header declared it. | `vcrd-cli/tests/verify.rs` `the_fully_specified_name_ed25519_verifies`; `suites/jws.rs` `names_a_signature_of_the_wrong_length` | Met: gap 4, fixed |
| §2.2 | — | `Ed448` is EdDSA with the Ed448 parameter set. | Rejected by name, attributed to vcrd ([ARCHITECTURE] §10 [C3]). | `vcrd-cli/tests/verify.rs` `an_algorithm_vcrd_does_not_implement_is_rejected_by_name` | Met, by name |
| §4.1.2; §4.4 | SHOULD (producer) | `EdDSA` is Deprecated: new deployments use the replacement, unless documented requirements prevent it. No rule for a verifier. | `verify.algorithm_deprecated`, `info`, attributed to the input, with the replacement for the key used (`suites/jws.rs:92`). `text` and `plain` count it at level 1 and list it from level 2 (`vcrd-cli/src/text.rs:252`, `:287`). | `vcrd-cli/tests/verify.rs` `the_deprecated_name_eddsa_is_reported_for_information`; `vcrd-cli/tests/output.rs` `level_1_counts_the_info_findings_that_level_2_lists` | Met: gaps 5 and 6, fixed |
| §4.4 | MUST NOT | An identifier marked Prohibited is not used. | §4.1.2 changes one JOSE signature registration, `EdDSA`, and to Deprecated. | — | Not applicable |
| §7 | MUST, RECOMMENDED (producer) | A key is used with one algorithm only, unless proven secure; a JWK carries `alg`. | Binds key holders. vcrd does not compare a carried `jwk`'s own `alg` with the header's. | — | Not applicable: binds key holders |

## [RFC 8032], as `ed25519-dalek` implements it

| Section | Keyword | Sentence (abridged) | Mechanism | Check | Status |
|---|---|---|---|---|---|
| §5.1.7 step 1 | — | Split the signature into two 32-byte halves. | The length is checked first: `verify.signature_length` (`suites/jws.rs:138`). | `suites/jws.rs` `names_a_signature_of_the_wrong_length` (new; see [checks shown to fail](#the-checks-shown-to-fail)) | Met |
| §5.1.7 step 1; §5.1.3 | — | Decode R as a point; decoding fails for y at or above p (step 1), for a y with no x (step 3), and for x = 0 with the sign bit set (step 4). | `verify_strict` compares the R it recomputes, encoded canonically, with the signature's bytes (`ed25519-dalek` `src/verifying.rs:384-385`), so any other encoding of R fails, as `verify.signature_invalid`. | By inspection of the crate | Met |
| §5.1.7 step 1; §8.4 | — | Decode S as an integer, 0 ≤ S < L; out of range, the signature is invalid. Without the check, signatures are malleable. | The suite checks it before `verify_strict`, and reports `verify.signature_scalar_out_of_range` (`suites/jws.rs:151`). `ed25519-dalek` checks it only while its `legacy_compatibility` feature is off (`src/signature.rs:68-94`). | `suites/jws.rs` `names_an_s_not_less_than_the_group_order`, which also passes with that feature on | Met: gap 8, fixed |
| §5.1.7 step 1; §5.1.3 | — | Decode the public key A as a point; decoding fails for y at or above p, and for x = 0 with the sign bit set. | `VerifyingKey::from_bytes` accepts both: `curve25519-dalek` reduces y modulo p (`src/backend/serial/u64/field.rs:325-336`). `ed25519_key` encodes the point again and compares (`keys.rs:149`): `did_key_undecodable`, `point_not_canonical`. | `keys.rs` `rejects_a_key_not_encoded_as_rfc8032_requires` | Met: gap 7, fixed |
| §5.1.7 step 3 | — | Check [8][S]B = [8]R + [8][k]A'; checking [S]B = R + [k]A' instead is sufficient. | `verify_strict` checks the latter (`src/verifying.rs:384`), and also rejects a small-order R or A (`:380`), which §5.1.7 accepts. A verifier that checks the cofactored equation can accept a signature vcrd rejects, as §8.8 warns. | `vcrd-core/tests/fixtures.rs` `a_lax_verifier_accepts_the_weak_key_and_small_order_signatures`; `vcrd-cli/tests/verify.rs` `a_weak_key_is_refused_at_resolution`, `a_small_order_r_is_named` | Met, and stricter, as [REQUIREMENTS] §10 asks |
| §8.3; §8.5 | SHOULD, SHOULD NOT, RECOMMENDED | Contexts and the prehash variants. | JOSE's `Ed25519` and `EdDSA` are pure Ed25519, with no context. | — | Not applicable |
| §8.7 | MUST | The receiver buffers the whole message before verifying. | vcrd reads the whole input, under the size limit, before parsing it ([ARCHITECTURE] §4). | By construction | Met |

## Key resolution: [did:key], [REQUIREMENTS] §10, [ARCHITECTURE] §8

[did:key] has no section numbers; its rows name the algorithm and step.

| Where | Keyword | Sentence (abridged) | Mechanism | Check | Status |
|---|---|---|---|---|---|
| [did:key] syntax | — | `did:key:` and a multibase value, base58btc (`z`) or base64url (`u`). | Only `z` is decoded; `u` is `not_base58btc` (`keys.rs:412-414`), as the Create algorithm's step 3 requires. The syntax and the algorithm differ here. | `keys.rs` `names_what_is_wrong_with_a_did_key` (new) | Met, as the algorithm says |
| Create, steps 2–3 | MUST | Split on `:`; with three components the version is 1; the version is a positive integer, and the multibase value begins with `z`, or `invalidDid`. | A component before the multibase value is `did_key_undecodable`, `version_present`, attributed to the input (`keys.rs:409`). The syntax has no version. | `keys.rs` `names_a_version_before_the_multibase_value` | Met: gap 10, fixed |
| Decode Public Key, steps 2–3 | — | Decode base58btc, then the multicodec header, as a varint; the rest is the key. | `bs58`, then `unsigned_varint` (`keys.rs:415-419`). | `keys.rs` `names_what_is_wrong_with_a_did_key`, `resolves_an_ed25519_did_key` | Met |
| Signature Method Creation, step 3 | MUST | The key's length is the codec's, 32 bytes for `ed25519-pub`, or `invalidPublicKeyLength`. | `key_length` (`keys.rs:430`). | `keys.rs` `names_what_is_wrong_with_a_did_key` | Met |
| Signature Method Creation, step 4 | MUST | The bytes are a proper encoding of the key type, or `invalidPublicKey`. | `point_invalid` when they are not a point, `point_not_canonical` when they encode one otherwise than [RFC 8032] §5.1.3 does (`ed25519_key`, `keys.rs:149`). | `keys.rs` `names_what_is_wrong_with_a_did_key`, `rejects_a_key_not_encoded_as_rfc8032_requires` | Met: gap 7, fixed |
| Signature Method Creation, step 7 | MUST | An unknown `publicKeyFormat` raises `unsupportedPublicKeyType`. | vcrd builds no DID document. | — | Not applicable |
| Key table | — | `0xec`, `x25519-pub`, 32 bytes, in the same table as the signing keys. | `verify.did_key_not_for_signing`, attributed to the input, as for [RFC 8037] §3.2. | `keys.rs` `a_key_agreement_key_is_not_for_signing` | Met: gap 9, fixed |
| [REQUIREMENTS] §10 | — | Key material from the caller, then the issuer identifier, then a carried key that matches one of those; a carried key alone only on the caller's opt-in, otherwise refused, and the refusal reported. | `resolve` and `compare_embedded` (`keys.rs:232`, `:255`); the runner does not block a credential that carries a key (`runner.rs:123`). | `keys.rs` `an_embedded_key_equal_to_the_did_key_matches`, `an_embedded_key_unlike_the_did_key_is_a_warning`, `an_embedded_key_alone_is_refused_by_policy`; `vcrd-cli/tests/verify.rs` `key_substitution_is_reported`, `a_key_the_credential_asserts_alone_is_refused` | Met for milestone 1. Caller keys and the opt-in: Later, milestone 2 |
| [REQUIREMENTS] §10 | — | Key material that cannot bind a signature is rejected at resolution, as its own finding; verification is the strictest the primitives offer. | `is_weak` at resolution (`keys.rs:336`); `verify_strict`, with vcrd's own checks of R and S (`suites/jws.rs:151`, `:159`). | `vcrd-cli/tests/verify.rs` `a_weak_key_is_refused_at_resolution`; `vcrd-core/tests/fixtures.rs` `a_lax_verifier_accepts_the_weak_key_and_small_order_signatures` | Met |
| [REQUIREMENTS] §10 | — | An unsupported algorithm fails by name, with what is supported. | `verify.algorithm_unsupported`, `supported: ["Ed25519", "EdDSA"]`. | `vcrd-cli/tests/verify.rs` `an_algorithm_vcrd_does_not_implement_is_rejected_by_name` | Met |
| [REQUIREMENTS] §10 | — | Every result says where the key came from, and for a carried key, whether it matched and whether the signature verifies under it. | `KeyProvenance` (`keys.rs:160`); the second verification (`runner.rs:225`). | `vcrd-cli/tests/verify.rs` `key_substitution_is_reported` | Met |
| [REQUIREMENTS] §10 | — | Offline methods first; methods that need the network only with the opt-in. | `did:key` alone; any other issuer is `verify.issuer_method_unsupported`, attributed to vcrd (`keys.rs:301`). | `vcrd-core/tests/inspect.rs` `a_url_issuer_vcrd_cannot_resolve_reaches_verify` | Met |
| [ARCHITECTURE] §8 | — | A codec vcrd can name but not use fails by name, attributed to vcrd. | `NAMED_CODECS` (`keys.rs:389`), now with `ed448-pub`. The [multicodec table] confirms its values, `0x1202` and `0x1205` among them, which [DEVELOPMENT-PLAN.md] lists as not verified. | `keys.rs` `names_a_key_type_it_cannot_use`, `a_key_agreement_key_is_not_for_signing` | Met: gap 9, fixed |
| [ARCHITECTURE] §8 | — | "No key material" says where vcrd looked. | `verify.no_key_material` (`keys.rs:239`). Milestone 1 never reports it: the runner blocks verify first (`runner.rs:123`), and `blocked_by` names `key_material` and where vcrd looked. | `vcrd-cli/tests/output.rs`, case `issuer-missing-verify-text-1` | Met |

## [VC-JOSE-COSE], the Recommendation of 2026-10-13

§3.1.3 is headed "This section is non-normative" and still has keyword sentences; its
rows keep them. The sentences [DEVELOPMENT-PLAN.md]'s milestone review quotes from the
earlier text read the same here, except that the fetch tool placed "Implementations MUST
support the JWS compact serialization" and "Use of the JWS JSON serialization is NOT
RECOMMENDED" in §3.1.2, at the end of the section on presentations, where the plan's
known input 9 cites §3.1.1.

| Section | Keyword | Sentence (abridged) | Mechanism | Check | Status |
|---|---|---|---|---|---|
| §1.1.1 | MUST | A conforming JWS document conforms to every MUST in §3.1. | Each MUST of §3.1 vcrd can check is an error finding, in the rows below. | — | Met |
| §1.1.2.1 | MUST | Issuers, holders and verifiers understand the effect of `alg: none`. | Always rejected, as `verify.algorithm_none` ([ARCHITECTURE] §8). | `vcrd-cli/tests/verify.rs` `alg_none_is_rejected` | Met |
| §1.1.2.1 | MUST | Verifiers ignore every JWT Claims Set without integrity protection. | Verify fails on `alg: none`, so such a result is never `passed`. Inspect still describes the claims, for information, as it does for any input. | `vcrd-cli/tests/verify.rs` `alg_none_is_rejected` | Met |
| §1.1.2.1; §3.1.3 | MUST NOT | `vc` and `vp` are not in a Claims Set that is a credential or presentation. | Beside a VCDM 2.0 payload, `inspect.jwt_claim_forbidden`; with no `@context`, `inspect.vcdm_1_1_jwt_encoding`, attributed to vcrd (`vc_jose.rs:351-367`, `:380-382`). | `vcrd-core/tests/inspect.rs` `a_vc_claim_beside_a_vcdm_2_0_payload_is_forbidden`, `names_the_vcdm_1_1_jwt_encoding`; `vcrd-cli/tests/inspect.rs` `vcdm_1_1_encoding_exits_6` | Met |
| §3.1.1 | MUST (producer) | An issuer secures the credential with [RFC 7515]. | — | — | Not applicable |
| §3.1.1 | SHOULD | `typ` is `vc+jwt`. | `inspect.typ_unexpected`, a warning (`vc_jose.rs:160-163`, `:175-185`). | `vcrd-core/tests/inspect.rs` `checks_typ_and_cty` | Met |
| §3.1.1 | SHOULD | `cty`, when present, is `vc`. | `inspect.cty_unexpected`, a warning (`vc_jose.rs:186-193`). | `vcrd-core/tests/inspect.rs` `checks_typ_and_cty` | Met |
| §3.1.1 | MUST | A verifier verifies with [RFC 7515]. | Round 1's [RFC 7515] table. | As there | Met |
| §3.1.1 | MAY | A secured credential may be nested in a JWE. | Five segments are `parse.not_compact_jws`, attributed to the input. | Gap 3's input | Later: [ARCHITECTURE] §10 [F3], gap 3. This sentence makes such a JWE valid input |
| §3.1.2 | MUST; NOT RECOMMENDED | Implementations support the compact serialization; the JSON serialization is not recommended. | Compact is read. The JSON serialization is recognized and reported as `parse.jws_json_serialization`, attributed to vcrd (`vc_jose.rs:743`). | `vcrd-core/tests/parse.rs` `jws_json_serialization_is_named_and_attributed_to_vcrd`; `vcrd-cli/tests/parse.rs` `jws_json_serialization_exits_6` | Met. Reading it: Later, [ARCHITECTURE] §10 [F1] |
| §3.1.2 | MUST, SHOULD | A presentation's `typ` is `vp+jwt` and `cty` `vp`; the credentials in it are enveloped and secured. | A payload whose `type` has `VerifiablePresentation` and not `VerifiableCredential` is a presentation (`vc_jose.rs:874`): `inspect.presentation_unsupported`, attributed to vcrd, with no credential checks, and verify blocked (`:368-379`). Its `typ` and `cty` are checked against `vp+jwt` and `vp`. | `vcrd-core/tests/inspect.rs` `a_presentation_is_named_and_not_checked_as_a_credential` | Named: gap 14, fixed. Reading presentations: Later, milestone 4 |
| §3.1.3 | — | Registered header parameters and claims are interpreted as the specifications in their registries define. | Round 1's [RFC 7515] and [RFC 7519] tables; the claims' JSON types, `inspect.jwt_claim_type` (`vc_jose.rs:430-464`). | As there; `vcrd-core/tests/inspect.rs` `registered_claims_have_their_types` | Met: gap 11, fixed |
| §3.1.3 | — | [RFC 7519] §5.3, Replicating Claims as Header Parameters, applies to credentials. | A header `iss` is compared with the issuer; any other member in both the header and the payload, other than [RFC 7515]'s header parameters, is compared with the claim: `inspect.replicated_claim_mismatch`, a warning (`vc_jose.rs:512-529`). | `vcrd-core/tests/inspect.rs` `a_claim_replicated_in_the_header_matches_the_claim` | Met: gap 12, fixed |
| §3.1.3 | — | `iat` and `exp` are the signature's issuance and expiration, not `validFrom` and `validUntil`. | `verify.proof_expired`, `verify.proof_not_yet_valid`, `verify.proof_issued_in_future`, apart from inspect's validity ([ARCHITECTURE] §10 [S6]). | Round 1's [RFC 7519] §4.1.4–4.1.6 rows | Met |
| §3.1.3 | NOT RECOMMENDED | `nbf`. | Checked as `exp` is, with no finding for its presence ([DEVELOPMENT-PLAN.md], milestone 1, known input 2). | `vcrd-core/tests/verify.rs` `a_not_before_after_the_clock_fails_verify` | Met |
| §3.1.3 | SHOULD; SHOULD NOT | JWT claims do not conflict with credential properties: `iss` and `issuer`, `jti` and `id`, `sub` and `credentialSubject.id`. The Recommendation writes "JWK claim `iss`", apparently meaning the JWT claim. | `inspect.jwt_claim_conflict`, a warning, for `jti` and `sub` when each is a string (`vc_jose.rs:485-505`); `iss` as §4.1.2 requires. | `vcrd-core/tests/inspect.rs` `jti_and_sub_should_not_conflict`, `registered_claims_have_their_types` | Met |
| §3.1.3 | MUST | Members not understood are ignored. | Round 1's [RFC 7515] §4 and [RFC 7519] §4 rows. | As there | Met |
| §4.1.1 | — | `kid` is a hint to the key used. | It never chooses the key ([ARCHITECTURE] §8). | `vcrd-cli/tests/inspect.rs` `kid_missing_exits_3_and_verify_passes` | Met |
| §4.1.1 | MUST | `kid` is present when the key of the issuer or subject is expressed as a DID URL. | For a DID issuer: `inspect.kid_missing` (`vc_jose.rs:545-547`), and `inspect.kid_foreign` when `kid` names another key, read from this sentence ([DEVELOPMENT-PLAN.md], milestone 1, known input 4) (`:555-577`). | `vcrd-core/tests/inspect.rs` `checks_kid_for_a_did_key_issuer`; `vcrd-cli/tests/inspect.rs` `kid_missing_exits_3_and_verify_passes` | Met for the issuer. The subject's key: Later, milestone 4 |
| §4.1.2 | MUST | When present in the header or the claims, `iss` matches `issuer`, or `issuer.id`. | `inspect.iss_mismatch`, for each location (`vc_jose.rs:469-484`); an `iss` that is not a string is `inspect.jwt_claim_type` instead. | `vcrd-core/tests/inspect.rs` `iss_must_match_the_issuer`, `registered_claims_have_their_types`; `vcrd-cli/tests/inspect.rs` `iss_mismatch_exits_3_and_shows_both_values` | Met; gap 11, fixed |
| §4.1.3 | MAY; RECOMMENDED | `cnf` identifies a proof-of-possession key; binding the credential to its holder is recommended. | With `cnf` in the header or the claims, `not_evaluated` lists `holder_binding`, `not_implemented` (`vc_jose.rs:400-405`). | `vcrd-core/tests/inspect.rs` `cnf_lists_holder_binding_as_not_evaluated` | Disclosed: gap 13, fixed. The check: Later, milestone 4 |
| §4.2 | MUST | With controlled identifier documents, the verification method's type is `JsonWebKey`, with the key in `publicKeyJwk`. | vcrd builds no document: a `did:key`'s key comes from its identifier. | — | Not applicable |
| §4.2 | MUST | With `iss` absent and the issuer a URL, `kid` is an absolute URL to a verification method. | `inspect.kid_missing`, `inspect.kid_not_absolute` (`vc_jose.rs:545-554`). | `vcrd-core/tests/inspect.rs` `checks_kid_for_a_url_issuer`, `checks_kid_for_a_did_key_issuer` | Met |
| §4.2 | RECOMMENDED | With URL identifiers, `kid` is an absolute URL with a JWK Thumbprint URI. | `inspect.kid_without_thumbprint`, a warning, for URLs other than DIDs (`vc_jose.rs:578-582`), as decided ([DEVELOPMENT-PLAN.md], milestone 1). | `vcrd-core/tests/inspect.rs` `checks_kid_for_a_url_issuer` | Met |
| §4.2 | MUST | With `iss` absent and the holder a URL, `kid` is an absolute URL. | — | — | Later: presentations, milestone 4 |
| §5 | SHOULD | Verifiers minimize the processing of untrusted data, during key discovery included. | vcrd parses and inspects the whole input before verify, by design ([REQUIREMENTS] §4), under limits checked before the work each bounds (§6). Key discovery reads only `issuer`. | — | Deviates: [REQUIREMENTS] §4 |
| §5 | SHOULD | After verification succeeds, the checks of §5.4 are made. | Inspect makes them, whatever verify finds. | — | Met |
| §5; §5.1 | — | The algorithm follows [RFC 7519]'s validation, and returns `status`, `document` and `mediaType`. | Round 1's [RFC 7519] §7.2 rows. The mapping from vcrd's result: [DEVELOPMENT-PLAN.md], milestone 1, known input 7. | — | Round 4 |
| §5.4 | MUST | Every claim expected for the `typ` is present. | [VCDM 2.0]'s required properties. | — | Round 4 |
| §5.4 | MUST | Claims understood are evaluated by the verifier's policies; claims not understood are ignored. | Each check made is a finding when it fails; each not made is listed in `not_evaluated`. | — | Met |
| §5.4 | MUST | The verified document is well-formed compact JSON-LD. | `@context` is checked as [VCDM 2.0] requires (round 4). No JSON-LD processing: `not_evaluated` lists `context_resolution`, `not_implemented`. | `vcrd-cli/tests/example.rs` `verify_exits_0_with_one_json_document` | Partly met. JSON-LD processing: Later, milestone 5 |
| §5.4 | SHOULD; MUST | `credentialSchema` and `credentialStatus` are checked; a type not understood is ignored. | Listed in `not_evaluated` as `schema_conformance` and `revocation_status`, `not_implemented` (`vcdm.rs:67-68`). | `vcrd-core/tests/inspect.rs` `lists_status_and_schema_as_not_evaluated` | Met by disclosure. The checks: Later |

## [VCDM 2.0], the Recommendation of 2025-05-15

The plan's list is §1.3, §2, §4.3–4.9, §6.1 and §7.1–7.2. Round 4 also read §4.10 and
§4.11, whose objects vcrd already checks for a `type`, and §11.1, which §4.6 cites.

| Section | Keyword | Sentence (abridged) | Mechanism | Check | Status |
|---|---|---|---|---|---|
| §1.3 | MUST | A conforming document is compacted JSON-LD meeting every relevant MUST of §4, §5 and §6, which MUST be enforced. | Each MUST of §4.3–4.9 is an error finding, in the rows below. JSON-LD processing: `not_evaluated` lists `context_resolution`, `not_implemented`. §5 is outside the plan's list. | The rows below | Met for §4.3–4.9. JSON-LD: Later, milestone 5 |
| §1.3 | MUST | A conforming document is a credential (`application/vc`) or a presentation (`application/vp`). | A presentation is named, `inspect.presentation_unsupported` (round 3, gap 14). | `vcrd-core/tests/inspect.rs` `a_presentation_is_named_and_not_checked_as_a_credential` | Met |
| §1.3 | MUST | A conforming document is secured by at least one securing mechanism (§4.12). | A compact JWS always carries its proof. A JSON credential no format reads is `parse.data_integrity_unsupported`, attributed to vcrd, with a `proof`, and `parse.not_secured`, attributed to the input, without one (`runner.rs:155-166`). | `vcrd-core/tests/parse.rs` `a_json_credential_is_named_by_whether_it_has_a_proof` | Met: gap 15, fixed. Reading Data Integrity: Later, milestone 5 |
| §1.3 | MUST | A conforming verifier verifies (§4.12), checks each required property, and produces errors for non-conforming documents. | Verify; the checks below, each an error finding. vcrd's result has its own structure, not §7.1's. | The rows below | Met. A result in §7.1's structure: Later, [ARCHITECTURE] §10 [Q7], gap 18 |
| §1.3 | MAY | Optional properties may be ignored. | vcrd checks the optional properties this table names: `id`, the validity bounds, `name` and `description`, and the `id` of status, schema and related objects. | The rows below | Met |
| §2 | — | Verification includes conformance, the securing mechanism, and, if present, the status check. | Inspect and verify; status listed in `not_evaluated` as `revocation_status`, `not_implemented` ([DEVELOPMENT-PLAN.md], milestone 1, known input 8). | `vcrd-core/tests/inspect.rs` `lists_status_and_schema_as_not_evaluated` | Met by disclosure. The glossary's *Verify*: round 5 |
| §2 | — | Validation, whether a claim from an issuer meets a verifier's requirements, is outside the specification's scope; verifiers trust certain issuers for certain claims. | `not_evaluated` lists `issuer_accreditation` in every report, `not_implemented` until the trust anchor input [REQUIREMENTS] §9 calls for exists (`runner.rs:98-105`). | `vcrd-core/tests/inspect.rs` `lists_status_and_schema_as_not_evaluated`, `the_example_conforms`; `vcrd-cli/tests/example.rs` `verify_exits_0_with_one_json_document` | Met by disclosure: gap 19, fixed |
| §2 | — | A URL is as the [WHATWG URL Standard] defines it. | `parse_url`, through the `url` crate (`vcdm.rs:339`); a URL the parser corrected is a warning ([DEVELOPMENT-PLAN.md], milestone 1, decided 2026-10-01). | `vcdm.rs` `names_url_errors_and_corrections`; `vcrd-core/tests/inspect.rs` `a_nonconforming_issuer_url_is_a_warning` | Met |
| §4.3 | MUST | Credentials include `@context`. | `inspect.context_missing` (`vcdm.rs:111-115`). | `vcrd-core/tests/inspect.rs` `checks_contexts` | Met |
| §4.3 | MUST | `@context` is an ordered set whose first item is `https://www.w3.org/ns/credentials/v2`. | `inspect.context_first_invalid` (`vcdm.rs:116-123`). A single value is read as a set of one, as for every property that may hold one or several. | `vcrd-core/tests/inspect.rs` `checks_contexts`, `the_first_context_is_shown_when_it_is_wrong` | Met |
| §4.3 | MUST | Later items are URLs and objects, each processable as a JSON-LD context. | A string item is checked as a URL; an item that is neither is `inspect.context_entry_invalid` (`vcdm.rs:124-130`). Whether each is processable needs JSON-LD. | `vcrd-core/tests/inspect.rs` `checks_contexts` | Met, except processability: Later, milestone 5 |
| §4.3 | MUST | Application developers understand every context their application uses. | vcrd reads only the base context's terms, and says so: `context_resolution`, `not_implemented`. | `vcrd-cli/tests/example.rs` `verify_exits_0_with_one_json_document` | Met by disclosure |
| §4.4 | OPTIONAL; MUST | `id`, if present, is a single URL. | Checked for the credential's `id` and each subject's (`vcdm.rs:307-315`), for `issuer.id` (§4.7), and for the `id` of each `credentialStatus`, `credentialSchema`, `termsOfUse`, `evidence` and `refreshService` object (`related_identifiers`, `vcdm.rs:173-188`). | `vcrd-core/tests/inspect.rs` `checks_subjects_and_identifiers`, `checks_the_ids_of_status_schema_and_related_objects` | Met: gap 16, fixed |
| §4.5 | MUST | Credentials contain `type`, whose value is one or more terms and absolute URL strings. | `inspect.type_missing`, `inspect.type_not_string` (`vcdm.rs:135-156`). Whether a string is a term or an absolute URL needs the contexts. | `vcrd-core/tests/inspect.rs` `checks_types` | Met, except term or URL: Later, milestone 5 |
| §4.5 | MUST | The table's objects have a `type`: a credential's includes `VerifiableCredential`, a presentation's `VerifiablePresentation`; `credentialStatus`, `termsOfUse`, `evidence`, `refreshService` and `credentialSchema` each have one. | `inspect.type_lacks_verifiable_credential`; `inspect.type_missing` for each object of those properties (`vcdm.rs:152-168`); a presentation: round 3. | `vcrd-core/tests/inspect.rs` `checks_types` | Met |
| §4.6 | OPTIONAL; MUST | `name` and `description`, if present, are each a string or a language value object (§11.1). | `inspect.language_value_invalid`, a warning, for a value that is neither, nor an array of them (`vcdm.rs:193-231`). | `vcrd-core/tests/inspect.rs` `checks_names_and_descriptions` | Deviates: a warning, not an error (gap 17, decided 2026-10-24) |
| §4.7 | MUST | A credential has an `issuer`, a URL or an object whose `id` is a URL. | `inspect.issuer_missing`, `inspect.issuer_invalid` (`vcdm.rs:235-263`); either blocks verify, for want of a key ([ARCHITECTURE] §4). | `vcrd-core/tests/inspect.rs` `a_missing_issuer_is_an_input_error_that_blocks_verify`, `an_issuer_that_is_not_a_url_is_an_input_error_that_blocks_verify` | Met |
| §4.7 | RECOMMENDED (producer) | The URL dereferences to a controlled identifier document. | — | — | Not applicable |
| §4.8 | MUST | A credential contains `credentialSubject`, a set of objects, each the subject of one or more claims serialized inside it. | `inspect.credential_subject_missing`, `inspect.credential_subject_invalid` and `inspect.credential_subject_empty`, errors; a subject with only an `id`, `inspect.credential_subject_no_claims`, a warning (`vcdm.rs:272-304`). | `vcrd-core/tests/inspect.rs` `an_empty_subject_is_its_own_error`, `checks_subjects_and_identifiers` | Met, except an `id`-only subject: Deviates, a warning ([DEVELOPMENT-PLAN.md], milestone 1, decided 2026-10-01; [ARCHITECTURE] §10 [S5]) |
| §4.9 | MUST | `validFrom` and `validUntil`, if present, are XML Schema 1.1 `dateTimeStamp` strings, and `validUntil` is not earlier than `validFrom`. | `inspect.date_time_invalid`, with whether [RFC 3339] would accept the value; `inspect.date_time_unrepresentable`, attributed to vcrd, outside the years -9999 to 9999; `inspect.valid_until_before_valid_from` (`vcdm.rs:378-424`). The differences from RFC 3339 are tabled in [ARCHITECTURE] §4 (known input 5). | `vcrd-core/tests/inspect.rs` `checks_validity_bounds_as_date_time_stamps`, `valid_until_before_valid_from_is_an_error`; `vcdm.rs` `follows_xml_schema_where_it_differs_from_rfc_3339` | Met |
| §2; §4.9 | — | Verification asks whether the statement is current. | `inspect.not_yet_valid` and `inspect.expired` against the clock and skew (`vcdm.rs:425-450`). | `vcrd-cli/tests/example.rs` `an_expired_credential_exits_3_with_verify_passed`, `clock_skew_tolerates_a_bound_just_passed` | Met |
| §4.10 | REQUIRED; MUST | A status object's `type` is required; its `id`, if present, follows §4.4. | `type`: as for §4.5. `id`: as for §4.4. | `vcrd-core/tests/inspect.rs` `checks_types`, `checks_the_ids_of_status_schema_and_related_objects` | Met: gap 16, fixed |
| §4.11 | MUST | Each `credentialSchema` has a `type` and an `id` that is a URL. | `type`: as for §4.5. `id`: absent, `inspect.id_missing`; not a URL, `inspect.url_invalid` (`vcdm.rs:173-188`). | `vcrd-core/tests/inspect.rs` `checks_types`, `checks_the_ids_of_status_schema_and_related_objects` | Met: gap 16, fixed |
| §6.1 | MUST | `application/vc` and `application/vp` use JSON-LD compacted document form. | Not checked: JSON-LD processing. | — | Later, milestone 5 |
| §7.1 | MUST; MAY | The algorithm verifies the securing mechanism, then checks that the document conforms, returning `status`, `document`, `mediaType`, `controller`, `controlledIdentifierDocument`, `warnings` and `errors`; the order may differ if the same inputs fail. | Inspect runs before verify, and both run. vcrd's result has its own structure (known input 7). | — | Later: [ARCHITECTURE] §10 [Q7], milestone 3, gap 18 |
| §7.2 | MUST; SHOULD | Each problem has a `type` URL, among `PARSING_ERROR`, `CRYPTOGRAPHIC_SECURITY_ERROR`, `MALFORMED_VALUE_ERROR` and `RANGE_ERROR`, and should have a `title` and `detail`. | A finding has a code, attribution, severity and structured detail, not a problem type ([REQUIREMENTS] §6). | — | Later: [ARCHITECTURE] §10 [Q7], milestone 3, gap 18 |
| §11.1 | MUST; SHOULD; MAY | A language value object has `@value`, a string; should have `@language`; may have `@direction`; has no other key; several may be an array. | `language_value_problem` (`vcdm.rs:211-231`): `value_missing`, `other_member`, `wrong_type`. `@language`'s form and `@direction`'s value are not checked. | `vcrd-core/tests/inspect.rs` `checks_names_and_descriptions` | Met, as a warning (gap 17) |

## The checks shown to fail

[REQUIREMENTS] §11 holds that a check which has never failed has not shown that it detects
anything. Each check below failed, with a fault planted or before the change it checks,
and then passed.

| # | Check | Fault, or state before | Result |
|---|---|---|---|
| R1 | `vcrd-core/tests/finding_reference.rs` | No `docs/findings.md` yet | Failed at reading it: `No such file or directory`. With the reference written: passed |
| R2 | The same | The anchor `verify.weak_key` renamed `verify.weak_keys` | `add to docs/findings.md: ["verify.weak_key"]; remove from it: ["verify.weak_keys"]` |
| R3 | The same | `parse.json_invalid` documented a second time | `a code documented twice` |
| R4 | The same | The codes of gap 1's fix added to `FindingDetail::code`, before their entries | `add to docs/findings.md: ["inspect.header_member_type", "verify.algorithm_invalid"]; remove from it: []` |
| R5 | `vcrd-core/tests/verify.rs` `a_header_without_alg_is_not_verified` | The suite accepting an absent `alg` (`None => None` in `suites/jws.rs`) | `left: []`, `right: [("verify.algorithm_missing", Input, Error)]` |
| R6 | `vcrd-cli/tests/debugging.rs` | The fixtures of gaps 1 and 2 generated, before `.vscode/launch.json` listed them | `add to .vscode/launch.json: ["fixtures/aud.jwt", "fixtures/header-member-types.jwt"]; remove from it: []` |
| R7 | `vcrd-cli/tests/verify.rs` `the_fully_specified_name_ed25519_verifies` | Before gap 4's fix | `left: Some(6)`, `right: Some(0)`, with `verify.algorithm_unsupported`, `declared: "Ed25519"`, `supported: ["EdDSA"]` |
| R8 | `vcrd-cli/tests/verify.rs` `the_deprecated_name_eddsa_is_reported_for_information` | Before gap 5's fix | `expected one verify.algorithm_deprecated` |
| R9 | `vcrd-core/tests/finding_reference.rs` | Gap 5's code added to `FindingDetail::code` before its entry | `add to docs/findings.md: ["verify.algorithm_deprecated"]; remove from it: []` |
| R10 | `vcrd-cli/tests/output.rs` `level_1_counts_the_info_findings_that_level_2_lists` | After gap 5's fix, before gap 6's | Failed at its first check: level 1's `text` named `verify.algorithm_deprecated`, in the verify row and in Findings |
| R11 | `keys.rs` `names_what_is_wrong_with_a_did_key`, new, which passed at its first run | `decode_did_key` reporting invalid base58btc as `CodecInvalid` | `left: CodecInvalid`, `right: Base58Invalid` |
| R12 | `suites/jws.rs` `names_a_signature_of_the_wrong_length`, new, which passed at its first run | The finding's algorithm fixed at `EdDSA`, as before gap 4's fix | `SignatureLength { algorithm: "EdDSA", expected: 64, found: 63 }` |
| R13 | `keys.rs` `rejects_a_key_not_encoded_as_rfc8032_requires` | Before gap 7's fix | The `did:key` of y = p + 3 resolved, with no finding: `did:key:z6Mkvg2JPc7mj3oXZCpWHB9ScRB6BvScZqnrR4Ew9Gjrd75G: []` |
| R14 | `suites/jws.rs` `names_an_s_not_less_than_the_group_order` | Before gap 8's fix | `left: ["verify.signature_invalid"]`, `right: ["verify.signature_scalar_out_of_range"]` |
| R15 | The same | Before gap 8's fix, with `ed25519-dalek`'s `legacy_compatibility` feature turned on in `Cargo.toml` | The outcome was `Verified { disclosed: None }`: S + L verifies. After the fix, with the feature on again, the test passed. `Cargo.toml` and `Cargo.lock` were restored each time |
| R16 | `keys.rs` `a_key_agreement_key_is_not_for_signing` | Before gap 9's fix | `left: Vcrd`, `right: Input`, for `DidKeyCodecUnsupported { codec: 236, name: None }` |
| R17 | `keys.rs` `names_a_version_before_the_multibase_value` | Before gap 10's fix | `left: NotBase58btc`, `right: VersionPresent` |

| R18 | `vcrd-core/tests/inspect.rs` `registered_claims_have_their_types` | Before gap 11's fix | The first finding was `IssMismatch { location: Payload, iss: None, issuer: "did:key:z6Mkps…" }`, not a type |
| R19 | `vcrd-core/tests/inspect.rs` `a_claim_replicated_in_the_header_matches_the_claim` | Before gap 12's fix | `left: []`, `right: [("inspect.replicated_claim_mismatch", Input, Warning)]` |
| R20 | `vcrd-core/tests/inspect.rs` `cnf_lists_holder_binding_as_not_evaluated` | Before gap 13's fix | `not_evaluated` was `[(IssuerAccreditation, OutOfScope), (ContextResolution, NotImplemented)]` |
| R21 | `vcrd-core/tests/inspect.rs` `a_presentation_is_named_and_not_checked_as_a_credential` | Before gap 14's fix | `left:` `typ_unexpected` and `cty_unexpected` warnings, and `type_lacks_verifiable_credential`, `issuer_missing` and `credential_subject_missing` errors, all attributed to the input; `right: [("inspect.presentation_unsupported", Vcrd, Error)]` |
| R22 | `vcrd-core/tests/finding_reference.rs` | Gaps 11, 12 and 14's codes added before their entries | `add to docs/findings.md: ["inspect.jwt_claim_type", "inspect.presentation_unsupported", "inspect.replicated_claim_mismatch"]; remove from it: []` |

| R23 | `vcrd-core/tests/parse.rs` `a_json_credential_is_named_by_whether_it_has_a_proof` | Before gap 15's fix | `left: [("parse.no_format_matched", Input, Error)]`, `right: [("parse.not_secured", Input, Error)]` |
| R24 | `vcrd-core/tests/inspect.rs` `checks_the_ids_of_status_schema_and_related_objects` | Before gap 16's fix | `left: []`, `right: [("inspect.url_invalid", "credentialStatus.id"), ("inspect.id_missing", "credentialSchema[1]")]` |
| R25 | `vcrd-core/tests/inspect.rs` `checks_names_and_descriptions` | Before gap 17's fix | `left: []`, `right: [("name", WrongType), ("description[0]", ValueMissing), ("description[1]", OtherMember { name: "@lang" })]` |
| R26 | `vcrd-core/tests/inspect.rs` `lists_status_and_schema_as_not_evaluated`, its expectation changed to gap 19's | Before gap 19's fix | `left: [(IssuerAccreditation, OutOfScope), …]`, `right: [(IssuerAccreditation, NotImplemented), …]` |
| R27 | `vcrd-core/tests/finding_reference.rs` | Gaps 15–17's codes added before their entries | `add to docs/findings.md: ["inspect.id_missing", "inspect.language_value_invalid", "parse.data_integrity_unsupported", "parse.not_secured"]; remove from it: []` |

The tests of gaps 7 to 17 were written against the new variants, added first with no
behavior, so each failed on what vcrd did rather than for want of a type.

The completeness test reads the codes from `FindingDetail::code` and the anchors from
the reference. It cannot check the entries' attribution and severity: core sets them
where each finding is made, not per code. Every code has one attribution and one
severity, except `parse.no_format_matched`, attributed to vcrd when vcrd was built with
no format and to the input otherwise.

## Gaps found

At the commit each round started from, each input was built from `examples/ed25519.jwt`
and run as `vcrd verify <input> --now 2026-10-01T00:00:00Z --format json`. Each gap fixed
then got a test, and a fixture where it needed one, which failed before the fix and
passed after it.

### Round 1, at `94ff6d0`


1. **A registered Header Parameter whose value is not a string was reported as absent,
   or not at all** ([RFC 7515] §4.1.1, §4.1.4, §4.1.9, §4.1.10). With `alg`, `kid`, `typ`
   and `cty` each the number 1: exit 3, `inspect.typ_unexpected` with `found: null`,
   `inspect.kid_missing` and `verify.algorithm_missing`, and nothing for `cty`. All four
   were read through `string()` (`vc_jose.rs:705`), which takes a non-string for absent.
   - *Decided* 2026-10-22: `inspect.header_member_type` for every registered member with
     a type of its own, and `verify.algorithm_invalid` for an `alg` that is not a
     string.
   - *Test:* `vcrd-cli/tests/verify.rs` `a_header_member_of_the_wrong_type_is_reported`,
     on `fixtures/header-member-types.jwt`, which sets all nine such members to 1.
   - *Before:* failed at its first check, `inspect.kid_missing` present, with inspect's
     findings `["inspect.typ_unexpected", "inspect.kid_missing"]`. *After:* passed.
2. **`aud` was neither checked nor reported** ([RFC 7519] §4.1.3). With
   `"aud": "https://verifier.example"` in the payload, `aud` appeared only among the
   metadata, and `not_evaluated` did not mention it.
   - *Decided* 2026-10-22: `not_evaluated` lists `audience` as `no_parameters_supplied`
     until milestone 4 gives vcrd an expected audience.
   - *Test:* `vcrd-cli/tests/verify.rs` `an_audience_is_listed_as_not_evaluated`, on
     `fixtures/aud.jwt`.
   - *Before:* failed: `not_evaluated` held only `issuer_accreditation` and
     `context_resolution`. *After:* passed.
3. **Valid JOSE that vcrd does not read is attributed to the input** ([RFC 7519] §7.2
   steps 6 and 8). A header with `"cty": "JWT"` over a payload that is itself a JWT:
   exit 2, `parse.json_invalid`. A five-segment JWE: exit 2, `parse.not_compact_jws`
   with `segments: 5`. Both are input vcrd does not support, which is exit 6 elsewhere,
   as for JWS JSON serialization.
   - *Decided* 2026-10-22: deferred, as [ARCHITECTURE] §10 [F3], with no milestone yet.

### Round 2, at `46a2ca7`

4. **`alg: "Ed25519"` was rejected as unsupported** ([RFC 9864] §2.2). The example with
   that `alg`: exit 6, `verify.algorithm_unsupported`, `supported: ["EdDSA"]`. RFC 9864
   registers the name for what `EdDSA` with an Ed25519 key names.
   - *Decided* 2026-10-23: verified exactly as `EdDSA` with an Ed25519 key is.
   - *Test:* `vcrd-cli/tests/verify.rs` `the_fully_specified_name_ed25519_verifies`, on
     `fixtures/alg-ed25519.jwt`. *Before:* R7. *After:* passed: exit 0, no finding.
5. **`EdDSA` was not reported as deprecated** ([RFC 9864] §4.1.2, §4.4). The example:
   exit 0, no finding. RFC 9864 says new deployments SHOULD use the replacement and sets
   no rule for a verifier.
   - *Decided* 2026-10-23: `verify.algorithm_deprecated`, `info`, attributed to the
     input, always in JSON, with the replacement for the key used.
   - *Test:* `vcrd-cli/tests/verify.rs` `the_deprecated_name_eddsa_is_reported_for_information`,
     on the example. *Before:* R8. *After:* passed. The example, which declares `EdDSA`
     as most credentials in use do, now has this one finding (`vcrd-cli/tests/example.rs`);
     `vcrd-core/tests/verify.rs` signs with `Ed25519`, so that its tests' findings are
     their own conditions'.
6. **Level 1 would list that finding for most credentials.** Not a gap in a standard: a
   consequence of gap 5 for `text` and `plain`, which listed every finding at level 1.
   - *Decided* 2026-10-23: level 1 leaves out the `info` findings, `parse.trailing_whitespace`
     included, from the findings and from each phase's kinds of finding, and says how
     many it left out; level 2 lists them ([docs/output.md](../output.md)).
   - *Test:* `vcrd-cli/tests/output.rs` `level_1_counts_the_info_findings_that_level_2_lists`.
     *Before:* R10. *After:* passed, and the expected files were regenerated, each
     difference read: the count at level 1, and the finding listed at levels 2 and 3.
7. **A public key whose y is encoded at or above p is accepted** ([RFC 8032] §5.1.3
   step 1; [did:key] Signature Method Creation, step 4). For each y from p to p + 18,
   with either sign bit, a scratch test, since removed, passed the 32 bytes to
   `VerifyingKey::from_bytes`, `is_weak` and `curve25519-dalek`'s decompression. 20
   encodings, of 10 values of y (p + 3 to p + 6, p + 9, p + 10, p + 14 to p + 16, p + 18),
   decode to points that are not weak, and none is the canonical encoding of its point;
   p and p + 1 are weak, and the rest are not points. RFC 8032 says each fails to decode.
   Such a key's `did:key` and thumbprint differ from those of its point's canonical
   encoding, so a carried `jwk` holding the canonical one is reported as a different
   key.
   - *Decided* 2026-10-23: rejected, as `verify.did_key_undecodable` with a new
     problem, `point_not_canonical`, and in a carried `jwk` as `inspect.jwk_invalid`.
     The identity point with its sign bit set, which RFC 8032 §5.1.3 step 4 rejects, is
     `point_not_canonical` too, where it was `verify.weak_key`.
   - *Test:* `keys.rs` `rejects_a_key_not_encoded_as_rfc8032_requires`. *Before:* R13.
     *After:* passed; y = 3, the same point encoded canonically, still resolves.
8. **An S at or above L is rejected only because of a feature setting, and not named**
   ([RFC 8032] §5.1.7 step 1, §8.4). With `ed25519-dalek`'s `legacy_compatibility`
   feature on, `check_scalar` accepts any S whose top three bits are clear
   (`src/signature.rs:68-86`), and S + L verifies as S does. Cargo unifies features across
   a build, so a program that links `vcrd-core` beside a crate that turns the feature on
   accepts such signatures, and vcrd's own tests do not run in that build. A valid
   signature with L added is a changed signature that a lax verifier accepts.
   - *Decided* 2026-10-23: the suite checks S < L before `verify_strict`, as it checks a
     small-order R, and names it `verify.signature_scalar_out_of_range`, attributed to
     the input.
   - *Test:* `suites/jws.rs` `names_an_s_not_less_than_the_group_order`, on RFC 8037
     A.5's signature with L added to S. *Before:* R14, and R15 with the feature on.
     *After:* passed, with the feature off and on.
9. **A `did:key` holding an X25519 key is attributed to vcrd** ([RFC 8037] §3.2). Codec
   `0xec`: exit 6, `verify.did_key_codec_unsupported`, `name: null`, which reads as a key
   type vcrd does not support yet. No verifier may use an X25519 key for a signature.
   `ed448-pub` (`0x1203`) and `x448-pub` (`0x1204`) are unnamed too.
   - *Decided* 2026-10-23: a new `verify.did_key_not_for_signing`, attributed to the
     input, for `x25519-pub` and `x448-pub`; `ed448-pub` named under
     `verify.did_key_codec_unsupported`, as `alg: "Ed448"` is named.
   - *Test:* `keys.rs` `a_key_agreement_key_is_not_for_signing`. *Before:* R16.
     *After:* passed.
10. **A `did:key` with a version is reported as not base58btc** ([did:key] Create, steps
    2–3). `did:key:1:z6Mk…` is exit 4, `verify.did_key_undecodable`, `not_base58btc`,
    though the identifier is base58btc after its version. The syntax has no version;
    the algorithm accepts one.
    - *Decided* 2026-10-23: a new problem, `version_present`, attributed to the input, as
      the syntax has no version.
    - *Test:* `keys.rs` `names_a_version_before_the_multibase_value`. *Before:* R17.
      *After:* passed.

### Round 3, at `30d1f91`

Each input below was the example's header and payload, edited with `jq` and re-encoded,
with the example's signature; run as `vcrd inspect <input> --now 2026-10-01T00:00:00Z
--format json`.

11. **A registered claim of the wrong JSON type is misreported** ([RFC 7519] §4.1.1–4.1.3,
    §4.1.7; [VC-JOSE-COSE] §3.1.3). With `iss`, `sub`, `jti` and `aud` each the number 1:
    `inspect.iss_mismatch` with `iss: null`, as if `iss` were JSON null;
    `inspect.jwt_claim_conflict` for `jti` and for `sub`; and for `aud`, only `audience`
    in `not_evaluated`. Round 1 checked the header's types (gap 1) and not these.
    - *Decided* 2026-10-23: a new `inspect.jwt_claim_type`, an error attributed to the
      input, with the claim, its location, the type expected and the type found, for the
      payload's `iss`, `sub`, `jti` and `aud` and the header's `iss`, as gap 1 did for
      the header. The comparisons skip a claim of the wrong type, so `iss_mismatch`'s
      `iss` is always a string.
    - *Test:* `vcrd-core/tests/inspect.rs` `registered_claims_have_their_types`.
      *Before:* R18. *After:* passed, with four `inspect.jwt_claim_type` findings and no
      other.
12. **A claim replicated in the header is not compared with the payload's** ([RFC 7519]
    §5.3, which [VC-JOSE-COSE] §3.1.3 applies to credentials). With a header `sub` other
    than the payload's: exit 0, no finding. §5.3 says a recipient SHOULD check that the
    values are identical.
    - *Decided* 2026-10-23: a warning, `inspect.replicated_claim_mismatch`, naming the
      claim and not its values, for each member other than [RFC 7515]'s header
      parameters that is in both and differs; `iss` keeps `inspect.iss_mismatch`.
    - *Test:* `vcrd-core/tests/inspect.rs` `a_claim_replicated_in_the_header_matches_the_claim`.
      *Before:* R19. *After:* passed; equal values, and a claim only in the header, give
      no finding.
13. **`cnf` is neither used nor reported** ([VC-JOSE-COSE] §4.1.3). With a `cnf` claim:
    exit 0, and `not_evaluated` does not mention holder binding. A credential bound to a
    holder's key verifies with nothing to say that possession was not shown.
    - *Decided* 2026-10-23: `not_evaluated` lists `holder_binding`, `not_implemented`,
      when `cnf` is in the header or the claims, until milestone 4's presentations.
    - *Test:* `vcrd-core/tests/inspect.rs` `cnf_lists_holder_binding_as_not_evaluated`.
      *Before:* R20. *After:* passed, for `cnf` in either place, and the example lists
      no holder binding.
14. **A presentation is attributed to the input** ([VC-JOSE-COSE] §3.1.2). A payload with
    `type: ["VerifiablePresentation"]` and a `holder`, under `typ: vp+jwt` and `cty: vp`:
    exit 3, with `inspect.type_lacks_verifiable_credential`, `inspect.issuer_missing` and
    `inspect.credential_subject_missing`, each attributed to the input, and warnings for
    `typ` and `cty`. vcrd reads presentations from milestone 4.
    - *Decided* 2026-10-23: a presentation, known by its `type`, is named,
      `inspect.presentation_unsupported`, attributed to vcrd (exit 6), and skips the
      credential checks, as VCDM 1.1's encoding does. `credential.kind` is
      `presentation`, its header is checked against `vp+jwt` and `vp`, and verify is
      blocked, since it names no issuer.
    - *Test:* `vcrd-core/tests/inspect.rs` `a_presentation_is_named_and_not_checked_as_a_credential`.
      *Before:* R21. *After:* passed. Through the binary, the same input exits 6 with
      that one inspect finding and `credential.kind: presentation`.

### Round 4, at `dda3a15`

Each input below was run as `vcrd inspect <input> --now 2026-10-01T00:00:00Z --format
json`: the JSON credentials as written, the others built as in round 3.

15. **A JSON credential is attributed to the input, with or without a proof**
    ([VCDM 2.0] §1.3, §4.12). A VCDM 2.0 credential as JSON, with a `DataIntegrityProof`
    (`eddsa-rdfc-2022`): exit 2, `parse.no_format_matched`, attributed to the input. It
    is a conforming document, in a format vcrd reads from milestone 5. The same
    credential with no `proof`: the same finding, though §1.3's reason it does not
    conform is that nothing secures it.
    - *Decided* 2026-10-24: when no format matches, a JSON object with `@context` and
      `type`, read within the depth limit, is named as a credential: with `proof`,
      `parse.data_integrity_unsupported`, attributed to vcrd (exit 6), as the JWS JSON
      serialization is; without, `parse.not_secured`, attributed to the input (exit 2).
    - *Test:* `vcrd-core/tests/parse.rs` `a_json_credential_is_named_by_whether_it_has_a_proof`.
      *Before:* R23. *After:* passed; a JSON object that is not a credential is still
      `parse.no_format_matched`. Through the binary, the two inputs above exit 6 and 2.
16. **The `id` of status and schema objects is not checked** ([VCDM 2.0] §4.4, §4.10,
    §4.11). A `credentialStatus` whose `id` is `not a url`, and a `credentialSchema` with
    no `id`: exit 0, no finding. §4.11 requires the schema's `id`, a URL; §4.4 makes any
    `id` a URL; §1.3 lets a verifier ignore optional properties, which status and schema
    are.
    - *Decided* 2026-10-24: the `id` of each `credentialStatus`, `credentialSchema`,
      `termsOfUse`, `evidence` and `refreshService` object is checked as a URL, as the
      credential's is, and a `credentialSchema` without one is a new
      `inspect.id_missing`: a missing `id` is a finding of its own, not
      `inspect.url_invalid`.
    - *Test:* `vcrd-core/tests/inspect.rs` `checks_the_ids_of_status_schema_and_related_objects`.
      *Before:* R24. *After:* passed: `inspect.url_invalid` for the status's `id`,
      `inspect.id_missing` for the schema, and nothing for a URL.
17. **`name` and `description` are not checked** ([VCDM 2.0] §4.6, §11.1). `name: 1` and
    `description: {"@value": 2}`: exit 0, no finding. Each MUST be a string or a language
    value object: `@value` a string, `@language` and `@direction` optional, no other
    key; §11.1 allows an array of them. The Recommendation's own Example 40 gives `name`
    a map keyed by language, which this sentence does not allow. Both are optional
    (§1.3).
    - *Decided* 2026-10-24: a new `inspect.language_value_invalid`, a warning attributed
      to the input, with the path and the problem, given Example 40 and §1.3.
    - *Test:* `vcrd-core/tests/inspect.rs` `checks_names_and_descriptions`. *Before:* R25.
      *After:* passed; a string, a language value object, and an array of them give no
      finding.
18. **vcrd's result is not mapped to §7.1's** ([VCDM 2.0] §1.3, §7.1, §7.2;
    [DEVELOPMENT-PLAN.md], milestone 1, known input 7). No document says which part of
    vcrd's result is §7.1's `status`, `document`, `mediaType`, `controller`, `warnings`
    and `errors`, or which findings are which of §7.2's problem types.
    - *Decided* 2026-10-24: not a mapping alone. A development task decides how vcrd
      produces a result that conforms exactly to §7.1's, with §7.2's problem types:
      through `--format json`, a format of its own such as `vcdm2`, or a conforming part
      of the JSON envelope. Recorded as [ARCHITECTURE] §10 [Q7], in milestone 3, with
      presentations in milestone 4. [Q7] names what it must settle: redaction of §7.1's
      `document`, the problem type of each finding, and the key fields.
19. **`issuer_accreditation`'s reason, `out_of_scope`, says vcrd will never check it**
    ([VCDM 2.0] §2's *validation*; [REQUIREMENTS] §9, §16 item 14). [REQUIREMENTS] §9: "a
    caller who wants issuer-accreditation checking supplies their own trust anchor as
    explicit input", which §16 item 14 has yet to design. So the check is planned, and
    no caller can supply its parameter yet.
    - *Decided* 2026-10-24: `not_implemented` until the trust anchor input exists, then
      `no_parameters_supplied` when a caller supplies none.
    - *Test:* `vcrd-core/tests/inspect.rs` `lists_status_and_schema_as_not_evaluated`,
      with the new reason. *Before:* R26. *After:* passed, with `the_example_conforms`
      and `vcrd-cli/tests/example.rs` updated likewise; the expected output files were
      regenerated, and their differences are this reason alone.

[ARCHITECTURE]: ../../ARCHITECTURE.md
[DEVELOPMENT-PLAN.md]: ../../DEVELOPMENT-PLAN.md
[did:key]: https://w3c-ccg.github.io/did-key-spec/
[multicodec table]: https://github.com/multiformats/multicodec/blob/master/table.csv
[REQUIREMENTS]: ../../REQUIREMENTS.md
[RFC 3339]: https://www.rfc-editor.org/rfc/rfc3339
[RFC 7515]: https://www.rfc-editor.org/rfc/rfc7515
[RFC 7519]: https://www.rfc-editor.org/rfc/rfc7519
[RFC 8032]: https://www.rfc-editor.org/rfc/rfc8032
[RFC 8037]: https://www.rfc-editor.org/rfc/rfc8037
[RFC 9864]: https://www.rfc-editor.org/rfc/rfc9864
[VC-JOSE-COSE]: https://www.w3.org/TR/2026/REC-vc-jose-cose-20261013/
[VCDM 2.0]: https://www.w3.org/TR/2025/REC-vc-data-model-2.0-20250515/
[WHATWG URL Standard]: https://url.spec.whatwg.org/
