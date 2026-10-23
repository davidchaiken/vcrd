# Milestone 1 review

**Scope.** [DEVELOPMENT-PLAN.md], milestone 1: the implementation reviewed against the
normative text of each standard it implements, as its milestone review lists them. The
review runs in rounds, one or two standards at a time, and this record grows with each:

| Round | Texts | State |
|---|---|---|
| 1 | [RFC 7515] (JSON Web Signature, JWS); [RFC 7519] (JSON Web Token, JWT) | below; gaps 1 and 2 fixed, gap 3 deferred |
| 2 | [RFC 8037], [RFC 9864] and [RFC 8032] (EdDSA); key resolution | to do |
| 3 | [VC-JOSE-COSE], the Recommendation of 2026-10-13, which is later than the text milestone 1 was built from (read 2026-09-19) | to do |
| 4 | [VCDM 2.0] (the Verifiable Credentials Data Model) | to do |
| 5 | the terminology check ([REQUIREMENTS] §15); slices 3–5's red-then-green records | to do |

Each round also completes the entries of [docs/findings.md](../findings.md) whose
standard it reads.

**Where checked.** Branch `milestone-1`, from `94ff6d0`. Toolchain 1.99.1 (clippy
0.1.99). Locally on macOS 27.0.1, arm64. Line numbers are those after this round's
changes, except in [Gaps found](#gaps-found), which describes `94ff6d0`.

**Texts.** Fetched on 2026-10-22 from rfc-editor.org, as plain text: [RFC 7515] and
[RFC 7519]. They came through a fetch tool's extraction, not a direct reading. Each row
abridges one sentence, or one procedural step, and keeps its keyword.

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
| §4 | MUST | Header Parameter names are unique; a recipient rejects a repeated name, or keeps the lexically last. | `Json::parse` keeps the last value and `Json::duplicate_names` lists each repeated name (`vcrd-core/src/json.rs:33`, `:79`); `duplicates` reports each as `inspect.duplicate_name` (`vc_jose.rs:145`). Verify still runs (decided 2026-09-24). | `json.rs` `keeps_duplicate_members_and_returns_the_last`, `lists_each_repeated_name_once_with_its_path_and_count`; `vcrd-core/tests/inspect.rs` `reports_each_duplicate_member_name` | Met |
| §4 | MUST | A Header Parameter that is not understood is ignored, unless `crit` lists it. | `JoseHeader::new` reads `alg`, `kid`, `typ`, `cty` and `jwk` (`vc_jose.rs:63-77`), and `crit` and `iss` are read where they are checked; nothing else is acted on. Every member appears in `format.header`. | By inspection | Met |
| §4.1.1–4.1.10 | — | Each registered Header Parameter's value has the type its section gives: a string, or for `x5c` an array of strings. | `header_members` checks each against `TYPED_HEADER_PARAMETERS` (`vc_jose.rs:157`, `:235`) and reports `inspect.header_member_type`, with the member, the type expected and the type found. `jwk` and `crit` have their own checks. | `vcrd-cli/tests/verify.rs` `a_header_member_of_the_wrong_type_is_reported`; `vcrd-core/tests/inspect.rs` `checks_that_x5c_is_an_array_of_strings` | Met: gap 1, fixed |
| §4.1.1 | MUST | `alg` is present, and a recipient understands and processes it. | The suite rejects an absent `alg` (`verify.algorithm_missing`), one that is not a string (`verify.algorithm_invalid`), `none`, and every name it does not implement (`verify.algorithm_unsupported`) (`suites/jws.rs:62-84`). | `vcrd-core/tests/verify.rs` `a_header_without_alg_is_not_verified` (new; see [checks shown to fail](#the-checks-shown-to-fail)); `vcrd-cli/tests/verify.rs` `a_header_member_of_the_wrong_type_is_reported`, `alg_none_is_rejected`, `an_algorithm_vcrd_does_not_implement_is_rejected_by_name` | Met: gap 1, fixed |
| §4.1.2, §4.1.5 | MUST | A recipient retrieving `jku` or `x5u` uses TLS and validates the server's identity. | vcrd retrieves nothing ([REQUIREMENTS] §10; [ARCHITECTURE] §8). | — | Not applicable: vcrd never retrieves keys |
| §4.1.3 | — | `jwk` is the public key that corresponds to the key that signed. | Parsed into a typed JWK (`check_jwk`, `vc_jose.rs:198`); private members reported; compared by thumbprint with the issuer's key; refused as the key unless the caller opts in ([REQUIREMENTS] §10). | `vcrd-core/tests/verify.rs` `a_jwk_with_private_members_is_an_inspect_error`, `a_malformed_jwk_does_not_stop_verify`, `an_oct_jwk_is_reported_as_symmetric_and_private`; `vcrd-cli/tests/verify.rs` `key_substitution_is_reported`, `a_key_the_credential_asserts_alone_is_refused` | Met |
| §4.1.4 | MUST (producer) | `kid` is a case-sensitive string. | Compared byte for byte (`check_kid`, `vc_jose.rs:448`). A `kid` that is not a string is `inspect.header_member_type`, not `inspect.kid_missing`. | As for §4.1.1–4.1.10 | Met: gap 1, fixed |
| §4.1.6 | MUST | A recipient validates the `x5c` chain, and treats a failure as invalid. | vcrd takes no key from `x5c`. | — | Not applicable: vcrd never uses certificates |
| §4.1.9, §4.1.10 | MUST | A recipient treats a `typ` or `cty` without `/` as if `application/` were prepended. | `media_type` lowercases and prefixes (`vc_jose.rs:223`) before comparing with `application/vc+jwt` and `application/vc`. A value that is not a string is `inspect.header_member_type` alone. | `vcrd-core/tests/inspect.rs` `checks_typ_and_cty` (`application/VC+JWT` passes); `vcrd-cli/tests/verify.rs` `a_header_member_of_the_wrong_type_is_reported` | Met: gap 1, fixed |
| §4.1.11 | MUST NOT (producer) | `crit` lists no name [RFC 7515] defines, no duplicate, no name absent from the header, and is not empty. | `check_crit` (`vc_jose.rs:264`) reports each as `inspect.crit_invalid`. | `vcrd-core/tests/inspect.rs` `checks_the_form_of_crit`; `vcrd-core/tests/verify.rs` `a_registered_name_in_crit_is_not_an_extension` | Met |
| §4.1.11 | MUST | A recipient understands and processes `crit`; an extension it does not support makes the JWS invalid. | `verify.crit_unsupported`, attributed to vcrd; the signature is still checked (`suites/jws.rs:46-60`; decided 2026-10-07). | `vcrd-cli/tests/verify.rs` `a_critical_extension_vcrd_does_not_implement_fails_verify`; `suites/jws.rs` `checks_the_signature_beside_an_unimplemented_critical_extension` | Met |
| §4.1.11 | MUST (producer) | `crit` is integrity protected: it appears only in the protected header. | A compact JWS has no other header (§7.1). | — | Met by construction |
| §5.2 step 1 | — | The compact form has three base64url segments separated by two periods. | `parse_compact` (`vc_jose.rs:542-545`) reports `parse.not_compact_jws`. | `vcrd-core/tests/parse.rs` `two_segments_is_not_a_compact_jws` | Met. A JWE's five segments: Later, gap 3 |
| §2; §5.2 steps 2, 6, 7 | — | Each segment is base64url without padding, line breaks, whitespace or other characters. | `decode` (`vc_jose.rs:708`) reports `parse.base64url_invalid` with the problem. | `vc_jose.rs` property tests `rejects_a_byte_outside_the_alphabet`, `rejects_padding`, `rejects_non_zero_discarded_bits`, `names_each_decoding_problem`; `vcrd-core/tests/parse.rs` `reports_every_bad_segment_and_keeps_the_good_ones` | Met |
| §5.2 step 3 | — | The header is a completely valid JSON object in UTF-8. | `decode_object` (`vc_jose.rs:725`) reports `parse.json_invalid` or `parse.json_not_object`. | `vcrd-core/tests/parse.rs` `reports_every_bad_segment_and_keeps_the_good_ones` | Met |
| §5.2 step 8 | MUST | `alg` is present and accurately describes the algorithm used. | The declared algorithm is checked, never obeyed: `EdDSA` is verified with an Ed25519 key only ([ARCHITECTURE] §8). | As for §4.1.1 | Met |
| §5.2, steps 9–10 | MUST | If no signature validates, the JWS is invalid. | `verify_strict` (`suites/jws.rs:105`); `verify.signature_invalid` fails verify. | `vcrd-cli/tests/verify.rs` `a_claim_changed_after_signing_fails_the_signature`; `suites/jws.rs` `rejects_rfc8037_a5_with_one_byte_changed` | Met |
| §5.2 | SHOULD | A recipient treats a JWS whose algorithm it does not accept as invalid. | `none` is always rejected; every other name vcrd does not implement is rejected by name. | `vcrd-cli/tests/verify.rs` `alg_none_is_rejected` | Met |
| §7.1 | — | A compact JWS is the three segments joined by periods, and nothing else. | Trailing ASCII whitespace is ignored and reported as `parse.trailing_whitespace`, `info`; leading whitespace is not a JWS. | `vcrd-core/tests/parse.rs` `accepts_trailing_whitespace_and_reports_it`, `leading_whitespace_is_not_a_jws`; `vcrd-cli/tests/parse.rs` `a_trailing_newline_is_reported_for_information` | Deviates: trailing whitespace, decided 2026-09-29 |

## [RFC 7519], JWT

| Section | Keyword | Sentence (abridged) | Mechanism | Check | Status |
|---|---|---|---|---|---|
| §4 | MUST | Claim names are unique; a parser rejects a repeated name, or keeps the lexically last. | As [RFC 7515] §4, for the payload. | `vcrd-core/tests/inspect.rs` `reports_each_duplicate_member_name` | Met |
| §4 | MUST | Claims an implementation does not understand are ignored. | No claim is rejected for being unknown; each is listed under `credential.claims` or `credential.metadata`. | By inspection | Met |
| §2 | — | A NumericDate counts seconds from the epoch, and may be fractional. | `proof_times` (`vc_jose.rs:316`) keeps the number as written and its value. | `vcrd-core/tests/verify.rs` `a_fractional_numeric_date_compares_as_written`, `a_numeric_date_beyond_any_calendar_compares` | Met |
| §4.1.1 | OPTIONAL | `iss` is a case-sensitive string or URI; its processing is application-specific. | [VC-JOSE-COSE] §4.1.2 defines it for credentials. | — | Round 3 |
| §4.1.2, §4.1.7 | MUST (producer) | `sub` is unique within its issuer, or globally; `jti` collides with negligible probability. | One credential cannot show uniqueness. Their agreement with `credentialSubject.id` and `id` is [VC-JOSE-COSE]'s. | — | Not applicable: producers' rules; agreement in round 3 |
| §4.1.3 | MUST | A principal that processes the JWT identifies itself with a value in `aud`; if it does not, the JWT is rejected. | vcrd is not told whom it verifies for. When `aud` is present, `not_evaluated` lists `audience`, `no_parameters_supplied` (`vc_jose.rs:371`). | `vcrd-cli/tests/verify.rs` `an_audience_is_listed_as_not_evaluated`; `vcrd-cli/tests/example.rs` `verify_exits_0_with_one_json_document` (no `aud`, no entry) | Later: the check, milestone 4. Disclosed meanwhile: gap 2, fixed |
| §4.1.4 | MUST | The JWT is not accepted on or after `exp`; a small leeway MAY allow for clock skew. | `proof_validity` (`runner.rs:243`) reports `verify.proof_expired` when `exp` is not later than the clock, less `--clock-skew`. | `vcrd-core/tests/verify.rs` `exp_equal_to_the_clock_has_expired`, `the_skew_applies_to_both_bounds`; `vcrd-cli/tests/verify.rs` `an_expired_signature_fails_verify` | Met |
| §4.1.5 | MUST | The JWT is not accepted before `nbf`; a small leeway MAY allow for clock skew. | `verify.proof_not_yet_valid` when `nbf` is later than the clock, plus the skew. | `vcrd-core/tests/verify.rs` `a_not_before_after_the_clock_fails_verify`, `the_skew_applies_to_both_bounds` | Met |
| §4.1.4–4.1.6 | MUST (producer) | `exp`, `nbf` and `iat` are NumericDates. | `inspect.numeric_date_invalid` (`vc_jose.rs:385-387`); the proof's validity is `unknown`. | `vcrd-core/tests/verify.rs` `a_time_that_is_not_a_number_leaves_the_proof_validity_unknown` | Met |
| §4.1.6 | — | `iat` is when the JWT was issued. No rule for the recipient. | `verify.proof_issued_in_future`, a warning, when it is after the clock plus the skew. | `vcrd-core/tests/verify.rs` `iat_after_the_clock_is_a_warning` | Met |
| §7.2 | MUST | If any step fails, the JWT is rejected. | Each step's failure is an error finding, which fails its phase. | The rows for each step | Met |
| §7.2 steps 1–4 | — | At least one period; the header base64url-decoded strictly; valid UTF-8 JSON. | As [RFC 7515] §5.2 steps 1–3. | As there | Met |
| §7.2 step 5 | — | Every header parameter is understood, or may be ignored. | As [RFC 7515] §4 and §4.1.11. | As there | Met |
| §7.2 step 6 | — | Determine whether the JWT is a JWS or a JWE (JSON Web Encryption). | vcrd reads only a JWS. A compact JWE's five segments are reported as `parse.not_compact_jws`, attributed to the input. | Gap 3's input | Later: [ARCHITECTURE] §10 [F3], gap 3 |
| §7.2 step 8 | — | If `cty` is `JWT`, the message is a nested JWT: start again with it. | Not read. The payload is parsed as JSON, and fails as `parse.json_invalid`, attributed to the input. | Gap 3's input | Later: [ARCHITECTURE] §10 [F3], gap 3 |
| §7.2 steps 9–10 | — | The payload is base64url-decoded strictly, and is a valid UTF-8 JSON object: the claims. | As [RFC 7515] §5.2 steps 2–3. | As there | Met |
| §7.2 | SHOULD | Reject a JWT whose algorithms the application does not accept. | As [RFC 7515] §5.2. | As there | Met |
| §7.3 | MUST | Strings are compared as Unicode code points, after JSON escapes are decoded. Outside the plan's list; read because §7.2 depends on it. | Comparisons use decoded strings: `iss` with `issuer`, `kid`; media types also lowercased, as media types are case-insensitive. | By inspection | Met |
| §5.3 | SHOULD | In a JWT that is a JWE, a recipient checks that claims replicated as Header Parameters are identical to the claims. Outside the plan's list. | vcrd reads no JWE. A header `iss` in a JWS is [VC-JOSE-COSE] §4.1.2's, in round 3. | — | Not applicable: concerns a JWE |

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

The completeness test reads the codes from `FindingDetail::code` and the anchors from
the reference. It cannot check the entries' attribution and severity: core sets them
where each finding is made, not per code. Every code has one attribution and one
severity, except `parse.no_format_matched`, attributed to vcrd when vcrd was built with
no format and to the input otherwise.

## Gaps found

At `94ff6d0`, each input was built from `examples/ed25519.jwt` and run as
`vcrd verify <input> --now 2026-10-01T00:00:00Z --format json`. Gaps 1 and 2 then got a
fixture and a test, which failed before the fix and passed after it.

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

[ARCHITECTURE]: ../../ARCHITECTURE.md
[DEVELOPMENT-PLAN.md]: ../../DEVELOPMENT-PLAN.md
[REQUIREMENTS]: ../../REQUIREMENTS.md
[RFC 7515]: https://www.rfc-editor.org/rfc/rfc7515
[RFC 7519]: https://www.rfc-editor.org/rfc/rfc7519
[RFC 8032]: https://www.rfc-editor.org/rfc/rfc8032
[RFC 8037]: https://www.rfc-editor.org/rfc/rfc8037
[RFC 9864]: https://www.rfc-editor.org/rfc/rfc9864
[VC-JOSE-COSE]: https://www.w3.org/TR/2026/REC-vc-jose-cose-20261013/
[VCDM 2.0]: https://www.w3.org/TR/2025/REC-vc-data-model-2.0-20250515/
