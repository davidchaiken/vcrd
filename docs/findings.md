# Finding codes

vcrd reports each condition it finds as a finding with a code, `<phase>.<condition>`,
such as `parse.base64url_invalid`. This reference lists every code `vcrd-core` reports,
grouped by phase. [output.md](output.md) describes a finding's keys, and
`vcrd-core/tests/finding_reference.rs` fails when a code is missing here, or listed here
and no longer reported. [Checks not evaluated](#checks-not-evaluated), at the end,
describes each check a result can list as not evaluated, and each reason;
`vcrd-cli/tests/not_evaluated_reference.rs` checks those the same way.

Each entry gives:

- **Meaning**: the condition.
- **Attribution and severity**, as the finding's `attribution` and `severity` report them.
  Only an error fails its phase. An error attributed to `vcrd` makes the exit code 6, one
  attributed to `policy` makes it 5, and one attributed to the `input` or the
  `environment` gives the code of its phase: 2 for parse, 3 for inspect, 4 for verify.
- **Detail**: the members of `detail` besides `type`, which repeats the condition.
- **Standard**: the text the condition comes from, or "none" for a rule of vcrd's own.
- **Remedy**: what the reader can do about it.

Abbreviations: JWS is JSON Web Signature ([RFC 7515]), JWT is JSON Web Token ([RFC 7519]),
JWK is JSON Web Key ([RFC 7517]), JOSE is JSON Object Signing and Encryption, VCDM is the
Verifiable Credentials Data Model, and DID is a Decentralized Identifier.

Each document named is linked to the version cited: an RFC, which never changes once
published; a W3C Recommendation by its dated address; and a document in this repository
relatively, so that it opens at the same commit as this one. The WHATWG URL Standard is a
living standard, with no fixed version to link. The did:key method, v0.9, is a W3C
Credentials Community Group draft, and the multicodec table a registry kept in a
repository; neither has a dated copy, so each is linked where it is published now.

## Parse

### <a id="parse.input_too_large"></a>`parse.input_too_large`

- **Meaning.** The input is larger than the size limit, 256 KiB. vcrd checks this before
  anything else, and reads at most one byte past the limit.
- **Attribution and severity.** `policy`, `error`.
- **Detail.** `limit`: the limit, in bytes. `read`: how many bytes vcrd read. `size`: the
  file's size, or `null` when the input is not a file.
- **Standard.** None: a structural limit ([REQUIREMENTS] §6, [ARCHITECTURE] §4).
- **Remedy.** Check that the input is the credential alone. The limit cannot yet be set
  from the command line ([DEVELOPMENT-PLAN.md], milestone 3).

### <a id="parse.nesting_too_deep"></a>`parse.nesting_too_deep`

- **Meaning.** A JSON document nests deeper than the depth limit, 32 levels. A scan finds
  this before any JSON is parsed.
- **Attribution and severity.** `policy`, `error`.
- **Detail.** `segment`: `header`, `payload` or `signature`, or `null` when the input as
  a whole is the JSON document. `limit`: the limit. `found`: the depth the scan reached.
- **Standard.** None: a structural limit ([ARCHITECTURE] §4).
- **Remedy.** As for `parse.input_too_large`.

### <a id="parse.too_many_claims"></a>`parse.too_many_claims`

- **Meaning.** The payload has more scalar values than the claim limit, 512; vcrd stopped
  listing them at the limit.
- **Attribution and severity.** `policy`, `error`.
- **Detail.** `limit`: the limit.
- **Standard.** None: a structural limit ([ARCHITECTURE] §4).
- **Remedy.** As for `parse.input_too_large`.

### <a id="parse.trailing_whitespace"></a>`parse.trailing_whitespace`

- **Meaning.** Whitespace follows the last segment, as when a file ends with a newline. A
  compact JWS has none; vcrd ignores it and says so.
- **Attribution and severity.** `input`, `info`.
- **Detail.** `bytes`: how many bytes of whitespace.
- **Standard.** [RFC 7515] §7.1. Ignoring it is vcrd's decision ([DEVELOPMENT-PLAN.md],
  milestone 1, 2026-09-29).
- **Remedy.** None needed. A stricter verifier may reject the token unless the whitespace
  is removed.

### <a id="parse.no_format_matched"></a>`parse.no_format_matched`

- **Meaning.** None of the formats vcrd knows recognized the input.
- **Attribution and severity.** `input`, `error`; `vcrd` when vcrd was built with no
  format.
- **Detail.** `registered`: the formats vcrd tried, such as `vc-jose`.
- **Standard.** None: vcrd's format detection ([ARCHITECTURE] §4).
- **Remedy.** Check that the input is a credential in one of the formats `registered`
  lists. Whitespace before a compact JWS, for instance, is not part of it.

### <a id="parse.not_compact_jws"></a>`parse.not_compact_jws`

- **Meaning.** The input looks like a compact JWS but does not have three segments.
- **Attribution and severity.** `input`, `error`.
- **Detail.** `segments`: how many dot-separated segments it has.
- **Standard.** [RFC 7515] §7.1 and §5.2 step 1.
- **Remedy.** A compact JWS is three base64url segments joined by two dots. Check that
  the token was not cut short or joined to another.

### <a id="parse.jws_json_serialization"></a>`parse.jws_json_serialization`

- **Meaning.** A JWS in JSON serialization, which vcrd does not read yet.
- **Attribution and severity.** `vcrd`, `error`.
- **Detail.** `syntax`: `general`, a `signatures` array, or `flattened`, one `signature`
  beside `payload`.
- **Standard.** [RFC 7515] §7.2. [VC-JOSE-COSE] requires implementations to support the
  compact serialization and does not recommend the JSON one, at the end of §3.1.2.
- **Remedy.** Use a verifier that reads JSON serialization. Reading it is planned
  ([ARCHITECTURE] §10 [F1]; [DEVELOPMENT-PLAN.md], milestone 4).

### <a id="parse.json_not_jws"></a>`parse.json_not_jws`

- **Meaning.** A JSON object that is not a JWS in JSON serialization: it has no
  `payload`, or neither `signature` nor `signatures`.
- **Attribution and severity.** `input`, `error`.
- **Detail.** None.
- **Standard.** [RFC 7515] §7.2.
- **Remedy.** Check that the input is a credential, not another JSON document.

### <a id="parse.data_integrity_unsupported"></a>`parse.data_integrity_unsupported`

- **Meaning.** The input is a JSON credential or presentation, an object with `@context`
  and `type`, secured by a proof inside it, as Data Integrity secures one. No format vcrd
  has reads it yet.
- **Attribution and severity.** `vcrd`, `error`.
- **Detail.** None.
- **Standard.** [VCDM 2.0] §4.12 names Data Integrity as an embedded securing mechanism.
- **Remedy.** Use a verifier that reads Data Integrity proofs. vcrd plans to read them
  in milestone 5 ([DEVELOPMENT-PLAN.md]).

### <a id="parse.not_secured"></a>`parse.not_secured`

- **Meaning.** The input is a JSON credential or presentation, an object with `@context`
  and `type`, with no `proof`: nothing secures it, so there is nothing to verify.
- **Attribution and severity.** `input`, `error`.
- **Detail.** None.
- **Standard.** [VCDM 2.0] §1.3: a conforming document MUST be secured by at least one
  securing mechanism (§4.12).
- **Remedy.** Nothing shows who made the credential, or that it is unchanged. Obtain it
  secured, as a JWS or with a proof.

### <a id="parse.base64url_invalid"></a>`parse.base64url_invalid`

- **Meaning.** A segment is not strict base64url.
- **Attribution and severity.** `input`, `error`.
- **Detail.** `segment`: `header`, `payload` or `signature`. `problem`:
  `invalid_symbol`, a byte outside the base64url alphabet, such as `+`, `/`, a space or a
  line break; `nonzero_trailing_bits`, bits after the last whole byte that must be zero;
  `invalid_length`, one more than a multiple of four, which no base64url text has; or
  `padding`, an `=`, which JWS omits.
- **Standard.** [RFC 7515] §2, and §5.2 steps 2, 6 and 7.
- **Remedy.** A token copied from a document or a terminal may have gained line breaks or
  spaces, and removing them restores it. Otherwise the issuer encoded it incorrectly.

### <a id="parse.json_invalid"></a>`parse.json_invalid`

- **Meaning.** A decoded segment, or the input as a whole, is not valid JSON in UTF-8.
- **Attribution and severity.** `input`, `error`.
- **Detail.** `segment`: `header`, `payload` or `signature`, or `null` for the input as a
  whole. `line`, `column`: where the JSON parser stopped.
- **Standard.** [RFC 7515] §5.2 step 3 for the header; [RFC 7519] §7.2 step 10 for the
  claims; [RFC 8259] for JSON.
- **Remedy.** Decoding the segment shows its text, and `line` and `column` point into it.
  The issuer must fix the credential.

### <a id="parse.json_not_object"></a>`parse.json_not_object`

- **Meaning.** A decoded segment is JSON but not an object.
- **Attribution and severity.** `input`, `error`.
- **Detail.** `segment`: `header` or `payload`.
- **Standard.** [RFC 7515] §5.2 step 3; [RFC 7519] §7.2 step 10.
- **Remedy.** The issuer must fix the credential.

## Inspect

### <a id="inspect.duplicate_name"></a>`inspect.duplicate_name`

- **Meaning.** A member name appears more than once in one object. vcrd keeps the last
  value, as [RFC 7515] §4 and [RFC 7519] §4 permit, reports each repeated name, and still
  verifies.
- **Attribution and severity.** `input`, `error`.
- **Detail.** `segment`: `header` or `payload`, or `null` when the input as a whole is
  the JSON document. `path`: where the name repeats. `count`: how many times it appears.
- **Standard.** [RFC 7515] §4; [RFC 7519] §4.
- **Remedy.** Software that keeps the first value instead reads a different credential
  from the same bytes. The issuer must reissue it with unique names.

### <a id="inspect.crit_invalid"></a>`inspect.crit_invalid`

- **Meaning.** The header's `crit` (Critical) breaks one of the rules for its value.
- **Attribution and severity.** `input`, `error`.
- **Detail.** `problem`: `not_array`; `empty`; `{"not_string": index}`, the item at that
  position; `{"duplicate": name}`; `{"registered": name}`, a name [RFC 7515] defines, which
  `crit` must not list; or `{"not_in_header": name}`.
- **Standard.** [RFC 7515] §4.1.11.
- **Remedy.** The issuer must fix the header.

### <a id="inspect.header_member_type"></a>`inspect.header_member_type`

- **Meaning.** A Header Parameter [RFC 7515] defines has a value of the wrong JSON type,
  such as a `kid` that is a number. It is reported as this, not as absent. `jwk` and
  `crit` have findings of their own.
- **Attribution and severity.** `input`, `error`.
- **Detail.** `member`: one of `alg`, `jku`, `kid`, `x5u`, `x5c`, `x5t`, `x5t#S256`,
  `typ` or `cty`. `expected`: `string`, or `array_of_strings` for `x5c`. `found`: the
  value's JSON type, `null`, `bool`, `number`, `string`, `array` or `object`; `array`
  for an `x5c` with an item that is not a string.
- **Standard.** [RFC 7515] §4.1.1–4.1.10.
- **Remedy.** The issuer must fix the header. An `alg` of the wrong type also stops
  verify (`verify.algorithm_invalid`).

### <a id="inspect.jwk_invalid"></a>`inspect.jwk_invalid`

- **Meaning.** The header's `jwk` is not a public key in a form the JWK specifications
  define. It does not stop verify, which takes the key from the issuer identifier.
- **Attribution and severity.** `input`, `error`.
- **Detail.** `problem`: `not_object`; `kty_missing`; `symmetric`, a `kty` of `oct`,
  which is a secret key; `{"member_missing": member}`, a member the key type requires; or
  `key_invalid`, an Ed25519 `x` that is not 32 bytes of strict base64url, or not a point.
- **Standard.** [RFC 7515] §4.1.3; [RFC 7517] §4; [RFC 7518] §6; [RFC 8037] §2.
- **Remedy.** The issuer must fix the header. A `symmetric` key in a credential is
  exposed to every reader of it, and anything it protects can be forged.

### <a id="inspect.jwk_kty_unsupported"></a>`inspect.jwk_kty_unsupported`

- **Meaning.** The header's `jwk` has a key type vcrd cannot read, so vcrd cannot compare
  it with the issuer key or make a proof with it.
- **Attribution and severity.** `vcrd`, `warning`.
- **Detail.** `kty`: the key type.
- **Standard.** [RFC 7517] §4.1.
- **Remedy.** None needed: an embedded key never decides the outcome when there is an
  issuer key, and this one is treated as not present ([ARCHITECTURE] §8, "Keys and
  proofs"). Only the comparison and its proof are missing.

### <a id="inspect.jwk_private_key"></a>`inspect.jwk_private_key`

- **Meaning.** The header's `jwk` carries private-key members, such as `d`, so whoever
  has the credential has the private key. vcrd shows their values only at `--unsafe 2`.
- **Attribution and severity.** `input`, `error`.
- **Detail.** `members`: the private members present.
- **Standard.** [RFC 7515] §4.1.3: `jwk` is the public key.
- **Remedy.** Treat the key as compromised: anything it signed can be forged. Its holder
  must replace it.

### <a id="inspect.numeric_date_invalid"></a>`inspect.numeric_date_invalid`

- **Meaning.** `exp`, `nbf` or `iat` is not a number. The proof's `validity` is then
  `unknown`.
- **Attribution and severity.** `input`, `error`.
- **Detail.** `claim`: the claim.
- **Standard.** [RFC 7519] §2 (NumericDate) and §4.1.4–4.1.6.
- **Remedy.** The issuer must fix the claim.

### <a id="inspect.context_missing"></a>`inspect.context_missing`

- **Meaning.** The credential has no `@context`.
- **Attribution and severity.** `input`, `error`.
- **Detail.** None.
- **Standard.** [VCDM 2.0] §4.3: credentials MUST include `@context`.
- **Remedy.** The payload is not a [VCDM 2.0] credential. One with a `vc` claim is
  [VCDM 1.1]'s encoding, reported as `inspect.vcdm_1_1_jwt_encoding` instead.

### <a id="inspect.context_first_invalid"></a>`inspect.context_first_invalid`

- **Meaning.** The first `@context` item is not `https://www.w3.org/ns/credentials/v2`.
- **Attribution and severity.** `input`, `error`.
- **Detail.** `found`: that item when it is a string, otherwise `null`.
- **Standard.** [VCDM 2.0] §4.3: `@context` MUST be an ordered set whose first item is
  that URL. A single value is read as a set of one.
- **Remedy.** `https://www.w3.org/2018/credentials/v1` first means a [VCDM 1.1]
  credential, which vcrd does not read yet ([ARCHITECTURE] §10 [F2]).

### <a id="inspect.context_entry_invalid"></a>`inspect.context_entry_invalid`

- **Meaning.** A later `@context` item is neither a string nor an object.
- **Attribution and severity.** `input`, `error`.
- **Detail.** `path`: the item.
- **Standard.** [VCDM 2.0] §4.3: later items MUST be URLs and objects, each processable
  as a JSON-LD context. A string item is checked as a URL (`inspect.url_invalid`);
  whether an item is processable needs JSON-LD, which vcrd does not do yet, and
  `not_evaluated` says so as `context_resolution`.
- **Remedy.** The issuer must list contexts as URLs or objects.

### <a id="inspect.type_missing"></a>`inspect.type_missing`

- **Meaning.** An object that must have a `type` has none, or an empty one.
- **Attribution and severity.** `input`, `error`.
- **Detail.** `path`: the object.
- **Standard.** [VCDM 2.0] §4.5: credentials MUST contain `type`, and its table lists the
  objects that MUST have one: `credentialStatus` (also §4.10), `termsOfUse`, `evidence`,
  `refreshService` and `credentialSchema` (also §4.11).
- **Remedy.** The issuer must give the object its type.

### <a id="inspect.type_not_string"></a>`inspect.type_not_string`

- **Meaning.** A `type` value is not a string.
- **Attribution and severity.** `input`, `error`.
- **Detail.** `path`: the value.
- **Standard.** [VCDM 2.0] §4.5: the value of `type` MUST be one or more terms and
  absolute URL strings. Whether a string is a term or an absolute URL depends on the
  contexts, which vcrd does not process yet.
- **Remedy.** The issuer must write each type as a string.

### <a id="inspect.type_lacks_verifiable_credential"></a>`inspect.type_lacks_verifiable_credential`

- **Meaning.** The credential's `type` does not include `VerifiableCredential`.
- **Attribution and severity.** `input`, `error`.
- **Detail.** None.
- **Standard.** [VCDM 2.0] §4.5's table: a credential's type includes
  `VerifiableCredential`.
- **Remedy.** A `type` with `VerifiablePresentation` instead is a presentation, reported
  as `inspect.presentation_unsupported`. Otherwise the issuer must add the type.

### <a id="inspect.issuer_missing"></a>`inspect.issuer_missing`

- **Meaning.** The credential has no `issuer`. With no issuer identifier, no key can be
  derived from one, so verify does not run unless another key source is available.
- **Attribution and severity.** `input`, `error`.
- **Detail.** None.
- **Standard.** [VCDM 2.0] §4.7: a verifiable credential MUST have an `issuer`.
- **Remedy.** Nothing says who issued the credential. `phases.verify.blocked_by` says
  where vcrd looked for a key.

### <a id="inspect.issuer_invalid"></a>`inspect.issuer_invalid`

- **Meaning.** `issuer` is neither a URL nor an object whose `id` is a URL. Verify is
  blocked as for `inspect.issuer_missing`.
- **Attribution and severity.** `input`, `error`.
- **Detail.** `problem`: `wrong_type`, neither a string nor an object; `no_id`, an object
  without a string `id`; or `{"not_url": error}`, with the URL parser's error.
- **Standard.** [VCDM 2.0] §4.7: `issuer` MUST be a URL or an object whose `id` is a URL;
  §2 defines a URL by the [WHATWG URL Standard].
- **Remedy.** As for `inspect.issuer_missing`.

### <a id="inspect.credential_subject_missing"></a>`inspect.credential_subject_missing`

- **Meaning.** The credential has no `credentialSubject`.
- **Attribution and severity.** `input`, `error`.
- **Detail.** None.
- **Standard.** [VCDM 2.0] §4.8: a verifiable credential MUST contain a
  `credentialSubject`.
- **Remedy.** The credential states no claims. The issuer must add its subjects.

### <a id="inspect.credential_subject_invalid"></a>`inspect.credential_subject_invalid`

- **Meaning.** A subject is not an object.
- **Attribution and severity.** `input`, `error`.
- **Detail.** `path`: the subject.
- **Standard.** [VCDM 2.0] §4.8: `credentialSubject` is a set of objects.
- **Remedy.** The issuer must write each subject as an object.

### <a id="inspect.credential_subject_empty"></a>`inspect.credential_subject_empty`

- **Meaning.** An empty subject object, or an empty set of subjects: present, and the
  subject of no claim.
- **Attribution and severity.** `input`, `error`.
- **Detail.** `path`: the subject, or the set.
- **Standard.** [VCDM 2.0] §4.8: each object MUST be the subject of one or more claims
  ([ARCHITECTURE] §10 [S5]).
- **Remedy.** As for `inspect.credential_subject_missing`.

### <a id="inspect.credential_subject_no_claims"></a>`inspect.credential_subject_no_claims`

- **Meaning.** A subject with an `id` and nothing else.
- **Attribution and severity.** `input`, `warning`.
- **Detail.** `path`: the subject.
- **Standard.** [VCDM 2.0] §4.8: each object MUST be the subject of one or more claims.
  vcrd reports one with only an `id` as a warning, not an error ([DEVELOPMENT-PLAN.md],
  milestone 1, decided 2026-10-01).
- **Remedy.** The credential names a subject and says nothing about it. Check that
  nothing was removed from it.

### <a id="inspect.url_invalid"></a>`inspect.url_invalid`

- **Meaning.** A value that must be a URL is not one under the [WHATWG URL Standard]. The
  value is not shown, since it may be a claim.
- **Attribution and severity.** `input`, `error`.
- **Detail.** `path`: the value. `error`: the URL parser's error.
- **Standard.** [VCDM 2.0] §2 defines a URL by the [WHATWG URL Standard]; §4.3 for a
  `@context` item, §4.4 for an `id`.
- **Remedy.** The issuer must write the value as a URL. A relative one, such as
  `/credentials/1`, is not.

### <a id="inspect.url_nonconforming"></a>`inspect.url_nonconforming`

- **Meaning.** A URL parses only after the parser corrected it, which the URL Standard
  calls a validation error.
- **Attribution and severity.** `input`, `warning`.
- **Detail.** `path`: the value. `violations`: the corrections, by the URL Standard's
  names.
- **Standard.** The [WHATWG URL Standard]'s validation errors. A warning, since the URL
  parses ([DEVELOPMENT-PLAN.md], milestone 1, decided 2026-10-01).
- **Remedy.** Another parser may read the URL differently, or reject it. The issuer can
  write it as the parser corrected it.

### <a id="inspect.id_missing"></a>`inspect.id_missing`

- **Meaning.** An object that must have an `id` has none: a `credentialSchema`. An `id`
  that is present and not a URL is `inspect.url_invalid` instead.
- **Attribution and severity.** `input`, `error`.
- **Detail.** `path`: the object, such as `credentialSchema[1]`.
- **Standard.** [VCDM 2.0] §4.11: each `credentialSchema` MUST have an `id`, a URL
  identifying the schema.
- **Remedy.** Without it, no verifier can find the schema. vcrd does not check schemas
  yet, and `not_evaluated` lists `schema_conformance`.

### <a id="inspect.language_value_invalid"></a>`inspect.language_value_invalid`

- **Meaning.** The credential's `name` or `description` is neither a string nor a
  language value object, nor an array of them.
- **Attribution and severity.** `input`, `warning`. A warning, though [VCDM 2.0] §4.6
  says MUST: both properties are optional, which §1.3 lets a verifier ignore, and the
  Recommendation's own Example 40 gives `name` a map keyed by language.
- **Detail.** `path`: the value, such as `name` or `description[0]`. `problem`:
  `wrong_type`, neither a string nor an object; `value_missing`, an object without a
  string `@value`; or `{"other_member": name}`, an object with a member other than
  `@value`, `@language` and `@direction`.
- **Standard.** [VCDM 2.0] §4.6 and §11.1.
- **Remedy.** Software that shows the credential's name may show nothing, or the wrong
  text. The issuer can write it as a string, or as `{"@value": …, "@language": …}`.

### <a id="inspect.date_time_invalid"></a>`inspect.date_time_invalid`

- **Meaning.** A validity bound is not an [XML Schema 1.1] `dateTimeStamp`.
- **Attribution and severity.** `input`, `error`.
- **Detail.** `field`: `validFrom` or `validUntil`. `valid_rfc3339`: whether [RFC 3339]
  would accept the value.
- **Standard.** [VCDM 2.0] §4.9: each MUST be a `dateTimeStamp` string. Where XML Schema
  and [RFC 3339] differ, vcrd follows XML Schema; [ARCHITECTURE] §4 lists the
  differences.
- **Remedy.** With `valid_rfc3339: true`, a verifier that reads RFC 3339 accepts the
  value; the issuer can write it as a `dateTimeStamp`, such as `2026-10-01T00:00:00Z`.

### <a id="inspect.date_time_unrepresentable"></a>`inspect.date_time_unrepresentable`

- **Meaning.** A `dateTimeStamp` outside the years vcrd can represent, -9999 to 9999.
- **Attribution and severity.** `vcrd`, `error`.
- **Detail.** `field`: `validFrom` or `validUntil`.
- **Standard.** None: [VCDM 2.0] §4.9 allows any year XML Schema does, and the `time`
  crate vcrd reads dates with stops at 9999 ([ARCHITECTURE] §4).
- **Remedy.** Use a verifier that represents the year. vcrd cannot compare the bound with
  the clock, so the credential's `validity` is `unknown`.

### <a id="inspect.valid_until_before_valid_from"></a>`inspect.valid_until_before_valid_from`

- **Meaning.** `validUntil` is earlier than `validFrom`.
- **Attribution and severity.** `input`, `error`.
- **Detail.** `valid_from`, `valid_until`: the two bounds.
- **Standard.** [VCDM 2.0] §4.9: `validUntil` MUST be the same as or later than
  `validFrom` ([ARCHITECTURE] §10 [S3]).
- **Remedy.** The credential is never valid. The issuer may have swapped the bounds.

### <a id="inspect.typ_unexpected"></a>`inspect.typ_unexpected`

- **Meaning.** The header's `typ` (Type) is absent, or not `vc+jwt`: `vp+jwt` for a
  presentation.
- **Attribution and severity.** `input`, `warning`.
- **Detail.** `found`: the value, or `null` when absent. `expected`: `vc+jwt` or `vp+jwt`.
  A `typ` that is not a string is `inspect.header_member_type` instead.
- **Standard.** [VC-JOSE-COSE] §3.1.1: `typ` SHOULD be `vc+jwt`; §3.1.2: `vp+jwt` for a
  presentation. Compared as a media type, ignoring case, with `application/` implied
  before a value with no `/` ([RFC 7515] §4.1.9).
- **Remedy.** None needed to verify. A verifier that checks `typ` may reject the token;
  the issuer can set it to `expected`.

### <a id="inspect.cty_unexpected"></a>`inspect.cty_unexpected`

- **Meaning.** The header's `cty` (Content Type) is present and not `vc`: `vp` for a
  presentation.
- **Attribution and severity.** `input`, `warning`.
- **Detail.** `found`: the value. `expected`: `vc` or `vp`.
- **Standard.** [VC-JOSE-COSE] §3.1.1 and §3.1.2: when present, `cty` SHOULD be `vc`, or
  `vp` for a presentation. Compared as `typ` is ([RFC 7515] §4.1.10).
- **Remedy.** As for `inspect.typ_unexpected`; the issuer can also leave `cty` out.

### <a id="inspect.vcdm_1_1_jwt_encoding"></a>`inspect.vcdm_1_1_jwt_encoding`

- **Meaning.** The payload follows [VCDM 1.1]'s JWT encoding: the credential inside a `vc`
  claim, or a presentation inside `vp`, with no [VCDM 2.0] `@context`. vcrd does not read
  it yet, and does not verify it.
- **Attribution and severity.** `vcrd`, `error`.
- **Detail.** `claim`: `vc` or `vp`.
- **Standard.** [VCDM 1.1]'s JWT encoding. [VC-JOSE-COSE] §1.1.2.1 forbids `vc` and `vp`
  in a credential it secures, so this is not a [VC-JOSE-COSE] credential.
- **Remedy.** Use a verifier that reads [VCDM 1.1]'s JWTs. vcrd plans to read them in
  milestone 5 ([ARCHITECTURE] §10 [F2]).

### <a id="inspect.presentation_unsupported"></a>`inspect.presentation_unsupported`

- **Meaning.** The payload is a verifiable presentation: its `type` has
  `VerifiablePresentation` and not `VerifiableCredential`. vcrd does not read
  presentations yet, so it does not check this one as a credential, and does not verify
  it: a presentation names a holder, not an issuer. `credential.kind` is
  `presentation`.
- **Attribution and severity.** `vcrd`, `error`.
- **Detail.** None.
- **Standard.** [VC-JOSE-COSE] §3.1.2 secures presentations; [VCDM 2.0] defines them.
- **Remedy.** Use a verifier that reads presentations, or verify each credential the
  presentation carries on its own. vcrd reads presentations from milestone 4
  ([DEVELOPMENT-PLAN.md]).

### <a id="inspect.jwt_claim_forbidden"></a>`inspect.jwt_claim_forbidden`

- **Meaning.** A `vc` or `vp` claim beside a [VCDM 2.0] payload.
- **Attribution and severity.** `input`, `error`.
- **Detail.** `claim`: `vc` or `vp`.
- **Standard.** [VC-JOSE-COSE] §1.1.2.1: `vc` and `vp` MUST NOT be present in a JWT
  Claims Set that is a credential or a presentation.
- **Remedy.** The payload mixes [VCDM 1.1]'s encoding with [VCDM 2.0]'s. Obtain the
  credential again from its issuer, in one of them.

### <a id="inspect.iss_mismatch"></a>`inspect.iss_mismatch`

- **Meaning.** `iss` (Issuer) does not match `issuer`, or `issuer.id`.
- **Attribution and severity.** `input`, `error`.
- **Detail.** `location`: `header` or `payload`, where the `iss` is. `iss`: its value.
  `issuer`: the credential's issuer identifier. An `iss` that is not a string is
  `inspect.jwt_claim_type` instead.
- **Standard.** [VC-JOSE-COSE] §4.1.2: `iss`, if present, MUST match `issuer`, or
  `issuer.id` when `issuer` is an object. Compared exactly, as [RFC 7519] §7.3 compares
  strings.
- **Remedy.** vcrd takes the key from `issuer`, so the finding says that the two
  disagree, not which is right. A verifier that reads `iss` would look for another
  issuer's key.

### <a id="inspect.jwt_claim_conflict"></a>`inspect.jwt_claim_conflict`

- **Meaning.** A JWT claim and the credential property for the same thing are both
  present and differ: `jti` and `id`, or `sub` and `credentialSubject.id`. The values are
  not shown, since they are claims.
- **Attribution and severity.** `input`, `warning`.
- **Detail.** `claim`: `jti` or `sub`. `property`: `id` or `credentialSubject.id`.
- **Standard.** [VC-JOSE-COSE] §3.1.3, a non-normative section: implementers SHOULD avoid
  JWT claims whose values conflict with the credential's properties.
- **Remedy.** A reader of the JWT claims and a reader of the credential would identify
  different things. `--unsafe` shows both values. A claim that is not a string is
  `inspect.jwt_claim_type` instead.

### <a id="inspect.jwt_claim_type"></a>`inspect.jwt_claim_type`

- **Meaning.** A registered JWT claim's value has the wrong JSON type. It is reported as
  that, and not compared with the credential.
- **Attribution and severity.** `input`, `error`.
- **Detail.** `location`: `payload`, or `header` for an `iss` there. `claim`: `iss`,
  `sub`, `jti` or `aud`. `expected`: `string`, or for `aud`
  `string_or_array_of_strings`. `found`: the value's JSON type.
- **Standard.** [RFC 7519] §4.1.1, §4.1.2 and §4.1.7 make `iss`, `sub` and `jti` strings,
  and §4.1.3 makes `aud` a string or an array of strings. [VC-JOSE-COSE] §3.1.3 has
  registered claims interpreted as their specifications define.
- **Remedy.** The issuer must give the claim the type its specification does.

### <a id="inspect.replicated_claim_mismatch"></a>`inspect.replicated_claim_mismatch`

- **Meaning.** A claim replicated as a header parameter differs from the claim in the
  payload. The values are not shown, since they may be claims.
- **Attribution and severity.** `input`, `warning`.
- **Detail.** `claim`: its name. `iss` is compared with the issuer instead, as
  `inspect.iss_mismatch`, and the header parameters [RFC 7515] defines are not claims.
- **Standard.** [RFC 7519] §5.3: a recipient SHOULD check that a replicated claim is
  identical to the claim. [VC-JOSE-COSE] §3.1.3 applies §5.3 to credentials.
- **Remedy.** vcrd reads claims from the payload. A reader of the header sees another
  value; `--unsafe` shows the payload's.

### <a id="inspect.kid_missing"></a>`inspect.kid_missing`

- **Meaning.** No `kid` (Key ID) where one is required: the issuer is a DID, or `iss` is
  absent and the issuer is a URL. A `kid` that is not a string is
  `inspect.header_member_type` instead.
- **Attribution and severity.** `input`, `error`.
- **Detail.** None.
- **Standard.** [VC-JOSE-COSE] §4.1.1: `kid` MUST be present when the issuer's key is
  expressed as a DID URL. §4.2: with `iss` absent and the issuer a URL, `kid` MUST be an
  absolute URL to a verification method.
- **Remedy.** vcrd never chooses the key by `kid`, so verify is unaffected. A verifier
  that does may not find the key.

### <a id="inspect.kid_not_absolute"></a>`inspect.kid_not_absolute`

- **Meaning.** `kid` is not an absolute URL, where `iss` is absent and the issuer is a
  URL.
- **Attribution and severity.** `input`, `error`.
- **Detail.** `kid`: its value.
- **Standard.** [VC-JOSE-COSE] §4.2.
- **Remedy.** As for `inspect.kid_missing`. With `iss` present, a relative `kid` is
  resolved against the issuer instead, and is not reported.

### <a id="inspect.kid_foreign"></a>`inspect.kid_foreign`

- **Meaning.** `kid`, resolved against the issuer when relative, does not identify one of
  the issuer's keys.
- **Attribution and severity.** `input`, `error`.
- **Detail.** `kid`: its value. `issuer`: the issuer identifier. `expected`: the key's
  identifier when the DID method determines it, as `did:key` does, otherwise `null`.
- **Standard.** [VC-JOSE-COSE] §4.1.1 requires `kid` when the issuer's key is a DID URL;
  vcrd reads that as requiring the issuer's key's DID URL, not another one
  ([DEVELOPMENT-PLAN.md], milestone 1, known input 4). [RFC 7515] §4.1.4 makes `kid` a
  hint.
- **Remedy.** vcrd verifies with the issuer's key whatever `kid` says. A verifier that
  follows `kid` would look for another key.

### <a id="inspect.kid_without_thumbprint"></a>`inspect.kid_without_thumbprint`

- **Meaning.** The issuer is a URL that is not a DID, and `kid` does not include a JWK
  Thumbprint URI.
- **Attribution and severity.** `input`, `warning`.
- **Detail.** `kid`: its value.
- **Standard.** [VC-JOSE-COSE] §4.2: with URL identifiers, `kid` is RECOMMENDED to be an
  absolute URL that includes a JWK Thumbprint URI ([RFC 7638]). vcrd applies it to URLs
  other than DIDs, whose key identifiers each DID method defines ([DEVELOPMENT-PLAN.md],
  milestone 1).
- **Remedy.** None needed to verify. A thumbprint in `kid` lets a verifier check the key
  it finds against the one the issuer meant.

### <a id="inspect.expired"></a>`inspect.expired`

- **Meaning.** `validUntil` is earlier than the clock, less the skew.
- **Attribution and severity.** `input`, `error`.
- **Detail.** `valid_until`, `now`, `skew_seconds`.
- **Standard.** [VCDM 2.0] §4.9 defines `validUntil`, and §2 makes verification ask
  whether the credential is a current statement. The signature's own expiry is
  `verify.proof_expired`.
- **Remedy.** `--now` checks the credential as of another time, and `--clock-skew`
  allows for clocks that differ.

### <a id="inspect.not_yet_valid"></a>`inspect.not_yet_valid`

- **Meaning.** `validFrom` is later than the clock, plus the skew.
- **Attribution and severity.** `input`, `error`.
- **Detail.** `valid_from`, `now`, `skew_seconds`.
- **Standard.** As for `inspect.expired`, with `validFrom`.
- **Remedy.** As for `inspect.expired`.

## Verify

### <a id="verify.no_proof"></a>`verify.no_proof`

- **Meaning.** The input carries nothing to verify.
- **Attribution and severity.** `input`, `error`.
- **Detail.** None.
- **Standard.** [VCDM 2.0] §1.3: a conforming document MUST be secured by at least one
  securing mechanism (§4.12).
- **Remedy.** Not reported in milestone 1: a compact JWS whose header or signature does
  not decode fails parse, which blocks verify. A format whose credentials carry the proof
  inside them, as Data Integrity's do, reports it for a credential with none.

### <a id="verify.suite_unavailable"></a>`verify.suite_unavailable`

- **Meaning.** A proof needs a proof suite this build of vcrd does not include.
- **Attribution and severity.** `vcrd`, `error`.
- **Detail.** `suite`: the suite, such as `jws`.
- **Standard.** None: vcrd's suite registry ([ARCHITECTURE] §5).
- **Remedy.** Use a build of vcrd with that suite's Cargo feature enabled.

### <a id="verify.algorithm_missing"></a>`verify.algorithm_missing`

- **Meaning.** The JWS header has no `alg` (Algorithm). Verify does not check the
  signature.
- **Attribution and severity.** `input`, `error`.
- **Detail.** None.
- **Standard.** [RFC 7515] §4.1.1 and §5.2 step 8.
- **Remedy.** The issuer must name the algorithm.

### <a id="verify.algorithm_invalid"></a>`verify.algorithm_invalid`

- **Meaning.** `alg` is present and not a string, so it names no algorithm. Verify does
  not check the signature. Inspect reports the same member as
  `inspect.header_member_type`.
- **Attribution and severity.** `input`, `error`.
- **Detail.** `found`: the value's JSON type.
- **Standard.** [RFC 7515] §4.1.1.
- **Remedy.** The issuer must name the algorithm as a string.

### <a id="verify.algorithm_none"></a>`verify.algorithm_none`

- **Meaning.** `alg` is `none`: the JWS is unsecured. vcrd always rejects it, whatever
  the caller's policy.
- **Attribution and severity.** `input`, `error`.
- **Detail.** None.
- **Standard.** [RFC 7515] §5.2, which tells a verifier to reject an algorithm it does not
  accept; [RFC 7518] §3.6 defines `none`. vcrd's rule is [ARCHITECTURE] §8.
- **Remedy.** The credential is not signed. Obtain a signed one.

### <a id="verify.algorithm_unsupported"></a>`verify.algorithm_unsupported`

- **Meaning.** vcrd does not implement the declared algorithm, so it does not check the
  signature.
- **Attribution and severity.** `vcrd`, `error`.
- **Detail.** `declared`: the algorithm the header names. `supported`: those vcrd
  implements.
- **Standard.** [RFC 7515] §4.1.1, which requires a verifier to understand `alg`;
  [REQUIREMENTS] §10.
- **Remedy.** Use a verifier that implements `declared`. vcrd's algorithms grow in
  milestone 2 ([DEVELOPMENT-PLAN.md]).

### <a id="verify.algorithm_deprecated"></a>`verify.algorithm_deprecated`

- **Meaning.** The header names its algorithm by a deprecated name: `EdDSA`, which
  [RFC 9864] replaces with one name per curve. vcrd checks the signature as usual, and
  this alone never fails verify.
- **Attribution and severity.** `input`, `info`. `text` and `plain` list it from
  verbosity level 2, and count it at level 1.
- **Detail.** `declared`: the name in the header. `replacement`: the name that replaces
  it for the key vcrd resolved, such as `Ed25519`, or `null` when no key was resolved.
- **Standard.** [RFC 9864] §2.2 and §4.1.2. Its §4.4 says new deployments SHOULD use the
  replacement, and it sets no rule for a verifier.
- **Remedy.** None needed. An issuer can declare `replacement` instead; a verifier
  written before [RFC 9864] may not know the new name.

### <a id="verify.signature_length"></a>`verify.signature_length`

- **Meaning.** The signature has the wrong length for its algorithm, so it is not
  checked.
- **Attribution and severity.** `input`, `error`.
- **Detail.** `algorithm`: as the header names it. `expected`, `found`: lengths, in
  bytes.
- **Standard.** [RFC 8037] §3.1 makes the JWS Signature the EdDSA signature, which
  [RFC 8032] §5.1.7 step 1 splits into two 32-byte halves.
- **Remedy.** Check that the third segment is the whole signature, and that the
  algorithm is the one the issuer used.

### <a id="verify.signature_invalid"></a>`verify.signature_invalid`

- **Meaning.** The signature does not verify under the key vcrd resolved: the header or
  payload changed after signing, or a different key signed it.
- **Attribution and severity.** `input`, `error`.
- **Detail.** `algorithm`: the algorithm checked.
- **Standard.** [RFC 7515] §5.2 steps 9 and 10; for Ed25519, [RFC 8032] §5.1.7. vcrd
  checks [S]B = R + [k]A', which §5.1.7 allows in place of the same equation multiplied
  by 8; a verifier that checks that one can accept a signature vcrd rejects (§8.8).
- **Remedy.** Any change to a segment invalidates the signature, re-encoding included.
  Compare `key_provenance` with the key the issuer says it signed with.

### <a id="verify.signature_small_order"></a>`verify.signature_small_order`

- **Meaning.** The R of an Ed25519 signature has small order. A verifier that checks only
  the group equation can accept such a signature; vcrd rejects it.
- **Attribution and severity.** `input`, `error`.
- **Detail.** `algorithm`: as the header names it.
- **Standard.** None requires the rejection: [RFC 8032] §5.1.7 accepts any R that
  decodes. Signing never produces such an R, so the signature was constructed some other
  way. vcrd uses the strictest verification its library offers, which rejects it, and
  names the reason ([REQUIREMENTS] §10; [ARCHITECTURE] §8).
- **Remedy.** Obtain the credential again from its issuer. Another verifier may accept
  this signature.

### <a id="verify.signature_scalar_out_of_range"></a>`verify.signature_scalar_out_of_range`

- **Meaning.** The S of an Ed25519 signature is not less than the group order L, so the
  signature is invalid. Signing never produces such an S; a verifier that does not check
  the range accepts S + L wherever it accepts S, so it is usually a valid signature
  changed afterward.
- **Attribution and severity.** `input`, `error`.
- **Detail.** `algorithm`: as the header names it.
- **Standard.** [RFC 8032] §5.1.7 step 1, and §8.4 on why the check matters. vcrd checks
  it itself, since `ed25519-dalek` skips it when another crate in the same build turns on
  its `legacy_compatibility` feature ([ARCHITECTURE] §8).
- **Remedy.** Obtain the credential again from its issuer. Another verifier may accept
  this signature.

### <a id="verify.crit_unsupported"></a>`verify.crit_unsupported`

- **Meaning.** `crit` lists extensions vcrd does not implement, so the JWS is invalid.
  vcrd still checks the signature and reports its outcome, for information.
- **Attribution and severity.** `vcrd`, `error`.
- **Detail.** `extensions`: those vcrd does not implement. `supported`: those it does,
  none yet.
- **Standard.** [RFC 7515] §4.1.11.
- **Remedy.** Use a verifier that implements the extensions.

### <a id="verify.proof_expired"></a>`verify.proof_expired`

- **Meaning.** `exp` is not later than the clock, less the skew: the signature has
  expired, whatever the credential's own validity period says.
- **Attribution and severity.** `input`, `error`.
- **Detail.** `claim`: `exp`. `value`: the number as written. `value_date_time`: the same
  instant as an [RFC 3339] date-time, or `null` outside the years -9999 to 9999. `now`: the
  clock. `skew_seconds`: the skew allowed.
- **Standard.** [RFC 7519] §4.1.4; [VC-JOSE-COSE] §3.1.3.
- **Remedy.** `--now` checks the signature as of another time, and `--clock-skew` allows
  for clocks that differ.

### <a id="verify.proof_not_yet_valid"></a>`verify.proof_not_yet_valid`

- **Meaning.** `nbf` (Not Before) is later than the clock, plus the skew.
- **Attribution and severity.** `input`, `error`.
- **Detail.** As for `verify.proof_expired`, with `claim` `nbf`.
- **Standard.** [RFC 7519] §4.1.5.
- **Remedy.** As for `verify.proof_expired`.

### <a id="verify.proof_issued_in_future"></a>`verify.proof_issued_in_future`

- **Meaning.** `iat` (Issued At) is later than the clock, plus the skew. [RFC 7519] sets no
  rule for it, so this is a warning.
- **Attribution and severity.** `input`, `warning`.
- **Detail.** As for `verify.proof_expired`, with `claim` `iat`.
- **Standard.** [RFC 7519] §4.1.6.
- **Remedy.** Usually a difference between the issuer's clock and the verifier's;
  `--clock-skew` allows for it.

### <a id="verify.no_key_material"></a>`verify.no_key_material`

- **Meaning.** vcrd found no key to verify with.
- **Attribution and severity.** `environment`, `error`.
- **Detail.** `consulted`: where vcrd looked: `issuer_identifier`, `caller_supplied`,
  `credential_embedded`.
- **Standard.** None: vcrd's order of key sources ([REQUIREMENTS] §10; [ARCHITECTURE]
  §8).
- **Remedy.** Not reported in milestone 1, whose only source is the issuer identifier:
  when a credential gives none, verify does not run, and `phases.verify.blocked_by`
  reports `missing: key_material` instead. Milestone 2 adds keys the caller supplies
  ([DEVELOPMENT-PLAN.md]).

### <a id="verify.issuer_method_unsupported"></a>`verify.issuer_method_unsupported`

- **Meaning.** The issuer identifier uses a URL scheme or DID method vcrd cannot resolve
  to a key.
- **Attribution and severity.** `vcrd`, `error`.
- **Detail.** `method`: the scheme, such as `https`, or the method, such as `did:web`.
- **Standard.** None: vcrd resolves offline methods first, `did:key` alone in milestone 1,
  and methods that need the network only with the caller's opt-in ([REQUIREMENTS] §8,
  §10).
- **Remedy.** Use a verifier that resolves `method`. Whether a caller-supplied key may
  stand in for an issuer key vcrd cannot obtain is an open question of milestone 2
  ([DEVELOPMENT-PLAN.md]).

### <a id="verify.did_key_undecodable"></a>`verify.did_key_undecodable`

- **Meaning.** The issuer is a `did:key` that cannot be decoded.
- **Attribution and severity.** `input`, `error`.
- **Detail.** `problem`, one of:
  - `version_present`: a component, such as `1`, comes before the multibase value;
  - `not_base58btc`: the multibase value does not start with `z`;
  - `base58_invalid`: it is not valid base58btc;
  - `codec_invalid`: the multicodec header is not a valid unsigned varint;
  - `{"key_length": {"expected": n, "found": m}}`: the key has the wrong length for its
    codec;
  - `point_invalid`: the key is not a point on the curve;
  - `point_not_canonical`: the key is a point, encoded other than as [RFC 8032] §5.1.3
    requires, so that the same point would have another `did:key` and thumbprint.
- **Standard.** [did:key] v0.9: the Create algorithm's step 3, the Decode Public Key
  algorithm, and the Signature Method Creation algorithm's steps 3 and 4; [RFC 8032]
  §5.1.3 for `point_not_canonical`. The method's syntax has no version, though its
  Create algorithm reads one.
- **Remedy.** The issuer identifier is malformed. Obtain the credential again from its
  issuer.

### <a id="verify.did_key_codec_unsupported"></a>`verify.did_key_codec_unsupported`

- **Meaning.** The `did:key` names a signing key type vcrd cannot use.
- **Attribution and severity.** `vcrd`, `error`.
- **Detail.** `codec`: the multicodec code, in hexadecimal. `name`: its name in the
  [multicodec table], when vcrd knows it, otherwise `null`.
- **Standard.** None: the key types vcrd implements ([ARCHITECTURE] §8).
- **Remedy.** Use a verifier that implements `name`. `p256-pub` and `p521-pub` arrive in
  milestone 2 ([DEVELOPMENT-PLAN.md]).

### <a id="verify.did_key_not_for_signing"></a>`verify.did_key_not_for_signing`

- **Meaning.** The `did:key` holds a key-agreement key, X25519 or X448, which cannot
  verify a signature.
- **Attribution and severity.** `input`, `error`.
- **Detail.** `codec`: the multicodec code, in hexadecimal. `name`: `x25519-pub` or
  `x448-pub`.
- **Standard.** [RFC 8037] §3.2: these keys MUST NOT be used for signing.
- **Remedy.** The issuer identifier names a key the issuer cannot sign with. Obtain the
  credential again from its issuer.

### <a id="verify.weak_key"></a>`verify.weak_key`

- **Meaning.** The key cannot bind a signature to a message, so vcrd refuses it.
- **Attribution and severity.** `input`, `error`.
- **Detail.** `key`: the key, with its `source`, `method` and `thumbprint`. `criterion`:
  the weak-key test it fails; for Ed25519, `small_order`.
- **Standard.** [REQUIREMENTS] §10, with the criteria in [ARCHITECTURE] §8. [RFC 8032]
  does not ask a verifier to check the key; vcrd checks it when the key is resolved, so
  that the finding names it.
- **Remedy.** The signature establishes nothing: under a small-order Ed25519 key,
  signatures that verify for almost any message can be made without a private key.

### <a id="verify.embedded_key_refused"></a>`verify.embedded_key_refused`

- **Meaning.** The only key on offer is the embedded key, one the credential carries
  about its own proof, which vcrd lets decide the outcome only if the caller opts in.
- **Attribution and severity.** `policy`, `error`.
- **Detail.** `location`: where the key is, such as `header.jwk`.
- **Standard.** [REQUIREMENTS] §10's key sources, with the rules in [ARCHITECTURE] §8,
  "Keys and proofs". [RFC 7515] §4.1.3 defines `jwk`.
- **Remedy.** The proof with the embedded key, `key_provenance.embedded_key.proof`,
  establishes only that whoever made the credential holds its private key. The opt-in
  arrives in milestone 2 ([DEVELOPMENT-PLAN.md]).

### <a id="verify.embedded_key_mismatch"></a>`verify.embedded_key_mismatch`

- **Meaning.** The embedded key is not the issuer key. It never changes the deciding
  proof key.
- **Attribution and severity.** `input`, `warning`.
- **Detail.** `embedded_key`: the embedded key, with its `location` and `thumbprint`.
  `key`: the issuer key, with its `source`, `method` and `thumbprint`.
- **Standard.** [RFC 7515] §4.1.3 makes `jwk` the public key that corresponds to the key
  that signed; [ARCHITECTURE] §8.
- **Remedy.** The credential carries a key other than the one its issuer identifier
  gives. `key_provenance.embedded_key.proof` says whether the proof with it is correct;
  when it is and the deciding proof is not, `verify.embedded_key_proof_correct` says so
  too.

### <a id="verify.embedded_key_proof_correct"></a>`verify.embedded_key_proof_correct`

- **Meaning.** The proof with the embedded key is correct and the deciding proof is not:
  whoever signed holds the embedded key's private key, and the embedded key is not the
  deciding proof key.
- **Attribution and severity.** `input`, `warning`. The deciding proof's own findings
  already fail verify.
- **Detail.** `embedded_key`: the embedded key, with its `location` and `thumbprint`.
  `key`: the deciding proof key, with its `source`, `method` and `thumbprint`.
- **Standard.** [RFC 8725] §3.8: the keys must belong to the issuer, or the application
  must reject the JWT. [ARCHITECTURE] §8's key and proof table, the row with the
  embedded proof correct and the issuer proof incorrect.
- **Remedy.** This is key substitution: a credential that names an issuer, signed with a
  key that is not the issuer's. The signature establishes nothing about the issuer.

## Checks not evaluated

A result's `not_evaluated` lists the checks vcrd did not make, each as `what`, the check,
and `why`, the reason, so that a result never reads as more than it checked
([REQUIREMENTS] §12, and §15's *Not evaluated*). A check is listed only when it applies
to the input: `revocation_status`, for example, only when the credential has
`credentialStatus`. When parse fails, only `issuer_accreditation` is listed, and `phases`
says which phases did not run.

vcrd does not assess trust ([REQUIREMENTS] §1, §4). These entries, with the rest of the
result, are information for the layer that decides whether to rely on a credential: each
says what the result does not establish, so that the layer can establish it another way,
or decide without it.

`text` names this section below its table of the checks not evaluated; `plain` and JSON
give the names alone. Each entry gives:

- **Meaning**: what the check would establish.
- **Listed**: when a result lists the check, and with which reason.
- **Standard**: the text the check comes from.
- **Takeaway**: what a result establishes without the check, and what it leaves to its
  reader.

### <a id="not_evaluated.issuer_accreditation"></a>`issuer_accreditation`

- **Meaning.** Whether a trust anchor the caller supplies, such as a list of accredited
  issuers, includes the credential's issuer. The anchor, and what inclusion in it means,
  are the caller's; vcrd would report whether the issuer is in it.
- **Listed.** In every result, as `not_implemented`: no caller can supply a trust anchor
  yet ([REQUIREMENTS] §9, §16 item 14). Once one can, a result made without one lists
  the check as `no_parameters_supplied`.
- **Standard.** [VCDM 2.0] Appendix A.3: the `issuer` property identifies the issuer to
  the verifier, and some ecosystems keep lists of verified issuers. Appendix A gives no
  conformance criteria for validation, the verifier's decision whether to rely on a
  credential.
- **Takeaway.** `passed` establishes that the signature verifies under the key the
  issuer identifier names: `key_provenance` says how vcrd derived that key, and its
  thumbprint names it. It does not establish who controls the identifier: anyone can
  generate a `did:key`, with no registration. The issuer identifier, the thumbprint and
  the provenance are what a trust layer needs to decide whether this issuer may issue
  this kind of credential.

### <a id="not_evaluated.context_resolution"></a>`context_resolution`

- **Meaning.** What the credential's `@context` documents define its terms to mean:
  obtaining each context and expanding the credential with [JSON-LD 1.1], so that each
  term, such as a type or a claim's name, maps to the IRI (Internationalized Resource
  Identifier) its issuer intended.
- **Listed.** For every VC-JOSE-COSE credential, as `not_implemented`.
- **Standard.** [VCDM 2.0] §4.3: each `@context` item after the first must be
  processable as a JSON-LD context. §5.3 lets an issuer give the digest of a context
  document, in `relatedResource`, for a verifier to compare. §6.3 describes processing
  without JSON-LD: accepting only the `@context` values an application knows, in the
  order it expects, with documents that match known digests.
- **Takeaway.** vcrd read the types and the claims' names as JSON strings. It checked
  that the first `@context` item is the VCDM 2.0 context and that later items are URLs or
  objects (`inspect.context_missing`, `inspect.context_first_invalid`,
  `inspect.context_entry_invalid`). It retrieved no context document, so it compared
  none with a digest. What a name such as `degree` means is whatever the listed contexts
  define. An application that depends on that meaning processes JSON-LD itself or, as
  §6.3 describes, accepts only the `@context` values it knows. They are in
  `credential.metadata`, as `@context[0]`, `@context[1]` and so on.

### <a id="not_evaluated.audience"></a>`audience`

- **Meaning.** Whether the JWT's `aud` claim names the recipient processing it.
- **Listed.** When the JWT has `aud`, as `no_parameters_supplied`: no caller can supply
  an expected audience until milestone 4 ([DEVELOPMENT-PLAN.md]).
- **Standard.** [RFC 7519] §4.1.3: when `aud` is present, a recipient that does not
  identify itself with one of its values must reject the JWT.
- **Takeaway.** A credential addressed to another recipient verifies the same. A
  recipient compares `aud`, in `credential.metadata`, with its own identifiers.

### <a id="not_evaluated.holder_binding"></a>`holder_binding`

- **Meaning.** Whether whoever presents the credential holds the private key that `cnf`
  names ([RFC 7800] §3.1).
- **Listed.** When the JWS header or the claims have `cnf`, as `not_implemented`: the
  check needs a presentation, which vcrd verifies from milestone 4 ([DEVELOPMENT-PLAN.md]).
- **Standard.** [VC-JOSE-COSE] §4.1.3: `cnf` identifies a proof-of-possession key, and
  binding a credential to its holder is recommended.
- **Takeaway.** A credential alone shows nothing about who presents it: a copy verifies
  the same. Possession of the `cnf` key is shown by a presentation signed with it, over
  a challenge from the verifier.

### <a id="not_evaluated.revocation_status"></a>`revocation_status`

- **Meaning.** The status the credential's `credentialStatus` points to, such as whether
  its issuer has revoked or suspended it.
- **Listed.** When the credential has `credentialStatus`, as `not_implemented`: checking
  it means fetching a status list ([REQUIREMENTS] §15's *Verify*).
- **Standard.** [VCDM 2.0] §4.10. VCDM 2.0 §2's *verification* includes the status check
  when `credentialStatus` is present.
- **Takeaway.** A credential its issuer has since revoked verifies the same. The
  `credentialStatus` entry says where the status is published.

### <a id="not_evaluated.schema_conformance"></a>`schema_conformance`

- **Meaning.** Whether the credential conforms to the schemas its `credentialSchema`
  names.
- **Listed.** When the credential has `credentialSchema`, as `not_implemented`.
- **Standard.** [VCDM 2.0] §4.11.
- **Takeaway.** vcrd checked the structure the data model requires, not the issuer's
  schema for this kind of credential: a claim that schema requires may be missing, or of
  another type.

### <a id="not_evaluated.replay_binding"></a>`replay_binding`

- **Meaning.** Whether a presentation is bound to the request it answers, by the
  verifier's challenge and domain, so that a recorded presentation cannot be replayed.
- **Listed.** Not yet: vcrd verifies presentations from milestone 4
  ([DEVELOPMENT-PLAN.md]). [REQUIREMENTS] §10 has a presentation verified without an
  expected challenge and domain report replay binding as not evaluated; the reason would
  be `no_parameters_supplied`.
- **Standard.** [REQUIREMENTS] §10, on presentation verification.
- **Takeaway.** A replayed presentation's signature verifies the same as the original's:
  only a comparison with the verifier's own challenge shows that it answers this request.

### Reasons

| `why` | Meaning | Listed |
|---|---|---|
| <a id="not_evaluated.reason.not_implemented"></a>`not_implemented` | vcrd does not make the check yet | for `issuer_accreditation`, `context_resolution`, `holder_binding`, `revocation_status` and `schema_conformance` |
| <a id="not_evaluated.reason.no_parameters_supplied"></a>`no_parameters_supplied` | the check needs a value from the caller, such as an expected audience, and none was supplied | for `audience` |
| <a id="not_evaluated.reason.requires_network"></a>`requires_network` | the check needs network access, which vcrd does not use by default ([REQUIREMENTS] §6) | not yet: for a check that fetches, such as `revocation_status` once vcrd reads status lists, run without network access |
| <a id="not_evaluated.reason.out_of_scope"></a>`out_of_scope` | vcrd does not intend to make the check | not yet: none of the checks above is out of scope |
| <a id="not_evaluated.reason.phase_not_reached"></a>`phase_not_reached` | the check belongs to a phase that did not run | not yet: when parse fails, the later phases' checks are left out, and `phases` says which phases did not run |

[ARCHITECTURE]: ../ARCHITECTURE.md
[DEVELOPMENT-PLAN.md]: ../DEVELOPMENT-PLAN.md
[did:key]: https://w3c-ccg.github.io/did-key-spec/
[JSON-LD 1.1]: https://www.w3.org/TR/2020/REC-json-ld11-20200716/
[multicodec table]: https://github.com/multiformats/multicodec/blob/master/table.csv
[REQUIREMENTS]: ../REQUIREMENTS.md
[RFC 3339]: https://www.rfc-editor.org/rfc/rfc3339
[RFC 7515]: https://www.rfc-editor.org/rfc/rfc7515
[RFC 7517]: https://www.rfc-editor.org/rfc/rfc7517
[RFC 7518]: https://www.rfc-editor.org/rfc/rfc7518
[RFC 7519]: https://www.rfc-editor.org/rfc/rfc7519
[RFC 7638]: https://www.rfc-editor.org/rfc/rfc7638
[RFC 7800]: https://www.rfc-editor.org/rfc/rfc7800
[RFC 8032]: https://www.rfc-editor.org/rfc/rfc8032
[RFC 8037]: https://www.rfc-editor.org/rfc/rfc8037
[RFC 8259]: https://www.rfc-editor.org/rfc/rfc8259
[RFC 8725]: https://www.rfc-editor.org/rfc/rfc8725
[RFC 9864]: https://www.rfc-editor.org/rfc/rfc9864
[VC-JOSE-COSE]: https://www.w3.org/TR/2026/REC-vc-jose-cose-20261013/
[VCDM 1.1]: https://www.w3.org/TR/2022/REC-vc-data-model-20220303/
[VCDM 2.0]: https://www.w3.org/TR/2025/REC-vc-data-model-2.0-20250515/
[WHATWG URL Standard]: https://url.spec.whatwg.org/
[XML Schema 1.1]: https://www.w3.org/TR/2012/REC-xmlschema11-2-20120405/
