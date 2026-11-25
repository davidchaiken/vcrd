//! The inputs vcrd-cli's tests sign: a credential, and a key set when there is a
//! caller-supplied key, for each row of ARCHITECTURE §8's key and proof table, built at
//! run time; and the committed examples of key sets in fixtures/ (DEVELOPMENT-PLAN.md,
//! milestone 2, decided 2026-11-18 and 2026-11-25). Signing is test code only: vcrd
//! itself only verifies.
//!
//! vcrd-core's tests/fixtures.rs generates the other committed inputs. The curated
//! example's header, payload and key derivation are repeated here, and
//! tests/key_set_examples.rs checks that `fixtures/caller-key-unlike-issuer.jwt` carries
//! the curated example's header and payload, so that the two cannot drift apart.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

/// The issuer of a credential whose issuer key vcrd cannot obtain.
pub const HTTPS_ISSUER: &str = "https://issuer.example";

/// The committed examples of key sets in fixtures/, by name: each a credential,
/// `NAME.jwt`, and the key set to verify it with, `NAME.jwks.json`.
pub const KEY_SET_EXAMPLES: [&str; 3] = [
    "caller-key-unlike-issuer",
    "key-set-kid",
    "key-set-kid-not-header-kid",
];

/// The credential and key set of a committed example, by name.
pub fn key_set_example(name: &str) -> (Vec<u8>, Vec<u8>) {
    match name {
        "caller-key-unlike-issuer" => caller_key_unlike_issuer(),
        "key-set-kid" => key_set_kid(),
        "key-set-kid-not-header-kid" => key_set_kid_not_header_kid(),
        other => panic!("no key set example named {other}"),
    }
}

/// One row of the key and proof table, as inputs: each kind of key as the distinct key
/// it is, by index, when the row has it, and the distinct key that signs, or none of
/// them.
pub struct TableRow {
    pub embedded: Option<usize>,
    pub issuer: Option<usize>,
    pub caller: Option<usize>,
    pub signer: Option<usize>,
}

/// A row's credential, and its key set when the row has a caller-supplied key
/// (DEVELOPMENT-PLAN.md, milestone 2, decided 2026-11-18 and 2026-11-25). The issuer is
/// the issuer key's `did:key`, with the DID URL as `kid`, or else an `https:` URL, with
/// `iss` equal to it and no `kid`, so that the header names no key. The embedded key is
/// the header's `jwk`; the caller-supplied key, a key set's one member, without `kid`.
/// When no key of the row signs, a fourth key does.
pub fn table_inputs(row: &TableRow) -> (Vec<u8>, Option<Vec<u8>>) {
    let key = |i: usize| signing_key(&format!("vcrd key and proof table: key {i}"));
    let signer = row.signer.map_or_else(
        || signing_key("vcrd key and proof table: a key that is none of the row's"),
        key,
    );
    let (mut header, payload) = match row.issuer {
        Some(i) => {
            let did = did_key(&key(i));
            (did_key_header(&did), payload(&did))
        }
        None => {
            let mut payload = payload(HTTPS_ISSUER);
            payload["iss"] = json!(HTTPS_ISSUER);
            (header(), payload)
        }
    };
    if let Some(e) = row.embedded {
        header["jwk"] = jwk(&key(e));
    }
    let credential = sign(&signer, &header, &payload);
    (credential, row.caller.map(|c| key_set(&[jwk(&key(c))])))
}

/// The curated example's header and payload, signed by another key, the one
/// fixtures/embedded-jwk.jwt embeds; the key set holds that key, in a member without
/// `kid`. The caller-supplied key is not the issuer key, and its proof is correct.
fn caller_key_unlike_issuer() -> (Vec<u8>, Vec<u8>) {
    let did = did_key(&curated_example_key());
    let signer = substitute_key();
    let credential = sign(&signer, &did_key_header(&did), &payload(&did));
    (credential, key_set(&[jwk(&signer)]))
}

/// How many members the key set of `key-set-kid` has, and which of them signed: not the
/// first or the last, so that neither explains which is chosen.
const KEY_SET_KID_MEMBERS: usize = 3;
pub const KEY_SET_KID_SIGNER: usize = 1;

/// An `https:` issuer, whose key vcrd cannot obtain, and a key set of several members,
/// each with its key's JWK Thumbprint URI (RFC 9278) as `kid`, as VC-JOSE-COSE §4.2
/// recommends. One member's key signed, and the header's `kid` names it.
fn key_set_kid() -> (Vec<u8>, Vec<u8>) {
    let keys: Vec<SigningKey> = (0..KEY_SET_KID_MEMBERS)
        .map(|n| signing_key(&format!("vcrd fixture: key set member {n}")))
        .collect();
    let signer = &keys[KEY_SET_KID_SIGNER];
    let mut header = header();
    header["kid"] = json!(thumbprint_uri(signer));
    let credential = sign(signer, &header, &payload(HTTPS_ISSUER));
    let members: Vec<Value> = keys
        .iter()
        .map(|key| {
            let mut member = jwk(key);
            member["kid"] = json!(thumbprint_uri(key));
            member
        })
        .collect();
    (credential, key_set(&members))
}

/// An `https:` issuer, and a key set of one member, holding the signer's key, whose `kid`
/// is the key's bare JWK Thumbprint (RFC 7638), while the header's is its Thumbprint URI
/// (RFC 9278): one key, named two ways. vcrd compares a member's `kid` as written, so
/// `--key-set-checks strict` makes the member ineligible, and `lenient` lets it decide,
/// with a warning (DEVELOPMENT-PLAN.md, milestone 2, decided 2026-11-24).
fn key_set_kid_not_header_kid() -> (Vec<u8>, Vec<u8>) {
    let signer = signing_key("vcrd fixture: a key whose member kid is not the header's");
    let mut header = header();
    header["kid"] = json!(thumbprint_uri(&signer));
    let credential = sign(&signer, &header, &payload(HTTPS_ISSUER));
    let mut member = jwk(&signer);
    member["kid"] = json!(thumbprint(&signer));
    (credential, key_set(&[member]))
}

/// A signing key from a seed derived from a label, as vcrd-core's generator derives
/// them, so that a label names the same key in both.
fn signing_key(label: &str) -> SigningKey {
    SigningKey::from_bytes(&Sha256::digest(label.as_bytes()).into())
}

/// The curated example's issuer key.
fn curated_example_key() -> SigningKey {
    signing_key("vcrd curated example: Ed25519 issuer")
}

/// The key vcrd-core's fixtures substitute for the issuer's.
fn substitute_key() -> SigningKey {
    signing_key("vcrd fixture: a key substituted for the issuer's")
}

/// `did:key` for an Ed25519 key: base58btc of the `ed25519-pub` multicodec prefix (0xed,
/// as an unsigned varint) and the key.
fn did_key(key: &SigningKey) -> String {
    let bytes = [&[0xed, 0x01][..], key.verifying_key().as_bytes()].concat();
    format!("did:key:z{}", bs58::encode(bytes).into_string())
}

/// An Ed25519 public key as a JWK (RFC 8037 §2).
fn jwk(key: &SigningKey) -> Value {
    json!({"kty": "OKP", "crv": "Ed25519", "x": b64(key.verifying_key().as_bytes())})
}

/// The key's JWK Thumbprint (RFC 7638): SHA-256 over its required members, which
/// serde_json writes in lexicographic order and without whitespace.
fn thumbprint(key: &SigningKey) -> String {
    b64(&Sha256::digest(serde_json::to_vec(&jwk(key)).unwrap()))
}

/// The key's JWK Thumbprint URI (RFC 9278).
fn thumbprint_uri(key: &SigningKey) -> String {
    format!(
        "urn:ietf:params:oauth:jwk-thumbprint:sha-256:{}",
        thumbprint(key)
    )
}

/// The curated example's header, without `kid`.
fn header() -> Value {
    json!({"alg": "EdDSA", "cty": "vc", "typ": "vc+jwt"})
}

/// The curated example's header for a `did:key` issuer, whose `kid` names the DID's one
/// key by its method-specific identifier.
fn did_key_header(did: &str) -> Value {
    let mut header = header();
    let fragment = did.strip_prefix("did:key:").unwrap();
    header["kid"] = json!(format!("{did}#{fragment}"));
    header
}

/// The curated example's payload, for an issuer.
fn payload(issuer: &str) -> Value {
    json!({
        "@context": [
            "https://www.w3.org/ns/credentials/v2",
            "https://www.w3.org/ns/credentials/examples/v2",
        ],
        "id": "urn:uuid:0d4a1f3e-6c2b-4e8a-9b1d-2f7c5a3e8b90",
        "type": ["VerifiableCredential", "ExampleDegreeCredential"],
        "issuer": issuer,
        "validFrom": "2026-01-01T00:00:00Z",
        "validUntil": "2031-01-01T00:00:00Z",
        "credentialSubject": {
            "id": "did:example:alice",
            "degree": {
                "type": "ExampleBachelorDegree",
                "name": "Bachelor of Science",
            },
        },
    })
}

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// A compact JWS (RFC 7515 §7.1). serde_json writes object members in order, so the
/// bytes are the same on every run.
fn sign(key: &SigningKey, header: &Value, payload: &Value) -> Vec<u8> {
    let header = b64(&serde_json::to_vec(header).unwrap());
    let payload = b64(&serde_json::to_vec(payload).unwrap());
    let signature = key.sign(format!("{header}.{payload}").as_bytes());
    format!("{header}.{payload}.{}", b64(&signature.to_bytes())).into_bytes()
}

/// A JWK Set (RFC 7517 §5) of these members, indented to be read by hand, with a final
/// newline.
fn key_set(members: &[Value]) -> Vec<u8> {
    let mut bytes = serde_json::to_vec_pretty(&json!({ "keys": members })).unwrap();
    bytes.push(b'\n');
    bytes
}
