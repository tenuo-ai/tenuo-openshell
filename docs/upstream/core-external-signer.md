# Draft core issue: sign issuance, approvals, and revocation lists with a key the process cannot read

Status: draft for tenuo-ai/tenuo, not filed. Checked against `tenuo` 0.3.2
and `origin/main` at `a77cf2b8`. Searches of tenuo-ai/tenuo issues for
"signer", "external signing", "KMS", "HSM", "PKCS11", "remote signing", and
"signing key" found no existing issue. #537 shipped `HolderSigner` and the
async surface for proofs of possession. #751 covers other primitives that
integrations re-implement.

## Problem

Production deployments hold issuer and approver keys in a KMS or HSM, where
the private key cannot be exported. AWS KMS, Google Cloud KMS (software
level), HashiCorp Vault Transit, PKCS#11 3.0 HSMs, and YubiHSM 2 all produce
RFC 8032 PureEdDSA Ed25519 signatures over caller-supplied bytes. Azure Key
Vault does not support Ed25519. Tenuo verifies exactly those signatures, so
the only gap is the API: several signing operations accept nothing but an
in-memory `SigningKey`.

| Operation | 0.3.2 API | External key |
| --- | --- | --- |
| Root mint | `WarrantBuilder::build(self, &SigningKey)`. The payload's `issuer` is set from `signing_key.public_key()` inside `build`. | No |
| Issue from an issuer warrant | `IssuanceBuilder::build(&SigningKey)`, `OwnedIssuanceBuilder::build(&SigningKey)` | No |
| Attenuate | `AttenuationBuilder::prepare() -> PreparedDelegation`, then `finalize(Signature)` | Yes (Rust) |
| Attenuate, FFI | `OwnedAttenuationBuilder::build(&SigningKey)`, Python `Warrant.attenuate(signing_key=)` | No |
| Proof of possession | `HolderSigner`, `AsyncHolderSigner` | Yes |
| Approval | `SignedApproval::create(ApprovalPayload, &SigningKey)`, `sdk::approve_request(.., &SigningKey, ..)`, `LocalApprovalSigner::new(SigningKey, ..)`. The approval preimage builder is private. | No |
| Signed revocation list | `SrlBuilder::build(self, &SigningKey)`, `SignedRevocationList::empty(&SigningKey)`. The fields are private. | No |
| Receipt | `ReceiptSigner` (SDK runtime). `Receipt::signing_preimage` and the `Receipt` fields are public. | Yes |

As a result, a deployment can keep its root key in a KMS only by having the
root sign once, offline, to a parent warrant, and then attenuating online.
Approvals and SRLs have no such workaround: an approval service or SRL
publisher must hold its raw key. Integrations either load keys into memory or
re-implement payload construction, which is exactly the duplication #751 is
removing.

`PreparedDelegation` and `HolderSigner` already establish the pattern:

- core builds and freezes the exact bytes;
- the caller signs them with raw Ed25519;
- core verifies the signature against the expected key before it returns an
  artifact.

This issue extends that pattern to the remaining operations.

## Proposal

### 1. Prepare and finalize for every signed artifact

This is the primitive. It serves sync, async, offline-ceremony, and FFI
callers without a callback across the language boundary.

```rust
impl WarrantBuilder {
    /// Required for prepare(): the payload commits to the issuer.
    pub fn issuer(self, issuer: PublicKey) -> Self;
    pub fn prepare(self) -> Result<PreparedWarrant>;
}

pub struct PreparedWarrant { /* payload, payload_bytes, envelope_version, final_bytes, issuer */ }
impl PreparedWarrant {
    /// SIGNATURE_CONTEXT || envelope_version || payload_bytes.
    pub fn final_signing_bytes(&self) -> &[u8];
    pub fn issuer(&self) -> &PublicKey;
    /// Verifies against `issuer` before returning.
    pub fn finalize(self, signature: Signature) -> Result<Warrant>;
}
```

The same shape applies to:

- `IssuanceBuilder` and `OwnedIssuanceBuilder` (finalize verifies against the
  issuer warrant's holder);
- `OwnedAttenuationBuilder`, which returns the existing `PreparedDelegation`;
- `ApprovalPayload`: `PreparedApproval::new(payload, approver: PublicKey)`,
  with `final_signing_bytes()` covering
  `SIGNATURE_CONTEXT || APPROVAL_CONTEXT || 1 || payload` and
  `finalize(Signature) -> SignedApproval`;
- `SrlBuilder::prepare(issuer: PublicKey) -> PreparedSrl`;
- `sdk::approve_request`: split into `prepare_approval(request, warrant,
  approver: &PublicKey, external_id, ttl) -> PreparedApproval`, which runs
  every existing check, and `finalize`.

`build(&SigningKey)` stays as sugar over prepare, sign, finalize, the way
`AttenuationBuilder::build` is today.

Each `finalize` checks the signature against the declared key and fails with
`Error::SignatureInvalid`. A misconfigured signer then fails closed at
issuance, not at the first verifier: the wrong KMS key, Ed25519ph instead of
pure, or a double context prefix.

### 2. A signer trait as convenience

```rust
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigningPurpose { Warrant, Delegation, Approval, RevocationList, Receipt }

pub struct SigningRequest<'a> { /* purpose, message: &'a [u8], warrant_id: Option<&'a str> */ }
impl SigningRequest<'_> {
    pub fn purpose(&self) -> SigningPurpose;
    /// Exact bytes to sign with PureEdDSA Ed25519. Never prehash.
    pub fn final_signing_bytes(&self) -> &[u8];
}

pub trait Signer: Send + Sync {
    fn public_key(&self) -> PublicKey;
    fn sign(&self, request: &SigningRequest<'_>) -> Result<Signature, SignerError>;
}

#[cfg(feature = "async")]
#[async_trait]
pub trait AsyncSigner: Send + Sync {
    fn public_key(&self) -> PublicKey;
    async fn sign(&self, request: &SigningRequest<'_>) -> Result<Signature, SignerError>;
}

impl Signer for SigningKey { /* sign_raw(final_signing_bytes) */ }
```

The builders gain `build_with(&dyn Signer)`, and `build_with_async(&dyn
AsyncSigner).await` behind the async feature, implemented over prepare and
finalize. Design points:

- **Purpose.** `purpose` lets one KMS client enforce policy per operation, for
  example requiring extra authorization for `Warrant`. `HolderSigner` already
  separates `sign_pop` from `sign_delegation` for the same reason.
- **`Send + Sync`.** Required so a signer can be shared across a server's
  tasks, matching `HolderSigner` and `ReceiptSigner`.
- **Async.** Remote signers are naturally async. `AsyncSigner` mirrors
  `AsyncHolderSigner`. A sync signer that blocks on network I/O must not be
  called on an async runtime thread; document that, and prefer the async
  variant or prepare and finalize.
- **Errors.** Reuse `SignerError` (`#[non_exhaustive]`, never carrying key
  material). Add `MessageTooLarge { limit: usize }`. AWS KMS signs at most
  4096 bytes in `RAW` mode and YubiHSM 2 at most 2019, while a warrant may be
  up to 64 KiB. The signer must refuse rather than prehash, since a prehash
  signature does not verify. Add `Refused`, distinct from `Failed`, for
  policy denials by the key service. Map both into `Error` and
  `DelegationError::Signer`.
- **Existing traits.** `HolderSigner` and `ReceiptSigner` stay. Provide
  adapters so one `Signer` can serve as either, and implement `Signer` for
  `LocalSigner` and `LocalReceiptSigner`.

### 3. Bindings

**Python.** Add `prepare()` to `MintBuilder`, `Warrant.grant_builder()`, the
SRL builder, and the approval helper. It returns an object with:

- `signing_bytes: bytes`;
- `issuer: PublicKey` (or `holder`/`approver`); and
- `finalize(signature: bytes) -> Warrant` (or `SignedApproval`/`SignedRevocationList`).

Also accept any object with a `public_key` attribute and a
`sign(message: bytes) -> bytes` method wherever a `SigningKey` is accepted,
calling it synchronously under the GIL. Async Python callers use `prepare()`,
`await` their KMS client, then `finalize()`. Wrap boto3 or google-cloud-kms
in an example, not a dependency.

**TypeScript and WASM.** Expose `prepareMint(...)`, `prepareAttenuation(...)`,
`prepareApproval(...)`, and `prepareRevocationList(...)`, each returning
`{ signingBytes: Uint8Array, finalize(signature: Uint8Array) }`. WASM cannot
block on I/O, so this is the primary shape there. A convenience
`mintWith(signer: { publicKey, sign(bytes): Promise<Uint8Array> })` can wrap
it in the TypeScript layer.

## Compatibility

- **Additive.** Every existing `build(&SigningKey)` keeps its signature and
  output.
- **Wire format and test vectors are unchanged.** The signed bytes are the
  same. Only who computes the signature changes.
- **Verification is unchanged.** Externally produced signatures are standard
  Ed25519 and verify with the existing code.
- **Issuer setter.** `WarrantBuilder::issuer(PublicKey)` must agree with the
  key passed to `build(&SigningKey)`. Make a mismatch an error, not a silent
  override.
- **Minimum supported Rust version.** No change; `async-trait` is already a
  dependency of the async feature.

## Acceptance

- A root warrant, an approval, and an SRL are each produced through
  `prepare` and `finalize` with a key outside the process, and verify with
  the unchanged verifiers.
- Each finalize rejects a signature from the wrong key, an Ed25519ph
  signature, and a signature over bytes with a doubled context prefix.
- Python and WASM tests round-trip each prepared artifact.
- A documented example signs with AWS KMS `ECC_NIST_EDWARDS25519` /
  `ED25519_SHA_512` / `MessageType=RAW`, and one with PKCS#11 `CKM_EDDSA`
  through SoftHSMv2 runs in CI.

## Motivation from tenuo-openshell

The OpenShell integration's operator CLI reads issuer and approver keys from
files (`read_secret` in `src/bin/tenuo-openshell.rs`), because core offers no
alternative for root mints and approvals. Enterprise operators will ask for
KMS- or HSM-held issuer keys, and multi-user platforms need an issuance
service that mints a short-lived warrant per request (tenuo-openshell#17).
See `docs/production-issuance.md` in tenuo-openshell.
