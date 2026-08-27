# Plan: Close KMS test-vector gaps, audit Caching CMM, add GCP KMS keyring

## Overview

Three workstreams that finish the conformance story and extend the SDK for
GCP-hosted deployments (the driving use case runs on GKE and wants
Vault-transit-style envelope encryption backed by Google Cloud KMS):

- **A. KMS vector coverage** - run the aws-kms test vectors offline via a
  record/replay mock, removing the current `:aws_kms_not_supported` skip.
- **B. Caching CMM conformance audit** - the implementation exists
  (`lib/aws_encryption_sdk/cmm/caching.ex`); verify it against the spec and
  close any gaps found.
- **C. GCP Cloud KMS keyring** - a new keyring following the existing
  `KmsClient` behaviour pattern, letting data keys be wrapped by GCP KMS
  keys with no AWS dependency.

## Current state (verified 2026-08-06)

- Vector harness (`test/support/test_vector_harness.ex`) supports keys
  manifest v3 and decrypt manifests v2-4. CI clones
  `awslabs/aws-encryption-sdk-test-vectors`, unzips `python-2.3.0`, and the
  vector suites run by default when vectors are present (2,861 success
  vectors + 4,240 error vectors per CHANGELOG).
- aws-kms vectors are skipped:
  - `test/test_vectors/full_decrypt_test.exs:154` -
    `build_single_keyring(_, %{"type" => "aws-kms"}, _)` returns
    `{:error, :aws_kms_not_supported}`
  - `test/test_vectors/error_decrypt_test.exs:286` - same
  - `test/support/test_vector_harness.ex:187` - `decode_key_material`
    returns `{:ok, :aws_kms}` because keys.json carries no local material
    for KMS keys, only the ARN.
- KMS client abstraction already exists:
  `lib/aws_encryption_sdk/keyring/kms_client.ex` (behaviour),
  `kms_client/ex_aws.ex` (production), `kms_client/mock.ex` (test mock,
  keyed by `{operation, key_id}`).
- Caching CMM exists with spec defaults (`max_bytes` 2^63-1,
  `max_messages` 2^32, required `max_age`), partition IDs, and a
  `LocalCache` + `CacheEntry` + `CryptographicMaterialsCache` cache layer.
- Keyring behaviour (`lib/aws_encryption_sdk/keyring/behaviour.ex`)
  reserves provider IDs starting with `aws-kms` for KMS keyrings and
  provides `generate_data_key/1` and precondition helpers.

## Workstream A: aws-kms vectors via record/replay

### Why record/replay

The decrypt vectors include the wrapped data keys (EDKs) in each message
header, but keys.json intentionally has no plaintext material for
`aws-kms` entries - decrypting those EDKs requires a real KMS Decrypt
call. The vector framework's KMS keys are AWS's public test keys
(decryptable by any authenticated AWS principal), so a one-time
credentialed run can capture every EDK's plaintext data key into a
committed fixture; after that, CI replays the fixture through a mock and
never needs AWS credentials.

The recorded plaintext data keys are public test material protecting
public test plaintexts - committing them is safe and is effectively what
the framework intends by making the keys publicly decryptable.

### A1. Recording task

- Add a mix task (suggest `mix esdk.record_kms_vectors`) or script under
  `scripts/` that:
  1. Loads the decrypt manifest via `TestVectorHarness`.
  2. Selects tests whose master keys include type `aws-kms` (and
     `aws-kms-mrk-aware` variants).
  3. For each, parses the message header, and for each EDK with provider
     id `aws-kms`, calls real KMS Decrypt (reuse `KmsClient.ExAws`) with
     the message's encryption context.
  4. Writes `test/fixtures/kms_vector_recordings.json`: map of
     `SHA-256(edk.ciphertext) (hex)` -> `%{plaintext_data_key: base64,
     key_id: arn}`. Keying by ciphertext hash keeps the fixture small,
     stable, and independent of test ids.
- Gate behind AWS credentials (same `:integration` conventions as
  `test/README.md`). Document the refresh procedure for new vector zips.

### A2. Replay client

- The existing `KmsClient.Mock` keys responses by `{operation, key_id}`,
  which cannot serve many distinct EDKs under one key ARN. Two options:
  - Extend `Mock` so a decrypt response value may be a function
    `(ciphertext, context) -> result`, or
  - Add a dedicated `KmsClient.Replay` that loads the recordings fixture
    and answers decrypt by ciphertext hash.
- Recommend `KmsClient.Replay` - it keeps `Mock` simple and the replay
  semantics explicit. It should verify the requested encryption context
  matches what KMS would enforce (record the context during A1 if needed).

### A3. Wire into the vector suites

- `full_decrypt_test.exs` / `error_decrypt_test.exs`: replace the
  `:aws_kms_not_supported` branches with construction of the appropriate
  keyring (`AwsKms`, `AwsKmsMrk`, discovery variants per the master-key
  spec in the manifest) configured with the Replay client.
- Skip (with a distinct, counted reason) only vectors whose EDKs are
  missing from the recordings fixture, so a stale fixture is visible
  rather than silently green.
- CI: no changes needed beyond the fixture being committed; the recording
  task is never run in CI.

### A4 (stretch). Encrypt-side manifests

- Implement the encrypt/"generate" manifest type from the
  aws-crypto-tools-test-vector-framework in the harness: produce
  ciphertexts from the manifest's plaintext + master-key specs (raw keys
  fully offline; KMS via GenerateDataKey only when credentials present).
- Minimum bar: round-trip our own outputs through our decrypt path.
- Full interop bar (optional CI job): decrypt our generated messages with
  the official Python ESDK (`pip install aws-encryption-sdk`) for raw AES
  / raw RSA cases. This is the last mile of the "compatible with all other
  implementations" claim and worth a badge in the README.

### Acceptance criteria

- `mix test` with vectors present executes aws-kms success and error
  vectors with zero network calls.
- Vector counts in CI output rise accordingly; skipped-vector reasons are
  reported and bounded.
- Recording procedure documented in `test/README.md`.

## Workstream B: Caching CMM conformance audit

The implementation looks substantially complete; this workstream is
verification, not a rewrite. Audit against
`framework/caching-cmm.md` and `framework/cryptographic-materials-cache.md`:

1. **Cache identifier formulas** - the spec pins exact SHA-384
   constructions (partition id + CMM-type prefix + serialized context /
   algorithm suite). Verify byte-for-byte; wrong identifiers still "work"
   but break cross-CMM cache sharing and violate the spec.
2. **Bypass rules** - the spec requires bypassing the cache for algorithm
   suites without a KDF; confirm.
3. **Limit enforcement** - `max_bytes` requires the plaintext length (or
   bound) to be threaded through `get_encryption_materials`; verify the
   encrypt path supplies it and that entries are evicted (not just
   skipped) when exceeded. Same for `max_messages` increment semantics
   and TTL pruning in `LocalCache`.
4. **Concurrency** - `LocalCache.start_link` suggests a process; confirm
   behavior under concurrent checkout (thundering-herd on a cold key:
   acceptable, but document), and that plaintext data keys in cache state
   never leak into logs/inspect output (consider a redacted Inspect impl
   for `CacheEntry` if not already present).
5. **Security guidance** - `guides/security-best-practices.md` should
   state the tradeoff (caching widens the blast radius of a compromised
   data key; spec-recommended TTLs) and recommend per-tenant partition
   IDs for multi-tenant use - that pattern (tenant-scoped caches so a
   tenant's keys can be evicted on suspension) is a first-class use case
   for the GKE deployment this plan supports.
6. Add any missing pieces as small PRs with spec-section citations;
   consider property tests for limit/TTL behavior.

### Acceptance criteria

- Written audit note (thoughts/shared/research/) mapping each MUST in
  caching-cmm.md to code or to a fix PR.
- Any fixes landed with tests; guide updated.

## Workstream C: GCP Cloud KMS keyring

### Design

Mirror the proven AWS pattern: a client behaviour + production/mock
implementations + a keyring.

- **`Keyring.GcpKmsClient` behaviour** - operations needed:
  - `encrypt(client, key_name, plaintext, aad)` -> `%{ciphertext, key_name}`
  - `decrypt(client, key_name, ciphertext, aad)` -> `%{plaintext}`
  GCP KMS has no GenerateDataKey; the keyring generates the data key
  locally (`Behaviour.generate_data_key/1`, spec-sanctioned "generate
  then encrypt") and wraps it via `encrypt`.
- **`Keyring.GcpKms` keyring**:
  - Provider ID: `"gcp-kms"` (passes `validate_provider_id/1`; the
    `aws-kms` prefix is reserved).
  - Provider info: full key resource name
    (`projects/P/locations/L/keyRings/R/cryptoKeys/K`). Note GCP decrypt
    is version-agnostic - the service picks the key version from the
    ciphertext, which matches the EDK model cleanly (no MRK-style
    region/ARN complexity; no discovery variant needed initially).
  - AAD: serialize the encryption context with the existing canonical
    serialization (`Format.EncryptionContext`) and pass it as GCP's
    `additionalAuthenticatedData`. This binds the ESDK encryption context
    into the KMS wrap itself, same trust property as AWS KMS's context.
  - on_decrypt: filter EDKs by provider id + key name (support a
    key-name allowlist like the AWS keyring), try serially per the
    keyring interface spec.
- **Production client**: REST (`cryptoKeys.encrypt` / `cryptoKeys.decrypt`)
  with an injected token source. To keep the core dependency-free,
  accept a `token_provider` fun (or module) in client opts rather than
  depending on Goth; ship a documented Goth recipe (Goth as an optional
  dep, or a companion package `aws_encryption_sdk_gcp` if the deps feel
  wrong in-tree). HTTP via an injected client fun to stay
  library-agnostic, mirroring however ExAws is isolated today.
- **`GcpKmsClient.Mock`** - same shape as the AWS mock.

### Interop caveat to document

Messages whose only EDKs are `gcp-kms` are not decryptable by the
official AWS ESDK implementations (they have no GCP keyring). That is
fine for closed ecosystems; for portability, document the multi-keyring
pattern (gcp-kms + raw RSA escrow, for example). State this explicitly in
the keyring moduledoc and choosing-components guide.

### Tests

- Unit tests with the mock covering on_encrypt/on_decrypt, AAD binding
  (context mismatch must fail), multi-EDK selection, and multi-keyring
  composition with raw AES.
- Round-trip property test: encrypt/decrypt with mock-backed GcpKms
  keyring across algorithm suites (committed and uncommitted).
- Integration tests gated by GCP credentials (`GCP_KMS_KEY_NAME` env,
  Workload Identity or ADC), tagged like the AWS `:integration` tests.
- No official vectors exist for GCP keyrings; consider contributing a
  small vendored manifest of our own (encrypted with a documented test
  key) so regressions are caught format-side.

### Acceptance criteria

- `GcpKms` keyring + client behaviour + mock merged with docs and guide
  updates (choosing-components gains a GCP section).
- Round-trip and AAD-mismatch tests green without any GCP account; the
  integration suite green against a real key.
- Caching CMM verified to compose with the GCP keyring (it operates above
  the keyring layer, so this should be a doc example plus one test).

## Suggested sequencing

1. **B** first (small, de-risks the layer the other work sits on).
2. **A1-A3** next (mechanical, high-value: unlocks thousands of skipped
   vectors).
3. **C** (new surface; benefits from the audited CMM and the replay
   pattern for its own mock tests).
4. **A4** stretch, alongside or after C.

## Open questions

- OQ1: In-tree optional Goth/HTTP deps for the GCP client, or a companion
  hex package? (Leaning: in-tree behaviour + injected functions, recipe in
  docs, no new hard deps.)
- OQ2: Should the recordings fixture also capture encryption context per
  EDK, or is the message-header context always authoritative for vector
  messages? Verify against a sample during A1.
- OQ3: Package naming/rebranding (the `aws_` prefix vs multi-cloud
  keyrings) - explicitly deferred; revisit bundled with the 1.0
  milestone.
