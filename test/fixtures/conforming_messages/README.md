# Messages written by another SDK that follows the specification

Two messages written by the AWS Encryption SDK for Python, committed so that
`test/aws_encryption_sdk/required_context_storage_test.exs` can assert that
this SDK decrypts a message whose required encryption context keys are NOT
stored in the header (the specification's form: client-apis/encrypt.md,
"Construct the header").

| File | Suite | Encryption context |
|---|---|---|
| `required-context-0478.bin` | 0x0478 | `required-a` = `value-a`, `required-b` = `value-b`, `stored-a` = `value-s` |
| `required-context-0578.bin` | 0x0578 | the same |

The plaintext of each is `fixture plaintext`. The header of each stores only
`stored-a` (and, at 0x0578, the compressed verification key); `required-a`
and `required-b` are only authenticated.

## How they were made

- `aws-encryption-sdk` 4.0.7 with the Material Providers Library 1.11.3 on
  Python 3.12, installed with `pip install --require-hashes`, no AWS
  environment variable set.
- The wrapping key is the same public-label test key as
  `../pre_1_1_messages/README.md` describes:
  SHA-256 of `aws-encryption-sdk-elixir pre-1.1 fixture test key`.
- A raw AES keyring (`create_raw_aes_keyring`, namespace `fixture-ns`, name
  `fixture-wrapping-key`, `ALG_AES256_GCM_IV12_TAG16`), a default CMM over it,
  and a required encryption context CMM over that
  (`create_required_encryption_context_cmm`, keys `required-a` and
  `required-b`).
- `EncryptionSDKClient(commitment_policy=REQUIRE_ENCRYPT_REQUIRE_DECRYPT)`,
  `encrypt` with the context above and `algorithm=` set to
  `AES_256_GCM_HKDF_SHA512_COMMIT_KEY` (0x0478) or
  `AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384` (0x0578).

SHA-256 of each file:

```
56f4dcd03c910169e089cfa7e2c92e522ae5bed96c4d05878c85ee8b18b2f962  required-context-0478.bin
66e24082a33d1a4b8f338864b13e6284a06411919a9527e5b0d58ca9e88abc4f  required-context-0578.bin
```
