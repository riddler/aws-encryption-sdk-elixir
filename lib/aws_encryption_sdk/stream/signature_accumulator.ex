defmodule AwsEncryptionSdk.Stream.SignatureAccumulator do
  @moduledoc """
  Incremental signature accumulation for streaming ECDSA operations.

  ## Purpose

  Enables ECDSA signing/verification for large messages without buffering
  the entire message in memory. Used internally by streaming encryption and
  decryption for signed algorithm suites.

  ## Memory Efficiency

  Instead of buffering the entire message for signing:

  - Accumulates SHA-384 hash state incrementally
  - Hash state size is constant (64 bytes) regardless of message size
  - Final signature is computed from hash digest

  This allows signing/verifying messages of any size with constant memory usage.

  ## Signed Algorithm Suites

  The AWS Encryption SDK includes algorithm suites with ECDSA P-384 signatures:

  - `AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384` (0x0578, default)
  - `AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384` (0x0378)

  For these suites, the entire message (header + all frames) is signed.

  ## Usage Context

  You typically don't use this module directly. It's used internally by:

  - `AwsEncryptionSdk.Stream.Encryptor` - Accumulates hash during encryption
  - `AwsEncryptionSdk.Stream.Decryptor` - Verifies signature during decryption

  ## Low-Level Example

  If implementing custom streaming or signature logic:

      # During encryption
      acc = SignatureAccumulator.init()
      acc = SignatureAccumulator.update(acc, header_bytes)
      acc = SignatureAccumulator.update(acc, frame1_bytes)
      acc = SignatureAccumulator.update(acc, frame2_bytes)
      signature = SignatureAccumulator.sign(acc, private_key)

      # During decryption
      acc = SignatureAccumulator.init()
      acc = SignatureAccumulator.update(acc, header_bytes)
      acc = SignatureAccumulator.update(acc, frame1_bytes)
      acc = SignatureAccumulator.update(acc, frame2_bytes)
      valid? = SignatureAccumulator.verify(acc, signature, public_key)

  ## Hash Algorithm

  Uses SHA-384 for hash accumulation, matching the ECDSA P-384 curve
  used by signed algorithm suites.

  ## See Also

  - `AwsEncryptionSdk.Stream.Encryptor` - Streaming encryption
  - `AwsEncryptionSdk.Stream.Decryptor` - Streaming decryption
  - `AwsEncryptionSdk.AlgorithmSuite` - Algorithm suite definitions
  """

  @type t :: %__MODULE__{
          hash_ctx: :crypto.hash_state()
        }

  defstruct [:hash_ctx]

  @doc """
  Initializes a new signature accumulator with SHA-384.
  """
  @spec init() :: t()
  def init do
    %__MODULE__{hash_ctx: :crypto.hash_init(:sha384)}
  end

  @doc """
  Updates the accumulator with additional data.
  """
  @spec update(t(), binary()) :: t()
  def update(%__MODULE__{hash_ctx: ctx} = acc, data) when is_binary(data) do
    %{acc | hash_ctx: :crypto.hash_update(ctx, data)}
  end

  @doc """
  Finalizes the hash and signs with ECDSA P-384.

  Returns DER-encoded signature.
  """
  @spec sign(t(), binary()) :: binary()
  def sign(%__MODULE__{hash_ctx: ctx}, private_key) when is_binary(private_key) do
    digest = :crypto.hash_final(ctx)
    :crypto.sign(:ecdsa, :sha384, {:digest, digest}, [private_key, :secp384r1])
  end

  @doc """
  Finalizes the hash and verifies an ECDSA P-384 signature.

  Returns `true` if valid, `false` otherwise.
  """
  @spec verify(t(), binary(), binary()) :: boolean()
  def verify(%__MODULE__{hash_ctx: ctx}, signature, public_key)
      when is_binary(signature) and is_binary(public_key) do
    digest = :crypto.hash_final(ctx)
    :crypto.verify(:ecdsa, :sha384, {:digest, digest}, signature, [public_key, :secp384r1])
  end

  @doc """
  Returns the current hash digest without finalizing.

  Useful for debugging or intermediate verification.
  """
  @spec digest(t()) :: binary()
  def digest(%__MODULE__{hash_ctx: ctx}) do
    # Clone context to avoid consuming it
    :crypto.hash_final(ctx)
  end
end
