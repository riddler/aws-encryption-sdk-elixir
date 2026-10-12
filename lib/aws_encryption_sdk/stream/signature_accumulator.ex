defmodule AwsEncryptionSdk.Stream.SignatureAccumulator do
  @moduledoc """
  Incremental signature accumulation for streaming ECDSA operations.

  ## Purpose

  Enables ECDSA signing/verification for large messages without buffering
  the entire message in memory. Used internally by streaming encryption and
  decryption for signed algorithm suites.

  ## Memory Efficiency

  Instead of buffering the entire message for signing:

  - Accumulates the suite's signature hash state incrementally
  - Hash state size is constant regardless of message size
  - Final signature is computed from hash digest

  This allows signing/verifying messages of any size with constant memory usage.

  ## Signed Algorithm Suites

  The AWS Encryption SDK includes algorithm suites with ECDSA signatures:

  - `AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384` (0x0578, default)
  - `AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384` (0x0378)
  - `AES_192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384` (0x0346)
  - `AES_128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256` (0x0214)

  For these suites, the entire message (header + all frames) is signed.

  ## Usage Context

  You typically don't use this module directly. It's used internally by:

  - `AwsEncryptionSdk.Stream.Encryptor` - Accumulates hash during encryption
  - `AwsEncryptionSdk.Stream.Decryptor` - Verifies signature during decryption

  ## Low-Level Example

  If implementing custom streaming or signature logic:

      # During encryption
      acc = SignatureAccumulator.init(algorithm_suite)
      acc = SignatureAccumulator.update(acc, header_bytes)
      acc = SignatureAccumulator.update(acc, frame1_bytes)
      acc = SignatureAccumulator.update(acc, frame2_bytes)
      signature = SignatureAccumulator.sign(acc, private_key)

      # During decryption
      acc = SignatureAccumulator.init(algorithm_suite)
      acc = SignatureAccumulator.update(acc, header_bytes)
      acc = SignatureAccumulator.update(acc, frame1_bytes)
      acc = SignatureAccumulator.update(acc, frame2_bytes)
      valid? = SignatureAccumulator.verify(acc, signature, public_key)

  ## Hash Algorithm and Curve

  `init/1` takes both from the algorithm suite: SHA-256 and P-256 for
  0x0214, SHA-384 and P-384 for 0x0346, 0x0378 and 0x0578. `init/0` uses
  SHA-384 and P-384.

  ## See Also

  - `AwsEncryptionSdk.Stream.Encryptor` - Streaming encryption
  - `AwsEncryptionSdk.Stream.Decryptor` - Streaming decryption
  - `AwsEncryptionSdk.AlgorithmSuite` - Algorithm suite definitions
  """

  alias AwsEncryptionSdk.Crypto.ECDSA

  @type t :: %__MODULE__{
          hash_ctx: :crypto.hash_state(),
          curve: ECDSA.curve()
        }

  defstruct [:hash_ctx, curve: :secp384r1]

  @doc """
  Initializes a new signature accumulator with SHA-384 on P-384.
  """
  @spec init() :: t()
  def init do
    init_for_curve(:secp384r1)
  end

  @doc """
  Initializes a new signature accumulator for a signed algorithm suite:
  SHA-256 on P-256 for 0x0214, SHA-384 on P-384 for 0x0346, 0x0378 and
  0x0578.
  """
  @spec init(AwsEncryptionSdk.AlgorithmSuite.t()) :: t()
  def init(suite) do
    suite |> ECDSA.curve_for_suite() |> init_for_curve()
  end

  defp init_for_curve(curve) do
    %__MODULE__{hash_ctx: :crypto.hash_init(ECDSA.hash_for_curve(curve)), curve: curve}
  end

  @doc """
  Updates the accumulator with additional data.
  """
  @spec update(t(), binary()) :: t()
  def update(%__MODULE__{hash_ctx: ctx} = acc, data) when is_binary(data) do
    %{acc | hash_ctx: :crypto.hash_update(ctx, data)}
  end

  @doc """
  Finalizes the hash and signs with ECDSA on the accumulator's curve.

  Returns DER-encoded signature.
  """
  @spec sign(t(), binary()) :: binary()
  def sign(%__MODULE__{hash_ctx: ctx, curve: curve}, private_key) when is_binary(private_key) do
    digest = :crypto.hash_final(ctx)

    :crypto.sign(:ecdsa, ECDSA.hash_for_curve(curve), {:digest, digest}, [private_key, curve])
  end

  @doc """
  Finalizes the hash and verifies an ECDSA signature on the accumulator's
  curve. The public key may be compressed or uncompressed.

  Returns `true` if valid, `false` otherwise, including for a public key
  that is not a point on the accumulator's curve.
  """
  @spec verify(t(), binary(), binary()) :: boolean()
  def verify(%__MODULE__{hash_ctx: ctx, curve: curve}, signature, public_key)
      when is_binary(signature) and is_binary(public_key) do
    digest = :crypto.hash_final(ctx)
    normalized_key = ECDSA.normalize_public_key(public_key, curve)

    try do
      :crypto.verify(
        :ecdsa,
        ECDSA.hash_for_curve(curve),
        {:digest, digest},
        signature,
        [normalized_key, curve]
      )
    rescue
      # :crypto raises on a key it cannot read as a point on the curve
      _error in [ArgumentError, ErlangError] -> false
    end
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
