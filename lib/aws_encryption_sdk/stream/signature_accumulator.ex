defmodule AwsEncryptionSdk.Stream.SignatureAccumulator do
  @moduledoc """
  Incremental signature accumulation for streaming operations.

  Uses SHA-384 hash accumulation to avoid buffering the entire message
  for ECDSA signing/verification.

  ## Example

      acc = SignatureAccumulator.init()
      acc = SignatureAccumulator.update(acc, header_bytes)
      acc = SignatureAccumulator.update(acc, frame1_bytes)
      acc = SignatureAccumulator.update(acc, frame2_bytes)
      signature = SignatureAccumulator.sign(acc, private_key)

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
