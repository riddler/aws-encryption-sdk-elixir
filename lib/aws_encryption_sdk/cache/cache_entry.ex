defmodule AwsEncryptionSdk.Cache.CacheEntry do
  @moduledoc """
  Cache entry containing cryptographic materials with usage metadata.

  ## Fields

  - `:materials` - EncryptionMaterials or DecryptionMaterials
  - `:creation_time` - Monotonic time when entry was created (seconds)
  - `:expiry_time` - Monotonic time when entry expires (seconds)
  - `:messages_used` - Number of messages encrypted with this entry
  - `:bytes_used` - Number of bytes encrypted with this entry
  """

  alias AwsEncryptionSdk.Materials.{DecryptionMaterials, EncryptionMaterials}

  @type materials :: EncryptionMaterials.t() | DecryptionMaterials.t()

  @type t :: %__MODULE__{
          materials: materials(),
          creation_time: integer(),
          expiry_time: integer(),
          messages_used: non_neg_integer(),
          bytes_used: non_neg_integer()
        }

  @enforce_keys [:materials, :creation_time, :expiry_time]
  defstruct [
    :materials,
    :creation_time,
    :expiry_time,
    messages_used: 0,
    bytes_used: 0
  ]

  @doc """
  Creates a new cache entry with the given materials and TTL.

  ## Parameters

  - `materials` - EncryptionMaterials or DecryptionMaterials
  - `max_age` - TTL in seconds

  ## Examples

      iex> alias AwsEncryptionSdk.Cache.CacheEntry
      iex> alias AwsEncryptionSdk.Materials.EncryptionMaterials
      iex> alias AwsEncryptionSdk.AlgorithmSuite
      iex> suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      iex> materials = EncryptionMaterials.new_for_encrypt(suite, %{})
      iex> entry = CacheEntry.new(materials, 300)
      iex> entry.messages_used
      0
  """
  @spec new(materials(), pos_integer()) :: t()
  def new(materials, max_age) when is_integer(max_age) and max_age > 0 do
    now = System.monotonic_time(:second)

    %__MODULE__{
      materials: materials,
      creation_time: now,
      expiry_time: now + max_age,
      messages_used: 0,
      bytes_used: 0
    }
  end

  @doc """
  Checks if the cache entry has expired.

  ## Examples

      iex> alias AwsEncryptionSdk.Cache.CacheEntry
      iex> alias AwsEncryptionSdk.Materials.EncryptionMaterials
      iex> alias AwsEncryptionSdk.AlgorithmSuite
      iex> suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      iex> materials = EncryptionMaterials.new_for_encrypt(suite, %{})
      iex> entry = CacheEntry.new(materials, 300)
      iex> CacheEntry.expired?(entry)
      false
  """
  @spec expired?(t()) :: boolean()
  def expired?(%__MODULE__{expiry_time: expiry_time}) do
    System.monotonic_time(:second) >= expiry_time
  end

  @doc """
  Checks if the cache entry has exceeded usage limits.

  ## Parameters

  - `entry` - The cache entry
  - `max_messages` - Maximum messages allowed
  - `max_bytes` - Maximum bytes allowed

  ## Examples

      iex> alias AwsEncryptionSdk.Cache.CacheEntry
      iex> alias AwsEncryptionSdk.Materials.EncryptionMaterials
      iex> alias AwsEncryptionSdk.AlgorithmSuite
      iex> suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      iex> materials = EncryptionMaterials.new_for_encrypt(suite, %{})
      iex> entry = %CacheEntry{
      ...>   materials: materials,
      ...>   creation_time: 0,
      ...>   expiry_time: 1000,
      ...>   messages_used: 100,
      ...>   bytes_used: 1000
      ...> }
      iex> CacheEntry.exceeded_limits?(entry, 50, 10000)
      true
  """
  @spec exceeded_limits?(t(), non_neg_integer(), non_neg_integer()) :: boolean()
  def exceeded_limits?(%__MODULE__{} = entry, max_messages, max_bytes) do
    entry.messages_used >= max_messages or entry.bytes_used >= max_bytes
  end
end
