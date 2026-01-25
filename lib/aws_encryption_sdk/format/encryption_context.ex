defmodule AwsEncryptionSdk.Format.EncryptionContext do
  @moduledoc """
  Encryption context serialization and validation.

  The encryption context is a key-value mapping of arbitrary, non-secret,
  UTF-8 encoded strings used as Additional Authenticated Data (AAD).

  ## Serialization Format

  Per structures.md:
  - Empty context: empty byte sequence (0 bytes)
  - Non-empty context:
    ```
    <<count::16-big, entry1::binary, entry2::binary, ...>>
    ```
  - Each entry:
    ```
    <<key_len::16-big, key::binary, value_len::16-big, value::binary>>
    ```
  - Entries MUST be sorted ascending by UTF-8 encoded key bytes

  ## Reserved Keys

  The prefix `aws-crypto-` is reserved for internal SDK use. User-provided
  encryption context MUST NOT contain keys with this prefix.
  """

  @reserved_prefix "aws-crypto-"

  @typedoc "Encryption context map"
  @type t :: %{String.t() => String.t()}

  @doc """
  Validates that user-provided encryption context does not contain reserved keys.

  Returns `:ok` if valid, or `{:error, {:reserved_keys, keys}}` if reserved keys found.

  ## Examples

      iex> AwsEncryptionSdk.Format.EncryptionContext.validate(%{"user-key" => "value"})
      :ok

      iex> AwsEncryptionSdk.Format.EncryptionContext.validate(%{"aws-crypto-public-key" => "value"})
      {:error, {:reserved_keys, ["aws-crypto-public-key"]}}
  """
  @spec validate(t()) :: :ok | {:error, {:reserved_keys, [String.t()]}}
  def validate(context) when is_map(context) do
    reserved_keys =
      context
      |> Map.keys()
      |> Enum.filter(&String.starts_with?(&1, @reserved_prefix))

    case reserved_keys do
      [] -> :ok
      keys -> {:error, {:reserved_keys, Enum.sort(keys)}}
    end
  end

  @doc """
  Serializes an encryption context to binary format.

  Empty maps produce an empty binary. Non-empty maps produce a count-prefixed
  sequence of key-value entries, sorted by key.

  ## Examples

      iex> AwsEncryptionSdk.Format.EncryptionContext.serialize(%{})
      <<>>

      iex> AwsEncryptionSdk.Format.EncryptionContext.serialize(%{"a" => "1"})
      <<0, 1, 0, 1, ?a, 0, 1, ?1>>
  """
  @spec serialize(t()) :: binary()
  def serialize(context) when map_size(context) == 0, do: <<>>

  def serialize(context) when is_map(context) do
    sorted_entries = Enum.sort_by(context, fn {k, _v} -> k end)
    count = length(sorted_entries)

    entries_binary =
      sorted_entries
      |> Enum.map(&serialize_entry/1)
      |> IO.iodata_to_binary()

    <<count::16-big, entries_binary::binary>>
  end

  @doc """
  Deserializes an encryption context from binary format.

  Returns `{:ok, context, rest}` on success.

  ## Examples

      iex> AwsEncryptionSdk.Format.EncryptionContext.deserialize(<<>>)
      {:ok, %{}, <<>>}
  """
  @spec deserialize(binary()) :: {:ok, t(), binary()} | {:error, term()}
  def deserialize(<<>>), do: {:ok, %{}, <<>>}

  def deserialize(<<count::16-big, rest::binary>>) when count > 0 do
    deserialize_entries(rest, count, %{})
  end

  def deserialize(<<0::16-big, rest::binary>>), do: {:ok, %{}, rest}

  def deserialize(_data), do: {:error, :invalid_encryption_context_format}

  # Private functions

  defp serialize_entry({key, value}) do
    key_len = byte_size(key)
    value_len = byte_size(value)
    <<key_len::16-big, key::binary, value_len::16-big, value::binary>>
  end

  defp deserialize_entries(rest, 0, acc), do: {:ok, acc, rest}

  defp deserialize_entries(
         <<key_len::16-big, key::binary-size(key_len), value_len::16-big,
           value::binary-size(value_len), rest::binary>>,
         n,
         acc
       ) do
    deserialize_entries(rest, n - 1, Map.put(acc, key, value))
  end

  defp deserialize_entries(_data, _n, _acc), do: {:error, :invalid_encryption_context_entry}
end
