defmodule AwsEncryptionSdk.Cache.LocalCache do
  @moduledoc """
  ETS-based local implementation of the Cryptographic Materials Cache.

  This cache stores materials in an ETS table owned by a GenServer process.
  Multiple Caching CMMs can share the same LocalCache instance.

  ## Example

      {:ok, cache} = LocalCache.start_link([])
      LocalCache.put_cache_entry(cache, cache_id, entry)
      {:ok, entry} = LocalCache.get_cache_entry(cache, cache_id)

  ## Options

  - `:name` - Optional registered name for the cache process
  """

  @behaviour AwsEncryptionSdk.Cache.CryptographicMaterialsCache

  use GenServer

  alias AwsEncryptionSdk.Cache.CacheEntry

  @type t :: pid() | atom()

  # Client API

  @doc """
  Starts a new LocalCache process.

  ## Options

  - `:name` - Optional registered name
  """
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    {name, opts} = Keyword.pop(opts, :name)

    if name do
      GenServer.start_link(__MODULE__, opts, name: name)
    else
      GenServer.start_link(__MODULE__, opts, [])
    end
  end

  @impl AwsEncryptionSdk.Cache.CryptographicMaterialsCache
  def put_cache_entry(cache, cache_id, %CacheEntry{} = entry)
      when is_binary(cache_id) and byte_size(cache_id) == 48 do
    GenServer.call(cache, {:put, cache_id, entry})
  end

  @impl AwsEncryptionSdk.Cache.CryptographicMaterialsCache
  def get_cache_entry(cache, cache_id)
      when is_binary(cache_id) and byte_size(cache_id) == 48 do
    GenServer.call(cache, {:get, cache_id})
  end

  @impl AwsEncryptionSdk.Cache.CryptographicMaterialsCache
  def delete_cache_entry(cache, cache_id)
      when is_binary(cache_id) and byte_size(cache_id) == 48 do
    GenServer.call(cache, {:delete, cache_id})
  end

  @impl AwsEncryptionSdk.Cache.CryptographicMaterialsCache
  def update_usage(cache, cache_id, messages, bytes)
      when is_binary(cache_id) and byte_size(cache_id) == 48 and
             is_integer(messages) and messages > 0 and
             is_integer(bytes) and bytes >= 0 do
    GenServer.call(cache, {:update_usage, cache_id, messages, bytes})
  end

  # Server Callbacks

  @impl GenServer
  def init(_opts) do
    table = :ets.new(:cache, [:set, :private])
    {:ok, %{table: table}}
  end

  @impl GenServer
  def handle_call({:put, cache_id, entry}, _from, %{table: table} = state) do
    :ets.insert(table, {cache_id, entry})
    {:reply, :ok, state}
  end

  def handle_call({:get, cache_id}, _from, %{table: table} = state) do
    result =
      case :ets.lookup(table, cache_id) do
        [{^cache_id, entry}] ->
          if CacheEntry.expired?(entry) do
            :ets.delete(table, cache_id)
            {:error, :cache_miss}
          else
            {:ok, entry}
          end

        [] ->
          {:error, :cache_miss}
      end

    {:reply, result, state}
  end

  def handle_call({:delete, cache_id}, _from, %{table: table} = state) do
    :ets.delete(table, cache_id)
    {:reply, :ok, state}
  end

  def handle_call({:update_usage, cache_id, messages, bytes}, _from, %{table: table} = state) do
    result =
      case :ets.lookup(table, cache_id) do
        [{^cache_id, entry}] ->
          updated = %{
            entry
            | messages_used: entry.messages_used + messages,
              bytes_used: entry.bytes_used + bytes
          }

          :ets.insert(table, {cache_id, updated})
          :ok

        [] ->
          {:error, :cache_miss}
      end

    {:reply, result, state}
  end

  @impl GenServer
  def terminate(_reason, %{table: table}) do
    :ets.delete(table)
    :ok
  end
end
