#!/usr/bin/env elixir
# Caching CMM Example
#
# Demonstrates the Caching Cryptographic Materials Manager (CMM) which
# caches data keys to reduce calls to your key provider. This is useful
# for high-throughput scenarios where key generation latency matters.
#
# Run with: mix run examples/caching_cmm.exs

alias AwsEncryptionSdk.Client
alias AwsEncryptionSdk.Cmm.Default
alias AwsEncryptionSdk.Cmm.Caching
alias AwsEncryptionSdk.Cache.LocalCache
alias AwsEncryptionSdk.Keyring.RawAes

defmodule CachingDemo do
  @num_encryptions 100
  @message_size 1024  # 1KB messages

  def run do
    IO.puts(String.duplicate("=", 60))
    IO.puts("Caching CMM Example")
    IO.puts(String.duplicate("=", 60))
    IO.puts("")

    # Generate test data
    messages = for i <- 1..@num_encryptions do
      "Message #{i}: " <> :crypto.strong_rand_bytes(@message_size - 20)
    end

    # Step 1: Set up keyring
    IO.puts("Step 1: Setting up Raw AES keyring...")
    {:ok, keyring} = setup_keyring()
    IO.puts("  ✓ Keyring created with 256-bit AES key")
    IO.puts("")

    # Step 2: Benchmark WITHOUT caching
    IO.puts("Step 2: Encrypting #{@num_encryptions} messages WITHOUT caching...")
    IO.puts("  (Each encryption generates a new data key)")
    {non_cached_time, _results} = benchmark_non_cached(keyring, messages)
    IO.puts("  ✓ Completed in #{format_time(non_cached_time)}")
    IO.puts("")

    # Step 3: Set up caching CMM
    IO.puts("Step 3: Setting up Caching CMM...")
    {:ok, cache} = LocalCache.start_link([])

    # Cache settings:
    # - max_age: 60 seconds TTL
    # - max_messages: 1000 encryptions before re-keying
    # - max_bytes: 10MB of plaintext before re-keying
    caching_cmm = Caching.new_with_keyring(keyring, cache,
      max_age: 60,
      max_messages: 1000,
      max_bytes: 10 * 1024 * 1024
    )

    IO.puts("  ✓ Cache configured:")
    IO.puts("    - max_age: 60 seconds (TTL)")
    IO.puts("    - max_messages: 1000 (re-key after 1000 encryptions)")
    IO.puts("    - max_bytes: 10 MB (re-key after 10MB encrypted)")
    IO.puts("")

    # Step 4: Benchmark WITH caching
    IO.puts("Step 4: Encrypting #{@num_encryptions} messages WITH caching...")
    IO.puts("  (First encryption generates key, rest reuse cached key)")
    {cached_time, _results} = benchmark_cached(caching_cmm, messages)
    IO.puts("  ✓ Completed in #{format_time(cached_time)}")
    IO.puts("")

    # Step 5: Show comparison
    IO.puts("Step 5: Performance comparison...")
    speedup = non_cached_time / max(cached_time, 1)
    IO.puts("  Without caching: #{format_time(non_cached_time)}")
    IO.puts("  With caching:    #{format_time(cached_time)}")
    IO.puts("  Speedup:         #{Float.round(speedup, 1)}x faster")
    IO.puts("")

    # Step 6: Demonstrate cache behavior
    IO.puts("Step 6: Demonstrating cache behavior...")
    demonstrate_cache_behavior(keyring, cache)
    IO.puts("")

    # Step 7: When to use caching
    IO.puts("Step 7: When to use Caching CMM...")
    IO.puts("  ✓ High-throughput encryption (many messages per second)")
    IO.puts("  ✓ Latency-sensitive applications")
    IO.puts("  ✓ Reducing KMS API calls (cost savings with AWS KMS)")
    IO.puts("  ✗ Single encryption operations (no benefit)")
    IO.puts("  ✗ When each message needs unique key material")
    IO.puts("")

    IO.puts(String.duplicate("=", 60))
    IO.puts("Caching CMM demonstration completed!")
    IO.puts(String.duplicate("=", 60))
  end

  defp setup_keyring do
    wrapping_key = :crypto.strong_rand_bytes(32)
    RawAes.new("example", "caching-demo-key", wrapping_key, :aes_256_gcm)
  end

  defp benchmark_non_cached(keyring, messages) do
    cmm = Default.new(keyring)
    client = Client.new(cmm)

    encryption_context = %{"benchmark" => "non-cached"}

    :timer.tc(fn ->
      Enum.map(messages, fn msg ->
        {:ok, result} = Client.encrypt(client, msg, encryption_context: encryption_context)
        result
      end)
    end)
  end

  defp benchmark_cached(caching_cmm, messages) do
    client = Client.new(caching_cmm)

    encryption_context = %{"benchmark" => "cached"}

    :timer.tc(fn ->
      Enum.map(messages, fn msg ->
        {:ok, result} = Client.encrypt(client, msg, encryption_context: encryption_context)
        result
      end)
    end)
  end

  defp demonstrate_cache_behavior(keyring, cache) do
    # Create a new caching CMM with low limits to show re-keying
    caching_cmm = Caching.new_with_keyring(keyring, cache,
      max_age: 60,
      max_messages: 5  # Re-key after 5 messages
    )
    client = Client.new(caching_cmm)

    IO.puts("  Testing with max_messages: 5")

    # Encrypt 8 messages to show re-keying at message 6
    for i <- 1..8 do
      {time, {:ok, _result}} = :timer.tc(fn ->
        Client.encrypt(client, "test message #{i}",
          encryption_context: %{"test" => "cache-behavior"}
        )
      end)

      status = if i == 1 or i == 6 do
        "cache MISS (new key generated)"
      else
        "cache HIT (reusing key)"
      end

      IO.puts("    Message #{i}: #{format_time(time)} - #{status}")
    end

    IO.puts("  ✓ Re-keying occurred at message 6 (exceeded max_messages: 5)")
  end

  defp format_time(microseconds) when microseconds >= 1_000_000 do
    "#{Float.round(microseconds / 1_000_000, 2)} sec"
  end
  defp format_time(microseconds) when microseconds >= 1000 do
    "#{Float.round(microseconds / 1000, 2)} ms"
  end
  defp format_time(microseconds) do
    "#{microseconds} μs"
  end
end

CachingDemo.run()
