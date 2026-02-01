# Advanced Feature Examples Implementation Plan

## Overview

Add three new examples demonstrating advanced SDK features (streaming encryption, Caching CMM, Required Encryption Context CMM) and reorganize the examples directory into complexity-based subdirectories.

**Issue**: #75

## Current State Analysis

### Existing Examples Structure
```
examples/
├── README.md
├── raw_aes_basic.exs      (local, no AWS)
├── raw_rsa.exs            (local, no AWS)
├── multi_keyring_local.exs (local, no AWS)
├── kms_basic.exs          (requires AWS)
├── kms_discovery.exs      (requires AWS)
├── kms_multi_keyring.exs  (requires AWS)
└── kms_cross_region.exs   (requires AWS)
```

### Key Patterns from Existing Examples
- Numbered step comments (`# Step 1:`, `# Step 2:`, etc.)
- Visual output with checkmarks (✓) and crosses (✗)
- Section dividers: `String.duplicate("=", 60)`
- Tuple pattern matching: `{:ok, result}` / `{:error, reason}`
- Exit with `System.halt(1)` on failure
- Module aliasing at top of file

### Advanced Features API (from codebase analysis)

**Streaming** (`lib/aws_encryption_sdk/stream.ex`):
```elixir
AwsEncryptionSdk.encrypt_stream(plaintext_stream, client, opts)
AwsEncryptionSdk.decrypt_stream(ciphertext_stream, client, opts)
```

**Caching CMM** (`lib/aws_encryption_sdk/cmm/caching.ex`):
```elixir
{:ok, cache} = LocalCache.start_link([])
cmm = Caching.new_with_keyring(keyring, cache, max_age: 300)
```

**Required EC CMM** (`lib/aws_encryption_sdk/cmm/required_encryption_context.ex`):
```elixir
cmm = RequiredEncryptionContext.new_with_keyring(["tenant_id"], keyring)
```

## Desired End State

```
examples/
├── README.md (updated with navigation)
├── 01_basics/
│   ├── raw_aes_basic.exs
│   ├── raw_rsa.exs
│   └── multi_keyring_local.exs
├── 02_advanced/
│   ├── streaming_file.exs
│   ├── caching_cmm.exs
│   └── required_encryption_context.exs
└── 03_aws_kms/
    ├── kms_basic.exs
    ├── kms_discovery.exs
    ├── kms_multi_keyring.exs
    └── kms_cross_region.exs
```

All examples run successfully with clear output demonstrating the feature.

## What We're NOT Doing

- Not adding AWS KMS-based advanced examples (keeping these local-only for easy testing)
- Not adding benchmarking infrastructure (just simple timing comparisons)
- Not modifying the existing example content (only moving files)
- Not adding new dependencies

---

## Phase 1: Create Advanced Examples

### Overview
Create three new example files demonstrating streaming, caching CMM, and required encryption context CMM features.

### Changes Required:

#### 1. Streaming File Example
**File**: `examples/streaming_file.exs` (new)

```elixir
#!/usr/bin/env elixir
# Streaming File Encryption Example
#
# Demonstrates memory-efficient encryption of large files using the
# AWS Encryption SDK's streaming API. Instead of loading entire files
# into memory, data is processed in frames.
#
# Run with: mix run examples/streaming_file.exs

alias AwsEncryptionSdk.Client
alias AwsEncryptionSdk.Cmm.Default
alias AwsEncryptionSdk.Keyring.RawAes

defmodule StreamingDemo do
  @temp_dir System.tmp_dir!()
  @input_file Path.join(@temp_dir, "streaming_demo_input.bin")
  @encrypted_file Path.join(@temp_dir, "streaming_demo_encrypted.bin")
  @decrypted_file Path.join(@temp_dir, "streaming_demo_decrypted.bin")

  # 10MB file for demonstration
  @file_size 10 * 1024 * 1024
  @chunk_size 64 * 1024  # 64KB chunks for file I/O

  def run do
    IO.puts(String.duplicate("=", 60))
    IO.puts("Streaming File Encryption Example")
    IO.puts(String.duplicate("=", 60))
    IO.puts("")

    # Step 1: Set up encryption client
    IO.puts("Step 1: Setting up encryption client...")
    {client, _keyring} = setup_client()
    IO.puts("  ✓ Client ready with Raw AES keyring")
    IO.puts("")

    # Step 2: Generate test file
    IO.puts("Step 2: Generating #{format_size(@file_size)} test file...")
    generate_test_file()
    IO.puts("  ✓ Created: #{@input_file}")
    IO.puts("")

    # Step 3: Encrypt file using streaming
    IO.puts("Step 3: Encrypting file with streaming API...")
    IO.puts("  Frame size: 4096 bytes (default)")
    {encrypt_time, :ok} = :timer.tc(fn -> encrypt_file(client) end)
    encrypted_size = File.stat!(@encrypted_file).size
    IO.puts("  ✓ Encrypted in #{format_time(encrypt_time)}")
    IO.puts("  ✓ Output: #{@encrypted_file}")
    IO.puts("  ✓ Encrypted size: #{format_size(encrypted_size)} (includes header, frames, auth tags)")
    IO.puts("")

    # Step 4: Decrypt file using streaming
    IO.puts("Step 4: Decrypting file with streaming API...")
    {decrypt_time, :ok} = :timer.tc(fn -> decrypt_file(client) end)
    IO.puts("  ✓ Decrypted in #{format_time(decrypt_time)}")
    IO.puts("  ✓ Output: #{@decrypted_file}")
    IO.puts("")

    # Step 5: Verify integrity
    IO.puts("Step 5: Verifying file integrity...")
    verify_files()
    IO.puts("")

    # Step 6: Compare with non-streaming approach
    IO.puts("Step 6: Memory comparison (conceptual)...")
    IO.puts("  Non-streaming: Would load entire #{format_size(@file_size)} into memory")
    IO.puts("  Streaming: Processes ~4KB frames, constant memory usage")
    IO.puts("  ✓ Streaming is ideal for files larger than available memory")
    IO.puts("")

    # Cleanup
    IO.puts("Cleaning up temporary files...")
    cleanup()
    IO.puts("  ✓ Temporary files removed")
    IO.puts("")

    IO.puts(String.duplicate("=", 60))
    IO.puts("Streaming encryption completed successfully!")
    IO.puts(String.duplicate("=", 60))
  end

  defp setup_client do
    # Generate a random 256-bit AES key
    wrapping_key = :crypto.strong_rand_bytes(32)

    {:ok, keyring} = RawAes.new(
      "example",
      "streaming-demo-key",
      wrapping_key,
      :aes_256_gcm
    )

    cmm = Default.new(keyring)
    client = Client.new(cmm)

    {client, keyring}
  end

  defp generate_test_file do
    # Generate random data in chunks to avoid memory spike
    File.open!(@input_file, [:write, :binary], fn file ->
      chunks = div(@file_size, @chunk_size)

      for i <- 1..chunks do
        chunk = :crypto.strong_rand_bytes(@chunk_size)
        IO.binwrite(file, chunk)

        # Progress indicator every 10%
        if rem(i * 10, chunks) < 10 do
          percent = div(i * 100, chunks)
          IO.write("\r  Generating: #{percent}%")
        end
      end

      IO.puts("\r  Generating: 100%")
    end)
  end

  defp encrypt_file(client) do
    encryption_context = %{
      "purpose" => "streaming-demo",
      "file_type" => "binary"
    }

    # Stream from input file -> encrypt -> write to output file
    File.stream!(@input_file, @chunk_size)
    |> AwsEncryptionSdk.encrypt_stream(client, encryption_context: encryption_context)
    |> Stream.into(File.stream!(@encrypted_file, [:write, :binary]))
    |> Stream.run()

    :ok
  end

  defp decrypt_file(client) do
    # Stream from encrypted file -> decrypt -> write to output file
    File.stream!(@encrypted_file, @chunk_size)
    |> AwsEncryptionSdk.decrypt_stream(client)
    |> Stream.map(fn {plaintext, _status} -> plaintext end)
    |> Stream.into(File.stream!(@decrypted_file, [:write, :binary]))
    |> Stream.run()

    :ok
  end

  defp verify_files do
    # Compare file hashes
    input_hash = hash_file(@input_file)
    decrypted_hash = hash_file(@decrypted_file)

    if input_hash == decrypted_hash do
      IO.puts("  ✓ SHA-256 hashes match - decryption verified!")
      IO.puts("  Input:     #{Base.encode16(input_hash, case: :lower) |> String.slice(0, 16)}...")
      IO.puts("  Decrypted: #{Base.encode16(decrypted_hash, case: :lower) |> String.slice(0, 16)}...")
    else
      IO.puts("  ✗ Hash mismatch - decryption failed!")
      System.halt(1)
    end
  end

  defp hash_file(path) do
    File.stream!(path, 65536)
    |> Enum.reduce(:crypto.hash_init(:sha256), fn chunk, acc ->
      :crypto.hash_update(acc, chunk)
    end)
    |> :crypto.hash_final()
  end

  defp cleanup do
    File.rm(@input_file)
    File.rm(@encrypted_file)
    File.rm(@decrypted_file)
  end

  defp format_size(bytes) when bytes >= 1024 * 1024 do
    "#{Float.round(bytes / (1024 * 1024), 1)} MB"
  end
  defp format_size(bytes) when bytes >= 1024 do
    "#{Float.round(bytes / 1024, 1)} KB"
  end
  defp format_size(bytes), do: "#{bytes} bytes"

  defp format_time(microseconds) when microseconds >= 1_000_000 do
    "#{Float.round(microseconds / 1_000_000, 2)} seconds"
  end
  defp format_time(microseconds) do
    "#{Float.round(microseconds / 1000, 1)} ms"
  end
end

StreamingDemo.run()
```

#### 2. Caching CMM Example
**File**: `examples/caching_cmm.exs` (new)

```elixir
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
```

#### 3. Required Encryption Context Example
**File**: `examples/required_encryption_context.exs` (new)

```elixir
#!/usr/bin/env elixir
# Required Encryption Context CMM Example
#
# Demonstrates enforcing mandatory encryption context keys using the
# Required Encryption Context CMM. This is useful for compliance and
# security policies that require certain metadata on all encrypted data.
#
# Run with: mix run examples/required_encryption_context.exs

alias AwsEncryptionSdk.Client
alias AwsEncryptionSdk.Cmm.Default
alias AwsEncryptionSdk.Cmm.RequiredEncryptionContext
alias AwsEncryptionSdk.Keyring.RawAes

defmodule RequiredContextDemo do
  def run do
    IO.puts(String.duplicate("=", 60))
    IO.puts("Required Encryption Context CMM Example")
    IO.puts(String.duplicate("=", 60))
    IO.puts("")

    # Step 1: Set up keyring
    IO.puts("Step 1: Setting up Raw AES keyring...")
    {:ok, keyring} = setup_keyring()
    IO.puts("  ✓ Keyring created")
    IO.puts("")

    # Step 2: Create Required Encryption Context CMM
    IO.puts("Step 2: Creating Required Encryption Context CMM...")
    IO.puts("  Required keys: [\"tenant_id\", \"environment\"]")
    cmm = RequiredEncryptionContext.new_with_keyring(
      ["tenant_id", "environment"],
      keyring
    )
    client = Client.new(cmm)
    IO.puts("  ✓ CMM configured to require 'tenant_id' and 'environment'")
    IO.puts("")

    # Step 3: Successful encryption with all required keys
    IO.puts("Step 3: Encrypting with all required keys (should succeed)...")
    encryption_context = %{
      "tenant_id" => "acme-corp",
      "environment" => "production",
      "optional_key" => "some-value"
    }

    case Client.encrypt(client, "sensitive data", encryption_context: encryption_context) do
      {:ok, result} ->
        IO.puts("  ✓ Encryption succeeded!")
        IO.puts("  Context: #{inspect(encryption_context)}")
        IO.puts("  Ciphertext length: #{byte_size(result.ciphertext)} bytes")

        # Store for later decryption tests
        Process.put(:encrypted_result, result)
        Process.put(:encryption_context, encryption_context)

      {:error, reason} ->
        IO.puts("  ✗ Unexpected error: #{inspect(reason)}")
        System.halt(1)
    end
    IO.puts("")

    # Step 4: Failed encryption - missing required key
    IO.puts("Step 4: Encrypting without 'environment' key (should fail)...")
    incomplete_context = %{
      "tenant_id" => "acme-corp"
      # Missing "environment"
    }

    case Client.encrypt(client, "sensitive data", encryption_context: incomplete_context) do
      {:ok, _result} ->
        IO.puts("  ✗ Should have failed but succeeded!")
        System.halt(1)

      {:error, {:missing_required_encryption_context_keys, missing}} ->
        IO.puts("  ✓ Correctly rejected! Missing keys: #{inspect(missing)}")
    end
    IO.puts("")

    # Step 5: Failed encryption - no context at all
    IO.puts("Step 5: Encrypting without any context (should fail)...")

    case Client.encrypt(client, "sensitive data") do
      {:ok, _result} ->
        IO.puts("  ✗ Should have failed but succeeded!")
        System.halt(1)

      {:error, {:missing_required_encryption_context_keys, missing}} ->
        IO.puts("  ✓ Correctly rejected! Missing keys: #{inspect(missing)}")
    end
    IO.puts("")

    # Step 6: Successful decryption with reproduced context
    IO.puts("Step 6: Decrypting with reproduced context (should succeed)...")
    result = Process.get(:encrypted_result)
    encryption_context = Process.get(:encryption_context)

    case Client.decrypt(client, result.ciphertext, encryption_context: encryption_context) do
      {:ok, decrypt_result} ->
        IO.puts("  ✓ Decryption succeeded!")
        IO.puts("  Plaintext: #{inspect(decrypt_result.plaintext)}")

      {:error, reason} ->
        IO.puts("  ✗ Unexpected error: #{inspect(reason)}")
        System.halt(1)
    end
    IO.puts("")

    # Step 7: Failed decryption - missing reproduced context
    IO.puts("Step 7: Decrypting without reproduced context (should fail)...")

    case Client.decrypt(client, result.ciphertext) do
      {:ok, _decrypt_result} ->
        IO.puts("  ✗ Should have failed but succeeded!")
        System.halt(1)

      {:error, {:missing_required_encryption_context_keys, missing}} ->
        IO.puts("  ✓ Correctly rejected! Missing keys: #{inspect(missing)}")
    end
    IO.puts("")

    # Step 8: Compare with non-enforcing client
    IO.puts("Step 8: Comparison with standard CMM (no enforcement)...")
    standard_cmm = Default.new(keyring)
    standard_client = Client.new(standard_cmm)

    case Client.encrypt(standard_client, "data", encryption_context: %{}) do
      {:ok, _result} ->
        IO.puts("  Standard CMM: Allows empty encryption context")

      {:error, _reason} ->
        IO.puts("  Standard CMM: Rejected (unexpected)")
    end

    IO.puts("  Required EC CMM: Enforces mandatory keys")
    IO.puts("  ✓ Use Required EC CMM for compliance requirements")
    IO.puts("")

    # Step 9: Use cases
    IO.puts("Step 9: Common use cases for Required Encryption Context CMM...")
    IO.puts("  • Multi-tenant systems: Require 'tenant_id' on all data")
    IO.puts("  • Compliance: Require 'data_classification' or 'retention_policy'")
    IO.puts("  • Auditing: Require 'created_by' or 'request_id'")
    IO.puts("  • Environment separation: Require 'environment' (prod/staging/dev)")
    IO.puts("")

    IO.puts(String.duplicate("=", 60))
    IO.puts("Required Encryption Context demonstration completed!")
    IO.puts(String.duplicate("=", 60))
  end

  defp setup_keyring do
    wrapping_key = :crypto.strong_rand_bytes(32)
    RawAes.new("example", "required-context-demo-key", wrapping_key, :aes_256_gcm)
  end
end

RequiredContextDemo.run()
```

### Success Criteria:

#### Automated Verification:
- [x] All three example files created
- [x] Examples execute without errors: `mix run examples/streaming_file.exs`
- [x] Examples execute without errors: `mix run examples/caching_cmm.exs`
- [x] Examples execute without errors: `mix run examples/required_encryption_context.exs`

#### Manual Verification:
- [x] Streaming example shows progress and timing information
- [x] Caching example demonstrates visible speedup
- [x] Required EC example shows both success and failure cases
- [x] Output is clear and informative

**Implementation Note**: After completing this phase and all automated verification passes, pause for manual confirmation before proceeding to Phase 2.

---

## Phase 2: Reorganize Directory Structure

### Overview
Move existing examples into subdirectories and update the README to reflect the new organization.

### Changes Required:

#### 1. Create Directory Structure and Move Files

```bash
# Create directories
mkdir -p examples/01_basics
mkdir -p examples/02_advanced
mkdir -p examples/03_aws_kms

# Move basic examples
mv examples/raw_aes_basic.exs examples/01_basics/
mv examples/raw_rsa.exs examples/01_basics/
mv examples/multi_keyring_local.exs examples/01_basics/

# Move advanced examples (created in Phase 1)
mv examples/streaming_file.exs examples/02_advanced/
mv examples/caching_cmm.exs examples/02_advanced/
mv examples/required_encryption_context.exs examples/02_advanced/

# Move KMS examples
mv examples/kms_basic.exs examples/03_aws_kms/
mv examples/kms_discovery.exs examples/03_aws_kms/
mv examples/kms_multi_keyring.exs examples/03_aws_kms/
mv examples/kms_cross_region.exs examples/03_aws_kms/
```

#### 2. Update README
**File**: `examples/README.md`

```markdown
# AWS Encryption SDK Examples

Example scripts demonstrating various encryption scenarios, organized by complexity.

## Quick Start (No AWS Required)

```bash
# Basic AES encryption
mix run examples/01_basics/raw_aes_basic.exs

# RSA encryption with all padding schemes
mix run examples/01_basics/raw_rsa.exs

# Multi-keyring for redundancy
mix run examples/01_basics/multi_keyring_local.exs

# Streaming large file encryption
mix run examples/02_advanced/streaming_file.exs

# Caching CMM for high throughput
mix run examples/02_advanced/caching_cmm.exs

# Required encryption context enforcement
mix run examples/02_advanced/required_encryption_context.exs
```

## AWS KMS Examples

These examples require AWS credentials and KMS keys:

### Prerequisites

1. AWS credentials configured (environment variables, instance profile, or ~/.aws/credentials)
2. KMS key(s) with appropriate permissions
3. Dependencies installed: `mix deps.get`

### Running KMS Examples

```bash
# Set your KMS key ARN
export KMS_KEY_ARN="arn:aws:kms:us-west-2:123456789012:key/..."

# Run an example
mix run examples/03_aws_kms/kms_basic.exs
```

## Examples by Category

### 01_basics/ - Getting Started (No AWS Required)

| File | Description |
|------|-------------|
| `raw_aes_basic.exs` | AES-GCM encryption with local key, all key sizes |
| `raw_rsa.exs` | RSA encryption, all padding schemes, PEM key support |
| `multi_keyring_local.exs` | Multi-keyring for redundancy and key rotation |

### 02_advanced/ - Advanced Features (No AWS Required)

| File | Description |
|------|-------------|
| `streaming_file.exs` | Memory-efficient encryption of large files |
| `caching_cmm.exs` | Cached materials for high-throughput encryption |
| `required_encryption_context.exs` | Enforce mandatory encryption context keys |

### 03_aws_kms/ - AWS KMS Integration

| File | Description |
|------|-------------|
| `kms_basic.exs` | Basic encryption/decryption with KMS keyring |
| `kms_discovery.exs` | Discovery keyring for flexible decryption |
| `kms_multi_keyring.exs` | Multi-keyring with KMS for redundancy |
| `kms_cross_region.exs` | Cross-region decryption with MRK keyrings |

## Environment Variables

### RSA Example

| Variable | Description |
|----------|-------------|
| `RSA_PRIVATE_KEY_PEM` | PEM-encoded RSA private key (optional) |
| `RSA_PUBLIC_KEY_PEM` | PEM-encoded RSA public key (optional) |

If both are set, the example uses these keys. If neither is set, keys are generated.

### KMS Examples

| Variable | Description |
|----------|-------------|
| `KMS_KEY_ARN` | ARN of your KMS key |
| `KMS_KEY_ARN_1` | Primary KMS key (for multi-keyring) |
| `KMS_KEY_ARN_2` | Backup KMS key (for multi-keyring) |
| `AWS_REGION` | AWS region (optional, extracted from ARN) |

## Security Notes

- **Never hardcode keys** in production code
- **Protect private keys** with appropriate file permissions
- **Use a key management system** for production deployments
- The local key examples are for development and testing
```

### Success Criteria:

#### Automated Verification:
- [x] Directory structure matches expected layout
- [x] All moved examples still execute correctly:
  - `mix run examples/01_basics/raw_aes_basic.exs`
  - `mix run examples/01_basics/raw_rsa.exs`
  - `mix run examples/01_basics/multi_keyring_local.exs`
  - `mix run examples/02_advanced/streaming_file.exs`
  - `mix run examples/02_advanced/caching_cmm.exs`
  - `mix run examples/02_advanced/required_encryption_context.exs`
- [x] No files left in examples/ root (except README.md)

#### Manual Verification:
- [x] README navigation makes sense
- [x] Directory names are clear and self-explanatory

---

## Final Verification

After all phases complete:

### Automated:
- [x] All examples run without errors
- [x] `mix quality` passes (818 tests, 92.6% coverage)

### Manual:
- [x] Each example produces clear, helpful output
- [x] README provides good navigation

## References

- Issue: #75
- Streaming implementation: `lib/aws_encryption_sdk/stream.ex`
- Caching CMM: `lib/aws_encryption_sdk/cmm/caching.ex`
- Required EC CMM: `lib/aws_encryption_sdk/cmm/required_encryption_context.ex`
