# Test Fixtures

This directory contains test fixtures for the AWS Encryption SDK for Elixir.

## Test Vectors

The `test_vectors/` subdirectory should contain AWS Encryption SDK test vectors.
This directory is gitignored and must be set up manually.

### Setup Instructions

#### Option 1: Download Python vectors (recommended)

```bash
mkdir -p test/fixtures/test_vectors
curl -L https://github.com/awslabs/aws-encryption-sdk-test-vectors/raw/master/vectors/awses-decrypt/python-2.3.0.zip -o /tmp/python-vectors.zip
unzip /tmp/python-vectors.zip -d test/fixtures/test_vectors
rm /tmp/python-vectors.zip
```

#### Option 2: Clone full repository

```bash
git clone https://github.com/awslabs/aws-encryption-sdk-test-vectors.git test/fixtures/test_vectors
cd test/fixtures/test_vectors/vectors/awses-decrypt
unzip python-2.3.0.zip
```

### Running Test Vector Tests

```bash
# Run all test vector tests
mix test --only test_vectors

# Run specific test vector categories
mix test --only algorithm:committed
mix test --only algorithm:signed
```

### Test Vector Format

Test vectors follow the AWS Crypto Tools Test Vector Framework:
- https://github.com/awslabs/aws-crypto-tools-test-vector-framework

Key files:
- `manifest.json` - Main decrypt manifest with test cases
- `keys.json` - Key material for test decryption
- `ciphertexts/` - Pre-encrypted test data
- `plaintexts/` - Expected plaintext outputs
