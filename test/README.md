# Testing Guide

## Running Tests

### Unit Tests (Default)

Run the full test suite without AWS credentials:

```bash
mix test
```

This runs all unit tests and mocked tests. Integration tests are excluded by default.

### Integration Tests with AWS KMS

Integration tests make real AWS API calls and require valid credentials.

#### Setup

1. **Copy the example environment file:**
   ```bash
   cp .env.example .env
   ```

2. **Fill in your AWS credentials in `.env`:**
   ```bash
   AWS_ACCESS_KEY_ID=your_access_key_id
   AWS_SECRET_ACCESS_KEY=your_secret_access_key
   AWS_REGION=us-east-1
   KMS_KEY_ARN=arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012
   ```

3. **Create a test KMS key (if needed):**
   ```bash
   aws kms create-key --description "Test key for aws_encryption_sdk integration tests"
   ```

   Copy the `KeyId` from the output and set it as your `KMS_KEY_ARN`.

#### Running Integration Tests

Load your environment variables and run the integration tests:

```bash
source .env && mix test --only integration
```

Or set them inline:

```bash
AWS_ACCESS_KEY_ID=xxx AWS_SECRET_ACCESS_KEY=yyy KMS_KEY_ARN=arn:... mix test --only integration
```

**Note:** Integration tests will make real AWS API calls. While KMS operations are very cheap (fractions of a cent), they are not free.

### Test Tags

- **`:integration`** - Tests that require AWS credentials and make real API calls
- **`:requires_aws`** - Alias for integration tests
- **`:skip`** - Tests that are temporarily disabled

### Coverage

Check test coverage:

```bash
mix test --cover
```

View detailed coverage report:

```bash
mix coveralls.html
open cover/excoveralls.html
```

## Test Organization

```
test/
├── aws_encryption_sdk/          # Unit tests mirroring lib/ structure
│   ├── keyring/
│   │   ├── kms_client/
│   │   │   ├── mock_test.exs           # Mock client unit tests
│   │   │   ├── ex_aws_test.exs         # ExAws client unit tests
│   │   │   └── ex_aws_integration_test.exs  # Real AWS integration tests
│   │   └── ...
│   └── ...
├── support/                     # Test support modules
└── test_helper.exs             # Test configuration
```

## CI/CD

In CI environments (GitHub Actions, etc.), set AWS credentials as repository secrets:

```yaml
env:
  AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
  AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
  KMS_KEY_ARN: ${{ secrets.KMS_KEY_ARN }}
  AWS_REGION: us-east-1

- name: Run integration tests
  run: mix test --only integration
```

## Troubleshooting

### "KMS_KEY_ARN environment variable not set"

Make sure you've sourced your `.env` file or set the environment variable:

```bash
export KMS_KEY_ARN="arn:aws:kms:us-east-1:123456789012:key/..."
```

### AWS Credentials Not Found

ExAws checks for credentials in this order:
1. Environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`)
2. AWS credentials file (`~/.aws/credentials`)
3. IAM instance role (when running on EC2)

Make sure at least one of these is configured.

### Region Mismatch

Ensure your `AWS_REGION` matches the region of your KMS key. You can find the region in the key ARN:

```
arn:aws:kms:us-east-1:123456789012:key/...
                ^^^^^^^^^
                This is the region
```

### Permission Errors

Your AWS credentials need these KMS permissions:
- `kms:GenerateDataKey`
- `kms:Encrypt`
- `kms:Decrypt`

Example IAM policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "kms:GenerateDataKey",
        "kms:Encrypt",
        "kms:Decrypt"
      ],
      "Resource": "arn:aws:kms:us-east-1:123456789012:key/*"
    }
  ]
}
```
