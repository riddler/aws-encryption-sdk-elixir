# Compile and load test support modules
Code.require_file("support/test_vector_setup.ex", __DIR__)
Code.require_file("support/test_vector_harness.ex", __DIR__)
Code.require_file("support/guide_code_extractor.ex", __DIR__)

# Configure ExUnit
# Exclude :skip by default
# Integration tests make real AWS KMS calls, so they only run when a test
# key is configured (KMS_KEY_ARN plus AWS credentials, as in CI). Force them
# with: source .env && mix test --only integration
exclude =
  if System.get_env("KMS_KEY_ARN") do
    [:skip]
  else
    [:skip, :integration]
  end

ExUnit.configure(exclude: exclude)

ExUnit.start()

# Check for test vectors (informational only)
alias AwsEncryptionSdk.TestSupport.TestVectorSetup

unless TestVectorSetup.vectors_available?() do
  TestVectorSetup.print_setup_instructions()
end
