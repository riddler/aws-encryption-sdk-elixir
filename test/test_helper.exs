# Compile and load test support modules
Code.require_file("support/test_vector_setup.ex", __DIR__)
Code.require_file("support/test_vector_harness.ex", __DIR__)
Code.require_file("support/guide_code_extractor.ex", __DIR__)

# Configure ExUnit
# Exclude :skip by default
# To exclude integration tests locally: mix test --exclude integration
ExUnit.configure(exclude: [:skip])

ExUnit.start()

# Check for test vectors (informational only)
alias AwsEncryptionSdk.TestSupport.TestVectorSetup

unless TestVectorSetup.vectors_available?() do
  TestVectorSetup.print_setup_instructions()
end
