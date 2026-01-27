# Compile and load test support modules
Code.require_file("support/test_vector_setup.ex", __DIR__)
Code.require_file("support/test_vector_harness.ex", __DIR__)

# Configure ExUnit
# Exclude :skip and :integration by default
# Run integration tests with: mix test --only integration
ExUnit.configure(exclude: [:skip, :integration])

ExUnit.start()

# Check for test vectors (informational only)
alias AwsEncryptionSdk.TestSupport.TestVectorSetup

unless TestVectorSetup.vectors_available?() do
  TestVectorSetup.print_setup_instructions()
end
