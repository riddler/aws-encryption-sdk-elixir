# Compile and load test support modules
Code.require_file("support/test_vector_setup.ex", __DIR__)
Code.require_file("support/test_vector_harness.ex", __DIR__)
Code.require_file("support/guide_code_extractor.ex", __DIR__)
Code.require_file("support/integration_gate.ex", __DIR__)

alias AwsEncryptionSdk.TestSupport.IntegrationGate

# Configure ExUnit
# Exclude :skip by default. Integration tests make real AWS KMS calls, so
# they run only when a test key is configured and AWS accepts the
# credentials - see IntegrationGate for what counts as unconfigured.
{:ok, _apps} = Application.ensure_all_started(:ex_aws)

exclude =
  case IntegrationGate.check() do
    :run ->
      [:skip]

    {:exclude, reason} ->
      IntegrationGate.print_skip_notice(reason)
      [:skip, :integration]
  end

ExUnit.configure(exclude: exclude)

ExUnit.start()

# Check for test vectors (informational only)
alias AwsEncryptionSdk.TestSupport.TestVectorSetup

unless TestVectorSetup.vectors_available?() do
  TestVectorSetup.print_setup_instructions()
end
