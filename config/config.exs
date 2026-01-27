import Config

# ExAws configuration
# These settings can be overridden with environment variables:
# - AWS_ACCESS_KEY_ID
# - AWS_SECRET_ACCESS_KEY
# - AWS_REGION (defaults to us-east-1)
config :ex_aws,
  access_key_id: [{:system, "AWS_ACCESS_KEY_ID"}, :instance_role],
  secret_access_key: [{:system, "AWS_SECRET_ACCESS_KEY"}, :instance_role],
  region: System.get_env("AWS_REGION", "us-east-1")

# HTTP client configuration for ExAws
config :ex_aws, :hackney_opts,
  follow_redirect: true,
  recv_timeout: 30_000

# Import environment-specific config if it exists
if File.exists?("config/#{config_env()}.exs") do
  import_config "#{config_env()}.exs"
end
