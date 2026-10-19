import Config

# ExAws configuration
# These settings can be overridden with environment variables:
# - AWS_ACCESS_KEY_ID
# - AWS_SECRET_ACCESS_KEY
# - AWS_SESSION_TOKEN (temporary credentials, such as an assumed role's)
# - AWS_REGION (defaults to us-east-1)
config :ex_aws,
  access_key_id: [{:system, "AWS_ACCESS_KEY_ID"}, :instance_role],
  secret_access_key: [{:system, "AWS_SECRET_ACCESS_KEY"}, :instance_role],
  region: System.get_env("AWS_REGION", "us-east-1")

# Temporary credentials (an assumed role's, as in CI) carry a session token.
# The key is set only when the variable is set and not empty: static keys
# need no token, and an instance role supplies its own with its keys, so
# with the variable absent ex_aws behaves exactly as without this block.
if System.get_env("AWS_SESSION_TOKEN") not in [nil, ""] do
  config :ex_aws, security_token: {:system, "AWS_SESSION_TOKEN"}
end

# HTTP client configuration for ExAws
config :ex_aws, :hackney_opts,
  follow_redirect: true,
  recv_timeout: 30_000

# Import environment-specific config if it exists
if File.exists?("config/#{config_env()}.exs") do
  import_config "#{config_env()}.exs"
end
