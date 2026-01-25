defmodule AwsEncryptionSdk.Format.Message do
  @moduledoc """
  Complete message serialization and deserialization.

  An AWS Encryption SDK message consists of:
  1. Header - Contains algorithm suite, message ID, encryption context, EDKs
  2. Body - Encrypted content (framed or non-framed)
  3. Footer - Optional ECDSA signature (only for signed algorithm suites)

  ## Message Structure

  ```
  +--------+--------+--------+
  | Header | Body   | Footer |
  +--------+--------+--------+
                    ^
                    |
                    Only present for signed suites
  ```
  """

  alias AwsEncryptionSdk.AlgorithmSuite
  alias AwsEncryptionSdk.Format.Body
  alias AwsEncryptionSdk.Format.Footer
  alias AwsEncryptionSdk.Format.Header

  @typedoc "Non-framed message body content"
  @type non_framed_body :: Body.non_framed()

  @typedoc "Framed message body content"
  @type framed_body :: [Body.frame()]

  @typedoc "Complete message structure"
  @type t :: %{
          header: Header.t(),
          body: non_framed_body() | framed_body(),
          footer: %{signature: binary()} | nil
        }

  @doc """
  Deserializes a complete message from binary data.

  Returns `{:ok, message, rest}` on success.
  """
  @spec deserialize(binary()) :: {:ok, t(), binary()} | {:error, term()}
  def deserialize(data) do
    with {:ok, header, rest} <- Header.deserialize(data),
         {:ok, body, rest} <- deserialize_body(rest, header),
         {:ok, footer, rest} <- deserialize_footer(rest, header.algorithm_suite) do
      message = %{
        header: header,
        body: body,
        footer: footer
      }

      {:ok, message, rest}
    end
  end

  @doc """
  Checks if a message requires a footer based on its algorithm suite.
  """
  @spec requires_footer?(Header.t()) :: boolean()
  def requires_footer?(%Header{algorithm_suite: suite}) do
    AlgorithmSuite.signed?(suite)
  end

  # Private functions

  defp deserialize_body(data, %Header{content_type: :non_framed}) do
    Body.deserialize_non_framed(data)
  end

  defp deserialize_body(data, %Header{content_type: :framed, frame_length: frame_length}) do
    Body.deserialize_all_frames(data, frame_length)
  end

  defp deserialize_footer(data, suite) do
    if AlgorithmSuite.signed?(suite) do
      Footer.deserialize(data)
    else
      {:ok, nil, data}
    end
  end
end
