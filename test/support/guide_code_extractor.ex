defmodule AwsEncryptionSdk.TestSupport.GuideCodeExtractor do
  @moduledoc """
  Extracts and parses Elixir code blocks from markdown guide files.

  This module enables testing code examples directly from the guides,
  ensuring documentation stays accurate and up-to-date.
  """

  @doc """
  Extracts all Elixir code blocks from a markdown file.

  Returns a list of code blocks with metadata.

  ## Options

  - `:include_comments` - Include comment-only blocks (default: false)
  - `:skip_pattern` - Regex pattern to skip blocks (default: nil)

  ## Returns

  List of maps with:
  - `:code` - The code string
  - `:line` - Starting line number
  - `:testable` - Whether this block should be tested (excludes incomplete examples)
  """
  @spec extract_code_blocks(String.t(), keyword()) :: [map()]
  def extract_code_blocks(file_path, opts \\ []) do
    content = File.read!(file_path)
    include_comments = Keyword.get(opts, :include_comments, false)
    skip_pattern = Keyword.get(opts, :skip_pattern)

    content
    |> String.split("\n")
    |> extract_blocks()
    |> Enum.filter(&should_include?(&1, include_comments, skip_pattern))
  end

  @doc """
  Groups consecutive code blocks together.

  This is useful when multiple code blocks in a guide build on each other
  and need to be executed in sequence.
  """
  @spec group_sequential_blocks([map()]) :: [[map()]]
  def group_sequential_blocks(blocks) do
    blocks
    |> Enum.chunk_by(fn block -> block[:section] end)
  end

  @doc """
  Cleans code for execution by removing output comment lines.

  Output comments are lines that show expected results (e.g., `# => "result"`).
  """
  @spec clean_code_for_execution(String.t()) :: String.t()
  def clean_code_for_execution(code) do
    code
    |> String.split("\n")
    |> Enum.reject(&String.match?(&1, ~r/^\s*#\s*=>/))
    |> Enum.join("\n")
  end

  # Private functions

  defp extract_blocks(lines) do
    lines
    |> Enum.with_index(1)
    |> Enum.reduce({[], nil, [], nil}, &process_line/2)
    |> finalize_extraction()
  end

  defp process_line({line, line_num}, {blocks, current_block, current_code, section}) do
    cond do
      # Start of elixir code block
      String.starts_with?(line, "```elixir") ->
        {blocks, line_num, [], section}

      # End of code block
      current_block && String.starts_with?(line, "```") ->
        code = Enum.reverse(current_code) |> Enum.join("\n")

        block = %{
          code: code,
          line: current_block,
          section: section,
          testable: testable?(code)
        }

        {[block | blocks], nil, [], section}

      # Inside code block
      current_block ->
        {blocks, current_block, [line | current_code], section}

      # Track sections for grouping
      String.starts_with?(line, "## ") ->
        section_name = String.trim_leading(line, "## ")
        {blocks, current_block, current_code, section_name}

      # Not in code block
      true ->
        {blocks, current_block, current_code, section}
    end
  end

  defp finalize_extraction({blocks, _current, _code, _section}) do
    Enum.reverse(blocks)
  end

  defp testable?(code) do
    # Skip blocks that are incomplete examples or error cases
    not (String.contains?(code, "...") or
           String.contains?(code, "12345678-1234-1234-1234-123456789012") or
           String.contains?(code, "123456789012") or
           String.contains?(code, "store_encrypted(result.ciphertext)") or
           String.contains?(code, "fetch_key_from_secrets_manager()") or
           String.contains?(code, "use_data(result.plaintext)") or
           String.contains?(code, "valid_context?(result.encryption_context)") or
           String.starts_with?(code, "mix "))
  end

  defp should_include?(block, include_comments, skip_pattern) do
    cond do
      # Skip if pattern matches
      skip_pattern && Regex.match?(skip_pattern, block.code) ->
        false

      # Skip comment-only blocks unless requested
      not include_comments && comment_only?(block.code) ->
        false

      true ->
        true
    end
  end

  defp comment_only?(code) do
    code
    |> String.split("\n")
    |> Enum.reject(&(String.trim(&1) == ""))
    |> Enum.all?(&String.starts_with?(String.trim(&1), "#"))
  end
end
