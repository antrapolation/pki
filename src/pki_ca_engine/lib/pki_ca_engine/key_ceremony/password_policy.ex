defmodule PkiCaEngine.KeyCeremony.PasswordPolicy do
  @moduledoc """
  Validation rules for per-ceremony custodian passwords.

  The password lives only for the duration of a single ceremony session,
  so policy is tuned for session use:

    - Minimum 12 characters. Balances memorable-across-the-session with
      brute-force cost on the encrypted share.
    - No complexity rules (no required mix of letter/digit/symbol). The
      length requirement is doing the work; complexity rules push
      people toward predictable substitutions.
    - Reject a small list of notorious common passwords so custodians
      can't pick e.g. "passwordpassword". The list is intentionally
      short — a full dictionary check adds friction without much
      additional security for a 12-char minimum.
  """

  @min_length 12

  # Intentionally small. These are passwords long enough to clear the
  # 12-char floor but still obviously guessable. Sourced from the most
  # common leaked-password lists, filtered to entries >= 12 chars.
  @common_passwords MapSet.new([
                      "password1234",
                      "passwordpassword",
                      "p@ssw0rd1234",
                      "123456789012",
                      "1234567890ab",
                      "qwertyuiopas",
                      "qwerty1234567",
                      "letmeinletmein",
                      "adminadminadmin",
                      "iloveyou1234",
                      "welcomewelcome",
                      "trustno1trustno1",
                      "changemechangeme",
                      "monkeymonkey123",
                      "password123!",
                      "Password1234"
                    ])

  @type validation_error ::
          {:too_short, pos_integer()}
          | :common_password
          | :mismatch
          | :empty

  @doc "Minimum required password length."
  def min_length, do: @min_length

  @doc """
  Validate a password against the policy. Returns `:ok` or
  `{:error, reason}`.
  """
  @spec validate(String.t()) :: :ok | {:error, validation_error()}
  def validate(password) when is_binary(password) do
    cond do
      password == "" ->
        {:error, :empty}

      String.length(password) < @min_length ->
        {:error, {:too_short, @min_length}}

      MapSet.member?(@common_passwords, password) ->
        {:error, :common_password}

      true ->
        :ok
    end
  end

  def validate(_), do: {:error, :empty}

  @doc """
  Validate a password and confirm it matches the confirmation field.
  """
  @spec validate_with_confirmation(String.t(), String.t()) ::
          :ok | {:error, validation_error()}
  def validate_with_confirmation(password, confirmation)
      when is_binary(password) and is_binary(confirmation) do
    cond do
      password != confirmation ->
        {:error, :mismatch}

      true ->
        validate(password)
    end
  end

  def validate_with_confirmation(_, _), do: {:error, :empty}

  @doc """
  Human-readable reason for a policy violation.
  """
  @spec humanize_error(validation_error()) :: String.t()
  def humanize_error({:too_short, n}), do: "Password must be at least #{n} characters."
  def humanize_error(:common_password), do: "Password is too common. Pick something less predictable."
  def humanize_error(:mismatch), do: "Passwords do not match."
  def humanize_error(:empty), do: "Password cannot be empty."
end
