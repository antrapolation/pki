defmodule PkiTenant.PortalUserManagement do
  @moduledoc """
  Profile + password operations on `PkiMnesia.Structs.PortalUser`.

  Scope is deliberately narrow — self-service profile editing and
  password rotation. Admin-level user CRUD (create/delete/role change)
  lives in a separate `users_live` port (Group D).

  Password storage supports both Argon2 (new default) and Bcrypt
  (legacy records). Updates always write Argon2.
  """

  alias PkiMnesia.Repo
  alias PkiMnesia.Structs.PortalUser

  @type update_error :: :not_found | :invalid_email | :invalid_display_name
  @type password_error :: :not_found | :wrong_password | :weak_password | :password_mismatch

  @doc """
  Update a user's profile (display_name and/or email). Does not touch
  password, role, or status.
  """
  @spec update_profile(String.t(), map()) :: {:ok, PortalUser.t()} | {:error, update_error()}
  def update_profile(user_id, attrs) when is_binary(user_id) and is_map(attrs) do
    display_name = attrs[:display_name] || attrs["display_name"]
    email = attrs[:email] || attrs["email"]

    with :ok <- validate_display_name(display_name),
         :ok <- validate_email(email),
         {:ok, user} <- fetch_user(user_id) do
      changes = %{
        display_name: String.trim(display_name || user.display_name || ""),
        email: normalize_email(email || user.email),
        updated_at: DateTime.utc_now() |> DateTime.truncate(:second)
      }

      Repo.update(user, changes)
    end
  end

  @doc """
  Verify the user's current password, then set a new one.

  The new password is validated for length (minimum 12) before the
  current-password check. Returns `{:error, :wrong_password}` when the
  current password doesn't match.
  """
  @spec verify_and_change_password(String.t(), String.t(), String.t(), String.t()) ::
          {:ok, PortalUser.t()} | {:error, password_error()}
  def verify_and_change_password(user_id, current_password, new_password, confirmation)
      when is_binary(user_id) and is_binary(current_password) and is_binary(new_password) and
             is_binary(confirmation) do
    with :ok <- validate_password(new_password, confirmation),
         {:ok, user} <- fetch_user(user_id),
         :ok <- verify_current(user, current_password) do
      hashed = Argon2.hash_pwd_salt(new_password)

      changes = %{
        password_hash: hashed,
        updated_at: DateTime.utc_now() |> DateTime.truncate(:second)
      }

      Repo.update(user, changes)
    end
  end

  # --- Private ---

  defp fetch_user(user_id) do
    case Repo.get(PortalUser, user_id) do
      {:ok, nil} -> {:error, :not_found}
      {:ok, user} -> {:ok, user}
      {:error, _} -> {:error, :not_found}
    end
  end

  defp validate_display_name(nil), do: :ok
  defp validate_display_name(""), do: :ok

  defp validate_display_name(dn) when is_binary(dn) do
    trimmed = String.trim(dn)

    cond do
      String.length(trimmed) > 128 -> {:error, :invalid_display_name}
      true -> :ok
    end
  end

  defp validate_display_name(_), do: {:error, :invalid_display_name}

  defp validate_email(nil), do: :ok
  defp validate_email(""), do: :ok

  defp validate_email(email) when is_binary(email) do
    trimmed = String.trim(email)

    cond do
      String.length(trimmed) > 320 -> {:error, :invalid_email}
      # A pragmatic local@domain check. RFC 5322 is too permissive to
      # be useful here; the real gate is the eventual email-verification
      # loop (out of scope).
      String.contains?(trimmed, "@") and String.contains?(trimmed, ".") -> :ok
      true -> {:error, :invalid_email}
    end
  end

  defp validate_email(_), do: {:error, :invalid_email}

  defp normalize_email(nil), do: nil
  defp normalize_email(""), do: nil

  defp normalize_email(email) when is_binary(email) do
    email |> String.trim() |> String.downcase()
  end

  defp validate_password(new_password, confirmation) do
    cond do
      new_password != confirmation -> {:error, :password_mismatch}
      String.length(new_password) < 12 -> {:error, :weak_password}
      true -> :ok
    end
  end

  defp verify_current(%PortalUser{password_hash: hash}, current_password)
       when is_binary(hash) do
    cond do
      String.starts_with?(hash, "$argon2") ->
        if Argon2.verify_pass(current_password, hash),
          do: :ok,
          else: {:error, :wrong_password}

      String.starts_with?(hash, "$2a$") or String.starts_with?(hash, "$2b$") ->
        if Bcrypt.verify_pass(current_password, hash),
          do: :ok,
          else: {:error, :wrong_password}

      true ->
        {:error, :wrong_password}
    end
  end

  defp verify_current(_, _), do: {:error, :wrong_password}
end
