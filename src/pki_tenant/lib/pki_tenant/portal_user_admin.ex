defmodule PkiTenant.PortalUserAdmin do
  @moduledoc """
  Admin-level CRUD for portal users.

  Scoped to the shared `PkiMnesia.Structs.PortalUser` table. Self-service
  profile + password rotation lives in `PkiTenant.PortalUserManagement`.

  Role catalog (stored as strings):

    * CA portal: `"ca_admin"`, `"key_manager"`, `"auditor"`
    * RA portal: `"ra_admin"`, `"ra_officer"`, `"auditor"`

  The `auditor` role appears in both portals' lists.

  Password handling: new users and reset-password flows generate a
  16-char random alphanumeric password, hash it with Argon2, and return
  the plaintext in the response tuple so the caller can show it once to
  the operator (email delivery is not wired yet).
  """

  alias PkiMnesia.Repo
  alias PkiMnesia.Structs.PortalUser

  @ca_roles ~w(ca_admin key_manager auditor)
  @ra_roles ~w(ra_admin ra_officer auditor)
  @all_roles Enum.uniq(@ca_roles ++ @ra_roles)
  @valid_statuses ~w(active suspended)

  @type scope :: :ca | :ra

  @doc "Valid role strings for a portal."
  @spec roles_for(scope()) :: [String.t()]
  def roles_for(:ca), do: @ca_roles
  def roles_for(:ra), do: @ra_roles

  @doc """
  List users whose role is visible in the given portal.

  Ordered by `inserted_at` ascending so newly-created users appear at
  the bottom of the page.
  """
  @spec list_users(scope()) :: [PortalUser.t()]
  def list_users(scope) when scope in [:ca, :ra] do
    allowed = roles_for(scope)

    case Repo.all(PortalUser) do
      {:ok, list} ->
        list
        |> Enum.filter(fn u -> role_str(u.role) in allowed end)
        |> Enum.sort_by(& &1.inserted_at, DateTime)

      _ ->
        []
    end
  end

  @doc """
  Create a user + random invitation password.

  Required attrs: `:username`, `:display_name`, `:email`, `:role`.

  Returns `{:ok, user, plaintext_password}` on success.
  """
  @spec create_user(map()) ::
          {:ok, PortalUser.t(), String.t()}
          | {:error, :invalid_username | :invalid_display_name | :invalid_email | :invalid_role | :username_taken | term()}
  def create_user(attrs) do
    username = attrs |> fetch(:username) |> trim_or_nil()
    display_name = attrs |> fetch(:display_name) |> trim_or_nil()
    email = attrs |> fetch(:email) |> trim_or_nil() |> maybe_downcase()
    role = attrs |> fetch(:role) |> role_str()

    with :ok <- validate_username(username),
         :ok <- validate_display_name(display_name),
         :ok <- validate_email(email),
         :ok <- validate_role(role),
         :ok <- guard_unique_username(username) do
      plaintext = generate_password()

      user =
        PortalUser.new(%{
          username: username,
          display_name: display_name,
          email: email,
          role: role,
          status: "active",
          password_hash: Argon2.hash_pwd_salt(plaintext)
        })

      case Repo.insert(user) do
        {:ok, inserted} -> {:ok, inserted, plaintext}
        {:error, reason} -> {:error, reason}
      end
    end
  end

  @doc "Set a user's status to `\"active\"` or `\"suspended\"`."
  @spec set_status(binary(), String.t()) ::
          {:ok, PortalUser.t()} | {:error, :not_found | :invalid_status | term()}
  def set_status(user_id, new_status) when new_status in @valid_statuses do
    with {:ok, user} <- fetch_user(user_id) do
      Repo.update(user, %{
        status: new_status,
        updated_at: DateTime.utc_now() |> DateTime.truncate(:second)
      })
    end
  end

  def set_status(_id, _bad), do: {:error, :invalid_status}

  @doc "Hard-delete a user."
  @spec delete_user(binary()) :: {:ok, binary()} | {:error, :not_found | term()}
  def delete_user(user_id) do
    with {:ok, _user} <- fetch_user(user_id) do
      Repo.delete(PortalUser, user_id)
    end
  end

  @doc """
  Generate a new random password and store the Argon2 hash.

  Returns `{:ok, user, plaintext}` so the operator can show it to the
  user once.
  """
  @spec reset_password(binary()) ::
          {:ok, PortalUser.t(), String.t()} | {:error, :not_found | term()}
  def reset_password(user_id) do
    with {:ok, user} <- fetch_user(user_id) do
      plaintext = generate_password()
      hashed = Argon2.hash_pwd_salt(plaintext)

      case Repo.update(user, %{
             password_hash: hashed,
             updated_at: DateTime.utc_now() |> DateTime.truncate(:second)
           }) do
        {:ok, updated} -> {:ok, updated, plaintext}
        {:error, reason} -> {:error, reason}
      end
    end
  end

  # --- Private ---

  defp fetch(attrs, key) do
    Map.get(attrs, key) || Map.get(attrs, Atom.to_string(key))
  end

  defp fetch_user(user_id) do
    case Repo.get(PortalUser, user_id) do
      {:ok, nil} -> {:error, :not_found}
      {:ok, user} -> {:ok, user}
      {:error, _} -> {:error, :not_found}
    end
  end

  defp trim_or_nil(nil), do: nil
  defp trim_or_nil(str) when is_binary(str), do: String.trim(str)
  defp trim_or_nil(other), do: other

  defp maybe_downcase(nil), do: nil
  defp maybe_downcase(str) when is_binary(str), do: String.downcase(str)

  defp role_str(nil), do: nil
  defp role_str(r) when is_atom(r), do: Atom.to_string(r)
  defp role_str(r) when is_binary(r), do: r

  defp validate_username(nil), do: {:error, :invalid_username}
  defp validate_username(""), do: {:error, :invalid_username}

  defp validate_username(u) when is_binary(u) do
    cond do
      String.length(u) < 3 -> {:error, :invalid_username}
      String.length(u) > 50 -> {:error, :invalid_username}
      not Regex.match?(~r/^[A-Za-z0-9._-]+$/, u) -> {:error, :invalid_username}
      true -> :ok
    end
  end

  defp validate_display_name(nil), do: {:error, :invalid_display_name}
  defp validate_display_name(""), do: {:error, :invalid_display_name}

  defp validate_display_name(d) when is_binary(d) do
    if String.length(d) <= 128, do: :ok, else: {:error, :invalid_display_name}
  end

  defp validate_email(nil), do: {:error, :invalid_email}
  defp validate_email(""), do: {:error, :invalid_email}

  defp validate_email(e) when is_binary(e) do
    cond do
      String.length(e) > 320 -> {:error, :invalid_email}
      String.contains?(e, "@") and String.contains?(e, ".") -> :ok
      true -> {:error, :invalid_email}
    end
  end

  defp validate_role(nil), do: {:error, :invalid_role}

  defp validate_role(r) when is_binary(r) do
    if r in @all_roles, do: :ok, else: {:error, :invalid_role}
  end

  defp guard_unique_username(username) do
    case Repo.where(PortalUser, fn u -> u.username == username end) do
      {:ok, []} -> :ok
      {:ok, _} -> {:error, :username_taken}
      {:error, reason} -> {:error, reason}
    end
  end

  defp generate_password do
    16
    |> :crypto.strong_rand_bytes()
    |> Base.url_encode64(padding: false)
    |> binary_part(0, 16)
  end
end
