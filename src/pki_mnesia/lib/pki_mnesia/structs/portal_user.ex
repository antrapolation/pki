defmodule PkiMnesia.Structs.PortalUser do
  @moduledoc """
  Per-tenant portal user (not platform user).

  `password_hash` is expected to be a Bcrypt/Argon2 hash string (e.g. "$2b$..." or "$argon2id$...").
  It must never store plaintext passwords.
  """

  @fields [:id, :username, :password_hash, :display_name, :email, :role,
           :status, :inserted_at, :updated_at]
  def fields, do: @fields

  defstruct @fields

  @type t :: %__MODULE__{
    id: binary(),
    username: String.t(),
    password_hash: binary(),
    display_name: String.t(),
    email: String.t(),
    role: atom(),
    status: String.t(),
    inserted_at: DateTime.t(),
    updated_at: DateTime.t()
  }

  def new(attrs \\ %{}) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)
    %__MODULE__{
      id: attrs[:id] || PkiMnesia.Id.generate(),
      username: attrs[:username],
      password_hash: attrs[:password_hash],
      display_name: attrs[:display_name],
      email: attrs[:email],
      role: attrs[:role],
      status: Map.get(attrs, :status, "active"),
      inserted_at: attrs[:inserted_at] || now,
      updated_at: attrs[:updated_at] || now
    }
  end
end
