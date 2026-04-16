defmodule PkiRaEngine.ApiKeyManagement do
  @moduledoc """
  API key management with hash-based lookup against Mnesia.

  Keys are stored as SHA-256 hashes. The raw key is only returned at creation time.
  """

  alias PkiMnesia.{Repo, Structs.ApiKey}

  @doc """
  Create a new API key.

  Generates a 32-byte random key, stores its SHA-256 hash.
  Returns the raw key (base64url-encoded) alongside the persisted record.
  The raw key is only visible at creation time.
  """
  @spec create_api_key(map()) :: {:ok, ApiKey.t(), String.t()} | {:error, term()}
  def create_api_key(attrs) do
    raw_key = generate_raw_key()
    key_hash = hash_key(raw_key)
    key_prefix = String.slice(raw_key, 0, 8)

    api_key =
      ApiKey.new(
        Map.merge(attrs, %{
          key_hash: key_hash,
          key_prefix: key_prefix
        })
      )

    case Repo.insert(api_key) do
      {:ok, api_key} -> {:ok, api_key, raw_key}
      error -> error
    end
  end

  @doc """
  Authenticate a raw API key string.

  Hashes the provided key and looks it up by the key_hash index.
  Checks that the key is active and not expired.
  """
  @spec authenticate(String.t()) :: {:ok, ApiKey.t()} | {:error, :invalid_key | :key_revoked | :key_expired}
  def authenticate(raw_key) do
    key_hash = hash_key(raw_key)

    case Repo.get_by(ApiKey, :key_hash, key_hash) do
      {:ok, nil} ->
        {:error, :invalid_key}

      {:ok, %{status: "revoked"}} ->
        {:error, :key_revoked}

      {:ok, %{expires_at: exp} = key} when not is_nil(exp) ->
        if DateTime.compare(DateTime.utc_now(), exp) == :gt,
          do: {:error, :key_expired},
          else: {:ok, key}

      {:ok, key} ->
        {:ok, key}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc "Revoke an API key by ID."
  @spec revoke_api_key(binary()) :: {:ok, ApiKey.t()} | {:error, :not_found | term()}
  def revoke_api_key(id) do
    case Repo.get(ApiKey, id) do
      {:ok, nil} ->
        {:error, :not_found}

      {:ok, key} ->
        Repo.update(key, %{status: "revoked", updated_at: DateTime.utc_now() |> DateTime.truncate(:second)})

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc "List API keys, optionally filtered by ra_instance_id."
  @spec list_api_keys(binary() | nil) :: {:ok, [ApiKey.t()]} | {:error, term()}
  def list_api_keys(ra_instance_id \\ nil) do
    if ra_instance_id do
      Repo.where(ApiKey, fn k -> k.ra_instance_id == ra_instance_id end)
    else
      Repo.all(ApiKey)
    end
  end

  # ── Private ─────────────────────────────────────────────────────────

  defp generate_raw_key do
    :crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false)
  end

  defp hash_key(raw_key) do
    :crypto.hash(:sha256, raw_key)
  end
end
