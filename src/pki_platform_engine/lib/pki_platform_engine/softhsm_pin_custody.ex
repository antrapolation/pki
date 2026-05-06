defmodule PkiPlatformEngine.SofthsmPinCustody do
  @moduledoc """
  Envelope encryption for per-tenant SoftHSM2 PINs.

  ## Threat model

  The raw user/SO PINs protect the per-tenant SoftHSM2 token —
  which stores the keystore's private key material at rest. A
  compromise of the platform database must **not** give the
  attacker the PINs that unlock those tokens.

  ## Envelope shape (v1)

  `%{
      "version"     => "v1",
      "salt"        => <16-byte base64 url-safe>,
      "iv"          => <12-byte base64 url-safe>,
      "user_pin_ct" => <ciphertext||tag, base64 url-safe>,
      "so_pin_ct"   => <ciphertext||tag, base64 url-safe>,
      "wrapped_at"  => ISO8601 timestamp
    }`

  `version` lets us migrate the KDF / AEAD later without breaking
  already-wrapped tenants. `wrap/3` always writes `"v1"`; `unwrap/2`
  reads the `"version"` field and dispatches.

  ## Cryptographic construction (v1)

  - **KEK:** 32-byte platform master key returned by
    `PkiPlatformEngine.SecretManager.master_key/0`.
  - **Per-tenant DEK:** `HKDF-SHA256(KEK, salt, "pki_softhsm_pin/v1/<tenant_id>", 32)`.
    Binding `tenant_id` into the HKDF `info` parameter means a stolen
    envelope can't be re-interpreted against another tenant.
  - **Cipher:** AES-256-GCM, random 12-byte IV, 16-byte auth tag.
  - **AAD:** `"pki_softhsm_pin/v1/<tenant_id>"`. Further binds the
    ciphertext to the tenant — swapping envelopes across tenants
    in the platform DB surfaces as a MAC failure on decrypt.

  ## Failure modes

  - `{:error, :no_master_key}` — `SecretManager` can't produce a
    key. Callers fall back to `.pins`-on-disk with a warning
    (`SofthsmTokenManager`).
  - `{:error, :decryption_failed}` — wrong master key, tampered
    ciphertext, or mismatched `tenant_id`. Never reveals which.
  - `{:error, :unsupported_envelope_version}` — envelope from a
    future scheme; upgrade platform or run the re-wrap task.
  """

  alias PkiPlatformEngine.{SecretManager, PlatformRepo, Tenant}

  @version "v1"
  @info_prefix "pki_softhsm_pin/v1/"
  @salt_bytes 16
  @iv_bytes 12
  @key_bytes 32

  @type envelope :: %{String.t() => String.t()}

  @doc """
  Wrap a pair of PINs for the given tenant. Returns the envelope
  map on success, ready to persist in `tenants.metadata`.

  Returns `{:error, :no_master_key}` if the `SecretManager`
  backend can't produce a KEK — caller must fall back to an
  unencrypted store.
  """
  @spec wrap(String.t(), String.t(), String.t()) ::
          {:ok, envelope()} | {:error, term()}
  def wrap(tenant_id, user_pin, so_pin)
      when is_binary(tenant_id) and is_binary(user_pin) and is_binary(so_pin) do
    with {:ok, kek} <- SecretManager.master_key() do
      salt = :crypto.strong_rand_bytes(@salt_bytes)
      iv = :crypto.strong_rand_bytes(@iv_bytes)
      dek = derive_dek(kek, salt, tenant_id)
      aad = aad_for(tenant_id)

      {user_ct, user_tag} =
        :crypto.crypto_one_time_aead(:aes_256_gcm, dek, iv, user_pin, aad, true)

      # Fresh IV for the second PIN so the same IV isn't reused across
      # the two AEAD operations under the same key — mandatory for
      # GCM's key-committing property.
      iv2 = :crypto.strong_rand_bytes(@iv_bytes)

      {so_ct, so_tag} =
        :crypto.crypto_one_time_aead(:aes_256_gcm, dek, iv2, so_pin, aad, true)

      {:ok,
       %{
         "version" => @version,
         "salt" => encode(salt),
         "iv" => encode(iv),
         "iv_so" => encode(iv2),
         "user_pin_ct" => encode(user_ct <> user_tag),
         "so_pin_ct" => encode(so_ct <> so_tag),
         "wrapped_at" => DateTime.utc_now() |> DateTime.to_iso8601()
       }}
    end
  end

  @doc """
  Unwrap a PIN envelope for the given tenant. Returns
  `{:ok, %{user_pin: ..., so_pin: ...}}` on success.

  `tenant_id` **must** match the id passed at wrap time — that's
  baked into the HKDF `info` and the AEAD `AAD`, so any mismatch
  surfaces as `{:error, :decryption_failed}`.
  """
  @spec unwrap(String.t(), envelope()) ::
          {:ok, %{user_pin: String.t(), so_pin: String.t()}} | {:error, term()}
  def unwrap(tenant_id, %{"version" => "v1"} = envelope) when is_binary(tenant_id) do
    with {:ok, kek} <- SecretManager.master_key(),
         {:ok, salt} <- decode(envelope["salt"]),
         {:ok, iv} <- decode(envelope["iv"]),
         {:ok, iv2} <- decode(envelope["iv_so"]),
         {:ok, user_ct_tag} <- decode(envelope["user_pin_ct"]),
         {:ok, so_ct_tag} <- decode(envelope["so_pin_ct"]) do
      dek = derive_dek(kek, salt, tenant_id)
      aad = aad_for(tenant_id)

      with {:ok, user_pin} <- decrypt_split(dek, iv, user_ct_tag, aad),
           {:ok, so_pin} <- decrypt_split(dek, iv2, so_ct_tag, aad) do
        {:ok, %{user_pin: user_pin, so_pin: so_pin}}
      end
    end
  end

  def unwrap(_tenant_id, %{"version" => other}) do
    {:error, {:unsupported_envelope_version, other}}
  end

  def unwrap(_tenant_id, _other), do: {:error, :malformed_envelope}

  @doc """
  Fetch and unwrap the SoftHSM2 user PIN for a tenant.

  Called via `:rpc.call` from a tenant BEAM node, which has no direct
  access to the platform PostgreSQL. Looks up the `pin_envelope` from
  `tenants.metadata["softhsm"]["pin_envelope"]` and unwraps it.

  Returns `{:ok, user_pin}` or `{:error, reason}`.
  """
  @spec get_user_pin(String.t()) :: {:ok, String.t()} | {:error, term()}
  def get_user_pin(tenant_id) when is_binary(tenant_id) do
    case PlatformRepo.get(Tenant, tenant_id) do
      {:ok, %Tenant{metadata: %{"softhsm" => %{"pin_envelope" => envelope}}}}
      when is_map(envelope) ->
        case unwrap(tenant_id, envelope) do
          {:ok, %{user_pin: pin}} -> {:ok, pin}
          {:error, _} = err -> err
        end

      {:ok, _} ->
        {:error, :no_pin_envelope}

      {:error, _} = err ->
        err
    end
  end

  # --- internals -------------------------------------------------------

  defp derive_dek(kek, salt, tenant_id) do
    info = @info_prefix <> tenant_id
    # RFC 5869 HKDF-SHA256:
    #   PRK = HMAC-SHA256(salt, IKM=kek)
    #   OKM = HMAC-SHA256(PRK, info || 0x01)  [first + only block]
    # HMAC-SHA256 outputs 32 bytes, so a single block already covers
    # our 32-byte DEK requirement — no counter loop needed.
    prk = :crypto.mac(:hmac, :sha256, salt, kek)
    :crypto.mac(:hmac, :sha256, prk, info <> <<1>>)
    |> binary_part(0, @key_bytes)
  end

  defp aad_for(tenant_id), do: @info_prefix <> tenant_id

  defp decrypt_split(dek, iv, ct_tag, aad) do
    # Last 16 bytes of the stored blob are the GCM tag — split back
    # out before handing to the decrypt primitive.
    ct_size = byte_size(ct_tag) - 16

    if ct_size < 0 do
      {:error, :decryption_failed}
    else
      ct = binary_part(ct_tag, 0, ct_size)
      tag = binary_part(ct_tag, ct_size, 16)

      case :crypto.crypto_one_time_aead(:aes_256_gcm, dek, iv, ct, aad, tag, false) do
        plaintext when is_binary(plaintext) -> {:ok, plaintext}
        _ -> {:error, :decryption_failed}
      end
    end
  rescue
    _ -> {:error, :decryption_failed}
  end

  defp encode(bin), do: Base.url_encode64(bin, padding: false)

  defp decode(nil), do: {:error, :malformed_envelope}

  defp decode(str) when is_binary(str) do
    case Base.url_decode64(str, padding: false) do
      {:ok, bin} -> {:ok, bin}
      :error -> {:error, :malformed_envelope}
    end
  end
end
