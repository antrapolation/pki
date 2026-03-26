defmodule PkiCaEngine.Api.KeyVaultController do
  @moduledoc """
  Thin controller for Key Vault endpoints.
  Delegates to PkiCaEngine.KeyVault for all operations.
  """

  import Plug.Conn
  alias PkiCaEngine.KeyVault
  alias PkiCaEngine.Api.Helpers

  def register(conn) do
    ca_instance_id = Helpers.resolve_instance_id(conn.body_params)
    name = conn.body_params["name"]
    algorithm = conn.body_params["algorithm"]
    protection_mode = conn.body_params["protection_mode"] || "split_auth_token"

    result =
      case protection_mode do
        "credential_own" ->
          with {:ok, acl_kem_public_key} <- decode_binary(conn.body_params["acl_kem_public_key"]) do
            KeyVault.register_keypair(ca_instance_id, name, algorithm, acl_kem_public_key)
          end

        "split_auth_token" ->
          threshold_k = conn.body_params["threshold_k"] || 2
          threshold_n = conn.body_params["threshold_n"] || 3
          KeyVault.register_keypair_split_auth(ca_instance_id, name, algorithm, threshold_k, threshold_n)

        "split_key" ->
          threshold_k = conn.body_params["threshold_k"] || 2
          threshold_n = conn.body_params["threshold_n"] || 3
          KeyVault.register_keypair_split_key(ca_instance_id, name, algorithm, threshold_k, threshold_n)
      end

    case result do
      {:ok, keypair} ->
        json(conn, 201, %{data: serialize_keypair(keypair)})

      {:ok, keypair, _shares} ->
        # For split modes, shares are returned but not exposed over HTTP
        # (they must be distributed to custodians via a secure channel)
        json(conn, 201, %{data: serialize_keypair(keypair), shares_generated: true})

      {:error, :invalid_base64} ->
        json(conn, 422, %{error: "invalid_base64"})

      {:error, %Ecto.Changeset{} = changeset} ->
        json(conn, 422, %{error: "validation_error", details: changeset_errors(changeset)})

      {:error, reason} ->
        json(conn, 422, %{error: inspect(reason)})
    end
  end

  def grant_access(conn, keypair_id) do
    credential_id = conn.body_params["credential_id"]
    acl_signing_algo = conn.body_params["acl_signing_algo"] || "ECC-P256"

    with {:ok, acl_signing_key} <- decode_binary(conn.body_params["acl_signing_key"]) do
      case KeyVault.grant_access(keypair_id, credential_id, acl_signing_key, acl_signing_algo) do
        {:ok, grant} ->
          json(conn, 201, %{data: %{id: grant.id, managed_keypair_id: grant.managed_keypair_id, credential_id: grant.credential_id}})

        {:error, reason} ->
          json(conn, 422, %{error: inspect(reason)})
      end
    else
      {:error, :invalid_base64} ->
        json(conn, 422, %{error: "invalid_base64"})
    end
  end

  def activate(conn, keypair_id) do
    protection_mode = conn.body_params["protection_mode"] || "credential_own"

    result =
      case protection_mode do
        "credential_own" ->
          with {:ok, acl_kem_private_key} <- decode_binary(conn.body_params["acl_kem_private_key"]) do
            kem_algo = conn.body_params["kem_algo"] || "ECDH-P256"
            KeyVault.activate_credential_own(keypair_id, acl_kem_private_key, kem_algo)
          end

        mode when mode in ["split_auth_token", "split_key"] ->
          with {:ok, shares} <- decode_binary_list(conn.body_params["shares"] || []) do
            KeyVault.activate_from_shares(keypair_id, shares)
          end
      end

    case result do
      {:ok, _private_key} ->
        # Never expose the private key over HTTP; just confirm activation succeeded
        json(conn, 200, %{status: "activated"})

      {:error, :invalid_base64} ->
        json(conn, 422, %{error: "invalid_base64"})

      {:error, reason} ->
        json(conn, 422, %{error: inspect(reason)})
    end
  end

  def revoke_grant(conn, keypair_id) do
    credential_id = conn.body_params["credential_id"]

    case KeyVault.revoke_grant(keypair_id, credential_id) do
      {:ok, _grant} ->
        json(conn, 200, %{status: "revoked"})

      {:error, :grant_not_found} ->
        json(conn, 404, %{error: "grant_not_found"})

      {:error, reason} ->
        json(conn, 422, %{error: inspect(reason)})
    end
  end

  def list(conn) do
    ca_instance_id = Helpers.resolve_instance_id(conn.query_params)
    keypairs = KeyVault.list_keypairs(ca_instance_id)
    json(conn, 200, %{data: Enum.map(keypairs, &serialize_keypair/1)})
  end

  def show(conn, keypair_id) do
    case KeyVault.get_keypair(keypair_id) do
      nil ->
        json(conn, 404, %{error: "not_found"})

      keypair ->
        json(conn, 200, %{data: serialize_keypair(keypair)})
    end
  end

  # --- Private helpers ---

  defp serialize_keypair(keypair) do
    %{
      id: keypair.id,
      ca_instance_id: keypair.ca_instance_id,
      name: keypair.name,
      algorithm: keypair.algorithm,
      protection_mode: keypair.protection_mode,
      status: keypair.status,
      public_key: safe_encode(keypair.public_key),
      inserted_at: keypair.inserted_at,
      updated_at: keypair.updated_at
    }
  end

  defp safe_encode(nil), do: nil
  defp safe_encode(bin) when is_binary(bin), do: Base.encode64(bin)

  defp decode_binary(nil), do: {:ok, nil}
  defp decode_binary(val) when is_binary(val) do
    case Base.decode64(val) do
      {:ok, bin} -> {:ok, bin}
      :error -> {:error, :invalid_base64}
    end
  end

  defp decode_binary_list(items) do
    Enum.reduce_while(items, {:ok, []}, fn item, {:ok, acc} ->
      case decode_binary(item) do
        {:ok, decoded} -> {:cont, {:ok, acc ++ [decoded]}}
        {:error, _} = err -> {:halt, err}
      end
    end)
  end

  defp changeset_errors(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Regex.replace(~r"%{(\w+)}", msg, fn _, key ->
        opts |> Keyword.get(String.to_existing_atom(key), key) |> to_string()
      end)
    end)
  end

  defp json(conn, status, body) do
    conn
    |> put_resp_content_type("application/json")
    |> send_resp(status, Jason.encode!(body))
  end
end
