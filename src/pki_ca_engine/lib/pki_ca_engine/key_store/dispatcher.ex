defmodule PkiCaEngine.KeyStore.Dispatcher do
  @moduledoc """
  Routes signing operations to the correct KeyStore adapter based on
  IssuerKey.keystore_type.

  All callers (CertificateSigning, OcspResponder, CrlPublisher) use this
  module instead of calling KeyActivation directly.
  """

  alias PkiMnesia.{Repo, Structs.IssuerKey}
  alias PkiCaEngine.KeyStore.{SoftwareAdapter, LocalHsmAdapter, RemoteHsmAdapter, MockHsmAdapter}

  @doc "Sign tbs_data using the adapter configured on the issuer key."
  def sign(issuer_key_id, tbs_data) do
    with {:ok, key} <- get_issuer_key(issuer_key_id) do
      case adapter_for(key.keystore_type) do
        {:error, _} = err -> err
        adapter -> adapter.sign(issuer_key_id, tbs_data)
      end
    end
  end

  @doc "Get the public key for the given issuer key."
  def get_public_key(issuer_key_id) do
    with {:ok, key} <- get_issuer_key(issuer_key_id) do
      case adapter_for(key.keystore_type) do
        {:error, _} = err -> err
        adapter -> adapter.get_public_key(issuer_key_id)
      end
    end
  end

  @doc "Check if the key is available for signing."
  def key_available?(issuer_key_id) do
    case get_issuer_key(issuer_key_id) do
      {:ok, key} ->
        case adapter_for(key.keystore_type) do
          {:error, _} -> false
          adapter -> adapter.key_available?(issuer_key_id)
        end
      _ -> false
    end
  end

  @doc """
  Authorize a session for the given issuer key using the provided auth tokens.

  Routes to the correct adapter based on `IssuerKey.keystore_type`.  The
  adapter derives an opaque session handle from `auth_tokens` (e.g. a
  deterministic PIN for SoftHSM-style adapters, or the raw key material for
  software keystores).

  Returns `{:ok, handle}` or `{:error, reason}`.
  """
  def authorize_session(issuer_key_id, auth_tokens) do
    with {:ok, key} <- get_issuer_key(issuer_key_id) do
      case adapter_for(key.keystore_type) do
        {:error, _} = err -> err
        adapter -> adapter.authorize_session(issuer_key_id, auth_tokens)
      end
    end
  end

  defp adapter_for(:software), do: SoftwareAdapter
  defp adapter_for(:local_hsm), do: LocalHsmAdapter
  defp adapter_for(:remote_hsm), do: RemoteHsmAdapter
  defp adapter_for(:mock_hsm), do: MockHsmAdapter
  defp adapter_for(_), do: {:error, :unknown_keystore_type}

  defp get_issuer_key(issuer_key_id) do
    case Repo.get(IssuerKey, issuer_key_id) do
      {:ok, nil} -> {:error, :issuer_key_not_found}
      {:ok, key} -> {:ok, key}
      {:error, _} = err -> err
    end
  end
end
