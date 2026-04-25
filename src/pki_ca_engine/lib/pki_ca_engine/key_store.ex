defmodule PkiCaEngine.KeyStore do
  @moduledoc """
  Behaviour for signing backends.

  Three adapters implement this:
  - SoftwareAdapter — wraps KeyActivation (threshold ceremony keys in memory)
  - LocalHsmAdapter — Erlang Port to PKCS#11 device co-located with BEAM
  - RemoteHsmAdapter — gRPC to Go agent on customer's site
  """

  @callback sign(issuer_key_id :: binary(), tbs_data :: binary()) ::
    {:ok, signature :: binary()} | {:error, term()}

  @callback get_public_key(issuer_key_id :: binary()) ::
    {:ok, public_key :: binary()} | {:error, term()}

  @callback key_available?(issuer_key_id :: binary()) :: boolean()

  @callback authorize_session(key_id :: binary(), auth_tokens :: [term()]) ::
    {:ok, session_handle :: term()} | {:error, reason :: term()}
end
