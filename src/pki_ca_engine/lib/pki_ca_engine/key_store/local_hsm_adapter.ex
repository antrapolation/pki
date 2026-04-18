defmodule PkiCaEngine.KeyStore.LocalHsmAdapter do
  @moduledoc """
  KeyStore adapter for local HSM devices via PKCS#11.

  Uses an Erlang Port to a C binary wrapping PKCS#11 via dlopen.
  Not yet implemented — see Phase D Task 3.
  """
  @behaviour PkiCaEngine.KeyStore

  @impl true
  def sign(_issuer_key_id, _tbs_data) do
    {:error, :not_implemented}
  end

  @impl true
  def get_public_key(_issuer_key_id) do
    {:error, :not_implemented}
  end

  @impl true
  def key_available?(_issuer_key_id) do
    false
  end
end
