defmodule PkiCaEngine.KeyStore.RemoteHsmAdapter do
  @moduledoc """
  KeyStore adapter for remote HSM devices via gRPC.

  Connects to a Go agent running on the customer's site over bidirectional
  gRPC streaming with mTLS. Not yet implemented — see Phase D Task 4.
  """
  @behaviour PkiCaEngine.KeyStore

  @impl true
  def sign(_issuer_key_id, _tbs_data) do
    {:error, :agent_not_connected}
  end

  @impl true
  def get_public_key(_issuer_key_id) do
    {:error, :agent_not_connected}
  end

  @impl true
  def key_available?(_issuer_key_id) do
    false
  end
end
