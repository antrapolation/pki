defmodule PkiCaEngine.KeyStore.LocalHsmAdapter do
  @moduledoc """
  KeyStore adapter for co-located PKCS#11 HSMs.

  Manages Pkcs11Port GenServer instances per HSM slot (keyed by library_path +
  slot_id). When sign/2 is called, it finds or starts the port for the key's
  HSM config, then delegates to Pkcs11Port.

  IssuerKey.hsm_config must contain:
    "library_path" — path to the PKCS#11 .so (e.g. /opt/homebrew/lib/softhsm/libsofthsm2.so)
    "slot_id"      — integer slot index (e.g. 0)
    "pin"          — user PIN
    "key_label"    — CKA_LABEL of the private key object
  """
  @behaviour PkiCaEngine.KeyStore

  alias PkiMnesia.{Repo, Structs.IssuerKey}
  alias PkiCaEngine.KeyStore.Pkcs11Port

  require Logger

  @impl true
  def sign(issuer_key_id, tbs_data) do
    with {:ok, key} <- get_issuer_key(issuer_key_id),
         {:ok, port_pid} <- get_or_start_port(key) do
      Pkcs11Port.call(port_pid, {:sign, key.hsm_config["key_label"], tbs_data})
    end
  end

  @impl true
  def get_public_key(issuer_key_id) do
    with {:ok, key} <- get_issuer_key(issuer_key_id),
         {:ok, port_pid} <- get_or_start_port(key) do
      Pkcs11Port.call(port_pid, {:get_public_key, key.hsm_config["key_label"]})
    end
  end

  @impl true
  def key_available?(issuer_key_id) do
    case get_issuer_key(issuer_key_id) do
      {:ok, %{keystore_type: :local_hsm}} -> true
      _ -> false
    end
  end

  @doc """
  Authorize a PKCS#11 session by deriving a deterministic PIN from the sorted
  custodian auth tokens.

  The PIN is derived as the first 16 hex characters of SHA-256 over the
  concatenation of sorted auth tokens.  This makes the ceremony repeatable
  (same k tokens → same PIN) while mixing all custodian contributions.

  The returned handle is `%{key_id: key_id, pin: pin, type: :softhsm}`.  It
  is stored in the `KeyActivation` lease and presented to the PKCS#11 port at
  signing time.
  """
  @impl true
  def authorize_session(key_id, auth_tokens) do
    pin =
      auth_tokens
      |> Enum.map(&to_string/1)
      |> Enum.sort()
      |> Enum.join()
      |> then(fn data -> :crypto.hash(:sha256, data) end)
      |> Base.encode16()
      |> binary_part(0, 16)

    {:ok, %{key_id: key_id, pin: pin, type: :softhsm}}
  end

  # -- Private --

  defp get_issuer_key(issuer_key_id) do
    case Repo.get(IssuerKey, issuer_key_id) do
      {:ok, nil} -> {:error, :issuer_key_not_found}
      {:ok, key} -> {:ok, key}
      {:error, _} = err -> err
    end
  end

  defp get_or_start_port(%IssuerKey{hsm_config: config}) do
    port_name = port_name_for(config)

    case Process.whereis(port_name) do
      nil -> start_port(config, port_name)
      pid -> {:ok, pid}
    end
  end

  defp start_port(config, port_name) do
    opts = [
      library_path: config["library_path"],
      slot_id: config["slot_id"],
      pin: config["pin"],
      name: port_name
    ]

    # Use start (not start_link) so that HSM init failures surface as error
    # tuples instead of crashing the calling process.
    case GenServer.start(Pkcs11Port, opts, name: port_name) do
      {:ok, pid} ->
        {:ok, pid}

      {:error, {:already_started, pid}} ->
        {:ok, pid}

      {:error, reason} ->
        Logger.error("Failed to start PKCS#11 port for #{inspect(port_name)}: #{inspect(reason)}")
        {:error, {:port_start_failed, reason}}
    end
  end

  # Derive a stable registered name from the library path + slot.
  # Using phash2 avoids atom length limits from long library paths.
  defp port_name_for(config) do
    lib = config["library_path"] || "unknown"
    slot = config["slot_id"] || 0
    :"pkcs11_port_#{:erlang.phash2({lib, slot})}"
  end
end
