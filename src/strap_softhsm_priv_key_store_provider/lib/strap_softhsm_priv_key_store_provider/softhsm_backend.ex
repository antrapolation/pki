defmodule StrapSofthsmPrivKeyStoreProvider.SofthsmBackend do
  @moduledoc """
  Backend for interacting with SoftHSM via PKCS#11.
  This module serves as a bridge for HSM-specific operations.
  """

  require Logger

  alias StrapSofthsmPrivKeyStoreProvider.Model.SofthsmPubKey
  alias StrapSofthsmPrivKeyStoreProvider.Model.SofthsmPrivKey

  alias StrapSofthsmPrivKeyStoreProvider.Native.SofthsmNif

  # Default library path for SoftHSM on Mac (Homebrew)
  @default_lib_path "/opt/homebrew/lib/softhsm/libsofthsm2.so"

  def initialize(opts) do
    lib_path = Map.get(opts, :pkcs11_lib_path, @default_lib_path)

    case SofthsmNif.get_info(lib_path) do
      {:ok, manufacturer} ->
        Logger.info("Initialized SoftHSM backend: #{manufacturer}")
        {:ok, %{lib_path: lib_path, opts: opts}}

      {:error, reason} ->
        Logger.error("Failed to initialize SoftHSM: #{inspect(reason)}")
        {:error, reason}
    end
  end

  def generate_key(type, state) do
    Logger.debug("Generating key of type #{inspect(type)} on HSM")

    lib_path = state.lib_path
    slot_id = Map.get(state.opts, :slot, 0)
    pin = Map.get(state.opts, :pin, "1234")

    bits = if is_integer(type.params), do: type.params, else: 2048

    case SofthsmNif.generate_key(lib_path, slot_id, pin, to_string(type.algo), bits) do
      {:ok, key_id, pub_material} ->
        pub =
          SofthsmPubKey.new(%{
            material: pub_material,
            algo: type.algo,
            params: type.params,
            key_id: key_id,
            process_group_name: type.process_group_name,
            landing_node: type.landing_node
          })

        priv =
          SofthsmPrivKey.new(%{
            key_id: key_id,
            slot: slot_id,
            algo: type.algo,
            params: type.params,
            process_group_name: type.process_group_name,
            landing_node: type.landing_node
          })

        {:ok, %{pub_key: pub, priv_key: priv}}

      error ->
        error
    end
  end

  def sign(key_id, algo, data, _opts, state) do
    Logger.debug("Signing data with key_id #{key_id} on HSM")

    lib_path = state.lib_path
    slot_id = Map.get(state.opts, :slot, 0)
    pin = Map.get(state.opts, :pin, "1234")

    case SofthsmNif.sign(lib_path, slot_id, pin, key_id, to_string(algo), data) do
      {:ok, signature} -> {:ok, signature}
      {:error, reason} -> {:error, reason}
      error -> error
    end
  end

  def verify(key_id, algo, data, signature, _opts, state) do
    Logger.debug("Verifying with key_id #{key_id}")
    lib_path = state.lib_path
    slot_id = Map.get(state.opts, :slot, 0)
    pin = Map.get(state.opts, :pin, "1234")

    case SofthsmNif.verify(lib_path, slot_id, pin, key_id, to_string(algo), data, signature) do
      :ok -> :ok
      {:error, reason} -> {:error, reason}
      error -> error
    end
  end

  def encrypt(key_id, algo, data, _opts, state) do
    Logger.debug("Encrypting with key_id #{key_id}")
    lib_path = state.lib_path
    slot_id = Map.get(state.opts, :slot, 0)
    pin = Map.get(state.opts, :pin, "1234")

    case SofthsmNif.encrypt(lib_path, slot_id, pin, key_id, to_string(algo), data) do
      {:ok, ciphertext} -> {:ok, ciphertext}
      {:error, reason} -> {:error, reason}
      error -> error
    end
  end

  def decrypt(key_id, algo, data, _opts, state) do
    Logger.debug("Decrypting with key_id #{key_id}")
    lib_path = state.lib_path
    slot_id = Map.get(state.opts, :slot, 0)
    pin = Map.get(state.opts, :pin, "1234")

    case SofthsmNif.decrypt(lib_path, slot_id, pin, key_id, to_string(algo), data) do
      {:ok, plaintext} -> {:ok, plaintext}
      {:error, reason} -> {:error, reason}
      error -> error
    end
  end

  def set_pin(old_pin, new_pin, state) do
    Logger.info("Updating HSM PIN")
    lib_path = state.lib_path
    slot_id = Map.get(state.opts, :slot, 0)

    case SofthsmNif.set_pin(lib_path, slot_id, old_pin, new_pin) do
      :ok -> :ok
      error -> error
    end
  end
end
