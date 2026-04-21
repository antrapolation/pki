defmodule StrapSofthsmPrivKeyStoreProvider.Native.SofthsmNif do
  use Rustler, otp_app: :strap_softhsm_priv_key_store_provider, crate: "softhsm_nif"

  def get_info(_lib_path), do: :erlang.nif_error(:nif_not_loaded)
  def list_slots(_lib_path), do: :erlang.nif_error(:nif_not_loaded)
  def init_token(_lib_path, _slot_id, _label, _pin), do: :erlang.nif_error(:nif_not_loaded)

  def generate_key(_lib_path, _slot_id, _pin, _algo, _bits),
    do: :erlang.nif_error(:nif_not_loaded)

  def sign(_lib_path, _slot_id, _pin, _key_id, _algo, _data),
    do: :erlang.nif_error(:nif_not_loaded)

  def verify(_lib_path, _slot_id, _pin, _key_id, _algo, _data, _signature),
    do: :erlang.nif_error(:nif_not_loaded)

  def encrypt(_lib_path, _slot_id, _pin, _key_id, _algo, _data),
    do: :erlang.nif_error(:nif_not_loaded)

  def decrypt(_lib_path, _slot_id, _pin, _key_id, _algo, _data),
    do: :erlang.nif_error(:nif_not_loaded)

  def set_pin(_lib_path, _slot_id, _old_pin, _new_pin),
    do: :erlang.nif_error(:nif_not_loaded)
end
