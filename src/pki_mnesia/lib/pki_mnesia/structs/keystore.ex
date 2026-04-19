defmodule PkiMnesia.Structs.Keystore do
  @moduledoc """
  Private keystore configuration per CA instance.

  One CA instance can have multiple keystores, typically at most one
  of each type (`"software"`, `"hsm"`). `config` is an arbitrary map
  — for HSM, it holds `{pkcs11_lib_path, slot_id, label,
  hsm_device_id}`; for software it's an empty map.
  """

  @fields [
    :id,
    :ca_instance_id,
    :type,
    :config,
    :status,
    :provider_name,
    :inserted_at,
    :updated_at
  ]
  def fields, do: @fields

  defstruct @fields

  @type t :: %__MODULE__{
          id: binary(),
          ca_instance_id: binary(),
          type: String.t(),
          config: map(),
          status: String.t(),
          provider_name: String.t() | nil,
          inserted_at: DateTime.t(),
          updated_at: DateTime.t()
        }

  def new(attrs \\ %{}) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    %__MODULE__{
      id: attrs[:id] || PkiMnesia.Id.generate(),
      ca_instance_id: attrs[:ca_instance_id],
      type: attrs[:type],
      config: normalize_config(attrs[:config]),
      status: Map.get(attrs, :status, "active"),
      provider_name: attrs[:provider_name],
      inserted_at: attrs[:inserted_at] || now,
      updated_at: attrs[:updated_at] || now
    }
  end

  @doc """
  Accept either a map or the legacy JSON-encoded binary and return
  a map. Returns `nil` for `nil`.
  """
  def decode_config(nil), do: nil
  def decode_config(v) when is_map(v), do: v

  def decode_config(v) when is_binary(v) do
    case Jason.decode(v) do
      {:ok, map} -> map
      _ -> nil
    end
  end

  defp normalize_config(nil), do: %{}
  defp normalize_config(v) when is_map(v), do: v
  defp normalize_config(v) when is_binary(v), do: decode_config(v) || %{}
end
