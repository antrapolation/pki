defmodule PkiMnesia.Structs.PreSignedCrl do
  @moduledoc """
  Pre-signed CRL record. Generated in batch at ceremony close when
  `crl_strategy == "pre_signed"`. Each record covers a specific
  `valid_from`/`valid_until` window and is served without requiring
  an active key lease.
  """

  @fields [:id, :issuer_key_id, :valid_from, :valid_until, :crl_der, :inserted_at]
  def fields, do: @fields

  defstruct @fields

  @type t :: %__MODULE__{
          id: binary(),
          issuer_key_id: binary(),
          valid_from: DateTime.t(),
          valid_until: DateTime.t(),
          crl_der: binary(),
          inserted_at: DateTime.t()
        }

  def new(attrs \\ %{}) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    %__MODULE__{
      id: attrs[:id] || PkiMnesia.Id.generate(),
      issuer_key_id: attrs[:issuer_key_id],
      valid_from: attrs[:valid_from],
      valid_until: attrs[:valid_until],
      crl_der: attrs[:crl_der],
      inserted_at: attrs[:inserted_at] || now
    }
  end
end
