defmodule PkiMnesia.Structs.ServiceConfig do
  @moduledoc """
  Validation-endpoint configuration: the URL + port that gets embedded
  in issued certificates as CRL / OCSP / TSA extensions. One row per
  service_type (upserted).
  """

  @fields [:id, :service_type, :url, :port, :status, :inserted_at, :updated_at]
  def fields, do: @fields

  defstruct @fields

  @type t :: %__MODULE__{
    id: binary(),
    service_type: String.t(),
    url: String.t() | nil,
    port: non_neg_integer() | nil,
    status: String.t(),
    inserted_at: DateTime.t(),
    updated_at: DateTime.t()
  }

  def new(attrs \\ %{}) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    %__MODULE__{
      id: attrs[:id] || PkiMnesia.Id.generate(),
      service_type: attrs[:service_type],
      url: attrs[:url],
      port: attrs[:port],
      status: Map.get(attrs, :status, "active"),
      inserted_at: attrs[:inserted_at] || now,
      updated_at: attrs[:updated_at] || now
    }
  end
end
