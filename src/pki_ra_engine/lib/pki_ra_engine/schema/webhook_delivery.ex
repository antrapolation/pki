defmodule PkiRaEngine.Schema.WebhookDelivery do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}

  @statuses ["pending", "delivered", "failed", "exhausted"]

  schema "webhook_deliveries" do
    field :api_key_id, :binary_id
    field :csr_id, :binary_id
    field :event, :string
    field :url, :string
    field :status, :string, default: "pending"
    field :attempts, :integer, default: 0
    field :last_http_status, :integer
    field :last_error, :string
    field :payload, :map

    timestamps()
  end

  def changeset(delivery, attrs) do
    delivery
    |> cast(attrs, [:api_key_id, :csr_id, :event, :url, :status, :attempts, :last_http_status, :last_error, :payload])
    |> validate_required([:api_key_id, :event, :url])
    |> validate_inclusion(:status, @statuses)
  end
end
