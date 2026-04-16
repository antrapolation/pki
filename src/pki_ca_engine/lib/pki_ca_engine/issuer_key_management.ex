defmodule PkiCaEngine.IssuerKeyManagement do
  @moduledoc """
  Issuer key CRUD and lifecycle management.
  Rewritten against Mnesia.
  """

  alias PkiMnesia.Repo
  alias PkiMnesia.Structs.IssuerKey

  @valid_statuses ["pending", "active", "suspended", "retired", "archived"]
  @valid_transitions %{
    "pending" => ["active"],
    "active" => ["suspended", "retired"],
    "suspended" => ["active", "retired"],
    "retired" => ["archived"]
  }

  def create_issuer_key(ca_instance_id, attrs) do
    key = IssuerKey.new(Map.put(attrs, :ca_instance_id, ca_instance_id))
    Repo.insert(key)
  end

  def get_issuer_key(id) do
    case Repo.get(IssuerKey, id) do
      {:ok, nil} -> {:error, :not_found}
      {:ok, key} -> {:ok, key}
      {:error, _} = err -> err
    end
  end

  def list_issuer_keys(ca_instance_id) do
    Repo.where(IssuerKey, fn k -> k.ca_instance_id == ca_instance_id end)
  end

  def activate_by_certificate(issuer_key, cert_attrs) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)
    Repo.update(issuer_key, %{
      status: "active",
      certificate_der: cert_attrs[:certificate_der],
      certificate_pem: cert_attrs[:certificate_pem],
      updated_at: now
    })
  end

  def transition_status(issuer_key_id, new_status) do
    with true <- new_status in @valid_statuses || {:error, :invalid_status},
         {:ok, key} <- get_issuer_key(issuer_key_id),
         allowed = Map.get(@valid_transitions, key.status, []),
         true <- new_status in allowed || {:error, {:invalid_transition, key.status, new_status}} do
      Repo.update(key, %{status: new_status, updated_at: DateTime.utc_now() |> DateTime.truncate(:second)})
    end
  end
end
