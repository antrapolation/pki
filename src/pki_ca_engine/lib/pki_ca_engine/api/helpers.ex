defmodule PkiCaEngine.Api.Helpers do
  @moduledoc "Shared helpers for CA Engine API controllers."

  import Ecto.Query
  alias PkiCaEngine.Schema.CaInstance

  @doc "Returns the ca_instance_id from params, falling back to the default instance."
  def resolve_instance_id(params) do
    case params["ca_instance_id"] do
      nil -> default_instance_id()
      "" -> default_instance_id()
      "default" -> default_instance_id()
      id -> id
    end
  end

  defp default_instance_id do
    PkiCaEngine.Repo.one(
      from(i in CaInstance, where: i.name == "default", select: i.id, limit: 1)
    )
  end
end
