defmodule PkiTenant.Health do
  @moduledoc """
  Health check module called by platform via :erpc.call.
  Returns :ok or detailed health map.
  """

  def check do
    %{
      status: :ok,
      mnesia: mnesia_status(),
      node: node(),
      uptime_seconds: :erlang.statistics(:wall_clock) |> elem(0) |> div(1000),
      memory_mb: :erlang.memory(:total) |> div(1_048_576)
    }
  end

  defp mnesia_status do
    case :mnesia.system_info(:is_running) do
      :yes -> :running
      _ -> :stopped
    end
  rescue
    _ -> :error
  end
end
