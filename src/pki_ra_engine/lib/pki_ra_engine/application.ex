defmodule PkiRaEngine.Application do
  # See https://hexdocs.pm/elixir/Application.html
  # for more information on OTP Applications
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    children =
      if Application.get_env(:pki_ra_engine, :start_application, true) do
        [
          PkiRaEngine.Repo,
          {Task.Supervisor, name: PkiRaEngine.TaskSupervisor}
        ] ++ dcv_poller_children() ++ reconciler_children()
      else
        []
      end

    # See https://hexdocs.pm/elixir/Supervisor.html
    # for other strategies and supported options
    PkiRaEngine.Telemetry.setup()

    if Application.get_env(:pki_ra_engine, :start_application, true) do
      opts = [strategy: :rest_for_one, name: PkiRaEngine.Supervisor]
      Supervisor.start_link(children, opts)
    else
      Supervisor.start_link([], strategy: :one_for_one)
    end
  end

  defp dcv_poller_children do
    if Application.get_env(:pki_ra_engine, :start_dcv_poller, true) do
      [PkiRaEngine.DcvPoller]
    else
      []
    end
  end

  defp reconciler_children do
    if Application.get_env(:pki_ra_engine, :start_csr_reconciler, true) do
      [PkiRaEngine.CsrReconciler]
    else
      []
    end
  end

end
