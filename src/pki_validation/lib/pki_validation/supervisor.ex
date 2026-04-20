defmodule PkiValidation.Supervisor do
  @moduledoc """
  Top-level supervisor for the pki_validation engine.

  Children:
  - `CrlPublisher` — GenServer that periodically generates the CRL from Mnesia
  - `Plug.Cowboy` (conditional) — OCSP/CRL HTTP listener, started when
    `config :pki_validation, :http, start: true` is set

  Hosting the HTTP listener here (instead of only in
  `PkiValidation.Application.start/2`) matters for the per-tenant BEAM
  architecture: tenants set `start_application: false` on `pki_validation`
  so `pki_tenant` can own the supervisor tree, but we still want the
  Validation HTTP listener to come up. With the listener supervised here,
  the tenant gets it for free when `pki_tenant` brings up this
  supervisor.

  OCSP is stateless (direct Mnesia lookups) so it needs no supervised
  GenServer of its own — the HTTP listener fans out to `OcspResponder`
  per request.
  """

  use Supervisor

  def start_link(opts \\ []) do
    Supervisor.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @impl true
  def init(_opts) do
    children = [{PkiValidation.CrlPublisher, []}] ++ http_children()
    Supervisor.init(children, strategy: :one_for_one)
  end

  defp http_children do
    case Application.get_env(:pki_validation, :http, []) do
      opts when is_list(opts) ->
        if Keyword.get(opts, :start, false) do
          port = Keyword.get(opts, :port, 4005)
          [{Plug.Cowboy, plug: PkiValidation.Api.Router, scheme: :http, port: port}]
        else
          []
        end

      _ ->
        []
    end
  end
end
