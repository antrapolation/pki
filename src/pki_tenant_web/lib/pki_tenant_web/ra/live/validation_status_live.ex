defmodule PkiTenantWeb.Ra.ValidationStatusLive do
  @moduledoc """
  Monitor the Validation Service (OCSP / CRL / TSA).

  Queries `/health`, `/crl`, and `/ocsp` over HTTP on an interval.
  The target URL is configurable via the `:validation_url`
  application env on `:pki_tenant_web` (default
  `http://localhost:4005`).
  """
  use PkiTenantWeb, :live_view

  require Logger

  @refresh_interval 30_000
  @request_timeout 5_000

  @impl true
  def mount(_params, _session, socket) do
    validation_url =
      Application.get_env(:pki_tenant_web, :validation_url, "http://localhost:4005")

    if connected?(socket), do: send(self(), :refresh)

    {:ok,
     assign(socket,
       page_title: "Validation Services",
       validation_url: validation_url,
       health: nil,
       crl: nil,
       ocsp_serial: "",
       ocsp_result: nil,
       loading: true
     )}
  end

  @impl true
  def handle_info(:refresh, socket) do
    url = socket.assigns.validation_url
    health = fetch_health(url)
    crl = fetch_crl(url)

    if connected?(socket), do: Process.send_after(self(), :refresh, @refresh_interval)

    {:noreply, assign(socket, health: health, crl: crl, loading: false)}
  end

  @impl true
  def handle_event("check_ocsp", %{"serial" => serial}, socket) when serial != "" do
    result = fetch_ocsp(serial, socket.assigns.validation_url)
    {:noreply, assign(socket, ocsp_serial: serial, ocsp_result: result)}
  end

  def handle_event("check_ocsp", _params, socket) do
    {:noreply, socket}
  end

  @impl true
  def handle_event("refresh", _params, socket) do
    send(self(), :refresh)
    {:noreply, assign(socket, loading: true)}
  end

  # --- HTTP helpers ---

  defp fetch_health(url) do
    case Req.get("#{url}/health", receive_timeout: @request_timeout) do
      {:ok, %{status: 200, body: body}} -> body
      _ -> %{"status" => "unreachable"}
    end
  rescue
    _ -> %{"status" => "unreachable"}
  end

  defp fetch_crl(url) do
    case Req.get("#{url}/crl", receive_timeout: @request_timeout) do
      {:ok, %{status: 200, body: body}} -> body
      _ -> nil
    end
  rescue
    _ -> nil
  end

  defp fetch_ocsp(serial, url) do
    case Req.post("#{url}/ocsp", json: %{serial_number: serial}, receive_timeout: @request_timeout) do
      {:ok, %{status: 200, body: body}} -> body
      {:ok, %{body: body}} -> body
      _ -> %{"status" => "error", "message" => "Service unreachable"}
    end
  rescue
    _ -> %{"status" => "error", "message" => "Service unreachable"}
  end

  defp health_ok?(health), do: is_map(health) and health["status"] == "ok"

  defp format_datetime(nil), do: "-"
  defp format_datetime(dt) when is_binary(dt), do: dt
  defp format_datetime(_), do: "-"

  @impl true
  def render(assigns) do
    ~H"""
    <div id="validation-status" class="space-y-6">
      <div class="flex items-center justify-between">
        <h1 class="text-2xl font-bold tracking-tight">Validation Services</h1>
        <button
          phx-click="refresh"
          class="btn btn-sm btn-outline gap-2"
          disabled={@loading}
        >
          <.icon name="hero-arrow-path" class={["size-4", @loading && "animate-spin"]} /> Refresh
        </button>
      </div>

      <div class="alert alert-info shadow-sm">
        <.icon name="hero-information-circle" class="size-5 shrink-0" />
        <span class="text-sm">
          Monitor the Validation Service health, view current CRL information, and check certificate
          revocation status via OCSP lookup.
        </span>
      </div>

      <section class="grid grid-cols-1 md:grid-cols-2 gap-4">
        <%!-- Service Health --%>
        <div class="card bg-base-100 shadow-sm border border-base-300">
          <div class="card-body">
            <h2 class="card-title text-sm font-semibold uppercase tracking-wide text-base-content/60">
              Service Health
            </h2>
            <div :if={@loading and is_nil(@health)} class="flex items-center gap-2 mt-2">
              <span class="loading loading-spinner loading-sm"></span>
              <span class="text-sm text-base-content/50">Checking…</span>
            </div>
            <div :if={not (@loading and is_nil(@health))} class="flex items-center gap-3 mt-2">
              <div class={[
                "flex items-center justify-center w-10 h-10 rounded-lg",
                health_ok?(@health) && "bg-success/10",
                not health_ok?(@health) && "bg-error/10"
              ]}>
                <.icon
                  name={if health_ok?(@health), do: "hero-check-circle", else: "hero-x-circle"}
                  class={[
                    "size-6",
                    health_ok?(@health) && "text-success",
                    not health_ok?(@health) && "text-error"
                  ]}
                />
              </div>
              <div>
                <p class="text-lg font-bold">
                  <%= if health_ok?(@health), do: "Healthy", else: "Unreachable" %>
                </p>
                <p class="text-xs text-base-content/50">
                  Validation Service at {@validation_url}
                </p>
              </div>
            </div>
          </div>
        </div>

        <%!-- Current CRL --%>
        <div class="card bg-base-100 shadow-sm border border-base-300">
          <div class="card-body">
            <h2 class="card-title text-sm font-semibold uppercase tracking-wide text-base-content/60">
              Current CRL
            </h2>
            <div :if={@loading and is_nil(@crl)} class="flex items-center gap-2 mt-2">
              <span class="loading loading-spinner loading-sm"></span>
              <span class="text-sm text-base-content/50">Loading…</span>
            </div>
            <div :if={not @loading and is_nil(@crl)} class="mt-2">
              <p class="text-sm text-base-content/50">CRL data unavailable.</p>
            </div>
            <div :if={not is_nil(@crl)} class="mt-2 space-y-2">
              <div class="grid grid-cols-2 gap-x-4 gap-y-1 text-sm">
                <span class="text-base-content/60">This Update</span>
                <span class="font-mono text-xs">{format_datetime(@crl["this_update"])}</span>
                <span class="text-base-content/60">Next Update</span>
                <span class="font-mono text-xs">{format_datetime(@crl["next_update"])}</span>
                <span class="text-base-content/60">Total Revoked</span>
                <span class="font-bold">
                  {@crl["total_revoked"] || @crl["revoked_count"] || "-"}
                </span>
                <span class="text-base-content/60">Version</span>
                <span>{@crl["version"] || "-"}</span>
              </div>
            </div>
          </div>
        </div>
      </section>

      <%!-- OCSP Lookup --%>
      <section class="card bg-base-100 shadow-sm border border-base-300">
        <div class="card-body">
          <h2 class="card-title text-sm font-semibold uppercase tracking-wide text-base-content/60">
            OCSP Lookup
          </h2>
          <p class="text-xs text-base-content/50 mb-3">
            Check the revocation status of a certificate by serial number.
          </p>
          <form phx-submit="check_ocsp" class="flex gap-2 items-end">
            <div class="form-control flex-1">
              <label class="label">
                <span class="label-text text-xs">Certificate Serial Number</span>
              </label>
              <input
                type="text"
                name="serial"
                value={@ocsp_serial}
                placeholder="e.g. 1A2B3C4D…"
                class="input input-bordered input-sm w-full font-mono"
              />
            </div>
            <button type="submit" class="btn btn-primary btn-sm">
              <.icon name="hero-magnifying-glass" class="size-4" /> Check
            </button>
          </form>

          <div :if={@ocsp_result} class="mt-4">
            <div class={[
              "alert shadow-sm",
              @ocsp_result["status"] == "good" && "alert-success",
              @ocsp_result["status"] in ["revoked", "error"] && "alert-error",
              @ocsp_result["status"] not in ["good", "revoked", "error"] && "alert-warning"
            ]}>
              <div>
                <p class="font-semibold text-sm">
                  Status: {String.upcase(@ocsp_result["status"] || "unknown")}
                </p>
                <p :if={@ocsp_result["message"]} class="text-xs mt-1">
                  {@ocsp_result["message"]}
                </p>
                <p :if={@ocsp_result["revocation_time"]} class="text-xs mt-1">
                  Revoked at: {format_datetime(@ocsp_result["revocation_time"])}
                </p>
                <p :if={@ocsp_result["revocation_reason"]} class="text-xs mt-1">
                  Reason: {@ocsp_result["revocation_reason"]}
                </p>
              </div>
            </div>
          </div>
        </div>
      </section>
    </div>
    """
  end
end
