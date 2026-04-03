defmodule PkiRaPortalWeb.ValidationStatusLive do
  use PkiRaPortalWeb, :live_view
  require Logger

  @validation_url Application.compile_env(:pki_ra_portal, :validation_url, "http://localhost:4005")
  @refresh_interval 30_000

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket) do
      send(self(), :refresh)
      :timer.send_interval(@refresh_interval, :refresh)
    end

    {:ok,
     assign(socket,
       page_title: "Validation Services",
       validation_url: @validation_url,
       health: nil,
       crl: nil,
       ocsp_serial: "",
       ocsp_result: nil,
       loading: true,
       error: nil
     )}
  end

  @impl true
  def handle_info(:refresh, socket) do
    health = fetch_health()
    crl = fetch_crl()
    {:noreply, assign(socket, health: health, crl: crl, loading: false, error: nil)}
  end

  @impl true
  def handle_event("check_ocsp", %{"serial" => serial}, socket) when serial != "" do
    result = fetch_ocsp(serial)
    {:noreply, assign(socket, ocsp_serial: serial, ocsp_result: result)}
  end

  def handle_event("check_ocsp", _, socket) do
    {:noreply, socket}
  end

  @impl true
  def handle_event("refresh", _, socket) do
    send(self(), :refresh)
    {:noreply, assign(socket, loading: true)}
  end

  defp fetch_health do
    case Req.get("#{@validation_url}/health", receive_timeout: 5000) do
      {:ok, %{status: 200, body: body}} -> body
      _ -> %{"status" => "unreachable"}
    end
  rescue
    _ -> %{"status" => "unreachable"}
  end

  defp fetch_crl do
    case Req.get("#{@validation_url}/crl", receive_timeout: 5000) do
      {:ok, %{status: 200, body: body}} -> body
      _ -> nil
    end
  rescue
    _ -> nil
  end

  defp fetch_ocsp(serial) do
    case Req.post("#{@validation_url}/ocsp", json: %{serial_number: serial}, receive_timeout: 5000) do
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
        <button phx-click="refresh" class="btn btn-sm btn-outline gap-2" disabled={@loading}>
          <.icon name="hero-arrow-path" class={["size-4", @loading && "animate-spin"]} />
          Refresh
        </button>
      </div>

      <%!-- Description banner --%>
      <div class="alert alert-info shadow-sm">
        <.icon name="hero-information-circle" class="size-5 shrink-0" />
        <span class="text-sm">
          Monitor the Validation Service health, view current CRL information, and check certificate revocation status via OCSP lookup.
        </span>
      </div>

      <%!-- Health + CRL Cards --%>
      <section class="grid grid-cols-1 md:grid-cols-2 gap-4">
        <%!-- Health Card --%>
        <div class="card bg-base-100 shadow-sm border border-base-300">
          <div class="card-body">
            <h2 class="card-title text-sm font-semibold uppercase tracking-wide text-base-content/60">
              Service Health
            </h2>
            <%= if @loading and is_nil(@health) do %>
              <div class="flex items-center gap-2 mt-2">
                <span class="loading loading-spinner loading-sm"></span>
                <span class="text-sm text-base-content/50">Checking...</span>
              </div>
            <% else %>
              <div class="flex items-center gap-3 mt-2">
                <div class={[
                  "flex items-center justify-center w-10 h-10 rounded-lg",
                  if(health_ok?(@health), do: "bg-success/10", else: "bg-error/10")
                ]}>
                  <.icon
                    name={if(health_ok?(@health), do: "hero-check-circle", else: "hero-x-circle")}
                    class={["size-6", if(health_ok?(@health), do: "text-success", else: "text-error")]}
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
            <% end %>
          </div>
        </div>

        <%!-- CRL Card --%>
        <div class="card bg-base-100 shadow-sm border border-base-300">
          <div class="card-body">
            <h2 class="card-title text-sm font-semibold uppercase tracking-wide text-base-content/60">
              Current CRL
            </h2>
            <%= if @loading and is_nil(@crl) do %>
              <div class="flex items-center gap-2 mt-2">
                <span class="loading loading-spinner loading-sm"></span>
                <span class="text-sm text-base-content/50">Loading...</span>
              </div>
            <% else %>
              <%= if is_nil(@crl) do %>
                <div class="mt-2">
                  <p class="text-sm text-base-content/50">CRL data unavailable.</p>
                </div>
              <% else %>
                <div class="mt-2 space-y-2">
                  <div class="grid grid-cols-2 gap-x-4 gap-y-1 text-sm">
                    <span class="text-base-content/60">This Update</span>
                    <span class="font-mono text-xs">{format_datetime(@crl["this_update"])}</span>
                    <span class="text-base-content/60">Next Update</span>
                    <span class="font-mono text-xs">{format_datetime(@crl["next_update"])}</span>
                    <span class="text-base-content/60">Total Revoked</span>
                    <span class="font-bold">{@crl["total_revoked"] || @crl["revoked_count"] || "-"}</span>
                    <span class="text-base-content/60">Version</span>
                    <span>{@crl["version"] || "-"}</span>
                  </div>
                </div>
              <% end %>
            <% end %>
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
                placeholder="e.g. 1A2B3C4D..."
                class="input input-bordered input-sm w-full font-mono"
              />
            </div>
            <button type="submit" class="btn btn-primary btn-sm">
              <.icon name="hero-magnifying-glass" class="size-4" />
              Check
            </button>
          </form>

          <%= if @ocsp_result do %>
            <div class="mt-4">
              <div class={[
                "alert shadow-sm",
                cond do
                  @ocsp_result["status"] == "good" -> "alert-success"
                  @ocsp_result["status"] in ["revoked", "error"] -> "alert-error"
                  true -> "alert-warning"
                end
              ]}>
                <div>
                  <p class="font-semibold text-sm">
                    Status: {String.upcase(@ocsp_result["status"] || "unknown")}
                  </p>
                  <%= if @ocsp_result["message"] do %>
                    <p class="text-xs mt-1">{@ocsp_result["message"]}</p>
                  <% end %>
                  <%= if @ocsp_result["revocation_time"] do %>
                    <p class="text-xs mt-1">Revoked at: {format_datetime(@ocsp_result["revocation_time"])}</p>
                  <% end %>
                  <%= if @ocsp_result["revocation_reason"] do %>
                    <p class="text-xs mt-1">Reason: {@ocsp_result["revocation_reason"]}</p>
                  <% end %>
                </div>
              </div>
            </div>
          <% end %>
        </div>
      </section>
    </div>
    """
  end
end
