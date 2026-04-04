defmodule PkiRaPortalWeb.CertificatesLive do
  use PkiRaPortalWeb, :live_view

  alias PkiRaPortal.RaEngineClient

  require Logger

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket), do: send(self(), :load_data)

    {:ok,
     assign(socket,
       page_title: "Certificates",
       certificates: [],
       status_filter: "all",
       selected_cert: nil,
       loading: true,
       page: 1,
       per_page: 20,
       revoke_reason: "unspecified",
       show_revoke_confirm: false
     )}
  end

  @impl true
  def handle_info(:load_data, socket) do
    {:noreply,
     socket
     |> assign(loading: false)
     |> load_certificates()}
  end

  @impl true
  def handle_event("filter_status", %{"status" => status}, socket) do
    {:noreply,
     socket
     |> assign(status_filter: status, selected_cert: nil, page: 1)
     |> load_certificates()}
  end

  @impl true
  def handle_event("view_cert", %{"serial" => serial}, socket) do
    opts = tenant_opts(socket)

    case RaEngineClient.get_certificate(serial, opts) do
      {:ok, cert} ->
        {:noreply, assign(socket, selected_cert: cert)}

      {:error, _} ->
        {:noreply, put_flash(socket, :error, "Certificate not found.")}
    end
  end

  @impl true
  def handle_event("close_detail", _, socket) do
    {:noreply, assign(socket, selected_cert: nil, revoke_reason: "unspecified", show_revoke_confirm: false)}
  end

  @impl true
  def handle_event("select_revoke_reason", %{"reason" => reason}, socket) do
    {:noreply, assign(socket, revoke_reason: reason)}
  end

  @impl true
  def handle_event("show_revoke_confirm", _, socket) do
    {:noreply, assign(socket, show_revoke_confirm: true)}
  end

  @impl true
  def handle_event("cancel_revoke", _, socket) do
    {:noreply, assign(socket, show_revoke_confirm: false)}
  end

  @impl true
  def handle_event("revoke_cert", _, socket) do
    user = socket.assigns[:current_user]
    role = user[:role] || user["role"]

    if role != "ra_admin" do
      {:noreply, put_flash(socket, :error, "Only RA administrators can revoke certificates.")}
    else
      cert = socket.assigns.selected_cert
      serial = cert[:serial_number] || cert[:issued_cert_serial]
      reason = socket.assigns[:revoke_reason] || "unspecified"
      opts = tenant_opts(socket)

      # Audit log
      Logger.info(
        "[certificates_live] Certificate revocation requested: serial=#{serial} reason=#{reason} by=#{user[:username] || user["username"]}"
      )

      case RaEngineClient.revoke_certificate(serial, reason, opts) do
        {:ok, _result} ->
          {:noreply,
           socket
           |> put_flash(:info, "Certificate #{serial} has been revoked.")
           |> assign(selected_cert: nil, show_revoke_confirm: false, revoke_reason: "unspecified")
           |> load_certificates()}

        {:error, _reason} ->
          {:noreply, put_flash(socket, :error, "Failed to revoke certificate. Please try again or contact support.")}
      end
    end
  end

  @impl true
  def handle_event("change_page", %{"page" => page}, socket) do
    case Integer.parse(page) do
      {p, ""} when p > 0 -> {:noreply, assign(socket, page: p)}
      _ -> {:noreply, socket}
    end
  end

  defp load_certificates(socket) do
    opts = tenant_opts(socket)
    status = socket.assigns.status_filter

    filters = if status != "all", do: [status: status], else: []

    certs = case RaEngineClient.list_certificates(filters, opts) do
      {:ok, certs} -> certs
      _ -> []
    end

    assign(socket, certificates: certs)
  end

  defp format_datetime(nil), do: "-"
  defp format_datetime(%DateTime{} = dt), do: Calendar.strftime(dt, "%Y-%m-%d %H:%M:%S")
  defp format_datetime(%NaiveDateTime{} = dt), do: Calendar.strftime(dt, "%Y-%m-%d %H:%M:%S")

  defp format_datetime(str) when is_binary(str) do
    case DateTime.from_iso8601(str) do
      {:ok, dt, _} -> Calendar.strftime(dt, "%Y-%m-%d %H:%M:%S")
      _ -> str
    end
  end

  defp format_datetime(_), do: "-"

  @impl true
  def render(assigns) do
    ~H"""
    <div class="space-y-4">
      <%!-- Description banner --%>
      <div class="alert border border-info/30 bg-info/5">
        <.icon name="hero-document-text" class="size-5 text-info shrink-0" />
        <div>
          <p class="text-sm font-medium text-base-content">Issued Certificates</p>
          <p class="text-xs text-base-content/60 mt-0.5">
            View certificates issued through this Registration Authority. Certificates are issued by
            the CA after CSR approval. RA administrators can revoke certificates when needed.
          </p>
        </div>
      </div>

      <%!-- Filters --%>
      <div class="card bg-base-100 shadow-sm border border-base-300">
        <div class="card-body p-4">
          <div class="flex flex-wrap items-end gap-4">
            <div>
              <label class="text-xs font-medium text-base-content/60 mb-1 block">Status</label>
              <select phx-change="filter_status" name="status" class="select select-sm select-bordered">
                <option value="all" selected={@status_filter == "all"}>All</option>
                <option value="active" selected={@status_filter == "active"}>Active</option>
                <option value="revoked" selected={@status_filter == "revoked"}>Revoked</option>
              </select>
            </div>
            <div class="text-sm text-base-content/50">
              {length(@certificates)} certificate(s)
            </div>
          </div>
        </div>
      </div>

      <%!-- Certificates table --%>
      <% paginated = @certificates |> Enum.drop((@page - 1) * @per_page) |> Enum.take(@per_page) %>
      <div class="card bg-base-100 shadow-sm border border-base-300">
        <div class="card-body p-0">
          <table class="table table-sm table-fixed w-full">
            <thead>
              <tr class="text-xs uppercase text-base-content/50">
                <th class="w-[18%]">Serial</th>
                <th class="w-[35%]">Subject DN</th>
                <th class="w-[15%]">Profile</th>
                <th class="w-[12%]">Status</th>
                <th class="w-[20%]">Issued At</th>
              </tr>
            </thead>
            <tbody>
              <tr :for={cert <- paginated}
                  class="hover cursor-pointer"
                  phx-click="view_cert"
                  phx-value-serial={cert[:serial_number] || cert[:issued_cert_serial]}>
                <td class="font-mono text-xs overflow-hidden text-ellipsis whitespace-nowrap">
                  {cert[:serial_number] || cert[:issued_cert_serial]}
                </td>
                <td class="overflow-hidden text-ellipsis whitespace-nowrap text-sm">
                  {cert[:subject_dn]}
                </td>
                <td class="text-xs overflow-hidden text-ellipsis whitespace-nowrap">
                  {cert[:cert_profile_name] || "-"}
                </td>
                <td>
                  <%= if cert[:status] == "revoked" do %>
                    <span class="badge badge-sm badge-error">revoked</span>
                  <% else %>
                    <span class="badge badge-sm badge-success">issued</span>
                  <% end %>
                </td>
                <td class="text-xs">{format_datetime(cert[:reviewed_at])}</td>
              </tr>
              <tr :if={paginated == []}>
                <td colspan="5" class="text-center text-base-content/50 py-8">
                  {if @loading, do: "Loading...", else: "No certificates found."}
                </td>
              </tr>
            </tbody>
          </table>

          <%!-- Pagination --%>
          <div :if={length(@certificates) > @per_page} class="flex items-center justify-between px-5 py-3 border-t border-base-300 text-sm">
            <span class="text-base-content/60">
              Showing {min((@page - 1) * @per_page + 1, length(@certificates))}-{min(@page * @per_page, length(@certificates))} of {length(@certificates)}
            </span>
            <div class="join">
              <button :for={p <- 1..max(ceil(length(@certificates) / @per_page), 1)}
                      phx-click="change_page" phx-value-page={p}
                      class={["join-item btn btn-xs", if(p == @page, do: "btn-active", else: "")]}>
                {p}
              </button>
            </div>
          </div>
        </div>
      </div>

      <%!-- Certificate Detail Panel --%>
      <%= if @selected_cert do %>
        <div class="card bg-base-100 shadow-sm border border-base-300">
          <div class="card-body">
            <div class="flex items-center justify-between mb-4">
              <h2 class="text-sm font-semibold">
                <.icon name="hero-document-text" class="size-4 inline text-sky-400" /> Certificate Details
              </h2>
              <button phx-click="close_detail" title="Close details" class="btn btn-ghost btn-sm btn-square">
                <.icon name="hero-x-mark" class="size-4" />
              </button>
            </div>

            <div class="grid grid-cols-2 gap-4 text-sm">
              <div>
                <label class="text-xs text-base-content/50">Serial Number</label>
                <p class="font-mono text-xs break-all">{@selected_cert[:serial_number] || @selected_cert[:issued_cert_serial]}</p>
              </div>
              <div>
                <label class="text-xs text-base-content/50">Status</label>
                <p>
                  <%= if @selected_cert[:status] == "revoked" do %>
                    <span class="badge badge-sm badge-error">revoked</span>
                  <% else %>
                    <span class="badge badge-sm badge-success">issued</span>
                  <% end %>
                </p>
              </div>
              <div class="col-span-2">
                <label class="text-xs text-base-content/50">Subject DN</label>
                <p class="font-mono text-xs break-all">{@selected_cert[:subject_dn]}</p>
              </div>
              <div>
                <label class="text-xs text-base-content/50">Certificate Profile</label>
                <p>{@selected_cert[:cert_profile_name] || "-"}</p>
              </div>
              <div>
                <label class="text-xs text-base-content/50">Reviewed By</label>
                <p>{@selected_cert[:reviewed_by] || "-"}</p>
              </div>
              <div>
                <label class="text-xs text-base-content/50">Submitted At</label>
                <p>{format_datetime(@selected_cert[:submitted_at])}</p>
              </div>
              <div>
                <label class="text-xs text-base-content/50">Issued At</label>
                <p>{format_datetime(@selected_cert[:reviewed_at])}</p>
              </div>
            </div>

            <%!-- Revocation section (ra_admin only, active certs only) --%>
            <% user_role = (@current_user || %{})[:role] || (@current_user || %{})["role"] %>
            <%= if user_role == "ra_admin" and @selected_cert[:status] != "revoked" do %>
              <div class="mt-4 pt-4 border-t border-base-300">
                <h3 class="text-sm font-semibold text-error mb-3">
                  <.icon name="hero-shield-exclamation" class="size-4 inline" /> Revoke Certificate
                </h3>

                <%= if @show_revoke_confirm do %>
                  <div class="alert alert-warning text-sm mb-3">
                    <.icon name="hero-exclamation-triangle" class="size-4 shrink-0" />
                    <span>This action is irreversible. The certificate will be added to the CRL.</span>
                  </div>
                  <div class="flex items-end gap-3">
                    <div>
                      <label class="text-xs font-medium text-base-content/60 mb-1 block">Revocation Reason</label>
                      <select phx-change="select_revoke_reason" name="reason" class="select select-sm select-bordered">
                        <option value="unspecified" selected={@revoke_reason == "unspecified"}>Unspecified</option>
                        <option value="key_compromise" selected={@revoke_reason == "key_compromise"}>Key Compromise</option>
                        <option value="ca_compromise" selected={@revoke_reason == "ca_compromise"}>CA Compromise</option>
                        <option value="affiliation_changed" selected={@revoke_reason == "affiliation_changed"}>Affiliation Changed</option>
                        <option value="superseded" selected={@revoke_reason == "superseded"}>Superseded</option>
                        <option value="cessation_of_operation" selected={@revoke_reason == "cessation_of_operation"}>Cessation of Operation</option>
                      </select>
                    </div>
                    <button phx-click="revoke_cert" class="btn btn-sm btn-error">
                      <.icon name="hero-shield-exclamation" class="size-4" /> Confirm Revocation
                    </button>
                    <button phx-click="cancel_revoke" class="btn btn-sm btn-ghost">Cancel</button>
                  </div>
                <% else %>
                  <button phx-click="show_revoke_confirm" class="btn btn-sm btn-outline btn-error">
                    <.icon name="hero-shield-exclamation" class="size-4" /> Revoke this Certificate
                  </button>
                <% end %>
              </div>
            <% end %>

            <div class="mt-4 pt-4 border-t border-base-300">
              <p class="text-xs text-base-content/40">
                <.icon name="hero-information-circle" class="size-3.5 inline" />
                Full certificate details (PEM, validity period, fingerprint) are available from the CA Portal.
                The RA tracks the issuance record linking the original CSR to the issued certificate serial.
              </p>
            </div>
          </div>
        </div>
      <% end %>
    </div>
    """
  end
end
