defmodule PkiCaPortalWeb.CertificatesLive do
  use PkiCaPortalWeb, :live_view

  alias PkiCaPortal.CaEngineClient
  import PkiCaPortalWeb.AuditHelpers, only: [audit_log: 4, audit_log: 5]

  require Logger

  @revocation_reasons [
    {"unspecified", "Unspecified"},
    {"key_compromise", "Key Compromise"},
    {"ca_compromise", "CA Compromise"},
    {"affiliation_changed", "Affiliation Changed"},
    {"superseded", "Superseded"},
    {"cessation_of_operation", "Cessation of Operation"}
  ]

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket), do: send(self(), :load_data)

    {:ok,
     assign(socket,
       page_title: "Certificates",
       certificates: [],
       issuer_keys: [],
       ca_instances: [],
       selected_ca_id: "",
       selected_issuer_key_id: "",
       selected_key_label: "",
       key_search: "",
       key_search_results: [],
       status_filter: "all",
       selected_cert: nil,
       revocation_reasons: @revocation_reasons,
       revoke_reason: "unspecified",
       loading: true,
       page: 1,
       per_page: 20
     )}
  end

  @impl true
  def handle_info(:load_data, socket) do
    opts = tenant_opts(socket)
    ca_id = socket.assigns.current_user[:ca_instance_id]

    ca_instances = case CaEngineClient.list_ca_instances(opts) do
      {:ok, instances} -> instances
      _ -> []
    end

    effective_ca_id = ca_id || case ca_instances do
      [first | _] -> first[:id]
      _ -> nil
    end

    issuer_keys = if effective_ca_id do
      case CaEngineClient.list_issuer_keys(effective_ca_id, opts) do
        {:ok, keys} -> keys
        _ -> []
      end
    else
      []
    end

    {:noreply,
     socket
     |> assign(
       ca_instances: ca_instances,
       selected_ca_id: effective_ca_id || "",
       issuer_keys: issuer_keys,
       loading: false
     )
     |> load_certificates()}
  end

  @impl true
  def handle_event("select_ca_instance", %{"ca_id" => ca_id}, socket) do
    opts = tenant_opts(socket)

    issuer_keys = case CaEngineClient.list_issuer_keys(ca_id, opts) do
      {:ok, keys} -> Enum.filter(keys, &(&1[:status] == "active"))
      _ -> []
    end

    {:noreply,
     socket
     |> assign(selected_ca_id: ca_id, issuer_keys: issuer_keys, selected_issuer_key_id: "", selected_cert: nil, page: 1)
     |> load_certificates()}
  end

  @impl true
  def handle_event("search_issuer_key", %{"value" => query}, socket) do
    results = if String.length(query) >= 1 do
      q = String.downcase(query)
      socket.assigns.issuer_keys
      |> Enum.filter(fn key ->
        String.contains?(String.downcase(key[:key_alias] || ""), q) or
        String.contains?(String.downcase(key[:algorithm] || ""), q)
      end)
    else
      []
    end

    {:noreply, assign(socket, key_search: query, key_search_results: results)}
  end

  @impl true
  def handle_event("select_issuer_key", %{"issuer_key_id" => id, "label" => label}, socket) do
    {:noreply,
     socket
     |> assign(selected_issuer_key_id: id, selected_key_label: label, key_search: "", key_search_results: [], selected_cert: nil, page: 1)
     |> load_certificates()}
  end

  @impl true
  def handle_event("select_issuer_key", %{"issuer_key_id" => id}, socket) do
    {:noreply,
     socket
     |> assign(selected_issuer_key_id: id, selected_cert: nil, page: 1)
     |> load_certificates()}
  end

  @impl true
  def handle_event("clear_issuer_key", _, socket) do
    {:noreply,
     socket
     |> assign(selected_issuer_key_id: "", selected_key_label: "", key_search: "", key_search_results: [], selected_cert: nil, page: 1)
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

    case CaEngineClient.get_certificate(serial, opts) do
      {:ok, cert} ->
        fingerprint = if cert[:cert_der] do
          :crypto.hash(:sha256, cert.cert_der) |> Base.encode16(case: :lower) |> format_fingerprint()
        else
          "-"
        end

        {:noreply, assign(socket, selected_cert: Map.put(cert, :fingerprint, fingerprint))}

      {:error, _} ->
        {:noreply, put_flash(socket, :error, "Certificate not found.")}
    end
  end

  @impl true
  def handle_event("close_detail", _, socket) do
    {:noreply, assign(socket, selected_cert: nil)}
  end

  @impl true
  def handle_event("revoke_cert", %{"serial" => serial, "reason" => reason}, socket) do
    opts = tenant_opts(socket)

    case CaEngineClient.revoke_certificate(serial, reason, opts) do
      {:ok, _} ->
        audit_log(socket, "certificate_revoked", "certificate", serial, %{reason: reason})

        {:noreply,
         socket
         |> put_flash(:info, "Certificate #{String.slice(serial, 0, 12)}... revoked.")
         |> assign(selected_cert: nil)
         |> load_certificates()}

      {:error, reason} ->
        Logger.error("[certificates] Failed to revoke #{serial}: #{inspect(reason)}")

        {:noreply,
         put_flash(socket, :error, PkiCaPortalWeb.ErrorHelpers.sanitize_error("Failed to revoke certificate", reason))}
    end
  end

  @impl true
  def handle_event("change_page", %{"page" => page}, socket) do
    {:noreply, assign(socket, page: String.to_integer(page))}
  end

  defp load_certificates(socket) do
    opts = tenant_opts(socket)
    issuer_key_id = socket.assigns.selected_issuer_key_id
    status = socket.assigns.status_filter

    certs = if issuer_key_id != "" do
      filters = if status != "all", do: [status: status], else: []
      case CaEngineClient.list_certificates(issuer_key_id, Keyword.merge(opts, filters: filters)) do
        {:ok, certs} -> certs
        _ -> []
      end
    else
      # Load from all issuer keys for this CA
      socket.assigns.issuer_keys
      |> Enum.flat_map(fn key ->
        filters = if status != "all", do: [status: status], else: []
        case CaEngineClient.list_certificates(key[:id], Keyword.merge(opts, filters: filters)) do
          {:ok, certs} -> certs
          _ -> []
        end
      end)
      |> Enum.sort_by(& &1[:inserted_at], {:desc, DateTime})
    end

    assign(socket, certificates: certs)
  end

  defp tenant_opts(socket), do: [tenant_id: socket.assigns[:tenant_id]]

  defp format_fingerprint(hex) do
    hex
    |> String.graphemes()
    |> Enum.chunk_every(2)
    |> Enum.map(&Enum.join/1)
    |> Enum.join(":")
  end

  defp format_datetime(nil), do: "-"
  defp format_datetime(%DateTime{} = dt), do: Calendar.strftime(dt, "%Y-%m-%d %H:%M:%S")
  defp format_datetime(%NaiveDateTime{} = dt), do: Calendar.strftime(dt, "%Y-%m-%d %H:%M:%S")
  defp format_datetime(_), do: "-"

  defp days_remaining(nil), do: "-"
  defp days_remaining(%DateTime{} = not_after) do
    days = DateTime.diff(not_after, DateTime.utc_now(), :day)
    cond do
      days < 0 -> "Expired"
      days == 0 -> "Expires today"
      days < 30 -> "#{days}d (expiring soon)"
      true -> "#{days}d"
    end
  end
  defp days_remaining(_), do: "-"

  defp validity_class(nil), do: ""
  defp validity_class(%DateTime{} = not_after) do
    days = DateTime.diff(not_after, DateTime.utc_now(), :day)
    cond do
      days < 0 -> "text-rose-400"
      days < 30 -> "text-amber-400"
      true -> "text-emerald-400"
    end
  end
  defp validity_class(_), do: ""

  @impl true
  def render(assigns) do
    ~H"""
    <div class="space-y-4">
      <%!-- Description --%>
      <div class="alert border border-info/30 bg-info/5">
        <.icon name="hero-document-text" class="size-5 text-info shrink-0" />
        <div>
          <p class="text-sm font-medium text-base-content">Issued Certificates</p>
          <p class="text-xs text-base-content/60 mt-0.5">
            View and manage certificates issued by this CA. Select an issuer key to filter certificates.
            Certificates can be revoked by a CA Admin — revoked certificates are published in the CRL and reflected in OCSP responses.
          </p>
        </div>
      </div>

      <%!-- Filters --%>
      <div class="card bg-base-100 shadow-sm border border-base-300">
        <div class="card-body p-4">
          <div class="flex flex-wrap items-end gap-4">
            <div>
              <label class="text-xs font-medium text-base-content/60 mb-1 block">CA Instance</label>
              <select phx-change="select_ca_instance" name="ca_id" class="select select-sm select-bordered">
                <option :for={ca <- @ca_instances} value={ca[:id]} selected={ca[:id] == @selected_ca_id}>
                  {ca[:name]}
                </option>
              </select>
            </div>
            <div class="relative">
              <label class="text-xs font-medium text-base-content/60 mb-1 block">Issuer Key</label>
              <input type="text"
                     name="key_search"
                     value={@key_search}
                     phx-keyup="search_issuer_key"
                     phx-debounce="300"
                     placeholder="Search key alias or algorithm..."
                     autocomplete="off"
                     class="input input-sm input-bordered w-64" />
              <div :if={@key_search != "" and @key_search_results != []} class="absolute z-30 mt-1 w-64 bg-base-100 border border-base-300 rounded-lg shadow-lg max-h-48 overflow-y-auto">
                <button :for={key <- @key_search_results}
                        type="button"
                        phx-click="select_issuer_key"
                        phx-value-issuer_key_id={key[:id]}
                        phx-value-label={"#{key[:key_alias]} (#{key[:algorithm]})"}
                        class="block w-full text-left px-3 py-2 text-sm hover:bg-base-200">
                  <span class="font-medium">{key[:key_alias]}</span>
                  <span class="text-xs text-base-content/50 ml-1">({key[:algorithm]})</span>
                </button>
              </div>
              <div :if={@selected_issuer_key_id != ""} class="mt-1">
                <span class="badge badge-sm badge-primary gap-1">
                  {@selected_key_label}
                  <button type="button" phx-click="clear_issuer_key" class="ml-1">&times;</button>
                </span>
              </div>
            </div>
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

      <%!--Certificates table --%>
      <% paginated = @certificates |> Enum.drop((@page - 1) * @per_page) |> Enum.take(@per_page) %>
      <div class="card bg-base-100 shadow-sm border border-base-300">
        <div class="card-body p-0">
          <table class="table table-sm table-fixed w-full">
            <thead>
              <tr class="text-xs uppercase text-base-content/50">
                <th class="w-[15%]">Serial</th>
                <th class="w-[30%]">Subject DN</th>
                <th class="w-[15%]">Issuer Key</th>
                <th class="w-[12%]">Valid Until</th>
                <th class="w-[8%]">Status</th>
                <th class="w-[10%]">Remaining</th>
                <th class="w-[10%] text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              <tr :for={cert <- paginated} class="hover cursor-pointer" phx-click="view_cert" phx-value-serial={cert[:serial_number]}>
                <td class="font-mono text-xs overflow-hidden text-ellipsis whitespace-nowrap">{cert[:serial_number]}</td>
                <td class="overflow-hidden text-ellipsis whitespace-nowrap text-sm">{cert[:subject_dn]}</td>
                <td class="text-xs overflow-hidden text-ellipsis whitespace-nowrap">
                  {find_key_alias(cert[:issuer_key_id], @issuer_keys)}
                </td>
                <td class="text-xs">{format_datetime(cert[:not_after])}</td>
                <td>
                  <span class={["badge badge-sm", if(cert[:status] == "active", do: "badge-success", else: "badge-error")]}>
                    {cert[:status]}
                  </span>
                </td>
                <td class={"text-xs #{validity_class(cert[:not_after])}"}>{days_remaining(cert[:not_after])}</td>
                <td class="text-right">
                  <button :if={cert[:status] == "active"} phx-click="view_cert" phx-value-serial={cert[:serial_number]} title="View & Revoke" class="btn btn-ghost btn-xs text-sky-400">
                    <.icon name="hero-eye" class="size-4" />
                  </button>
                </td>
              </tr>
              <tr :if={paginated == []}>
                <td colspan="7" class="text-center text-base-content/50 py-8">
                  {if @loading, do: "Loading...", else: "No certificates found."}
                </td>
              </tr>
            </tbody>
          </table>

          <%!--Pagination --%>
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

      <%!--Certificate Detail Panel --%>
      <%= if @selected_cert do %>
        <div class="card bg-base-100 shadow-sm border border-base-300">
          <div class="card-body">
            <div class="flex items-center justify-between mb-4">
              <h2 class="text-sm font-semibold">
                <.icon name="hero-document-text" class="size-4 inline" /> Certificate Details
              </h2>
              <button phx-click="close_detail" class="btn btn-ghost btn-sm btn-square">
                <.icon name="hero-x-mark" class="size-4" />
              </button>
            </div>

            <div class="grid grid-cols-2 gap-4 text-sm">
              <div>
                <label class="text-xs text-base-content/50">Serial Number</label>
                <p class="font-mono text-xs break-all">{@selected_cert[:serial_number]}</p>
              </div>
              <div>
                <label class="text-xs text-base-content/50">Status</label>
                <p>
                  <span class={["badge badge-sm", if(@selected_cert[:status] == "active", do: "badge-success", else: "badge-error")]}>
                    {@selected_cert[:status]}
                  </span>
                  <%= if @selected_cert[:revoked_at] do %>
                    <span class="text-xs text-base-content/50 ml-2">
                      Revoked: {format_datetime(@selected_cert[:revoked_at])} ({@selected_cert[:revocation_reason]})
                    </span>
                  <% end %>
                </p>
              </div>
              <div class="col-span-2">
                <label class="text-xs text-base-content/50">Subject DN</label>
                <p class="font-mono text-xs break-all">{@selected_cert[:subject_dn]}</p>
              </div>
              <div>
                <label class="text-xs text-base-content/50">Not Before</label>
                <p>{format_datetime(@selected_cert[:not_before])}</p>
              </div>
              <div>
                <label class="text-xs text-base-content/50">Not After</label>
                <p class={validity_class(@selected_cert[:not_after])}>
                  {format_datetime(@selected_cert[:not_after])} ({days_remaining(@selected_cert[:not_after])})
                </p>
              </div>
              <div class="col-span-2">
                <label class="text-xs text-base-content/50">SHA-256 Fingerprint</label>
                <p class="font-mono text-xs break-all">{@selected_cert[:fingerprint] || "-"}</p>
              </div>
            </div>

            <%!--PEM Download --%>
            <div :if={@selected_cert[:cert_pem]} class="mt-4">
              <label class="text-xs text-base-content/50">Certificate PEM</label>
              <textarea readonly class="textarea textarea-bordered w-full font-mono text-xs h-24 mt-1">{@selected_cert[:cert_pem]}</textarea>
            </div>

            <%!--Revoke Action --%>
            <div :if={@selected_cert[:status] == "active" and @current_user[:role] == "ca_admin"} class="mt-4 border-t border-base-300 pt-4">
              <h3 class="text-sm font-semibold text-rose-400 mb-2">
                <.icon name="hero-exclamation-triangle" class="size-4 inline" /> Revoke Certificate
              </h3>
              <form phx-submit="revoke_cert" class="flex items-end gap-3">
                <input type="hidden" name="serial" value={@selected_cert[:serial_number]} />
                <div class="flex-1">
                  <label class="text-xs text-base-content/50 mb-1 block">Reason</label>
                  <select name="reason" class="select select-sm select-bordered w-full">
                    <option :for={{val, label} <- @revocation_reasons} value={val}>{label}</option>
                  </select>
                </div>
                <button type="submit"
                        data-confirm="Are you sure you want to revoke this certificate? This action cannot be undone."
                        class="btn btn-error btn-sm">
                  <.icon name="hero-no-symbol" class="size-4" /> Revoke
                </button>
              </form>
            </div>
          </div>
        </div>
      <% end %>
    </div>
    """
  end

  defp find_key_alias(nil, _), do: "-"
  defp find_key_alias(id, keys) do
    case Enum.find(keys, &(&1[:id] == id)) do
      nil -> String.slice(to_string(id), 0, 8)
      key -> key[:key_alias]
    end
  end
end
