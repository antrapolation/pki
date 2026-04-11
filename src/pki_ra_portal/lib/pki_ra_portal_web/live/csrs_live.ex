defmodule PkiRaPortalWeb.CsrsLive do
  use PkiRaPortalWeb, :live_view

  require Logger

  alias PkiRaPortal.RaEngineClient

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket), do: send(self(), :load_data)

    {:ok,
     socket
     |> assign(
       page_title: "CSR Management",
       csrs: [],
       ra_instances: [],
       loading: true,
       selected_ra_instance_id: "",
       status_filter: "all",
       selected_csr: nil,
       dcv_challenge: nil,
       reject_reason: "",
       page: 1,
       per_page: 10
     )
     |> apply_pagination()}
  end

  @impl true
  def handle_info(:load_data, socket) do
    import PkiRaPortalWeb.SafeEngine, only: [safe_load: 3]

    safe_load(socket, fn ->
      opts = tenant_opts(socket)

      csrs = case RaEngineClient.list_csrs([], opts) do
        {:ok, c} -> c
        {:error, _} -> []
      end

      ra_instances =
        case RaEngineClient.list_ra_instances(opts) do
          {:ok, instances} -> instances
          {:error, _} -> []
        end

      {:noreply,
       socket
       |> assign(
         csrs: csrs,
         ra_instances: ra_instances,
         loading: false
       )
       |> apply_pagination()}
    end, retry_msg: :load_data)
  end

  @impl true
  def handle_info({:dcv_updated, challenge}, socket) do
    {:noreply, assign(socket, dcv_challenge: ensure_map(challenge))}
  end

  @impl true
  def handle_event("filter_ra_instance", %{"ra_instance_id" => ra_instance_id}, socket) do
    filters = build_filters(socket.assigns.status_filter, ra_instance_id)
    csrs = case RaEngineClient.list_csrs(filters, tenant_opts(socket)) do
      {:ok, c} -> c
      {:error, _} -> []
    end
    {:noreply, socket |> assign(csrs: csrs, selected_ra_instance_id: ra_instance_id, page: 1) |> apply_pagination()}
  end

  @impl true
  def handle_event("filter_status", %{"status" => status}, socket) do
    filters = build_filters(status, socket.assigns.selected_ra_instance_id)
    csrs = case RaEngineClient.list_csrs(filters, tenant_opts(socket)) do
      {:ok, c} -> c
      {:error, _} -> []
    end
    {:noreply, socket |> assign(csrs: csrs, status_filter: status, page: 1) |> apply_pagination()}
  end

  @impl true
  def handle_event("view_csr", %{"id" => id}, socket) do
    opts = tenant_opts(socket)
    csr = case RaEngineClient.get_csr(id, opts) do
      {:ok, c} -> c
      {:error, _} -> nil
    end

    dcv_challenge =
      case RaEngineClient.get_dcv_status(id, opts) do
        {:ok, challenges} when is_list(challenges) -> List.first(challenges)
        _ -> nil
      end

    if connected?(socket) do
      # Unsubscribe from previous CSR's DCV topic to avoid duplicate messages
      if prev = socket.assigns[:selected_csr] do
        Phoenix.PubSub.unsubscribe(PkiRaPortal.PubSub, "dcv:#{prev.id}")
      end
      Phoenix.PubSub.subscribe(PkiRaPortal.PubSub, "dcv:#{id}")
    end

    {:noreply, assign(socket, selected_csr: csr, dcv_challenge: dcv_challenge)}
  end

  @impl true
  def handle_event("close_detail", _params, socket) do
    {:noreply, assign(socket, selected_csr: nil, dcv_challenge: nil)}
  end

  @impl true
  def handle_event("approve_csr", %{"id" => id}, socket) do
    if get_role(socket) not in ["ra_admin", "ra_officer"] do
      {:noreply, put_flash(socket, :error, "Unauthorized")}
    else
      case RaEngineClient.approve_csr(id, %{reviewer_user_id: socket.assigns.current_user[:id] || socket.assigns.current_user["id"]}, tenant_opts(socket)) do
        {:ok, _} ->
          filters = build_filters(socket.assigns.status_filter, socket.assigns.selected_ra_instance_id)
          csrs = case RaEngineClient.list_csrs(filters, tenant_opts(socket)) do
            {:ok, c} -> c
            {:error, _} -> []
          end

          {:noreply,
           socket
           |> assign(csrs: csrs, selected_csr: nil)
           |> apply_pagination()
           |> put_flash(:info, "CSR approved successfully")}

        {:error, reason} ->
          Logger.error("[csrs] Failed to approve CSR: #{inspect(reason)}")
          {:noreply, put_flash(socket, :error, PkiRaPortalWeb.ErrorHelpers.sanitize_error("Failed to approve CSR", reason))}
      end
    end
  end

  @impl true
  def handle_event("reject_csr", %{"csr_id" => id, "reason" => reason}, socket) do
    if get_role(socket) not in ["ra_admin", "ra_officer"] do
      {:noreply, put_flash(socket, :error, "Unauthorized")}
    else
      reason = String.slice(reason, 0, 500)
      case RaEngineClient.reject_csr(id, reason, %{reviewer_user_id: socket.assigns.current_user[:id] || socket.assigns.current_user["id"]}, tenant_opts(socket)) do
        {:ok, _} ->
          filters = build_filters(socket.assigns.status_filter, socket.assigns.selected_ra_instance_id)
          csrs = case RaEngineClient.list_csrs(filters, tenant_opts(socket)) do
            {:ok, c} -> c
            {:error, _} -> []
          end

          {:noreply,
           socket
           |> assign(csrs: csrs, selected_csr: nil)
           |> apply_pagination()
           |> put_flash(:info, "CSR rejected")}

        {:error, reason} ->
          Logger.error("[csrs] Failed to reject CSR: #{inspect(reason)}")
          {:noreply, put_flash(socket, :error, PkiRaPortalWeb.ErrorHelpers.sanitize_error("Failed to reject CSR", reason))}
      end
    end
  end

  @impl true
  def handle_event("change_page", %{"page" => page}, socket) do
    case Integer.parse(page) do
      {p, ""} when p > 0 -> {:noreply, socket |> assign(page: p) |> apply_pagination()}
      _ -> {:noreply, socket}
    end
  end

  @impl true
  def handle_event("start_dcv", %{"csr_id" => csr_id, "method" => method}, socket) do
    if get_role(socket) not in ["ra_admin", "ra_officer"] do
      {:noreply, put_flash(socket, :error, "Unauthorized")}
    else
      opts = tenant_opts(socket) ++ [user_id: socket.assigns.current_user[:id]]

      case RaEngineClient.start_dcv(csr_id, method, opts) do
        {:ok, challenge} ->
          audit_log(socket, "dcv_started", "csr", csr_id, %{method: method, domain: challenge[:domain]})
          {:noreply, assign(socket, dcv_challenge: ensure_map(challenge))}

        {:error, reason} ->
          Logger.error("[csrs] Failed to start DCV: #{inspect(reason)}")
          {:noreply, put_flash(socket, :error, PkiRaPortalWeb.ErrorHelpers.sanitize_error("Failed to start domain validation", reason))}
      end
    end
  end

  @impl true
  def handle_event("verify_dcv", %{"csr-id" => csr_id}, socket) do
    if get_role(socket) not in ["ra_admin", "ra_officer"] do
      {:noreply, put_flash(socket, :error, "Unauthorized")}
    else
      opts = tenant_opts(socket)

      case RaEngineClient.verify_dcv(csr_id, opts) do
        {:ok, result} ->
          result_map = ensure_map(result)
          status = result_map[:status]

          if status == "passed" do
            audit_log(socket, "dcv_passed", "csr", csr_id, %{})
            {:noreply, socket |> put_flash(:info, "Domain validation passed!") |> assign(dcv_challenge: result_map)}
          else
            {:noreply, assign(socket, dcv_challenge: result_map)}
          end

        {:error, reason} ->
          Logger.error("[csrs] DCV verify failed: #{inspect(reason)}")
          {:noreply, put_flash(socket, :error, PkiRaPortalWeb.ErrorHelpers.sanitize_error("Verification check failed", reason))}
      end
    end
  end

  defp get_role(socket) do
    user = socket.assigns[:current_user]
    user[:role] || user["role"]
  end

  defp audit_log(socket, action, target_type, target_id, details) do
    PkiPlatformEngine.PlatformAudit.log(action, %{
      actor_id: socket.assigns.current_user[:id],
      actor_username: socket.assigns.current_user[:username],
      target_type: target_type,
      target_id: target_id,
      tenant_id: socket.assigns[:tenant_id],
      portal: "ra",
      details: details
    })
  end

  defp ensure_map(%{__struct__: _} = struct), do: Map.from_struct(struct)
  defp ensure_map(map) when is_map(map), do: map
  defp ensure_map(_), do: nil

  defp dcv_status_class("passed"), do: "badge-success"
  defp dcv_status_class("pending"), do: "badge-warning"
  defp dcv_status_class("expired"), do: "badge-error"
  defp dcv_status_class("failed"), do: "badge-error"
  defp dcv_status_class(_), do: "badge-ghost"

  defp build_filters(status, ra_instance_id) do
    filters = if status == "all", do: [], else: [status: status]
    if ra_instance_id != "", do: filters ++ [ra_instance_id: ra_instance_id], else: filters
  end

  defp apply_pagination(socket) do
    items = socket.assigns.csrs
    total = length(items)
    per_page = socket.assigns.per_page
    total_pages = max(ceil(total / per_page), 1)
    page = min(socket.assigns.page, total_pages)
    start_idx = (page - 1) * per_page
    paged = items |> Enum.drop(start_idx) |> Enum.take(per_page)

    assign(socket, paged_csrs: paged, total_pages: total_pages, page: page)
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div id="csrs-page" class="space-y-6">
      <h1 class="text-2xl font-bold tracking-tight">CSR Management</h1>

      <%!-- Filters --%>
      <section id="csr-filter" class="flex items-center gap-6">
        <form phx-change="filter_ra_instance" class="flex items-center gap-3">
          <label for="ra-instance-filter" class="text-xs font-medium text-base-content/60">Filter by RA Instance</label>
          <select name="ra_instance_id" id="ra-instance-filter" class="select select-bordered select-sm">
            <option value="">All</option>
            <option
              :for={inst <- @ra_instances}
              value={inst.id}
              selected={@selected_ra_instance_id == inst.id}
            >
              {inst.name}
            </option>
          </select>
        </form>
        <form phx-change="filter_status" class="flex items-center gap-3">
          <label for="status" class="text-sm font-medium text-base-content/60">Filter by status:</label>
          <select name="status" id="status-filter" class="select select-sm select-bordered">
            <option value="all" selected={@status_filter == "all"}>All</option>
            <option value="pending" selected={@status_filter == "pending"}>Pending</option>
            <option value="approved" selected={@status_filter == "approved"}>Approved</option>
            <option value="rejected" selected={@status_filter == "rejected"}>Rejected</option>
          </select>
        </form>
      </section>

      <%!-- CSR Table --%>
      <section id="csr-table" class="card bg-base-100 shadow-sm border border-base-300">
        <div class="card-body">
          <div>
            <table class="table table-sm table-fixed w-full">
              <thead>
                <tr class="border-base-300">
                  <th class="font-semibold text-xs uppercase tracking-wider w-[12%]">ID</th>
                  <th class="font-semibold text-xs uppercase tracking-wider w-[25%]">Subject</th>
                  <th class="font-semibold text-xs uppercase tracking-wider w-[18%]">Profile</th>
                  <th class="font-semibold text-xs uppercase tracking-wider w-[10%]">Status</th>
                  <th class="font-semibold text-xs uppercase tracking-wider w-[15%]">Submitted</th>
                  <th class="font-semibold text-xs uppercase tracking-wider w-[20%]">Actions</th>
                </tr>
              </thead>
              <tbody id="csr-list">
                <tr :for={csr <- @paged_csrs} id={"csr-#{csr.id}"} class="hover:bg-base-200/50 border-base-300">
                  <td class="font-mono text-xs overflow-hidden text-ellipsis whitespace-nowrap">{csr.id}</td>
                  <td class="overflow-hidden text-ellipsis whitespace-nowrap">{csr.subject}</td>
                  <td class="overflow-hidden text-ellipsis whitespace-nowrap">{csr.profile_name}</td>
                  <td>
                    <span class={[
                      "badge badge-sm",
                      csr.status == "pending" && "badge-warning",
                      csr.status == "approved" && "badge-success",
                      csr.status == "rejected" && "badge-error"
                    ]}>
                      {csr.status}
                    </span>
                  </td>
                  <td class="text-xs text-base-content/60"><.local_time dt={csr.submitted_at} /></td>
                  <td class="flex gap-1">
                    <button phx-click="view_csr" phx-value-id={csr.id} title="View Details" class="btn btn-ghost btn-xs text-sky-400">
                      <.icon name="hero-eye" class="size-4" />
                    </button>
                    <button
                      :if={csr.status == "verified"}
                      phx-click="approve_csr"
                      phx-value-id={csr.id}
                      title="Approve"
                      class="btn btn-ghost btn-xs text-emerald-400"
                    >
                      <.icon name="hero-check" class="size-4" />
                    </button>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
          <div :if={@total_pages > 1} class="flex justify-center mt-4">
            <div class="join">
              <button
                :for={p <- 1..@total_pages}
                phx-click="change_page"
                phx-value-page={p}
                class={["join-item btn btn-sm", p == @page && "btn-active"]}
              >
                {p}
              </button>
            </div>
          </div>
        </div>
      </section>

      <%!-- CSR Detail Panel --%>
      <section :if={@selected_csr} id="csr-detail" class="card bg-base-100 shadow-sm border border-base-300">
        <div class="card-body">
          <div class="flex items-center justify-between">
            <h2 class="card-title text-sm font-semibold uppercase tracking-wide text-base-content/60">CSR Detail</h2>
            <button phx-click="close_detail" class="btn btn-xs btn-ghost">
              Close
            </button>
          </div>

          <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mt-3">
            <div>
              <span class="text-xs font-medium text-base-content/50 uppercase">ID</span>
              <p class="font-mono text-sm">{@selected_csr.id}</p>
            </div>
            <div>
              <span class="text-xs font-medium text-base-content/50 uppercase">Subject</span>
              <p class="text-sm">{@selected_csr.subject}</p>
            </div>
            <div>
              <span class="text-xs font-medium text-base-content/50 uppercase">Status</span>
              <p>
                <span id="csr-status" class={[
                  "badge badge-sm",
                  @selected_csr.status == "pending" && "badge-warning",
                  @selected_csr.status == "approved" && "badge-success",
                  @selected_csr.status == "rejected" && "badge-error"
                ]}>
                  {@selected_csr.status}
                </span>
              </p>
            </div>
            <div>
              <span class="text-xs font-medium text-base-content/50 uppercase">Profile</span>
              <p class="text-sm">{@selected_csr.profile_name}</p>
            </div>
            <div>
              <span class="text-xs font-medium text-base-content/50 uppercase">Public Key Algorithm</span>
              <p class="font-mono text-sm">{@selected_csr.public_key_algorithm}</p>
            </div>
            <div>
              <span class="text-xs font-medium text-base-content/50 uppercase">Requestor</span>
              <p class="text-sm">{@selected_csr.requestor}</p>
            </div>
          </div>

          <div :if={@selected_csr.status == "verified"} id="csr-actions" class="mt-4 pt-4 border-t border-base-300 space-y-4">
            <%!-- NOTE: Only disables when a DCV challenge exists but hasn't passed.
                 If DCV is required by cert profile but no challenge initiated yet,
                 the button stays active — server-side approve_csr still rejects. --%>
            <%= if @dcv_challenge && @dcv_challenge[:status] != "passed" do %>
              <button disabled class="btn btn-sm btn-success btn-disabled" title="Complete domain validation before approving">
                <.icon name="hero-check" class="size-4" /> Approve
              </button>
              <p class="text-xs text-warning">Domain validation must pass before this CSR can be approved.</p>
            <% else %>
              <button phx-click="approve_csr" phx-value-id={@selected_csr.id} class="btn btn-sm btn-success">
                <.icon name="hero-check" class="size-4" /> Approve
              </button>
            <% end %>

            <form phx-submit="reject_csr" id="reject-form" class="space-y-2">
              <input type="hidden" name="csr_id" value={@selected_csr.id} />
              <label for="reason" class="label text-xs font-medium">Rejection Reason</label>
              <textarea
                name="reason"
                id="reject-reason"
                required
                rows="3"
                class="textarea textarea-bordered w-full text-sm"
                placeholder="Provide a reason for rejection..."
              ></textarea>
              <button type="submit" class="btn btn-sm btn-error btn-outline">
                <.icon name="hero-x-mark" class="size-4" /> Reject
              </button>
            </form>
          </div>

          <%!-- DCV Section --%>
          <div :if={@selected_csr.status in ["verified", "approved"]} class="mt-4 border-t border-base-300 pt-4">
            <h3 class="text-sm font-semibold mb-3">
              <.icon name="hero-globe-alt" class="size-4 inline" /> Domain Validation
            </h3>

            <%= if @dcv_challenge do %>
              <div class="bg-base-200/50 rounded-lg p-3 text-sm space-y-2">
                <div class="flex items-center justify-between">
                  <span>Status:</span>
                  <span class={["badge badge-sm", dcv_status_class(@dcv_challenge[:status])]}>
                    {@dcv_challenge[:status]}
                  </span>
                </div>
                <div class="flex items-center justify-between">
                  <span>Method:</span>
                  <span class="font-mono text-xs">{@dcv_challenge[:method]}</span>
                </div>
                <div :if={@dcv_challenge[:status] == "pending"}>
                  <div class="alert alert-info text-xs mt-2">
                    <%= if @dcv_challenge[:method] == "http-01" do %>
                      <p>Place this content at:<br/>
                      <code class="break-all">http://{@dcv_challenge[:domain]}/.well-known/pki-validation/{@dcv_challenge[:token]}</code></p>
                      <p class="mt-1">Content: <code class="break-all">{@dcv_challenge[:token_value]}</code></p>
                    <% else %>
                      <p>Add TXT record:<br/>
                      <code>_pki-validation.{@dcv_challenge[:domain]}</code></p>
                      <p class="mt-1">Value: <code class="break-all">{@dcv_challenge[:token_value]}</code></p>
                    <% end %>
                  </div>
                  <button phx-click="verify_dcv" phx-value-csr-id={@selected_csr.id} class="btn btn-primary btn-sm mt-2">
                    <.icon name="hero-arrow-path" class="size-4" /> Verify Now
                  </button>
                </div>
              </div>
            <% else %>
              <form phx-submit="start_dcv" class="flex items-end gap-3">
                <input type="hidden" name="csr_id" value={@selected_csr.id} />
                <div>
                  <label class="text-xs text-base-content/50 mb-1 block">Method</label>
                  <select name="method" class="select select-sm select-bordered">
                    <option value="http-01">HTTP-01</option>
                    <option value="dns-01">DNS-01</option>
                  </select>
                </div>
                <button type="submit" class="btn btn-primary btn-sm">
                  <.icon name="hero-play" class="size-4" /> Start DCV
                </button>
              </form>
            <% end %>
          </div>
        </div>
      </section>
    </div>
    """
  end
end
