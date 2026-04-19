defmodule PkiTenantWeb.Ra.CsrsLive do
  use PkiTenantWeb, :live_view

  require Logger

  alias PkiRaEngine.{CsrValidation, CertProfileConfig, DcvChallenge}
  alias PkiMnesia.{Repo, Structs.RaInstance}

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket), do: send(self(), :load_data)

    {:ok,
     socket
     |> assign(
       page_title: "CSR Management",
       csrs: [],
       ra_instances: [],
       cert_profiles: [],
       loading: true,
       selected_ra_instance_id: "",
       status_filter: "all",
       selected_csr: nil,
       dcv_challenge: nil,
       reject_reason: "",
       show_submit_modal: false,
       page: 1,
       per_page: 10
     )
     |> apply_pagination()}
  end

  @impl true
  def handle_info(:load_data, socket) do
    csrs = case CsrValidation.list_csrs() do
      {:ok, c} -> c
      {:error, _} -> []
    end

    ra_instances =
      case Repo.all(RaInstance) do
        {:ok, instances} -> instances
        {:error, _} -> []
      end

    cert_profiles =
      case CertProfileConfig.list_profiles() do
        {:ok, profiles} -> profiles
        {:error, _} -> []
      end

    {:noreply,
     socket
     |> assign(
       csrs: csrs,
       ra_instances: ra_instances,
       cert_profiles: cert_profiles,
       loading: false
     )
     |> apply_pagination()}
  end

  @impl true
  def handle_info({:dcv_updated, challenge}, socket) do
    {:noreply, assign(socket, dcv_challenge: ensure_map(challenge))}
  end

  @impl true
  def handle_event("filter_ra_instance", %{"ra_instance_id" => ra_instance_id}, socket) do
    filters = build_filters(socket.assigns.status_filter, ra_instance_id)
    csrs = case CsrValidation.list_csrs(filters) do
      {:ok, c} -> c
      {:error, _} -> []
    end
    {:noreply, socket |> assign(csrs: csrs, selected_ra_instance_id: ra_instance_id, page: 1) |> apply_pagination()}
  end

  @impl true
  def handle_event("filter_status", %{"status" => status}, socket) do
    filters = build_filters(status, socket.assigns.selected_ra_instance_id)
    csrs = case CsrValidation.list_csrs(filters) do
      {:ok, c} -> c
      {:error, _} -> []
    end
    {:noreply, socket |> assign(csrs: csrs, status_filter: status, page: 1) |> apply_pagination()}
  end

  @impl true
  def handle_event("view_csr", %{"id" => id}, socket) do
    csr = case CsrValidation.get_csr(id) do
      {:ok, c} -> c
      {:error, _} -> nil
    end

    dcv_challenge =
      case DcvChallenge.get_for_csr(id) do
        {:ok, challenges} when is_list(challenges) -> List.first(challenges)
        _ -> nil
      end

    if connected?(socket) do
      # Unsubscribe from previous CSR's DCV topic to avoid duplicate messages
      if prev = socket.assigns[:selected_csr] do
        Phoenix.PubSub.unsubscribe(PkiTenantWeb.PubSub, "dcv:#{prev.id}")
      end
      Phoenix.PubSub.subscribe(PkiTenantWeb.PubSub, "dcv:#{id}")
    end

    {:noreply, assign(socket, selected_csr: csr, dcv_challenge: dcv_challenge)}
  end

  @impl true
  def handle_event("close_detail", _params, socket) do
    {:noreply, assign(socket, selected_csr: nil, dcv_challenge: nil)}
  end

  @impl true
  def handle_event("open_submit_modal", _params, socket) do
    {:noreply, assign(socket, show_submit_modal: true)}
  end

  @impl true
  def handle_event("close_submit_modal", _params, socket) do
    {:noreply, assign(socket, show_submit_modal: false)}
  end

  @impl true
  def handle_event("submit_csr", %{"csr_pem" => csr_pem, "cert_profile_id" => cert_profile_id}, socket) do
    cond do
      get_role(socket) not in ["ra_admin", "ra_officer"] ->
        {:noreply, put_flash(socket, :error, "Unauthorized")}

      cert_profile_id == "" ->
        {:noreply, put_flash(socket, :error, "Select a certificate profile.")}

      String.trim(csr_pem) == "" ->
        {:noreply, put_flash(socket, :error, "Paste a CSR PEM.")}

      true ->
        case CsrValidation.submit_csr(csr_pem, cert_profile_id) do
          {:ok, csr} ->
            PkiTenant.AuditBridge.log("csr_submitted_via_portal", %{csr_id: csr.id, cert_profile_id: cert_profile_id})

            filters = build_filters(socket.assigns.status_filter, socket.assigns.selected_ra_instance_id)
            csrs = case CsrValidation.list_csrs(filters) do
              {:ok, c} -> c
              {:error, _} -> []
            end

            {:noreply,
             socket
             |> assign(csrs: csrs, show_submit_modal: false)
             |> apply_pagination()
             |> put_flash(:info, "CSR submitted")}

          {:error, reason} ->
            Logger.error("[csrs] Failed to submit CSR: #{inspect(reason)}")
            {:noreply, put_flash(socket, :error, PkiTenantWeb.ErrorHelpers.sanitize_error("Failed to submit CSR", reason))}
        end
    end
  end

  @impl true
  def handle_event("approve_csr", %{"id" => id}, socket) do
    if get_role(socket) not in ["ra_admin", "ra_officer"] do
      {:noreply, put_flash(socket, :error, "Unauthorized")}
    else
      reviewer_id = socket.assigns.current_user[:id] || socket.assigns.current_user["id"]

      case CsrValidation.approve_csr(id, reviewer_id) do
        {:ok, _} ->
          filters = build_filters(socket.assigns.status_filter, socket.assigns.selected_ra_instance_id)
          csrs = case CsrValidation.list_csrs(filters) do
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
          {:noreply, put_flash(socket, :error, PkiTenantWeb.ErrorHelpers.sanitize_error("Failed to approve CSR", reason))}
      end
    end
  end

  @impl true
  def handle_event("reject_csr", params, socket) do
    id = Map.get(params, "csr_id")
    reason = Map.get(params, "reason", "")

    cond do
      get_role(socket) not in ["ra_admin", "ra_officer"] ->
        {:noreply, put_flash(socket, :error, "Unauthorized")}

      is_nil(id) or id == "" ->
        {:noreply, put_flash(socket, :error, "Missing CSR ID.")}

      reason == "" ->
        {:noreply, put_flash(socket, :error, "Rejection reason is required.")}

      true ->
        reason = String.slice(reason, 0, 500)
        reviewer_id = socket.assigns.current_user[:id] || socket.assigns.current_user["id"]

        case CsrValidation.reject_csr(id, reviewer_id, reason) do
          {:ok, _} ->
            filters = build_filters(socket.assigns.status_filter, socket.assigns.selected_ra_instance_id)
            csrs = case CsrValidation.list_csrs(filters) do
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
            {:noreply, put_flash(socket, :error, PkiTenantWeb.ErrorHelpers.sanitize_error("Failed to reject CSR", reason))}
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
  def handle_event("start_dcv", params, socket) do
    csr_id = Map.get(params, "csr_id")
    method = Map.get(params, "method")

    cond do
      get_role(socket) not in ["ra_admin", "ra_officer"] ->
        {:noreply, put_flash(socket, :error, "Unauthorized")}

      is_nil(csr_id) or csr_id == "" ->
        {:noreply, put_flash(socket, :error, "Missing CSR ID.")}

      is_nil(method) or method == "" ->
        {:noreply, put_flash(socket, :error, "Please select a validation method.")}

      true ->
        # DcvChallenge.create_challenge needs (csr_id, domain, opts)
        # Extract domain from the CSR
        domain = extract_domain_from_csr(csr_id)
        challenge_type = if method == "http-01", do: "http", else: "dns"

        case DcvChallenge.create_challenge(csr_id, domain, challenge_type: challenge_type) do
          {:ok, challenge} ->
            PkiTenant.AuditBridge.log("dcv_started", %{csr_id: csr_id, method: method, domain: challenge.domain})
            {:noreply, assign(socket, dcv_challenge: ensure_map(challenge))}

          {:error, reason} ->
            Logger.error("[csrs] Failed to start DCV: #{inspect(reason)}")
            {:noreply, put_flash(socket, :error, PkiTenantWeb.ErrorHelpers.sanitize_error("Failed to start domain validation", reason))}
        end
    end
  end

  @impl true
  def handle_event("verify_dcv", %{"csr-id" => csr_id}, socket) do
    if get_role(socket) not in ["ra_admin", "ra_officer"] do
      {:noreply, put_flash(socket, :error, "Unauthorized")}
    else
      case DcvChallenge.check_dcv_passed(csr_id) do
        :ok ->
          PkiTenant.AuditBridge.log("dcv_passed", %{csr_id: csr_id})

          # Reload the challenge to get updated status
          dcv_challenge = case DcvChallenge.get_for_csr(csr_id) do
            {:ok, [c | _]} -> ensure_map(c)
            _ -> nil
          end

          {:noreply,
           socket
           |> put_flash(:info, "Domain validation passed!")
           |> assign(dcv_challenge: dcv_challenge)}

        {:error, reason} ->
          Logger.error("[csrs] DCV verify failed: #{inspect(reason)}")

          # Reload challenge for display
          dcv_challenge = case DcvChallenge.get_for_csr(csr_id) do
            {:ok, [c | _]} -> ensure_map(c)
            _ -> socket.assigns.dcv_challenge
          end

          {:noreply,
           socket
           |> assign(dcv_challenge: dcv_challenge)
           |> put_flash(:error, PkiTenantWeb.ErrorHelpers.sanitize_error("Verification check failed", reason))}
      end
    end
  end

  defp get_role(socket) do
    user = socket.assigns[:current_user]
    user[:role] || user["role"]
  end

  defp ensure_map(%{__struct__: _} = struct), do: Map.from_struct(struct)
  defp ensure_map(map) when is_map(map), do: map
  defp ensure_map(_), do: nil

  defp dcv_status_class("passed"), do: "badge-success"
  defp dcv_status_class("verified"), do: "badge-success"
  defp dcv_status_class("pending"), do: "badge-warning"
  defp dcv_status_class("expired"), do: "badge-error"
  defp dcv_status_class("failed"), do: "badge-error"
  defp dcv_status_class(_), do: "badge-ghost"

  defp profile_name_for(_profiles, nil), do: "-"
  defp profile_name_for(profiles, profile_id) do
    case Enum.find(profiles, fn p -> p.id == profile_id end) do
      nil -> profile_id
      p -> p.name
    end
  end

  defp build_filters(status, ra_instance_id) do
    filters = if status == "all", do: [], else: [status: status]
    if ra_instance_id != "", do: filters ++ [ra_instance_id: ra_instance_id], else: filters
  end

  defp extract_domain_from_csr(csr_id) do
    case CsrValidation.get_csr(csr_id) do
      {:ok, csr} ->
        # Extract domain from subject DN (CN=example.com -> example.com)
        dn = csr.subject_dn || ""
        case Regex.run(~r/CN=([^,\/]+)/, dn) do
          [_, domain] -> domain
          _ -> "unknown"
        end
      _ -> "unknown"
    end
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
      <div class="flex items-center justify-between">
        <h1 class="text-2xl font-bold tracking-tight">CSR Management</h1>
        <button phx-click="open_submit_modal" class="btn btn-primary btn-sm">
          <.icon name="hero-plus" class="size-4" /> Submit CSR
        </button>
      </div>

      <%!-- Submit CSR Modal --%>
      <div :if={@show_submit_modal} class="modal modal-open">
        <div class="modal-box max-w-2xl">
          <h3 class="font-bold text-lg mb-4">Submit CSR</h3>
          <form phx-submit="submit_csr" class="space-y-4">
            <div>
              <label class="label text-xs font-medium">Certificate Profile</label>
              <select name="cert_profile_id" required class="select select-bordered w-full">
                <option value="">Select profile...</option>
                <option :for={p <- @cert_profiles} value={p.id}>{p.name}</option>
              </select>
            </div>
            <div>
              <label class="label text-xs font-medium">CSR (PEM)</label>
              <textarea
                name="csr_pem"
                required
                rows="12"
                class="textarea textarea-bordered w-full font-mono text-xs"
                placeholder="-----BEGIN CERTIFICATE REQUEST-----&#10;...&#10;-----END CERTIFICATE REQUEST-----"
              ></textarea>
            </div>
            <div class="modal-action">
              <button type="button" phx-click="close_submit_modal" class="btn btn-ghost btn-sm">Cancel</button>
              <button type="submit" class="btn btn-primary btn-sm">Submit</button>
            </div>
          </form>
        </div>
      </div>

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
                  <td class="overflow-hidden text-ellipsis whitespace-nowrap">{csr.subject_dn}</td>
                  <td class="overflow-hidden text-ellipsis whitespace-nowrap">{profile_name_for(@cert_profiles, csr.cert_profile_id)}</td>
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
              <p class="text-sm">{@selected_csr.subject_dn}</p>
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
              <p class="text-sm">{profile_name_for(@cert_profiles, @selected_csr.cert_profile_id)}</p>
            </div>
            <div>
              <span class="text-xs font-medium text-base-content/50 uppercase">Public Key Algorithm</span>
              <p class="font-mono text-sm">{Map.get(@selected_csr, :public_key_algorithm, "-")}</p>
            </div>
            <div>
              <span class="text-xs font-medium text-base-content/50 uppercase">Requestor</span>
              <p class="text-sm">{Map.get(@selected_csr, :requestor, "-")}</p>
            </div>
          </div>

          <div :if={@selected_csr.status == "verified"} id="csr-actions" class="mt-4 pt-4 border-t border-base-300 space-y-4">
            <%!-- NOTE: Only disables when a DCV challenge exists but hasn't passed.
                 If DCV is required by cert profile but no challenge initiated yet,
                 the button stays active — server-side approve_csr still rejects. --%>
            <%= if @dcv_challenge && @dcv_challenge[:status] != "passed" && @dcv_challenge[:status] != "verified" do %>
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
                  <span class="font-mono text-xs">{@dcv_challenge[:challenge_type] || @dcv_challenge[:method]}</span>
                </div>
                <div :if={@dcv_challenge[:status] == "pending"}>
                  <div class="alert alert-info text-xs mt-2">
                    <%= if (@dcv_challenge[:challenge_type] || @dcv_challenge[:method]) == "http" do %>
                      <p>Place this content at:<br/>
                      <code class="break-all">http://{@dcv_challenge[:domain]}/.well-known/pki-validation/{@dcv_challenge[:challenge_token]}</code></p>
                      <p class="mt-1">Content: <code class="break-all">{@dcv_challenge[:challenge_token]}</code></p>
                    <% else %>
                      <p>Add TXT record:<br/>
                      <code>_pki-validation.{@dcv_challenge[:domain]}</code></p>
                      <p class="mt-1">Value: <code class="break-all">{@dcv_challenge[:challenge_token]}</code></p>
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
