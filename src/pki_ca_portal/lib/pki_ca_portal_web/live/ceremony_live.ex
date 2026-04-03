defmodule PkiCaPortalWeb.CeremonyLive do
  use PkiCaPortalWeb, :live_view

  alias PkiCaPortal.CaEngineClient
  import PkiCaPortalWeb.AuditHelpers, only: [audit_log: 4, audit_log: 5]

  @algorithms [
    {"KAZ-SIGN-128", "Post-Quantum — KAZ-Sign level 1"},
    {"KAZ-SIGN-192", "Post-Quantum — KAZ-Sign level 3"},
    {"KAZ-SIGN-256", "Post-Quantum — KAZ-Sign level 5"},
    {"ML-DSA-44", "Post-Quantum — NIST FIPS 204 level 2"},
    {"ML-DSA-65", "Post-Quantum — NIST FIPS 204 level 3"},
    {"ML-DSA-87", "Post-Quantum — NIST FIPS 204 level 5"},
    {"SLH-DSA-SHA2-128f", "Post-Quantum — NIST FIPS 205 fast"},
    {"SLH-DSA-SHA2-128s", "Post-Quantum — NIST FIPS 205 small"},
    {"SLH-DSA-SHA2-192f", "Post-Quantum — NIST FIPS 205 L3 fast"},
    {"SLH-DSA-SHA2-192s", "Post-Quantum — NIST FIPS 205 L3 small"},
    {"SLH-DSA-SHA2-256f", "Post-Quantum — NIST FIPS 205 L5 fast"},
    {"SLH-DSA-SHA2-256s", "Post-Quantum — NIST FIPS 205 L5 small"},
    {"ECC-P256", "Classical — fast, widely supported"},
    {"ECC-P384", "Classical — stronger"},
    {"RSA-2048", "Classical — legacy compatibility"},
    {"RSA-4096", "Classical — legacy, stronger"}
  ]

  @time_window_options [
    {1, "1 hour"},
    {2, "2 hours"},
    {4, "4 hours"},
    {8, "8 hours"},
    {12, "12 hours"},
    {24, "24 hours"},
    {48, "2 days"},
    {72, "3 days"},
    {168, "1 week"}
  ]

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket), do: send(self(), :load_data)

    {:ok,
     assign(socket,
       page_title: "Key Ceremony",
       ceremonies: [],
       keystores: [],
       ca_instances: [],
       algorithms: @algorithms,
       time_window_options: @time_window_options,
       effective_ca_id: nil,
       selected_ca_id: "",
       loading: true,
       page: 1,
       per_page: 10,
       # Wizard state
       wizard_step: nil,
       active_ceremony: nil,
       private_key: nil,
       public_key: nil,
       public_key_fingerprint: nil,
       is_root: true,
       subject_dn: "",
       key_managers: [],
       auditors: [],
       custodians: [],
       custodian_passwords: [],
       csr_pem: nil,
       wizard_error: nil,
       wizard_busy: false,
       # Progress dashboard state
       participants: [],
       activity_log: []
     )}
  end

  @impl true
  def handle_info(:load_data, socket) do
    ca_id = socket.assigns.current_user[:ca_instance_id]
    opts = tenant_opts(socket)

    ca_instances =
      case CaEngineClient.list_ca_instances(opts) do
        {:ok, instances} -> instances
        {:error, _} -> []
      end

    effective_ca_id = ca_id || case ca_instances do
      [first | _] -> first[:id]
      [] -> nil
    end

    {ceremonies, keystores} = load_for_ca(effective_ca_id, opts)

    key_managers = load_key_managers(opts)
    auditors = load_auditors(opts)

    {:noreply,
     assign(socket,
       ceremonies: ceremonies,
       keystores: keystores,
       ca_instances: ca_instances,
       effective_ca_id: effective_ca_id,
       selected_ca_id: effective_ca_id || "",
       key_managers: key_managers,
       auditors: auditors,
       loading: false
     )}
  end

  def handle_info(:wipe_private_key, socket) do
    # Safety net: discard private key if still held after error timeout
    if socket.assigns.private_key do
      {:noreply, assign(socket, private_key: nil, public_key: nil, wizard_error: "Private key discarded (timeout). Please restart the ceremony.")}
    else
      {:noreply, socket}
    end
  end

  # ---------------------------------------------------------------------------
  # PubSub handlers for progress dashboard
  # ---------------------------------------------------------------------------

  def handle_info({:custodian_ready, %{user_id: _uid, username: username} = details}, socket) do
    participants = update_participant_status(socket.assigns.participants, details[:user_id], "accepted")
    entry = %{timestamp: DateTime.utc_now(), message: "#{username} accepted their key share"}
    activity_log = [entry | socket.assigns.activity_log]
    {:noreply, assign(socket, participants: participants, activity_log: activity_log)}
  end

  def handle_info({:witness_attested, %{phase: phase} = details}, socket) do
    auditor_name = details[:auditor_name] || "Auditor"
    participants = update_participant_status(socket.assigns.participants, details[:auditor_id], "attested (#{phase})")
    entry = %{timestamp: DateTime.utc_now(), message: "#{auditor_name} attested to #{phase} phase"}
    activity_log = [entry | socket.assigns.activity_log]
    {:noreply, assign(socket, participants: participants, activity_log: activity_log)}
  end

  def handle_info({:phase_changed, %{phase: phase}}, socket) do
    entry = %{timestamp: DateTime.utc_now(), message: "Ceremony phase changed to: #{phase}"}
    activity_log = [entry | socket.assigns.activity_log]
    {:noreply, assign(socket, activity_log: activity_log)}
  end

  def handle_info({:ceremony_failed, %{reason: reason}}, socket) do
    entry = %{timestamp: DateTime.utc_now(), message: "Ceremony failed: #{reason}"}
    activity_log = [entry | socket.assigns.activity_log]
    opts = tenant_opts(socket)
    {ceremonies, _} = load_for_ca(socket.assigns.effective_ca_id, opts)

    {:noreply,
     socket
     |> assign(activity_log: activity_log, ceremonies: ceremonies)
     |> put_flash(:error, "Ceremony failed: #{reason}")}
  end

  def handle_info({:ceremony_completed, _details}, socket) do
    entry = %{timestamp: DateTime.utc_now(), message: "Ceremony completed successfully"}
    activity_log = [entry | socket.assigns.activity_log]
    opts = tenant_opts(socket)
    {ceremonies, _} = load_for_ca(socket.assigns.effective_ca_id, opts)

    {:noreply,
     socket
     |> assign(
       activity_log: activity_log,
       ceremonies: ceremonies,
       wizard_step: :done
     )
     |> put_flash(:info, "Ceremony completed successfully.")}
  end

  # ---------------------------------------------------------------------------
  # List view events
  # ---------------------------------------------------------------------------

  @impl true
  def handle_event("select_ca_instance", %{"ca_instance_id" => ca_instance_id}, socket) do
    ca_id = if ca_instance_id == "", do: nil, else: ca_instance_id
    {ceremonies, keystores} = load_for_ca(ca_id, tenant_opts(socket))

    {:noreply,
     assign(socket,
       ceremonies: ceremonies,
       keystores: keystores,
       effective_ca_id: ca_id,
       selected_ca_id: ca_instance_id,
       page: 1
     )}
  end

  def handle_event("change_page", %{"page" => page}, socket) do
    {:noreply, assign(socket, page: parse_int(page) || 1)}
  end

  def handle_event("cancel_ceremony_record", %{"id" => ceremony_id}, socket) do
    opts = tenant_opts(socket)

    case CaEngineClient.cancel_ceremony(ceremony_id, opts) do
      {:ok, _} ->
        audit_log(socket, "ceremony_cancelled", "ceremony", ceremony_id)
        {ceremonies, _} = load_for_ca(socket.assigns.effective_ca_id, opts)
        {:noreply,
         socket
         |> assign(ceremonies: ceremonies)
         |> put_flash(:info, "Ceremony cancelled.")}

      {:error, reason} ->
        {:noreply, put_flash(socket, :error, "Cancel failed: #{format_error(reason)}")}
    end
  end

  def handle_event("delete_ceremony_record", %{"id" => ceremony_id}, socket) do
    opts = tenant_opts(socket)

    case CaEngineClient.delete_ceremony(ceremony_id, opts) do
      :ok ->
        audit_log(socket, "ceremony_deleted", "ceremony", ceremony_id)
        {ceremonies, _} = load_for_ca(socket.assigns.effective_ca_id, opts)
        {:noreply,
         socket
         |> assign(ceremonies: ceremonies)
         |> put_flash(:info, "Ceremony deleted.")}

      {:error, reason} ->
        {:noreply, put_flash(socket, :error, "Delete failed: #{format_error(reason)}")}
    end
  end

  def handle_event("start_wizard", _params, socket) do
    {:noreply,
     assign(socket,
       wizard_step: 1,
       active_ceremony: nil,
       private_key: nil,
       public_key: nil,
       public_key_fingerprint: nil,
       is_root: true,
       subject_dn: "",
       custodians: [],
       custodian_passwords: [],
       csr_pem: nil,
       wizard_error: nil,
       wizard_busy: false,
       participants: [],
       activity_log: []
     )}
  end

  def handle_event("cancel_wizard", _params, socket) do
    {:noreply,
     assign(socket,
       wizard_step: nil,
       active_ceremony: nil,
       private_key: nil,
       public_key: nil,
       public_key_fingerprint: nil,
       csr_pem: nil,
       wizard_error: nil,
       wizard_busy: false,
       participants: [],
       activity_log: []
     )}
  end

  # Resume ceremony — show progress dashboard for in-progress ceremonies
  def handle_event("resume_ceremony", %{"id" => ceremony_id}, socket) do
    opts = tenant_opts(socket)

    case CaEngineClient.get_ceremony(ceremony_id, opts) do
      {:ok, ceremony} ->
        if ceremony[:status] in ["initiated", "in_progress"] do
          # Subscribe to PubSub for live updates
          Phoenix.PubSub.subscribe(PkiCaPortal.PubSub, "ceremony:#{ceremony_id}")

          domain_info = ceremony[:domain_info] || %{}
          participants = build_participants_from_ceremony(ceremony)

          {:noreply,
           assign(socket,
             wizard_step: :progress,
             active_ceremony: ceremony,
             is_root: Map.get(domain_info, "is_root", true),
             participants: participants,
             activity_log: [%{timestamp: DateTime.utc_now(), message: "Resumed monitoring ceremony"}],
             wizard_error: nil,
             wizard_busy: false
           )}
        else
          {:noreply, put_flash(socket, :info, "Ceremony already completed.")}
        end

      {:error, _} ->
        {:noreply, put_flash(socket, :error, "Ceremony not found.")}
    end
  end

  # ---------------------------------------------------------------------------
  # Step 1: Initiate witnessed ceremony
  # ---------------------------------------------------------------------------

  def handle_event("initiate_ceremony", params, socket) do
    ca_id = params["ca_instance_id"]
    opts = tenant_opts(socket)

    selected_custodian_ids = parse_multi_select(params["custodian_ids"])
    auditor_user_id = params["auditor_user_id"]
    time_window_hours = parse_int(params["time_window_hours"]) || 24

    cond do
      is_nil(ca_id) or ca_id == "" ->
        {:noreply, assign(socket, wizard_error: "Please select a CA Instance.")}

      is_nil(params["keystore_id"]) or params["keystore_id"] == "" ->
        {:noreply, assign(socket, wizard_error: "Please select a Keystore.")}

      Enum.empty?(selected_custodian_ids) ->
        {:noreply, assign(socket, wizard_error: "Please select at least one key manager as custodian.")}

      is_nil(auditor_user_id) or auditor_user_id == "" ->
        {:noreply, assign(socket, wizard_error: "Please select an auditor witness.")}

      true ->
        # Rate limit ceremony creation: 10 per hour per tenant
        tenant_id = socket.assigns[:tenant_id] || "global"
        rate_key = "ceremony_initiate:#{tenant_id}"

        case Hammer.check_rate(rate_key, 60 * 60 * 1000, 10) do
          {:deny, _} ->
            {:noreply, assign(socket, wizard_error: "Too many ceremonies initiated. Please wait before creating another.")}

          {:error, reason} ->
            require Logger
            Logger.error("[rate_limit] Hammer error for #{rate_key}: #{inspect(reason)}")
            {:noreply, assign(socket, wizard_error: "Service temporarily unavailable. Please try again.")}

          {:allow, _} ->
            is_root = params["is_root"] == "true"

            ceremony_params = %{
              algorithm: params["algorithm"],
              keystore_id: params["keystore_id"],
              threshold_k: params["threshold_k"],
              threshold_n: params["threshold_n"],
              domain_info: %{"is_root" => is_root},
              initiated_by: socket.assigns.current_user[:id],
              is_root: is_root,
              key_alias: params["key_alias"],
              custodian_user_ids: selected_custodian_ids,
              auditor_user_id: auditor_user_id,
              time_window_hours: time_window_hours
            }

            case CaEngineClient.initiate_witnessed_ceremony(ca_id, ceremony_params, opts) do
              {:ok, ceremony} ->
                audit_log(socket, "ceremony_initiated", "ceremony", ceremony[:id], %{
                  algorithm: params["algorithm"],
                  ca_instance_id: ca_id,
                  is_root: is_root,
                  key_alias: params["key_alias"],
                  custodian_count: length(selected_custodian_ids),
                  auditor_user_id: auditor_user_id,
                  time_window_hours: time_window_hours
                })

                # Send notifications to participants
                PkiCaPortal.CeremonyNotifications.notify_ceremony_initiated(ceremony, %{
                  custodian_user_ids: selected_custodian_ids,
                  auditor_user_id: auditor_user_id
                })

                # Subscribe to PubSub for live updates
                Phoenix.PubSub.subscribe(PkiCaPortal.PubSub, "ceremony:#{ceremony[:id]}")

                {ceremonies, keystores} = load_for_ca(ca_id, opts)
                participants = build_participants_from_selections(selected_custodian_ids, auditor_user_id, socket.assigns)

                {:noreply,
                 socket
                 |> assign(
                   ceremonies: ceremonies,
                   keystores: keystores,
                   effective_ca_id: ca_id,
                   active_ceremony: ceremony,
                   is_root: is_root,
                   wizard_step: :progress,
                   wizard_error: nil,
                   participants: participants,
                   activity_log: [%{timestamp: DateTime.utc_now(), message: "Ceremony initiated — waiting for participants"}]
                 )}

              {:error, reason} ->
                {:noreply, assign(socket, wizard_error: "Failed to initiate: #{format_error(reason)}")}
            end
        end
    end
  end

  # ---------------------------------------------------------------------------
  # Progress dashboard events
  # ---------------------------------------------------------------------------

  def handle_event("cancel_active_ceremony", _params, socket) do
    ceremony = socket.assigns.active_ceremony

    if ceremony do
      CaEngineClient.fail_ceremony(ceremony[:id], "cancelled_by_admin")
      audit_log(socket, "ceremony_cancelled", "ceremony", ceremony[:id])
    end

    opts = tenant_opts(socket)
    {ceremonies, _} = load_for_ca(socket.assigns.effective_ca_id, opts)

    {:noreply,
     socket
     |> assign(
       wizard_step: nil,
       active_ceremony: nil,
       participants: [],
       activity_log: [],
       ceremonies: ceremonies
     )
     |> put_flash(:info, "Ceremony cancelled.")}
  end

  def handle_event("finish_wizard", _params, socket) do
    {:noreply,
     assign(socket,
       wizard_step: nil,
       active_ceremony: nil,
       private_key: nil,
       public_key: nil,
       public_key_fingerprint: nil,
       csr_pem: nil,
       wizard_error: nil,
       wizard_busy: false,
       participants: [],
       activity_log: []
     )}
  end

  # ---------------------------------------------------------------------------
  # Private helpers
  # ---------------------------------------------------------------------------

  defp load_key_managers(opts) do
    case CaEngineClient.list_portal_users(opts) do
      {:ok, users} ->
        users
        |> Enum.filter(fn u -> u[:role] == "key_manager" and u[:status] == "active" end)
        |> Enum.map(fn u -> %{id: u[:id], username: u[:username], display_name: u[:display_name]} end)

      {:error, _} -> []
    end
  end

  defp load_auditors(opts) do
    case CaEngineClient.list_portal_users(opts) do
      {:ok, users} ->
        users
        |> Enum.filter(fn u -> u[:role] == "auditor" and u[:status] == "active" end)
        |> Enum.map(fn u -> %{id: u[:id], username: u[:username], display_name: u[:display_name]} end)

      {:error, _} -> []
    end
  end

  defp build_participants_from_selections(custodian_ids, auditor_id, assigns) do
    custodian_participants =
      Enum.map(custodian_ids, fn uid ->
        km = Enum.find(assigns.key_managers, &(&1.id == uid))
        %{
          user_id: uid,
          name: if(km, do: km.display_name || km.username, else: uid),
          role: "key_manager",
          status: "pending",
          timestamp: nil
        }
      end)

    auditor_participant =
      case Enum.find(assigns.auditors, &(&1.id == auditor_id)) do
        nil ->
          %{user_id: auditor_id, name: auditor_id, role: "auditor", status: "waiting", timestamp: nil}
        aud ->
          %{user_id: auditor_id, name: aud.display_name || aud.username, role: "auditor", status: "waiting", timestamp: nil}
      end

    custodian_participants ++ [auditor_participant]
  end

  defp build_participants_from_ceremony(ceremony) do
    # Build participant list from ceremony data (shares + attestations)
    custodians =
      (ceremony[:shares] || [])
      |> Enum.map(fn share ->
        %{
          user_id: share[:user_id],
          name: share[:username] || share[:user_id] || "Unknown",
          role: "key_manager",
          status: if(share[:status] == "accepted", do: "accepted", else: "pending"),
          timestamp: share[:updated_at]
        }
      end)

    auditor =
      if ceremony[:auditor_user_id] do
        %{
          user_id: ceremony[:auditor_user_id],
          name: ceremony[:auditor_username] || ceremony[:auditor_user_id],
          role: "auditor",
          status: "waiting",
          timestamp: nil
        }
      end

    if auditor, do: custodians ++ [auditor], else: custodians
  end

  defp update_participant_status(participants, user_id, new_status) do
    Enum.map(participants, fn p ->
      if p.user_id == user_id do
        %{p | status: new_status, timestamp: DateTime.utc_now()}
      else
        p
      end
    end)
  end

  defp parse_multi_select(nil), do: []
  defp parse_multi_select(val) when is_binary(val), do: [val]
  defp parse_multi_select(val) when is_list(val), do: Enum.filter(val, &(&1 != ""))

  defp load_for_ca(nil, _opts), do: {[], []}
  defp load_for_ca(ca_id, opts) do
    ceremonies = case CaEngineClient.list_ceremonies(ca_id, opts) do
      {:ok, c} -> c
      {:error, _} -> []
    end
    keystores = case CaEngineClient.list_keystores(ca_id, opts) do
      {:ok, ks} -> ks
      {:error, _} -> []
    end
    {ceremonies, keystores}
  end

  defp tenant_opts(socket) do
    case socket.assigns[:tenant_id] do
      nil -> []
      tid -> [tenant_id: tid]
    end
  end

  defp keystore_display(ks) do
    config = if ks[:config], do: PkiCaEngine.Schema.Keystore.decode_config(ks.config), else: nil
    label = if config, do: config["label"], else: nil

    case {ks.type, label} do
      {"hsm", l} when is_binary(l) -> "HSM — #{l}"
      {"hsm", _} -> "HSM"
      {"software", _} -> "Software"
      {type, _} -> type
    end
  end

  defp format_error({:validation_error, errors}) when is_map(errors) do
    errors
    |> Enum.map(fn {k, v} -> "#{k}: #{inspect(v)}" end)
    |> Enum.join(", ")
  end
  defp format_error(reason), do: inspect(reason)

  defp parse_int(v) when is_integer(v), do: v
  defp parse_int(v) when is_binary(v) do
    case Integer.parse(v) do
      {n, _} -> n
      :error -> nil
    end
  end
  defp parse_int(_), do: nil

  defp format_datetime(nil), do: "-"
  defp format_datetime(%NaiveDateTime{} = dt) do
    Calendar.strftime(dt, "%d %b %Y, %H:%M")
  end
  defp format_datetime(%DateTime{} = dt) do
    Calendar.strftime(dt, "%d %b %Y, %H:%M")
  end
  defp format_datetime(%{year: _, month: _, day: _, hour: _, minute: _} = dt) do
    Calendar.strftime(dt, "%d %b %Y, %H:%M")
  end
  defp format_datetime(_), do: "-"

  defp status_badge_class("initiated"), do: "badge-warning"
  defp status_badge_class("in_progress"), do: "badge-info"
  defp status_badge_class("completed"), do: "badge-success"
  defp status_badge_class("failed"), do: "badge-error"
  defp status_badge_class(_), do: "badge-ghost"

  defp ceremony_resumable?(ceremony) do
    ceremony[:status] in ["initiated", "in_progress"]
  end

  defp participant_role_class("key_manager"), do: "badge-info"
  defp participant_role_class("auditor"), do: "badge-accent"
  defp participant_role_class(_), do: "badge-ghost"

  defp participant_status_class("accepted"), do: "badge-success"
  defp participant_status_class("pending"), do: "badge-warning"
  defp participant_status_class("waiting"), do: "badge-ghost"
  defp participant_status_class("attested" <> _), do: "badge-success"
  defp participant_status_class(_), do: "badge-ghost"

  defp format_role("key_manager"), do: "Key Manager"
  defp format_role("auditor"), do: "Auditor"
  defp format_role(role), do: role

  # ---------------------------------------------------------------------------
  # Render
  # ---------------------------------------------------------------------------

  @impl true
  def render(assigns) do
    ~H"""
    <div id="ceremony-page" class="space-y-6">
      <%!-- Wizard overlay --%>
      <%= if @wizard_step do %>
        {render_wizard(assigns)}
      <% else %>
        {render_list_view(assigns)}
      <% end %>
    </div>
    """
  end

  defp render_list_view(assigns) do
    ~H"""
    <%!-- Server-side HSM disclaimer --%>
    <div class="alert border border-info/30 bg-info/5">
      <.icon name="hero-information-circle" class="size-5 text-info shrink-0" />
      <div>
        <p class="text-sm font-medium text-base-content">Server-Side HSM Only</p>
        <p class="text-xs text-base-content/60 mt-0.5">
          Key ceremonies use server-side HSM devices managed by the platform. Keys are generated and stored on the server's HSM hardware via PKCS#11.
          Client-side HSM (e.g., USB tokens on your laptop) is not supported in this version.
        </p>
      </div>
    </div>

    <%!-- CA Instance selector + New Ceremony button --%>
    <div class="flex items-center justify-between">
      <div class="flex items-center gap-3">
        <label class="text-xs font-medium text-base-content/60">CA Instance</label>
        <form phx-change="select_ca_instance">
          <select name="ca_instance_id" class="select select-bordered select-sm">
            <option value="">Select CA Instance</option>
            <option
              :for={inst <- @ca_instances}
              value={inst.id}
              selected={@selected_ca_id == inst.id}
            >
              {inst.name}
            </option>
          </select>
        </form>
      </div>
      <button
        :if={@effective_ca_id && not Enum.empty?(@keystores)}
        phx-click="start_wizard"
        class="btn btn-primary btn-sm"
      >
        <.icon name="hero-shield-check" class="size-4" />
        New Key Ceremony
      </button>
    </div>

    <%!-- No CA instance selected --%>
    <div :if={is_nil(@effective_ca_id) and not @loading} class="card bg-base-100 shadow-sm border border-base-300">
      <div class="card-body text-center py-8 text-base-content/50 text-sm">
        Select a CA instance above to view ceremonies and initiate new ones.
      </div>
    </div>

    <%!-- No keystores warning --%>
    <div :if={@effective_ca_id && Enum.empty?(@keystores)} class="alert alert-warning text-sm">
      <.icon name="hero-exclamation-triangle" class="size-4" />
      <span>No keystores configured for this CA instance. <a href="/keystores" class="link link-primary">Configure one first.</a></span>
    </div>

    <%!-- Ceremony history table --%>
    <div :if={@effective_ca_id} id="ceremony-table" class="card bg-base-100 shadow-sm border border-base-300">
      <div class="card-body p-0">
        <div class="px-5 py-4 border-b border-base-300">
          <h2 class="text-sm font-semibold text-base-content">Ceremony History</h2>
        </div>
        <% paginated = @ceremonies |> Enum.drop((@page - 1) * @per_page) |> Enum.take(@per_page) %>
        <% total = length(@ceremonies) %>
        <% total_pages = max(ceil(total / @per_page), 1) %>
        <div :if={Enum.empty?(@ceremonies)} class="p-8 text-center text-base-content/50 text-sm">
          No ceremonies yet for this CA instance.
        </div>
        <div :if={not Enum.empty?(@ceremonies)}>
          <table class="table table-sm w-full">
            <thead>
              <tr class="text-xs uppercase text-base-content/50">
                <th class="w-[100px]">ID</th>
                <th class="w-[80px]">Type</th>
                <th class="w-[120px]">Algorithm</th>
                <th class="w-[80px]">Status</th>
                <th class="w-[120px]">Created</th>
                <th class="w-[100px]"></th>
              </tr>
            </thead>
            <tbody>
              <tr :for={c <- paginated} class="hover">
                <td class="font-mono text-xs truncate max-w-[100px]">{String.slice(c[:id] || "", 0..7)}</td>
                <td class="text-sm">{c[:ceremony_type]}</td>
                <td class="font-mono text-sm truncate max-w-[120px]">{c[:algorithm]}</td>
                <td>
                  <span class={"badge badge-sm #{status_badge_class(c[:status])}"}>{c[:status]}</span>
                </td>
                <td class="text-xs text-base-content/60">{format_datetime(c[:inserted_at])}</td>
                <td class="flex items-center gap-1">
                  <button
                    :if={ceremony_resumable?(c)}
                    phx-click="resume_ceremony"
                    phx-value-id={c[:id]}
                    class="btn btn-ghost btn-xs"
                  >
                    Resume
                  </button>
                  <button
                    :if={c[:status] in ["initiated", "in_progress"]}
                    phx-click="cancel_ceremony_record"
                    phx-value-id={c[:id]}
                    data-confirm="Cancel this ceremony? The pending issuer key will be removed."
                    class="btn btn-ghost btn-xs text-warning"
                  >
                    Cancel
                  </button>
                  <button
                    :if={c[:status] in ["failed"]}
                    phx-click="delete_ceremony_record"
                    phx-value-id={c[:id]}
                    data-confirm="Permanently delete this ceremony record?"
                    class="btn btn-ghost btn-xs text-error"
                  >
                    Delete
                  </button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <div :if={total > @per_page} class="flex items-center justify-between px-5 py-3 border-t border-base-300 text-sm">
          <span class="text-base-content/60">
            Showing {min((@page - 1) * @per_page + 1, total)}–{min(@page * @per_page, total)} of {total}
          </span>
          <div class="join">
            <button class="join-item btn btn-sm" phx-click="change_page" phx-value-page={@page - 1} disabled={@page == 1}>«</button>
            <button class="join-item btn btn-sm btn-active">{@page}</button>
            <button class="join-item btn btn-sm" phx-click="change_page" phx-value-page={@page + 1} disabled={@page >= total_pages}>»</button>
          </div>
        </div>
      </div>
    </div>
    """
  end

  # ---------------------------------------------------------------------------
  # Wizard renderer
  # ---------------------------------------------------------------------------

  defp render_wizard(assigns) do
    ~H"""
    <div id="ceremony-wizard">
      <%!-- Step indicator --%>
      <ul class="steps steps-horizontal w-full mb-8">
        <li class={"step #{if @wizard_step in [:progress, :done] or @wizard_step == 1, do: "step-primary"}"}>
          <span class="text-xs">Initiate</span>
        </li>
        <li class={"step #{if @wizard_step in [:progress, :done], do: "step-primary"}"}>
          <span class="text-xs">In Progress</span>
        </li>
        <li class={"step #{if @wizard_step == :done, do: "step-primary"}"}>
          <span class="text-xs">Complete</span>
        </li>
      </ul>

      <%!-- Error banner --%>
      <div :if={@wizard_error} class="alert alert-error mb-4 text-sm">
        <.icon name="hero-exclamation-circle" class="size-4" />
        <span>{@wizard_error}</span>
      </div>

      <%!-- Step content --%>
      <%= case @wizard_step do %>
        <% 1 -> %>
          {render_step_initiate(assigns)}
        <% :progress -> %>
          {render_progress_dashboard(assigns)}
        <% :done -> %>
          {render_step_done(assigns)}
        <% _ -> %>
          <div></div>
      <% end %>

      <%!-- Cancel button (only on step 1) --%>
      <div :if={@wizard_step == 1} class="mt-6 flex justify-end">
        <button phx-click="cancel_wizard" class="btn btn-ghost btn-sm">Cancel</button>
      </div>
    </div>
    """
  end

  # Step 1: Initiate
  defp render_step_initiate(assigns) do
    ~H"""
    <div class="card bg-base-100 shadow-sm border border-base-300">
      <div class="card-body">
        <h2 class="text-sm font-semibold text-base-content mb-4">
          <.icon name="hero-shield-check" class="size-4 inline" /> Step 1 — Initiate Witnessed Key Ceremony
        </h2>

        <form phx-submit="initiate_ceremony" class="space-y-4">
          <input type="hidden" name="ca_instance_id" value={@effective_ca_id} />

          <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label class="block text-xs font-medium text-base-content/60 mb-1">Algorithm</label>
              <select name="algorithm" class="select select-bordered select-sm w-full">
                <%= for {algo, desc} <- @algorithms do %>
                  <option value={algo}>{algo} — {desc}</option>
                <% end %>
              </select>
            </div>
            <div>
              <label class="block text-xs font-medium text-base-content/60 mb-1">Keystore</label>
              <select name="keystore_id" class="select select-bordered select-sm w-full" required>
                <option value="" disabled selected>Select Keystore</option>
                <option :for={ks <- @keystores} value={ks.id}>{keystore_display(ks)}</option>
              </select>
            </div>
            <div>
              <label class="block text-xs font-medium text-base-content/60 mb-1">Key Alias</label>
              <input type="text" name="key_alias" placeholder="e.g. root-key-2026" class="input input-bordered input-sm w-full" />
            </div>
            <div>
              <label class="block text-xs font-medium text-base-content/60 mb-1">Certificate Type</label>
              <select name="is_root" class="select select-bordered select-sm w-full">
                <option value="true" selected={@is_root}>Root CA (self-signed)</option>
                <option value="false" selected={not @is_root}>Sub-CA (generates CSR)</option>
              </select>
            </div>
            <div>
              <label class="block text-xs font-medium text-base-content/60 mb-1">Threshold K (min. to reconstruct)</label>
              <input type="number" name="threshold_k" min="2" value="2" class="input input-bordered input-sm w-full" />
            </div>
            <div>
              <label class="block text-xs font-medium text-base-content/60 mb-1">Threshold N (total key custodians)</label>
              <input type="number" name="threshold_n" min="2" value="3" class="input input-bordered input-sm w-full" />
            </div>
          </div>

          <%!-- Participant assignment section --%>
          <div class="divider text-xs text-base-content/40">Participant Assignment</div>

          <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label class="block text-xs font-medium text-base-content/60 mb-1">
                Key Manager Custodians
                <span class="text-base-content/40">(hold Ctrl/Cmd to multi-select)</span>
              </label>
              <select name="custodian_ids[]" multiple class="select select-bordered select-sm w-full h-32" required>
                <option
                  :for={km <- @key_managers}
                  value={km.id}
                >
                  {km.display_name || km.username}
                </option>
              </select>
              <p :if={Enum.empty?(@key_managers)} class="text-xs text-warning mt-1">
                No active key managers found. <a href="/users" class="link link-primary">Add key manager users first.</a>
              </p>
            </div>
            <div class="space-y-4">
              <div>
                <label class="block text-xs font-medium text-base-content/60 mb-1">Auditor Witness</label>
                <select name="auditor_user_id" class="select select-bordered select-sm w-full" required>
                  <option value="" disabled selected>Select Auditor</option>
                  <option
                    :for={aud <- @auditors}
                    value={aud.id}
                  >
                    {aud.display_name || aud.username}
                  </option>
                </select>
                <p :if={Enum.empty?(@auditors)} class="text-xs text-warning mt-1">
                  No active auditors found. <a href="/users" class="link link-primary">Add auditor users first.</a>
                </p>
              </div>
              <div>
                <label class="block text-xs font-medium text-base-content/60 mb-1">Time Window</label>
                <select name="time_window_hours" class="select select-bordered select-sm w-full">
                  <%= for {hours, label} <- @time_window_options do %>
                    <option value={hours} selected={hours == 24}>{label}</option>
                  <% end %>
                </select>
                <p class="text-xs text-base-content/40 mt-1">
                  All participants must complete their actions within this window.
                </p>
              </div>
            </div>
          </div>

          <div class="pt-2">
            <button type="submit" class="btn btn-primary btn-sm">
              <.icon name="hero-arrow-right" class="size-4" />
              Initiate Ceremony
            </button>
          </div>
        </form>
      </div>
    </div>
    """
  end

  # Progress Dashboard
  defp render_progress_dashboard(assigns) do
    ~H"""
    <div class="space-y-4">
      <%!-- Ceremony details card --%>
      <div class="card bg-base-100 shadow-sm border border-base-300">
        <div class="card-body">
          <h2 class="text-sm font-semibold text-base-content mb-4">
            <.icon name="hero-signal" class="size-4 inline" /> Ceremony Progress
          </h2>

          <div class="bg-base-200/50 rounded-lg p-4 text-sm space-y-1">
            <div class="flex gap-2">
              <span class="text-base-content/50 w-28">Ceremony ID:</span>
              <span class="font-mono">{String.slice(@active_ceremony[:id] || "", 0..7)}</span>
            </div>
            <div class="flex gap-2">
              <span class="text-base-content/50 w-28">Algorithm:</span>
              <span class="font-mono font-semibold">{@active_ceremony[:algorithm]}</span>
            </div>
            <div class="flex gap-2">
              <span class="text-base-content/50 w-28">Threshold:</span>
              <span>{@active_ceremony[:threshold_k]}-of-{@active_ceremony[:threshold_n]}</span>
            </div>
            <div class="flex gap-2">
              <span class="text-base-content/50 w-28">Type:</span>
              <span><%= if @is_root, do: "Root CA (self-signed)", else: "Sub-CA (CSR)" %></span>
            </div>
            <div class="flex gap-2">
              <span class="text-base-content/50 w-28">Status:</span>
              <span class={"badge badge-sm #{status_badge_class(@active_ceremony[:status])}"}>{@active_ceremony[:status]}</span>
            </div>
          </div>
        </div>
      </div>

      <%!-- Participant status table --%>
      <div class="card bg-base-100 shadow-sm border border-base-300">
        <div class="card-body">
          <h3 class="text-sm font-semibold text-base-content mb-3">
            <.icon name="hero-user-group" class="size-4 inline" /> Participants
          </h3>

          <div>
            <table class="table table-sm w-full">
              <thead>
                <tr class="text-xs uppercase text-base-content/50">
                  <th class="w-1/5">Participant</th>
                  <th class="w-[80px]">Role</th>
                  <th class="w-[80px]">Status</th>
                  <th class="w-[120px]">Timestamp</th>
                </tr>
              </thead>
              <tbody>
                <tr :for={p <- @participants} class="hover">
                  <td class="text-sm font-medium truncate max-w-[150px]">{p.name}</td>
                  <td>
                    <span class={"badge badge-sm #{participant_role_class(p.role)}"}>{format_role(p.role)}</span>
                  </td>
                  <td>
                    <span class={"badge badge-sm #{participant_status_class(p.status)}"}>{p.status}</span>
                  </td>
                  <td class="text-xs text-base-content/60">
                    <%= if p.timestamp do %>
                      {Calendar.strftime(p.timestamp, "%H:%M:%S")}
                    <% else %>
                      —
                    <% end %>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>

          <div :if={Enum.empty?(@participants)} class="text-sm text-base-content/50 text-center py-4">
            No participants assigned yet.
          </div>
        </div>
      </div>

      <%!-- Activity log --%>
      <div class="card bg-base-100 shadow-sm border border-base-300">
        <div class="card-body">
          <h3 class="text-sm font-semibold text-base-content mb-3">
            <.icon name="hero-clock" class="size-4 inline" /> Activity Log
          </h3>

          <div :if={Enum.empty?(@activity_log)} class="text-sm text-base-content/50 text-center py-4">
            No activity yet.
          </div>

          <div :if={not Enum.empty?(@activity_log)} class="space-y-2 max-h-64 overflow-y-auto">
            <div :for={entry <- @activity_log} class="flex items-start gap-3 text-sm">
              <span class="text-xs text-base-content/40 font-mono shrink-0 mt-0.5">
                {Calendar.strftime(entry.timestamp, "%H:%M:%S")}
              </span>
              <span class="text-base-content/70">{entry.message}</span>
            </div>
          </div>
        </div>
      </div>

      <%!-- Cancel button --%>
      <div class="flex justify-between items-center">
        <button phx-click="finish_wizard" class="btn btn-ghost btn-sm">
          <.icon name="hero-arrow-left" class="size-4" /> Back to List
        </button>
        <button
          phx-click="cancel_active_ceremony"
          data-confirm="Cancel this ceremony? All pending work will be lost."
          class="btn btn-error btn-sm btn-outline"
        >
          <.icon name="hero-x-circle" class="size-4" /> Cancel Ceremony
        </button>
      </div>
    </div>
    """
  end

  # Done
  defp render_step_done(assigns) do
    ~H"""
    <div class="card bg-base-100 shadow-sm border border-base-300">
      <div class="card-body text-center py-10">
        <div class="flex items-center justify-center w-16 h-16 rounded-full bg-success/10 mx-auto mb-4">
          <.icon name="hero-check-badge" class="size-10 text-success" />
        </div>
        <h2 class="text-lg font-bold text-base-content mb-1">Ceremony Complete</h2>
        <p class="text-sm text-base-content/60 mb-4">
          Ceremony <span class="font-mono">{String.slice(@active_ceremony[:id] || "", 0..7)}</span> has been completed successfully.
        </p>

        <%!-- Participant summary --%>
        <div :if={not Enum.empty?(@participants)} class="mb-6 text-left max-w-xl mx-auto">
          <label class="block text-xs font-medium text-base-content/60 mb-2">Ceremony Participants</label>
          <div class="bg-base-200/50 rounded-lg p-3 space-y-1">
            <div :for={p <- @participants} class="flex gap-2 text-sm">
              <span class="text-base-content/50 w-24">{format_role(p.role)}:</span>
              <span class="font-medium">{p.name}</span>
              <span class={"badge badge-xs #{participant_status_class(p.status)} ml-auto"}>{p.status}</span>
            </div>
          </div>
        </div>

        <div class="alert border border-info/30 bg-info/5 text-left max-w-xl mx-auto mb-6">
          <.icon name="hero-information-circle" class="size-5 text-info shrink-0" />
          <div class="text-sm">
            <p>The private key has been securely handled by the ceremony orchestrator.</p>
            <p class="text-xs text-base-content/60">Only the encrypted Shamir shares remain in the database.</p>
          </div>
        </div>

        <button phx-click="finish_wizard" class="btn btn-primary btn-sm">
          <.icon name="hero-arrow-left" class="size-4" /> Back to Ceremony List
        </button>
      </div>
    </div>
    """
  end
end
