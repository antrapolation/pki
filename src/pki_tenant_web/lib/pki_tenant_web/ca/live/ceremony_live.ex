defmodule PkiTenantWeb.Ca.CeremonyLive do
  use PkiTenantWeb, :live_view

  require Logger

  alias PkiCaEngine.CaInstanceManagement
  alias PkiCaEngine.CeremonyOrchestrator
  alias PkiCaEngine.KeystoreManagement
  alias PkiMnesia.Repo
  alias PkiMnesia.Structs.{KeyCeremony, CeremonyParticipant, ThresholdShare}

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

  @impl true
  def mount(_params, _session, socket) do
    {:ok,
     assign(socket,
       page_title: "Key Ceremony",
       ceremonies: [],
       keystores: [],
       ca_instances: [],
       algorithms: @algorithms,
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
       csr_pem: nil,
       wizard_error: nil,
       wizard_busy: false,
       # Progress dashboard state
       participants: [],
       activity_log: []
     )}
  end

  @impl true
  def handle_params(params, _uri, socket) do
    if connected?(socket) do
      send(self(), {:load_data, params["ca"]})
    end

    {:noreply, socket}
  end

  @impl true
  def handle_info({:load_data, url_ca_id}, socket) do
    try do
      user_ca_id = socket.assigns.current_user[:ca_instance_id]

      ca_instances =
        case CaInstanceManagement.list_ca_instances() do
          {:ok, instances} -> instances
          _ -> []
        end

      # Priority: URL param > user's assigned CA > first available
      effective_ca_id =
        cond do
          url_ca_id && url_ca_id != "" -> url_ca_id
          user_ca_id -> user_ca_id
          true ->
            case ca_instances do
              [first | _] -> first.id
              [] -> nil
            end
        end

      {ceremonies, keystores} = load_for_ca(effective_ca_id)

      {:noreply,
       assign(socket,
         ceremonies: ceremonies,
         keystores: keystores,
         ca_instances: ca_instances,
         effective_ca_id: effective_ca_id,
         selected_ca_id: effective_ca_id || "",
         loading: false
       )}
    rescue
      e ->
        Logger.warning("[CeremonyLive] Failed to load data: #{Exception.message(e)}")
        {:noreply, assign(socket, loading: false)}
    end
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

  def handle_info({:custodian_ready, %{username: username}}, socket) do
    entry = %{timestamp: DateTime.utc_now(), message: "#{username} accepted their key share"}
    activity_log = [entry | socket.assigns.activity_log] |> Enum.take(50)

    # Refresh participants
    participants = if socket.assigns.active_ceremony do
      build_participants_from_ceremony(socket.assigns.active_ceremony)
    else
      socket.assigns.participants
    end

    {:noreply, assign(socket, participants: participants, activity_log: activity_log)}
  end

  def handle_info({:witness_attested, %{phase: phase} = details}, socket) do
    auditor_name = details[:auditor_name] || "Auditor"
    entry = %{timestamp: DateTime.utc_now(), message: "#{auditor_name} attested to #{phase} phase"}
    activity_log = [entry | socket.assigns.activity_log] |> Enum.take(50)
    {:noreply, assign(socket, activity_log: activity_log)}
  end

  def handle_info({:phase_changed, %{phase: phase}}, socket) do
    entry = %{timestamp: DateTime.utc_now(), message: "Ceremony phase changed to: #{phase}"}
    activity_log = [entry | socket.assigns.activity_log] |> Enum.take(50)
    {:noreply, assign(socket, activity_log: activity_log)}
  end

  def handle_info({:ceremony_failed, %{reason: reason}}, socket) do
    entry = %{timestamp: DateTime.utc_now(), message: "Ceremony failed: #{reason}"}
    activity_log = [entry | socket.assigns.activity_log] |> Enum.take(50)
    {ceremonies, _} = load_for_ca(socket.assigns.effective_ca_id)

    {:noreply,
     socket
     |> assign(activity_log: activity_log, ceremonies: ceremonies)
     |> put_flash(:error, "Ceremony failed: #{reason}")}
  end

  def handle_info({:ceremony_completed, _details}, socket) do
    entry = %{timestamp: DateTime.utc_now(), message: "Ceremony completed successfully"}
    activity_log = [entry | socket.assigns.activity_log] |> Enum.take(50)
    {ceremonies, _} = load_for_ca(socket.assigns.effective_ca_id)

    {:noreply,
     socket
     |> assign(
       activity_log: activity_log,
       ceremonies: ceremonies,
       wizard_step: :done
     )
     |> put_flash(:info, "Ceremony completed successfully.")}
  end

  def handle_info(_msg, socket), do: {:noreply, socket}

  # ---------------------------------------------------------------------------
  # List view events
  # ---------------------------------------------------------------------------

  @impl true
  def handle_event("select_ca_instance", %{"ca_instance_id" => ca_instance_id}, socket) do
    path = if ca_instance_id == "", do: "/ceremony", else: "/ceremony?ca=#{ca_instance_id}"
    {:noreply, push_patch(socket, to: path)}
  end

  def handle_event("change_page", %{"page" => page}, socket) do
    {:noreply, assign(socket, page: parse_int(page) || 1)}
  end

  def handle_event("cancel_ceremony_record", %{"id" => ceremony_id}, socket) do
    case CeremonyOrchestrator.fail_ceremony(ceremony_id, "cancelled_by_admin") do
      {:ok, _} ->
        PkiTenant.AuditBridge.log("ceremony_cancelled", %{ceremony_id: ceremony_id})
        {ceremonies, _} = load_for_ca(socket.assigns.effective_ca_id)
        {:noreply,
         socket
         |> assign(ceremonies: ceremonies)
         |> put_flash(:info, "Ceremony cancelled.")}

      {:error, reason} ->
        {:noreply, put_flash(socket, :error, "Cancel failed: #{format_error(reason)}")}
    end
  end

  def handle_event("delete_ceremony_record", %{"id" => ceremony_id}, socket) do
    case Repo.delete(KeyCeremony, ceremony_id) do
      {:ok, _} ->
        PkiTenant.AuditBridge.log("ceremony_deleted", %{ceremony_id: ceremony_id})
        {ceremonies, _} = load_for_ca(socket.assigns.effective_ca_id)
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

  # View ceremony — show progress dashboard for any ceremony (active or completed)
  def handle_event("view_ceremony", %{"id" => ceremony_id}, socket) do
    case Repo.get(KeyCeremony, ceremony_id) do
      {:ok, ceremony} when not is_nil(ceremony) ->
        if ceremony.status not in ["failed"] do
          Phoenix.PubSub.subscribe(PkiTenantWeb.PubSub, "ceremony:#{ceremony_id}")

          domain_info = ceremony.domain_info || %{}
          participants = build_participants_from_ceremony(ceremony)
          timeline = build_ceremony_timeline(ceremony)

          {:noreply,
           assign(socket,
             wizard_step: :progress,
             active_ceremony: ceremony,
             is_root: Map.get(domain_info, "is_root", true),
             participants: participants,
             activity_log: timeline,
             wizard_error: nil,
             wizard_busy: false
           )}
        else
          {:noreply, put_flash(socket, :error, "Cannot view a failed ceremony.")}
        end

      _ ->
        {:noreply, put_flash(socket, :error, "Ceremony not found.")}
    end
  end

  # Resume ceremony — show progress dashboard for in-progress ceremonies
  def handle_event("resume_ceremony", %{"id" => ceremony_id}, socket) do
    case Repo.get(KeyCeremony, ceremony_id) do
      {:ok, ceremony} when not is_nil(ceremony) ->
        if ceremony.status in ["initiated", "in_progress", "preparing"] do
          Phoenix.PubSub.subscribe(PkiTenantWeb.PubSub, "ceremony:#{ceremony_id}")

          domain_info = ceremony.domain_info || %{}
          participants = build_participants_from_ceremony(ceremony)
          timeline = build_ceremony_timeline(ceremony)

          {:noreply,
           assign(socket,
             wizard_step: :progress,
             active_ceremony: ceremony,
             is_root: Map.get(domain_info, "is_root", true),
             participants: participants,
             activity_log: timeline,
             wizard_error: nil,
             wizard_busy: false
           )}
        else
          {:noreply, put_flash(socket, :info, "Ceremony already completed.")}
        end

      _ ->
        {:noreply, put_flash(socket, :error, "Ceremony not found.")}
    end
  end

  # ---------------------------------------------------------------------------
  # Step 1: Initiate witnessed ceremony
  # ---------------------------------------------------------------------------

  def handle_event("initiate_ceremony", params, socket) do
    ca_id = params["ca_instance_id"]

    # Custodian names are free-form per-ceremony. Custodians are not portal
    # users — they sit down at the ceremony, enter their name and a
    # per-ceremony password in the custodian-entry step. We just need the
    # list of names at initiation time so Mnesia can create placeholder
    # ThresholdShare records keyed by custodian_name.
    custodian_names = parse_custodian_names(params["custodian_names"])
    auditor_name = String.trim(params["auditor_name"] || "")
    threshold_n = parse_int(params["threshold_n"]) || 3

    cond do
      is_nil(ca_id) or ca_id == "" ->
        {:noreply, assign(socket, wizard_error: "Please select a CA Instance.")}

      is_nil(params["keystore_id"]) or params["keystore_id"] == "" ->
        {:noreply, assign(socket, wizard_error: "Please select a Keystore.")}

      Enum.empty?(custodian_names) ->
        {:noreply, assign(socket, wizard_error: "Enter at least one custodian name.")}

      length(custodian_names) != length(Enum.uniq(custodian_names)) ->
        {:noreply, assign(socket, wizard_error: "Custodian names must be unique within a ceremony.")}

      length(custodian_names) != threshold_n ->
        {:noreply,
         assign(socket,
           wizard_error:
             "You entered #{length(custodian_names)} custodian name(s) but threshold N is #{threshold_n}. Names and N must match."
         )}

      auditor_name == "" ->
        {:noreply, assign(socket, wizard_error: "Enter the external auditor's name.")}

      true ->
        # Rate limit ceremony creation: 10 per hour per tenant
        tenant_id = socket.assigns[:tenant_id] || "global"
        rate_key = "ceremony_initiate:#{tenant_id}"

        case Hammer.check_rate(rate_key, 60 * 60 * 1000, 10) do
          {:deny, _} ->
            {:noreply, assign(socket, wizard_error: "Too many ceremonies initiated. Please wait before creating another.")}

          {:error, reason} ->
            Logger.error("[rate_limit] Hammer error for #{rate_key}: #{inspect(reason)}")
            {:noreply, assign(socket, wizard_error: "Service temporarily unavailable. Please try again.")}

          {:allow, _} ->
            is_root = params["is_root"] == "true"
            initiated_by = socket.assigns.current_user[:username] || socket.assigns.current_user[:display_name] || "unknown"

            ceremony_params = %{
              algorithm: params["algorithm"],
              keystore_id: params["keystore_id"],
              threshold_k: parse_int(params["threshold_k"]) || 2,
              threshold_n: threshold_n,
              is_root: is_root,
              key_alias: params["key_alias"],
              custodian_names: custodian_names,
              auditor_name: auditor_name,
              ceremony_mode: :full,
              initiated_by: initiated_by,
              subject_dn: params["subject_dn"]
            }

            case CeremonyOrchestrator.initiate(ca_id, ceremony_params) do
              {:ok, {ceremony, _key, _shares, participants_list, _transcript}} ->
                PkiTenant.AuditBridge.log("ceremony_initiated", %{
                  ceremony_id: ceremony.id,
                  algorithm: params["algorithm"],
                  ca_instance_id: ca_id,
                  is_root: is_root,
                  key_alias: params["key_alias"],
                  custodian_count: length(custodian_names),
                  auditor_name: auditor_name
                })

                # Subscribe to PubSub for live updates
                Phoenix.PubSub.subscribe(PkiTenantWeb.PubSub, "ceremony:#{ceremony.id}")

                {ceremonies, keystores} = load_for_ca(ca_id)

                participants = Enum.map(participants_list, fn p ->
                  %{
                    name: p.name,
                    role: to_string(p.role),
                    status: if(p.role == :auditor, do: "waiting", else: "pending"),
                    timestamp: nil
                  }
                end)

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
      CeremonyOrchestrator.fail_ceremony(ceremony.id, "cancelled_by_admin")
      PkiTenant.AuditBridge.log("ceremony_cancelled", %{ceremony_id: ceremony.id})
    end

    {ceremonies, _} = load_for_ca(socket.assigns.effective_ca_id)

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

  # Free-form custodian names: one per line or comma-separated in a textarea.
  # Trim whitespace, drop empty entries, cap name length at 128 chars.
  defp parse_custodian_names(nil), do: []

  defp parse_custodian_names(raw) when is_binary(raw) do
    raw
    |> String.split(~r/[\n,]/, trim: true)
    |> Enum.map(&String.trim/1)
    |> Enum.reject(&(&1 == ""))
    |> Enum.map(&String.slice(&1, 0, 128))
  end

  defp parse_custodian_names(_), do: []

  defp build_participants_from_ceremony(ceremony) do
    # Build participant list from CeremonyParticipant records
    participants = case Repo.get_all_by_index(CeremonyParticipant, :ceremony_id, ceremony.id) do
      {:ok, parts} -> parts
      _ -> []
    end

    shares = case Repo.get_all_by_index(ThresholdShare, :issuer_key_id, ceremony.issuer_key_id) do
      {:ok, s} -> s
      _ -> []
    end

    Enum.map(participants, fn p ->
      share = Enum.find(shares, fn s -> s.custodian_name == p.name end)
      share_status = if share, do: share.status, else: "pending"

      status = cond do
        p.role == :auditor -> if(p.identity_verified_at, do: "witnessed", else: "waiting")
        share_status == "accepted" -> "accepted"
        true -> "pending"
      end

      %{
        name: p.name,
        role: to_string(p.role),
        status: status,
        timestamp: p.identity_verified_at || (share && share.updated_at)
      }
    end)
  rescue
    _ -> []
  end

  defp build_ceremony_timeline(ceremony) do
    shares = case Repo.get_all_by_index(ThresholdShare, :issuer_key_id, ceremony.issuer_key_id) do
      {:ok, s} -> s
      _ -> []
    end

    initiated = [%{timestamp: ceremony.inserted_at, message: "Ceremony initiated — #{ceremony.algorithm}, #{ceremony.threshold_k}-of-#{ceremony.threshold_n} threshold"}]

    assigned = Enum.map(shares, fn s ->
      %{timestamp: s.inserted_at, message: "Share ##{s.share_index} assigned to #{s.custodian_name}"}
    end)

    accepted = shares
    |> Enum.filter(fn s -> s.status == "accepted" and s.updated_at end)
    |> Enum.map(fn s ->
      %{timestamp: s.updated_at, message: "#{s.custodian_name} accepted share ##{s.share_index}"}
    end)

    completed = if ceremony.status == "completed" do
      [%{timestamp: ceremony.updated_at, message: "Ceremony completed successfully"}]
    else
      []
    end

    (initiated ++ assigned ++ accepted ++ completed)
    |> Enum.filter(fn e -> e.timestamp != nil end)
    |> Enum.sort_by(fn e -> to_sortable_time(e.timestamp) end)
  rescue
    _ -> []
  end

  defp to_sortable_time(%DateTime{} = dt), do: DateTime.to_unix(dt, :microsecond)
  defp to_sortable_time(%NaiveDateTime{} = dt), do: NaiveDateTime.to_iso8601(dt)
  defp to_sortable_time(%{year: y, month: mo, day: d, hour: h, minute: mi, second: s}),
    do: :io_lib.format("~4..0B-~2..0B-~2..0BT~2..0B:~2..0B:~2..0B", [y, mo, d, h, mi, s]) |> IO.iodata_to_binary()
  defp to_sortable_time(_), do: ""


  defp load_for_ca(nil), do: {[], []}
  defp load_for_ca(ca_id) do
    ceremonies = case Repo.get_all_by_index(KeyCeremony, :ca_instance_id, ca_id) do
      {:ok, c} -> c
      _ -> []
    end
    keystores = case KeystoreManagement.list_keystores(nil, ca_id) do
      {:ok, ks} -> ks
      _ -> []
    end
    {ceremonies, keystores}
  rescue
    _ -> {[], []}
  end

  defp keystore_display(ks) do
    config = if ks.config, do: PkiCaEngine.Schema.Keystore.decode_config(ks.config), else: nil
    label = if config, do: config["label"], else: nil

    case {ks.type, label} do
      {"hsm", l} when is_binary(l) -> "HSM — #{l}"
      {"hsm", _} -> "HSM"
      {"software", _} -> "Software"
      {type, _} -> type
    end
  rescue
    _ -> ks.type || "unknown"
  end

  defp format_error({:validation_error, errors}) when is_map(errors) do
    errors
    |> Enum.map(fn {k, v} -> "#{humanize_field(k)}: #{Enum.join(List.wrap(v), ", ")}" end)
    |> Enum.join("; ")
  end
  defp format_error(%Ecto.Changeset{} = changeset) do
    changeset
    |> Ecto.Changeset.traverse_errors(fn {msg, opts} ->
      Enum.reduce(opts, msg, fn {k, v}, acc -> String.replace(acc, "%{#{k}}", to_string(v)) end)
    end)
    |> Enum.map(fn {field, msgs} -> "#{humanize_field(field)} #{Enum.join(List.wrap(msgs), ", ")}" end)
    |> Enum.join("; ")
  end
  defp format_error(reason) when is_binary(reason), do: reason
  defp format_error(_reason), do: "an unexpected error occurred"

  defp humanize_field(:key_alias), do: "Key alias"
  defp humanize_field(:ca_instance_id), do: "CA instance"
  defp humanize_field(:algorithm), do: "Algorithm"
  defp humanize_field(:keystore_id), do: "Keystore"
  defp humanize_field(:threshold_k), do: "Threshold (k)"
  defp humanize_field(:threshold_n), do: "Threshold (n)"
  defp humanize_field(field) when is_atom(field) or is_binary(field) do
    field |> to_string() |> String.replace("_", " ") |> String.capitalize()
  end

  defp parse_int(v) when is_integer(v), do: v
  defp parse_int(v) when is_binary(v) do
    case Integer.parse(v) do
      {n, _} -> n
      :error -> nil
    end
  end
  defp parse_int(_), do: nil

  defp format_datetime(nil), do: "-"
  defp format_datetime(%NaiveDateTime{} = dt), do: Calendar.strftime(dt, "%Y-%m-%d %H:%M:%S")
  defp format_datetime(%DateTime{} = dt), do: Calendar.strftime(dt, "%Y-%m-%d %H:%M:%S")
  defp format_datetime(%{year: _, month: _, day: _, hour: _, minute: _} = dt), do: Calendar.strftime(dt, "%Y-%m-%d %H:%M:%S")
  defp format_datetime(_), do: "-"

  defp status_badge_class("initiated"), do: "badge-warning"
  defp status_badge_class("preparing"), do: "badge-warning"
  defp status_badge_class("in_progress"), do: "badge-info"
  defp status_badge_class("generating"), do: "badge-info"
  defp status_badge_class("completed"), do: "badge-success"
  defp status_badge_class("failed"), do: "badge-error"
  defp status_badge_class(_), do: "badge-ghost"

  defp ceremony_resumable?(ceremony) do
    ceremony.status in ["initiated", "in_progress", "preparing"]
  end

  defp participant_role_class("key_manager"), do: "badge-info"
  defp participant_role_class("custodian"), do: "badge-info"
  defp participant_role_class("auditor"), do: "badge-accent"
  defp participant_role_class(_), do: "badge-ghost"

  defp participant_status_class("accepted"), do: "badge-success"
  defp participant_status_class("pending"), do: "badge-warning"
  defp participant_status_class("waiting"), do: "badge-ghost"
  defp participant_status_class("witnessed"), do: "badge-success"
  defp participant_status_class("attested" <> _), do: "badge-success"
  defp participant_status_class(_), do: "badge-ghost"

  defp format_role("key_manager"), do: "Key Manager"
  defp format_role("custodian"), do: "Custodian"
  defp format_role("auditor"), do: "Auditor"
  defp format_role(role), do: to_string(role)

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
          <table class="table table-sm table-fixed w-full">
            <thead>
              <tr class="text-xs uppercase text-base-content/50">
                <th class="w-[10%]">ID</th>
                <th class="w-[18%]">Key Alias</th>
                <th class="w-[10%]">Type</th>
                <th class="w-[16%]">Algorithm</th>
                <th class="w-[10%]">Status</th>
                <th class="w-[18%]">Created</th>
                <th class="w-[18%]"></th>
              </tr>
            </thead>
            <tbody>
              <tr :for={c <- paginated} class="hover">
                <td class="font-mono text-xs overflow-hidden text-ellipsis whitespace-nowrap">{String.slice(c.id || "", 0..7)}</td>
                <td class="text-sm overflow-hidden text-ellipsis whitespace-nowrap" title={ceremony_key_alias(c)}>{ceremony_key_alias(c)}</td>
                <td class="text-sm">{Map.get(c.domain_info || %{}, "is_root", true) |> then(fn r -> if r, do: "root", else: "sub-ca" end)}</td>
                <td class="font-mono text-sm overflow-hidden text-ellipsis whitespace-nowrap">{c.algorithm}</td>
                <td>
                  <span class={"badge badge-sm #{status_badge_class(c.status)}"}>{c.status}</span>
                </td>
                <td class="text-xs text-base-content/60"><.local_time dt={c.inserted_at} /></td>
                <td class="flex items-center gap-1">
                  <button
                    :if={c.status not in ["failed"]}
                    phx-click="view_ceremony"
                    phx-value-id={c.id}
                    title="View details"
                    class="btn btn-ghost btn-xs text-primary"
                  >
                    <.icon name="hero-eye" class="size-4" />
                  </button>
                  <button
                    :if={ceremony_resumable?(c)}
                    phx-click="resume_ceremony"
                    phx-value-id={c.id}
                    title="Resume"
                    class="btn btn-ghost btn-xs text-sky-400"
                  >
                    <.icon name="hero-play" class="size-4" />
                  </button>
                  <button
                    :if={c.status in ["initiated", "in_progress", "preparing"]}
                    phx-click="cancel_ceremony_record"
                    phx-value-id={c.id}
                    data-confirm="Cancel this ceremony? The pending issuer key will be removed."
                    title="Cancel"
                    class="btn btn-ghost btn-xs text-amber-400"
                  >
                    <.icon name="hero-x-mark" class="size-4" />
                  </button>
                  <button
                    :if={c.status in ["failed"]}
                    phx-click="delete_ceremony_record"
                    phx-value-id={c.id}
                    data-confirm="Permanently delete this ceremony record?"
                    title="Delete"
                    class="btn btn-ghost btn-xs text-rose-400"
                  >
                    <.icon name="hero-trash" class="size-4" />
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

  defp ceremony_key_alias(ceremony) do
    # Try to get alias from linked issuer key
    case PkiCaEngine.IssuerKeyManagement.get_issuer_key(ceremony.issuer_key_id) do
      {:ok, key} when not is_nil(key) -> key.key_alias || "—"
      _ -> "—"
    end
  rescue
    _ -> "—"
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

  # Step 1: Initiate — uses custodian_names (not user IDs) for new Mnesia ceremony API
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
              <input type="text" name="key_alias" placeholder="e.g. root-key-2026" maxlength="100" class="input input-bordered input-sm w-full" />
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
          <div class="divider text-xs text-base-content/40">Participants (single-session ceremony)</div>

          <p class="text-xs text-base-content/60 -mt-2 mb-2">
            This ceremony runs end-to-end in one session. Custodians and the
            auditor are external — they are NOT portal users. Enter the
            names that will be recorded in the printed transcript. Each
            custodian will choose their own per-ceremony password when they
            sit down at the next step.
          </p>

          <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label class="block text-xs font-medium text-base-content/60 mb-1">
                Custodian names (one per line, must match threshold N)
              </label>
              <textarea
                name="custodian_names"
                rows="4"
                placeholder="Alice Johnson&#10;Bob Mendez&#10;Charlie Nakamura"
                class="textarea textarea-bordered textarea-sm w-full font-mono"
                required
              ></textarea>
              <p class="text-xs text-base-content/40 mt-1">
                Free text, 1-128 chars per name. Names must be unique within
                this ceremony. They become the identifier on each custodian's
                share and on the signature line of the printed transcript.
              </p>
            </div>

            <div>
              <label class="block text-xs font-medium text-base-content/60 mb-1">
                External auditor name
              </label>
              <input
                type="text"
                name="auditor_name"
                maxlength="128"
                placeholder="e.g. Jane Roe, Big Four Audit Firm"
                class="input input-bordered input-sm w-full"
                required
              />
              <p class="text-xs text-base-content/40 mt-1">
                The external auditor observing and signing the printed
                transcript at session end. Not a system user; just a name on
                the paper record.
              </p>
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
              <span class="font-mono">{String.slice(@active_ceremony.id || "", 0..7)}</span>
            </div>
            <div class="flex gap-2">
              <span class="text-base-content/50 w-28">Algorithm:</span>
              <span class="font-mono font-semibold">{@active_ceremony.algorithm}</span>
            </div>
            <div class="flex gap-2">
              <span class="text-base-content/50 w-28">Threshold:</span>
              <span>{@active_ceremony.threshold_k}-of-{@active_ceremony.threshold_n}</span>
            </div>
            <div class="flex gap-2">
              <span class="text-base-content/50 w-28">Type:</span>
              <span><%= if @is_root, do: "Root CA (self-signed)", else: "Sub-CA (CSR)" %></span>
            </div>
            <div class="flex gap-2">
              <span class="text-base-content/50 w-28">Status:</span>
              <span class={"badge badge-sm #{status_badge_class(@active_ceremony.status)}"}>{@active_ceremony.status}</span>
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
            <table class="table table-sm table-fixed w-full">
              <thead>
                <tr class="text-xs uppercase text-base-content/50">
                  <th class="w-[35%]">Participant</th>
                  <th class="w-[18%]">Role</th>
                  <th class="w-[17%]">Status</th>
                  <th class="w-[30%]">Timestamp</th>
                </tr>
              </thead>
              <tbody>
                <tr :for={p <- @participants} class="hover">
                  <td class="text-sm font-medium overflow-hidden text-ellipsis whitespace-nowrap">{p.name}</td>
                  <td>
                    <span class={"badge badge-sm #{participant_role_class(p.role)}"}>{format_role(p.role)}</span>
                  </td>
                  <td>
                    <span class={"badge badge-sm #{participant_status_class(p.status)}"}>{p.status}</span>
                  </td>
                  <td class="text-xs text-base-content/60">
                    <.local_time dt={p.timestamp} />
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
            <.icon name="hero-clock" class="size-4 inline" /> Ceremony Timeline
          </h3>

          <div :if={Enum.empty?(@activity_log)} class="text-sm text-base-content/50 text-center py-4">
            No events recorded yet.
          </div>

          <div :if={not Enum.empty?(@activity_log)} class="space-y-2 max-h-64 overflow-y-auto">
            <div :for={entry <- @activity_log} class="flex items-start gap-3 text-sm">
              <span class="text-xs text-base-content/40 font-mono shrink-0 mt-0.5 w-36">
                <.local_time dt={entry.timestamp} />
              </span>
              <span class="text-base-content/70">{entry.message}</span>
            </div>
          </div>
        </div>
      </div>

      <%!-- Action buttons --%>
      <div class="flex justify-between items-center">
        <button phx-click="finish_wizard" class="btn btn-ghost btn-sm">
          <.icon name="hero-arrow-left" class="size-4" /> Back to List
        </button>
        <button
          :if={@active_ceremony.status not in ["completed", "failed"]}
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
          Ceremony <span class="font-mono">{String.slice(@active_ceremony.id || "", 0..7)}</span> has been completed successfully.
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
