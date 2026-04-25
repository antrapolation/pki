defmodule PkiTenantWeb.Ca.CeremonyLive do
  use PkiTenantWeb, :live_view

  require Logger

  alias PkiCaEngine.CaInstanceManagement
  alias PkiCaEngine.CeremonyOrchestrator
  alias PkiCaEngine.KeystoreManagement
  alias PkiMnesia.Repo
  alias PkiMnesia.Structs.{KeyCeremony, CeremonyParticipant, ThresholdShare}
  alias PkiTenantWeb.Ca.CustodianPinVault

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
       # Initiate form state (tracked for reactive warning banner)
       selected_key_mode: "threshold",
       selected_key_role: "operational_sub",
       # Progress dashboard state
       participants: [],
       activity_log: [],
       # Slot-based custodian acceptance state
       slot_states: [],
       entering_slot: nil,
       entry_error: nil,
       # PIN isolation: LiveView holds only opaque tokens; actual PIN bytes
       # live exclusively in a CustodianPinVault GenServer process.
       vault_pid: nil,
       entered_tokens: %{},
       # :idle | :running | :completed | :failed
       execution_state: nil,
       execution_error: nil,
       completed_ceremony: nil
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

  def handle_info(:execute_keygen, socket) do
    ceremony = socket.assigns.active_ceremony
    vault_pid = socket.assigns.vault_pid
    entered_tokens = socket.assigns.entered_tokens

    # Consume all tokens from the vault, producing a {name, password} list.
    # The vault removes each PIN from its state on consume, so no plaintext
    # lingers there after this block. Clear vault_pid and entered_tokens from
    # the socket BEFORE calling execute_keygen so a raise leaves no residue.
    passwords =
      Enum.map(entered_tokens, fn {name, token} ->
        {:ok, pin} = CustodianPinVault.consume(vault_pid, token)
        {name, pin}
      end)

    if is_pid(vault_pid), do: CustodianPinVault.stop(vault_pid)
    socket = assign(socket, vault_pid: nil, entered_tokens: %{})

    # Convert to the list-of-{name, password} tuples the orchestrator
    # expects. Wrap in try/rescue so a raise during keygen ends up in
    # :failed state rather than crashing the LiveView.
    try do
      case CeremonyOrchestrator.execute_keygen(ceremony.id, passwords) do
        {:ok, _} ->
          # Re-read the ceremony so we have fingerprint + updated status.
          completed =
            case Repo.get(KeyCeremony, ceremony.id) do
              {:ok, c} -> c
              _ -> ceremony
            end

          PkiTenant.AuditBridge.log("ceremony_key_generated", %{
            ceremony_id: ceremony.id,
            fingerprint: Map.get(completed.domain_info || %{}, "fingerprint")
          })

          :erlang.garbage_collect()

          {:noreply,
           socket
           |> assign(
             execution_state: :completed,
             execution_error: nil,
             completed_ceremony: completed,
             slot_states: load_slot_states(completed),
             activity_log:
               [
                 %{timestamp: DateTime.utc_now(), message: "Key generated, shares encrypted, ceremony complete."}
                 | socket.assigns.activity_log
               ]
               |> Enum.take(50)
           )}

        {:error, reason} ->
          :erlang.garbage_collect()

          {:noreply,
           socket
           |> assign(
             execution_state: :failed,
             execution_error: format_error(reason),
             activity_log:
               [
                 %{timestamp: DateTime.utc_now(), message: "Key generation failed: #{format_error(reason)}"}
                 | socket.assigns.activity_log
               ]
               |> Enum.take(50)
           )}
      end
    rescue
      e ->
        Logger.error("[ceremony_live] execute_keygen raised: #{Exception.message(e)}")
        if is_pid(socket.assigns.vault_pid), do: CustodianPinVault.stop(socket.assigns.vault_pid)
        :erlang.garbage_collect()

        {:noreply,
         socket
         |> assign(
           vault_pid: nil,
           entered_tokens: %{},
           execution_state: :failed,
           execution_error: "An unexpected error occurred during key generation."
         )}
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

  # Vault crash monitor -- fires if the CustodianPinVault GenServer goes down
  # unexpectedly mid-ceremony. Tokens held by the socket can no longer be
  # consumed, so we cancel the ceremony and surface a clear error.
  def handle_info({:DOWN, _ref, :process, pid, _reason}, socket) do
    if pid == socket.assigns[:vault_pid] do
      ceremony = socket.assigns[:active_ceremony]

      if ceremony && ceremony.status not in ["completed", "failed"] do
        CeremonyOrchestrator.fail_ceremony(ceremony.id, "vault_crash")
      end

      Logger.error("[CeremonyLive] CustodianPinVault #{inspect(pid)} crashed mid-ceremony -- resetting state")

      {:noreply,
       socket
       |> assign(
         vault_pid: nil,
         entered_tokens: %{},
         execution_state: :failed,
         execution_error: "Key entry session lost — ceremony cancelled. Please start a new ceremony.",
         entering_slot: nil
       )
       |> put_flash(:error, "Key entry session lost — ceremony cancelled. Please start a new ceremony.")}
    else
      {:noreply, socket}
    end
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
       activity_log: [],
       selected_key_mode: "threshold",
       selected_key_role: "operational_sub"
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
  # Step 1: Initiate form changes (tracked for reactive UI)
  # ---------------------------------------------------------------------------

  def handle_event("change_initiate_form", params, socket) do
    {:noreply,
     assign(socket,
       selected_key_mode: params["key_mode"] || socket.assigns.selected_key_mode,
       selected_key_role: params["key_role"] || socket.assigns.selected_key_role
     )}
  end

  # ---------------------------------------------------------------------------
  # Step 1: Initiate single-session ceremony
  # ---------------------------------------------------------------------------

  def handle_event("initiate_ceremony", params, socket) do
    ca_id = params["ca_instance_id"]

    # At initiation we only know how many custodians (threshold_n) and who
    # the auditor is. Each custodian's real name + per-ceremony password is
    # collected at their turn in the entry step. Mnesia gets placeholder
    # names "Custodian 1..N" which get overwritten with real names on
    # accept_share_by_slot.
    auditor_name = String.trim(params["auditor_name"] || "")
    threshold_k = parse_int(params["threshold_k"]) || 2
    threshold_n = parse_int(params["threshold_n"]) || 3

    cond do
      is_nil(ca_id) or ca_id == "" ->
        {:noreply, assign(socket, wizard_error: "Please select a CA Instance.")}

      is_nil(params["keystore_id"]) or params["keystore_id"] == "" ->
        {:noreply, assign(socket, wizard_error: "Please select a Keystore.")}

      (params["key_mode"] || "threshold") == "threshold" and (threshold_n < 2 or threshold_n > 20) ->
        {:noreply, assign(socket, wizard_error: "Threshold N must be between 2 and 20.")}

      (params["key_mode"] || "threshold") == "threshold" and (threshold_k > threshold_n or threshold_k < 2) ->
        {:noreply,
         assign(socket,
           wizard_error: "Threshold K must be between 2 and #{threshold_n}."
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
            placeholder_names = Enum.map(1..threshold_n, fn i -> "Custodian #{i}" end)
            key_mode = params["key_mode"] || "threshold"
            key_role = params["key_role"] || "operational_sub"

            ceremony_params = %{
              algorithm: params["algorithm"],
              keystore_id: params["keystore_id"],
              keystore_mode: params["keystore_mode"] || "softhsm",
              threshold_k: threshold_k,
              threshold_n: threshold_n,
              is_root: is_root,
              key_alias: params["key_alias"],
              custodian_names: placeholder_names,
              auditor_name: auditor_name,
              ceremony_mode: :full,
              initiated_by: initiated_by,
              subject_dn: params["subject_dn"],
              key_mode: key_mode,
              key_role: key_role
            }

            case CeremonyOrchestrator.initiate(ca_id, ceremony_params) do
              {:ok, {ceremony, _key, _shares, participants_list, _transcript}} ->
                PkiTenant.AuditBridge.log("ceremony_initiated", %{
                  ceremony_id: ceremony.id,
                  algorithm: params["algorithm"],
                  ca_instance_id: ca_id,
                  is_root: is_root,
                  key_alias: params["key_alias"],
                  keystore_mode: ceremony.keystore_mode,
                  custodian_count: threshold_n,
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

                slot_states = load_slot_states(ceremony)

                # Start a fresh vault for this ceremony's PIN isolation.
                {:ok, vault_pid} = CustodianPinVault.start_link()
                Process.monitor(vault_pid)

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
                   activity_log: [%{timestamp: DateTime.utc_now(), message: "Ceremony initiated — Custodian #1 up next"}],
                   slot_states: slot_states,
                   entering_slot: next_pending_slot(slot_states),
                   entry_error: nil,
                   vault_pid: vault_pid,
                   entered_tokens: %{},
                   execution_state: :idle,
                   execution_error: nil,
                   completed_ceremony: nil
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

  # Sequential custodian entry. The dialog is open for exactly one slot at a
  # time. After each successful submission it advances to the next pending
  # slot automatically, or closes when all N are accepted. No
  # "pick a slot" step — the system drives the order so two custodians
  # can't enter the same slot or skip ahead.

  def handle_event("submit_slot_entry", params, socket) do
    slot = socket.assigns.entering_slot
    ceremony = socket.assigns.active_ceremony
    real_name = String.trim(params["custodian_name"] || "")
    password = params["password"] || ""
    confirmation = params["password_confirmation"] || ""

    cond do
      is_nil(slot) or is_nil(ceremony) ->
        {:noreply, socket}

      real_name == "" ->
        {:noreply, assign(socket, entry_error: "Enter your name.")}

      true ->
        with :ok <- PkiCaEngine.KeyCeremony.PasswordPolicy.validate_with_confirmation(password, confirmation),
             {:ok, _updated} <- CeremonyOrchestrator.accept_share_by_slot(ceremony.id, slot, real_name, password) do
          PkiTenant.AuditBridge.log("custodian_share_accepted", %{
            ceremony_id: ceremony.id,
            slot: slot,
            custodian_name: real_name
          })

          new_slot_states = load_slot_states(ceremony)
          next_slot = next_pending_slot(new_slot_states)

          # Store the PIN in the vault; hold only the opaque token in socket state.
          token = CustodianPinVault.store(socket.assigns.vault_pid, password)
          accumulated = Map.put(socket.assigns.entered_tokens, real_name, token)

          if next_slot do
            {:noreply,
             socket
             |> assign(
               entering_slot: next_slot,
               entry_error: nil,
               slot_states: new_slot_states,
               entered_tokens: accumulated
             )
             |> put_flash(:info, "#{real_name} accepted Custodian ##{slot}. Now Custodian ##{next_slot}.")}
          else
            # Last slot just accepted. Schedule execute_keygen on the next
            # message loop tick so the UI gets a chance to render the
            # "generating…" state before the (potentially slow) keygen
            # runs synchronously in handle_info.
            send(self(), :execute_keygen)

            {:noreply,
             socket
             |> assign(
               entering_slot: nil,
               entry_error: nil,
               slot_states: new_slot_states,
               entered_tokens: accumulated,
               execution_state: :running
             )
             |> put_flash(:info, "All custodians have accepted. Generating key…")}
          end
        else
          {:error, :duplicate_name} ->
            {:noreply, assign(socket, entry_error: "Another custodian in this ceremony has already used that name. Add a qualifier (e.g. department).")}

          {:error, :empty_name} ->
            {:noreply, assign(socket, entry_error: "Enter your name.")}

          {:error, :empty_password} ->
            {:noreply, assign(socket, entry_error: "Password cannot be empty.")}

          {:error, {:invalid_share_status, status}} ->
            {:noreply, assign(socket, entry_error: "This slot is no longer pending (#{status}). Refresh the page.")}

          {:error, {:invalid_ceremony_status, status}} ->
            {:noreply, assign(socket, entry_error: "Ceremony is no longer accepting shares (status: #{status}).")}

          {:error, reason} when is_atom(reason) ->
            msg = PkiCaEngine.KeyCeremony.PasswordPolicy.humanize_error(reason)
            {:noreply, assign(socket, entry_error: msg)}

          {:error, {:too_short, _n} = reason} ->
            {:noreply, assign(socket, entry_error: PkiCaEngine.KeyCeremony.PasswordPolicy.humanize_error(reason))}

          other ->
            Logger.error("[ceremony_live] unexpected error on submit_slot_entry: #{inspect(other)}")
            {:noreply, assign(socket, entry_error: "Unexpected error. Try again.")}
        end
    end
  end

  def handle_event("cancel_active_ceremony", _params, socket) do
    ceremony = socket.assigns.active_ceremony

    if ceremony do
      CeremonyOrchestrator.fail_ceremony(ceremony.id, "cancelled_by_admin")
      PkiTenant.AuditBridge.log("ceremony_cancelled", %{ceremony_id: ceremony.id})
    end

    if is_pid(socket.assigns.vault_pid), do: CustodianPinVault.stop(socket.assigns.vault_pid)

    {ceremonies, _} = load_for_ca(socket.assigns.effective_ca_id)

    {:noreply,
     socket
     |> assign(
       wizard_step: nil,
       active_ceremony: nil,
       vault_pid: nil,
       entered_tokens: %{},
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

  @impl true
  def terminate(_reason, socket) do
    if pid = socket.assigns[:vault_pid], do: CustodianPinVault.stop(pid)
    :ok
  end

  # ---------------------------------------------------------------------------
  # Private helpers
  # ---------------------------------------------------------------------------

  # Load share state for the slot-entry dashboard. Returns a list sorted
  # by share_index of %{slot, name, status}.
  defp load_slot_states(nil), do: []

  defp load_slot_states(ceremony) do
    case Repo.get_all_by_index(ThresholdShare, :issuer_key_id, ceremony.issuer_key_id) do
      {:ok, shares} ->
        shares
        |> Enum.sort_by(& &1.share_index)
        |> Enum.map(fn s ->
          %{slot: s.share_index, name: s.custodian_name, status: s.status}
        end)

      _ ->
        []
    end
  rescue
    _ -> []
  end

  # Lowest-numbered pending slot, or nil if every slot is already accepted.
  defp next_pending_slot(slot_states) do
    slot_states
    |> Enum.find(fn %{status: status} -> status == "pending" end)
    |> case do
      nil -> nil
      %{slot: n} -> n
    end
  end

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

      # Auditor is a name-on-the-transcript, not a workflow actor — no
      # in-system verification happens in the single-session model.
      # Custodians flow through pending → accepted → active via the
      # slot-entry modal.
      status = cond do
        p.role == :auditor -> "registered"
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
    keystores = KeystoreManagement.list_keystores(ca_id)
    {ceremonies, keystores}
  rescue
    _ -> {[], []}
  end

  defp keystore_display(ks) do
    config = PkiMnesia.Structs.Keystore.decode_config(ks.config)
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
  defp participant_status_class("registered"), do: "badge-info"
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

        <form phx-submit="initiate_ceremony" phx-change="change_initiate_form" class="space-y-4">
          <input type="hidden" name="ca_instance_id" value={@effective_ca_id} />

          <%!-- WebTrust §6.2.2 dual-control warning for non-threshold modes --%>
          <div :if={@selected_key_mode in ["password", "single_custodian"]} class="alert alert-warning text-sm">
            <.icon name="hero-exclamation-triangle" class="size-4 shrink-0" />
            <span>This mode does not meet WebTrust §6.2.2 dual-control. Use only for internal/private CAs.</span>
          </div>

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
              <label class="block text-xs font-medium text-base-content/60 mb-1">Key Role</label>
              <select name="key_role" class="select select-bordered select-sm w-full">
                <option value="root" selected={@selected_key_role == "root"}>Root CA</option>
                <option value="issuing_sub" selected={@selected_key_role == "issuing_sub"}>Issuing Sub-CA</option>
                <option value="operational_sub" selected={@selected_key_role == "operational_sub"}>Operational Sub-CA</option>
              </select>
              <p class="text-xs text-base-content/40 mt-1">
                Root CA keys require threshold mode (WebTrust §6.2.2).
              </p>
            </div>
            <div class="md:col-span-2">
              <label class="block text-xs font-medium text-base-content/60 mb-2">Key Protection Mode</label>
              <div class="flex flex-wrap gap-4">
                <label class="flex items-center gap-2 cursor-pointer">
                  <input type="radio" name="key_mode" value="threshold" class="radio radio-sm" checked={@selected_key_mode == "threshold"} />
                  <span class="text-sm">Threshold (k-of-n) <span class="text-xs text-base-content/40">(recommended)</span></span>
                </label>
                <label class="flex items-center gap-2 cursor-pointer">
                  <input type="radio" name="key_mode" value="password" class="radio radio-sm" checked={@selected_key_mode == "password"} />
                  <span class="text-sm">Password <span class="text-xs text-base-content/40">(single envelope)</span></span>
                </label>
                <label class="flex items-center gap-2 cursor-pointer">
                  <input type="radio" name="key_mode" value="single_custodian" class="radio radio-sm" checked={@selected_key_mode == "single_custodian"} />
                  <span class="text-sm">Single Custodian <span class="text-xs text-base-content/40">(internal only)</span></span>
                </label>
              </div>
              <p class="text-xs text-base-content/40 mt-1">
                Shamir threshold (k-of-n) is required for Root CA and meets WebTrust dual-control. Password and single-custodian modes use a single AES-256-GCM key envelope (k=1, n=1).
              </p>
            </div>
            <div class="md:col-span-2">
              <label class="block text-xs font-medium text-base-content/60 mb-2">Key Storage Mode</label>
              <div class="flex flex-wrap gap-4">
                <%= if Mix.env() != :prod do %>
                  <label class="flex items-center gap-2 cursor-pointer">
                    <input type="radio" name="keystore_mode" value="software" class="radio radio-sm" />
                    <span class="text-sm">Software <span class="text-xs text-base-content/40">(dev/test only)</span></span>
                  </label>
                <% end %>
                <label class="flex items-center gap-2 cursor-pointer">
                  <input type="radio" name="keystore_mode" value="softhsm" class="radio radio-sm" checked />
                  <span class="text-sm">SoftHSM <span class="text-xs text-base-content/40">(PKCS#11, default)</span></span>
                </label>
                <label class="flex items-center gap-2 cursor-pointer">
                  <input type="radio" name="keystore_mode" value="hsm" class="radio radio-sm" />
                  <span class="text-sm">Hardware HSM <span class="text-xs text-base-content/40">(required in prod)</span></span>
                </label>
              </div>
              <p class="text-xs text-base-content/40 mt-1">
                Selects how the generated private key material is protected. HSM mode requires a configured HSM keystore for this CA.
              </p>
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
            This ceremony runs end-to-end in one session. Threshold N above
            is the number of custodians. Each custodian will enter their
            own name and a per-ceremony password when it's their turn on
            the next step — no need to enter them here. Custodians and the
            auditor are external, not portal users; what they type becomes
            the printed-transcript record.
          </p>

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
              transcript at session end.
            </p>
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

      <%!-- Execution state banner --%>
      <div :if={@execution_state == :running} class="alert alert-info">
        <.icon name="hero-cog-6-tooth" class="size-5 animate-spin" />
        <div>
          <div class="font-semibold text-sm">Generating key and encrypting shares…</div>
          <div class="text-xs opacity-70">
            Do not navigate away. Post-quantum algorithms can take several seconds.
          </div>
        </div>
      </div>

      <div :if={@execution_state == :completed and @completed_ceremony} class="card bg-success/5 border-success/40 border shadow-sm">
        <div class="card-body">
          <h3 class="text-sm font-semibold text-success">
            <.icon name="hero-check-circle" class="size-5 inline" /> Ceremony complete
          </h3>
          <p class="text-xs text-base-content/70">
            The keypair is generated, shares are encrypted per custodian,
            and passwords have been wiped from server memory. The auditor
            must now print the transcript; each custodian signs the printed
            transcript in pen, then the auditor signs.
          </p>

          <div class="bg-base-100 rounded p-3 text-xs space-y-1 font-mono">
            <div :if={Map.get(@completed_ceremony.domain_info || %{}, "fingerprint")}>
              <span class="text-base-content/50">Public key SHA-256:</span>
              <span>{Map.get(@completed_ceremony.domain_info || %{}, "fingerprint")}</span>
            </div>
            <div>
              <span class="text-base-content/50">Ceremony status:</span>
              <span class="badge badge-xs badge-success">{@completed_ceremony.status}</span>
            </div>
          </div>

          <div class="card-actions justify-end mt-2">
            <.link
              href={"/ceremonies/#{@completed_ceremony.id}/transcript"}
              target="_blank"
              class="btn btn-primary btn-sm"
            >
              <.icon name="hero-printer" class="size-4" /> Print transcript
            </.link>
            <button phx-click="finish_wizard" class="btn btn-ghost btn-sm">
              Back to list
            </button>
          </div>
        </div>
      </div>

      <div :if={@execution_state == :failed} class="alert alert-error">
        <.icon name="hero-x-circle" class="size-5" />
        <div>
          <div class="font-semibold text-sm">Key generation failed</div>
          <div class="text-xs">{@execution_error}</div>
          <div class="text-xs opacity-70 mt-1">
            Passwords have been wiped from memory. The ceremony is marked
            failed — start a new one.
          </div>
        </div>
      </div>

      <%!-- Custodian slots (single-session) --%>
      <div :if={not Enum.empty?(@slot_states)} class="card bg-base-100 shadow-sm border border-base-300">
        <div class="card-body">
          <h3 class="text-sm font-semibold text-base-content mb-3">
            <.icon name="hero-key" class="size-4 inline" /> Custodian Shares
          </h3>

          <p class="text-xs text-base-content/60 mb-3">
            Each custodian enters their name and a per-ceremony password in
            sequence. A dialog appears automatically for the next pending
            slot — hand the screen to that custodian when it opens.
          </p>

          <table class="table table-sm table-fixed w-full">
            <thead>
              <tr class="text-xs uppercase text-base-content/50">
                <th class="w-[20%]">Slot</th>
                <th class="w-[55%]">Custodian</th>
                <th class="w-[25%]">Status</th>
              </tr>
            </thead>
            <tbody>
              <tr :for={s <- @slot_states} class="hover">
                <td class="text-sm font-mono">Custodian #{s.slot}</td>
                <td class="text-sm">
                  <span :if={s.status == "pending"} class="text-base-content/40 italic">— awaiting entry —</span>
                  <span :if={s.status != "pending"} class="font-medium">{s.name}</span>
                </td>
                <td>
                  <span class={"badge badge-sm #{slot_status_class(s.status)}"}>{s.status}</span>
                </td>
              </tr>
            </tbody>
          </table>
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

      <%!-- Sequential custodian-entry modal --%>
      <%= if @entering_slot do %>
        {render_slot_entry_dialog(assigns)}
      <% end %>
    </div>
    """
  end

  # Modal shown while a custodian is at the keyboard entering their name
  # and per-ceremony password. There's no cancel button — the modal only
  # closes on successful submission, and the whole ceremony can be
  # cancelled from the dashboard below. This keeps the flow linear:
  # operator opens the dialog, custodian fills in, next custodian.
  defp render_slot_entry_dialog(assigns) do
    ~H"""
    <div class="modal modal-open" role="dialog" aria-labelledby="slot-entry-title">
      <div class="modal-box max-w-md">
        <h2 id="slot-entry-title" class="text-base font-semibold mb-1">
          Custodian #{@entering_slot} — enter your details
        </h2>
        <p class="text-xs text-base-content/60 mb-4">
          Your name appears on the signed paper transcript. Your password
          is used only for this ceremony and is not stored after the
          session ends. Minimum {PkiCaEngine.KeyCeremony.PasswordPolicy.min_length()} characters.
        </p>

        <form phx-submit="submit_slot_entry" class="space-y-3" autocomplete="off">
          <div>
            <label class="block text-xs font-medium text-base-content/70 mb-1">
              Name (as it should appear on the transcript)
            </label>
            <input
              type="text"
              name="custodian_name"
              maxlength="128"
              autofocus
              required
              class="input input-bordered input-sm w-full"
            />
          </div>

          <div>
            <label class="block text-xs font-medium text-base-content/70 mb-1">
              Password
            </label>
            <input
              type="password"
              name="password"
              minlength={PkiCaEngine.KeyCeremony.PasswordPolicy.min_length()}
              required
              class="input input-bordered input-sm w-full font-mono"
            />
          </div>

          <div>
            <label class="block text-xs font-medium text-base-content/70 mb-1">
              Confirm password
            </label>
            <input
              type="password"
              name="password_confirmation"
              minlength={PkiCaEngine.KeyCeremony.PasswordPolicy.min_length()}
              required
              class="input input-bordered input-sm w-full font-mono"
            />
          </div>

          <div :if={@entry_error} class="alert alert-error text-sm py-2">
            <span>{@entry_error}</span>
          </div>

          <div class="modal-action mt-4">
            <button type="submit" class="btn btn-primary btn-sm">
              Accept share
            </button>
          </div>
        </form>
      </div>
    </div>
    """
  end

  defp slot_status_class("pending"), do: "badge-ghost"
  defp slot_status_class("accepted"), do: "badge-info"
  defp slot_status_class("active"), do: "badge-success"
  defp slot_status_class(_), do: "badge-ghost"

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
