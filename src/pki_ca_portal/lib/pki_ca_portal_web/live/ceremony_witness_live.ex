defmodule PkiCaPortalWeb.CeremonyWitnessLive do
  use PkiCaPortalWeb, :live_view

  alias PkiCaPortal.CaEngineClient
  alias PkiCaPortal.CustodianPasswordStore
  alias PkiCaPortal.CeremonyNotifications
  import PkiCaPortalWeb.AuditHelpers, only: [audit_log: 5]

  require Logger

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket), do: send(self(), :load_ceremonies)

    {:ok,
     assign(socket,
       page_title: "Ceremony Witness",
       ceremonies: [],
       selected_ceremony: nil,
       attestations: [],
       shares: [],
       activity_log: [],
       witness_password: "",
       loading: true,
       attesting: false,
       attest_error: nil,
       keygen_result: nil
     )}
  end

  @impl true
  def handle_info(:load_ceremonies, socket) do
    import PkiCaPortalWeb.SafeEngine, only: [safe_load: 3]

    safe_load(socket, fn ->
      user = socket.assigns.current_user
      opts = tenant_opts(socket)

      ceremonies =
        case CaEngineClient.list_my_witness_ceremonies(user[:id], opts) do
          {:ok, list} -> list
          {:error, _} -> []
        end

      # Subscribe to PubSub for each ceremony
      if connected?(socket) do
        Enum.each(ceremonies, fn c ->
          ceremony_id = c[:id] || c.id
          Phoenix.PubSub.subscribe(PkiCaPortal.PubSub, "ceremony:#{ceremony_id}")
        end)
      end

      {:noreply, assign(socket, ceremonies: ceremonies, loading: false)}
    end, retry_msg: :load_ceremonies)
  end

  # ---------------------------------------------------------------------------
  # PubSub handlers
  # ---------------------------------------------------------------------------

  @impl true
  def handle_info({:custodian_ready, _payload}, socket) do
    socket = add_activity(socket, "A custodian has accepted their share.")

    case socket.assigns.selected_ceremony do
      nil ->
        {:noreply, socket}

      ceremony ->
        shares = load_shares(ceremony, tenant_opts(socket))
        {:noreply, assign(socket, shares: shares)}
    end
  end

  def handle_info({:witness_attested, _payload}, socket) do
    socket = add_activity(socket, "Witness attestation recorded.")

    case socket.assigns.selected_ceremony do
      nil ->
        {:noreply, socket}

      ceremony ->
        attestations = load_attestations(ceremony[:id], tenant_opts(socket))
        {:noreply, assign(socket, attestations: attestations)}
    end
  end

  def handle_info({:phase_changed, _payload}, socket) do
    socket = add_activity(socket, "Ceremony phase has changed.")
    {:noreply, reload_selected_ceremony(socket)}
  end

  def handle_info({:ceremony_failed, payload}, socket) do
    reason = payload[:reason] || "unknown"
    socket = add_activity(socket, "Ceremony failed: #{reason}")
    {:noreply, reload_selected_ceremony(socket)}
  end

  def handle_info(_msg, socket), do: {:noreply, socket}

  # ---------------------------------------------------------------------------
  # Events
  # ---------------------------------------------------------------------------

  @impl true
  def handle_event("select_ceremony", %{"id" => ceremony_id}, socket) do
    opts = tenant_opts(socket)

    ceremony = Enum.find(socket.assigns.ceremonies, fn c ->
      (c[:id] || c.id) == ceremony_id
    end)

    case ceremony do
      nil ->
        {:noreply, put_flash(socket, :error, "Ceremony not found.")}

      ceremony ->
        attestations = load_attestations(ceremony_id, opts)
        shares = load_shares(ceremony, opts)
        timeline = build_ceremony_timeline(ceremony, shares, attestations)

        {:noreply,
         assign(socket,
           selected_ceremony: ceremony,
           attestations: attestations,
           shares: shares,
           activity_log: timeline,
           witness_password: "",
           attest_error: nil,
           keygen_result: nil
         )}
    end
  end

  def handle_event("back_to_list", _params, socket) do
    {:noreply,
     assign(socket,
       selected_ceremony: nil,
       attestations: [],
       shares: [],
       activity_log: [],
       witness_password: "",
       attest_error: nil
     )}
  end

  def handle_event("update_witness_password", %{"value" => value}, socket) do
    {:noreply, assign(socket, witness_password: value)}
  end

  def handle_event("witness_phase", %{"phase" => phase, "password" => password}, socket) do
    user = socket.assigns.current_user
    ceremony = socket.assigns.selected_ceremony
    opts = tenant_opts(socket)
    ceremony_id = ceremony[:id]

    socket = assign(socket, attesting: true, attest_error: nil)

    # Step 1: Re-authenticate
    case CaEngineClient.authenticate_with_session(user[:username], password, opts) do
      {:ok, _user_data, _session_data} ->
        # Step 2: Record attestation
        details = %{
          phase: phase,
          witnessed_at: DateTime.utc_now() |> DateTime.to_iso8601(),
          auditor_username: user[:username]
        }

        case CaEngineClient.attest_ceremony(ceremony_id, user[:id], phase, details, opts) do
          {:ok, _attestation} ->
            # Step 3: Broadcast
            Phoenix.PubSub.broadcast(
              PkiCaPortal.PubSub,
              "ceremony:#{ceremony_id}",
              {:witness_attested, %{phase: phase, auditor_id: user[:id]}}
            )

            # Step 4: Audit log
            audit_log(socket, "ceremony_witness_attested", "ceremony", ceremony_id, %{
              phase: phase,
              auditor_id: user[:id],
              auditor_username: user[:username]
            })

            # Step 5: If preparation phase — check readiness and trigger keygen
            socket =
              if phase == "preparation" do
                handle_preparation_attestation(socket, ceremony_id, opts)
              else
                socket
              end

            # Step 6: Notification
            CeremonyNotifications.notify_witness_attested(ceremony, phase)

            # Step 7: Notify auditor of next witness step
            if phase == "key_generation" do
              CeremonyNotifications.notify_auditor_witness_completion(ceremony)
            end

            # Refresh attestations and ceremony list
            attestations = load_attestations(ceremony_id, opts)
            ceremonies = reload_ceremonies(socket)

            updated_ceremony =
              Enum.find(ceremonies, fn c -> (c[:id] || c.id) == ceremony_id end) || ceremony

            {:noreply,
             socket
             |> assign(
               attestations: attestations,
               ceremonies: ceremonies,
               selected_ceremony: updated_ceremony,
               witness_password: "",
               attesting: false,
               attest_error: nil
             )
             |> add_activity("Witnessed #{phase} phase.")
             |> put_flash(:info, "#{String.capitalize(phase)} phase witnessed successfully.")}

          {:error, reason} ->
            {:noreply,
             assign(socket,
               attesting: false,
               attest_error: "Attestation failed: #{format_error(reason)}"
             )}
        end

      {:error, _reason} ->
        {:noreply,
         assign(socket,
           attesting: false,
           attest_error: "Authentication failed. Please check your password."
         )}
    end
  end

  # ---------------------------------------------------------------------------
  # Private helpers
  # ---------------------------------------------------------------------------

  defp handle_preparation_attestation(socket, ceremony_id, opts) do
    case CaEngineClient.check_ceremony_readiness(ceremony_id, opts) do
      :ready ->
        # All custodians ready + witness attested — trigger keygen
        passwords = CustodianPasswordStore.get_all_passwords(ceremony_id)

        case CaEngineClient.execute_ceremony_keygen(ceremony_id, passwords, opts) do
          {:ok, result} ->
            CustodianPasswordStore.wipe_ceremony(ceremony_id)

            audit_log(socket, "ceremony_keygen_triggered", "ceremony", ceremony_id, %{
              triggered_by: "witness_attestation"
            })

            Phoenix.PubSub.broadcast(
              PkiCaPortal.PubSub,
              "ceremony:#{ceremony_id}",
              {:phase_changed, %{phase: "key_generation"}}
            )

            # Notify auditor that key generation is done and needs witnessing
            CeremonyNotifications.notify_auditor_keygen_done(socket.assigns.selected_ceremony)

            assign(socket, keygen_result: result)
            |> add_activity("Key generation triggered automatically.")

          {:error, reason} ->
            CustodianPasswordStore.wipe_ceremony(ceremony_id)
            Logger.error("[ceremony_witness] Keygen failed for #{ceremony_id}: #{inspect(reason)}")
            assign(socket, attest_error: "Key generation failed: #{format_error(reason)}")
        end

      _not_ready ->
        add_activity(socket, "Preparation witnessed. Waiting for all custodians to be ready.")
    end
  end

  defp reload_selected_ceremony(socket) do
    ceremonies = reload_ceremonies(socket)
    ceremony = socket.assigns.selected_ceremony

    updated =
      if ceremony do
        Enum.find(ceremonies, fn c -> (c[:id] || c.id) == ceremony[:id] end) || ceremony
      else
        nil
      end

    assign(socket, ceremonies: ceremonies, selected_ceremony: updated)
  end

  defp reload_ceremonies(socket) do
    user = socket.assigns.current_user
    opts = tenant_opts(socket)

    case CaEngineClient.list_my_witness_ceremonies(user[:id], opts) do
      {:ok, list} -> list
      {:error, _} -> socket.assigns.ceremonies
    end
  end

  defp load_attestations(ceremony_id, opts) do
    case CaEngineClient.list_ceremony_attestations(ceremony_id, opts) do
      {:ok, list} -> list
      {:error, _} -> []
    end
  end

  defp load_shares(ceremony, opts) do
    issuer_key_id = ceremony[:issuer_key_id]

    if issuer_key_id do
      case CaEngineClient.list_threshold_shares(issuer_key_id, opts) do
        {:ok, list} -> list
        {:error, _} -> []
      end
    else
      []
    end
  end

  defp build_ceremony_timeline(ceremony, shares, attestations) do
    # 1. Ceremony initiated
    initiated = [%{
      time: ceremony[:inserted_at],
      message: "Ceremony initiated — #{ceremony[:algorithm]}, #{ceremony[:threshold_k]}-of-#{ceremony[:threshold_n]} threshold"
    }]

    # 2. Custodian share assignments (from inserted_at on shares)
    assigned = shares
    |> Enum.map(fn share ->
      name = share[:custodian_username] || "Custodian #{share[:share_index]}"
      %{
        time: share[:inserted_at],
        message: "Share ##{share[:share_index]} assigned to #{name}"
      }
    end)

    # 3. Custodian share acceptances
    accepted = shares
    |> Enum.filter(fn s -> s[:status] == "accepted" and s[:accepted_at] end)
    |> Enum.map(fn share ->
      name = share[:custodian_username] || "Custodian #{share[:share_index]}"
      %{
        time: share[:accepted_at],
        message: "#{name} accepted share ##{share[:share_index]} (label: #{share[:key_label] || "—"})"
      }
    end)

    # 4. Witness attestations
    attested = attestations
    |> Enum.map(fn att ->
      phase = att[:phase] || att["phase"] || "unknown"
      %{
        time: att[:attested_at] || att[:inserted_at],
        message: "Auditor witnessed #{phase} phase"
      }
    end)

    # 5. Ceremony completion
    completed = if ceremony[:status] == "completed" do
      [%{time: ceremony[:updated_at], message: "Ceremony completed successfully"}]
    else
      []
    end

    (initiated ++ assigned ++ accepted ++ attested ++ completed)
    |> Enum.filter(fn e -> e.time != nil end)
    |> Enum.sort_by(fn e -> to_comparable_time(e.time) end)
  end

  defp to_comparable_time(%DateTime{} = dt), do: DateTime.to_unix(dt, :microsecond)
  defp to_comparable_time(%NaiveDateTime{} = dt), do: NaiveDateTime.to_iso8601(dt)
  defp to_comparable_time(%{year: y, month: mo, day: d, hour: h, minute: mi, second: s}),
    do: :io_lib.format("~4..0B-~2..0B-~2..0BT~2..0B:~2..0B:~2..0B", [y, mo, d, h, mi, s]) |> IO.iodata_to_binary()
  defp to_comparable_time(_), do: ""

  defp add_activity(socket, message) do
    entry = %{
      message: message,
      time: DateTime.utc_now()
    }

    update(socket, :activity_log, fn log -> [entry | log] |> Enum.take(50) end)
  end

  defp tenant_opts(socket) do
    opts = [tenant_id: socket.assigns[:tenant_id]]

    case get_in(socket.assigns, [:current_user, :role]) do
      nil -> opts
      role -> [{:user_role, role} | opts]
    end
  end

  defp format_error({:validation_error, errors}) when is_map(errors) do
    errors
    |> Enum.map(fn {k, v} -> "#{k}: #{inspect(v)}" end)
    |> Enum.join(", ")
  end

  defp format_error(reason), do: inspect(reason)

  defp short_id(nil), do: "..."
  defp short_id(id) when is_binary(id), do: String.slice(id, 0, 8)
  defp short_id(_), do: "..."

  defp status_badge_class("initiated"), do: "badge-warning"
  defp status_badge_class("in_progress"), do: "badge-info"
  defp status_badge_class("key_generation"), do: "badge-accent"
  defp status_badge_class("completed"), do: "badge-success"
  defp status_badge_class("failed"), do: "badge-error"
  defp status_badge_class(_), do: "badge-ghost"

  defp phase_attested?(attestations, phase) do
    Enum.any?(attestations, fn a ->
      (a[:phase] || a["phase"]) == phase
    end)
  end

  defp all_custodians_accepted?(shares) do
    Enum.all?(shares, fn s ->
      status = s[:status] || s["status"]
      status == "accepted"
    end)
  end

  defp format_datetime(nil), do: "-"
  defp format_datetime(%NaiveDateTime{} = dt), do: Calendar.strftime(dt, "%Y-%m-%d %H:%M:%S")
  defp format_datetime(%DateTime{} = dt), do: Calendar.strftime(dt, "%Y-%m-%d %H:%M:%S")
  defp format_datetime(%{year: _, month: _, day: _, hour: _, minute: _} = dt), do: Calendar.strftime(dt, "%Y-%m-%d %H:%M:%S")
  defp format_datetime(_), do: "-"

  # ---------------------------------------------------------------------------
  # Render
  # ---------------------------------------------------------------------------

  @impl true
  def render(assigns) do
    ~H"""
    <div id="ceremony-witness-page" class="space-y-6">
      <%= if @selected_ceremony do %>
        {render_detail(assigns)}
      <% else %>
        {render_list(assigns)}
      <% end %>
    </div>
    """
  end

  defp render_list(assigns) do
    ~H"""
    <div class="alert border border-info/30 bg-info/5">
      <.icon name="hero-eye" class="size-5 text-info shrink-0" />
      <div>
        <p class="text-sm font-medium text-base-content">Auditor Witness Portal</p>
        <p class="text-xs text-base-content/60 mt-0.5">
          As an auditor, you witness each phase of key ceremonies to ensure proper procedure is followed.
          Select a ceremony below to begin witnessing.
        </p>
      </div>
    </div>

    <div :if={@loading} class="flex justify-center py-12">
      <span class="loading loading-spinner loading-md text-primary"></span>
    </div>

    <div :if={not @loading and Enum.empty?(@ceremonies)} class="card bg-base-100 shadow-sm border border-base-300">
      <div class="card-body text-center py-12 text-base-content/50 text-sm">
        <.icon name="hero-clipboard-document-check" class="size-8 mx-auto mb-2 opacity-40" />
        <p>No ceremonies assigned to you for witnessing.</p>
      </div>
    </div>

    <div :if={not @loading and not Enum.empty?(@ceremonies)} class="space-y-3">
      <h2 class="text-sm font-semibold text-base-content">Assigned Ceremonies</h2>

      <div class="grid gap-3">
        <div
          :for={ceremony <- @ceremonies}
          class="card bg-base-100 shadow-sm border border-base-300 cursor-pointer hover:border-primary/40 transition-colors"
          phx-click="select_ceremony"
          phx-value-id={ceremony[:id]}
        >
          <div class="card-body p-4">
            <div class="flex items-center justify-between">
              <div class="flex items-center gap-3">
                <div class="text-sm font-mono font-medium text-base-content">
                  {short_id(ceremony[:id])}
                </div>
                <span class={"badge badge-sm #{status_badge_class(ceremony[:status])}"}>
                  {ceremony[:status]}
                </span>
              </div>
              <div class="flex items-center gap-4 text-xs text-base-content/60">
                <span class="font-medium text-base-content/70">{ceremony[:ca_instance_name] || "—"}</span>
                <span>{ceremony[:algorithm]}</span>
                <span>{ceremony[:threshold_k]}-of-{ceremony[:threshold_n]}</span>
                <span><.local_time dt={ceremony[:initiated_at] || ceremony[:inserted_at]} /></span>
                <.icon name="hero-chevron-right" class="size-4" />
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
    """
  end

  defp render_detail(assigns) do
    ~H"""
    <div class="flex items-center gap-2 mb-4">
      <button phx-click="back_to_list" class="btn btn-ghost btn-sm gap-1">
        <.icon name="hero-arrow-left" class="size-4" />
        Back
      </button>
      <h2 class="text-sm font-semibold text-base-content">
        Ceremony {short_id(@selected_ceremony[:id])}
      </h2>
      <span class={"badge badge-sm #{status_badge_class(@selected_ceremony[:status])}"}>
        {@selected_ceremony[:status]}
      </span>
    </div>

    <%!-- Ceremony details card --%>
    <div class="card bg-base-100 shadow-sm border border-base-300">
      <div class="card-body p-4">
        <h3 class="text-xs font-semibold text-base-content/60 uppercase tracking-wider mb-3">
          Ceremony Details
        </h3>
        <div class="grid grid-cols-2 md:grid-cols-5 gap-4 text-sm">
          <div>
            <div class="text-xs text-base-content/50">CA Instance</div>
            <div class="font-medium">{@selected_ceremony[:ca_instance_name] || "—"}</div>
          </div>
          <div>
            <div class="text-xs text-base-content/50">Algorithm</div>
            <div class="font-medium">{@selected_ceremony[:algorithm]}</div>
          </div>
          <div>
            <div class="text-xs text-base-content/50">Threshold</div>
            <div class="font-medium">{@selected_ceremony[:threshold_k]}-of-{@selected_ceremony[:threshold_n]}</div>
          </div>
          <div>
            <div class="text-xs text-base-content/50">Status</div>
            <div class="font-medium">{@selected_ceremony[:status]}</div>
          </div>
          <div>
            <div class="text-xs text-base-content/50">Initiated</div>
            <div class="font-medium"><.local_time dt={@selected_ceremony[:initiated_at] || @selected_ceremony[:inserted_at]} /></div>
          </div>
        </div>
      </div>
    </div>

    <%!-- Ceremony Timeline --%>
    <div class="card bg-base-100 shadow-sm border border-base-300">
      <div class="card-body p-4">
        <h3 class="text-xs font-semibold text-base-content/60 uppercase tracking-wider mb-3">
          Ceremony Timeline
        </h3>
        <div :if={Enum.empty?(@activity_log)} class="text-xs text-base-content/40 italic py-2">
          No events recorded yet.
        </div>
        <div :if={not Enum.empty?(@activity_log)} class="space-y-1.5">
          <div :for={entry <- @activity_log} class="flex items-start gap-3 text-xs">
            <span class="text-base-content/40 font-mono shrink-0 w-36"><.local_time dt={entry.time} /></span>
            <span class="text-base-content/70">{entry.message}</span>
          </div>
        </div>
      </div>
    </div>

    <%!-- Phase cards --%>
    <div class="space-y-4">
      {render_preparation_phase(assigns)}
      {render_keygen_phase(assigns)}
      {render_completion_phase(assigns)}
    </div>

    <%!-- Attestation error --%>
    <div :if={@attest_error} class="alert alert-error text-sm">
      <.icon name="hero-exclamation-circle" class="size-4" />
      <span>{@attest_error}</span>
    </div>
    """
  end

  # -- Preparation phase card --
  defp render_preparation_phase(assigns) do
    ~H"""
    <div class="card bg-base-100 shadow-sm border border-base-300">
      <div class="card-body p-4">
        <div class="flex items-center justify-between mb-3">
          <h3 class="text-sm font-semibold text-base-content flex items-center gap-2">
            <span class="badge badge-sm badge-outline">1</span>
            Preparation Phase
          </h3>
          <%= if phase_attested?(@attestations, "preparation") do %>
            <span class="badge badge-success badge-sm gap-1">
              <.icon name="hero-check-circle" class="size-3" />
              Witnessed
            </span>
          <% else %>
            <span class="badge badge-warning badge-sm">Pending</span>
          <% end %>
        </div>

        <%!-- Custodian share status --%>
        <div class="mb-3">
          <div class="text-xs text-base-content/50 mb-2">Custodian Shares</div>
          <%= if Enum.empty?(@shares) do %>
            <div class="text-xs text-base-content/40 italic">No shares distributed yet.</div>
          <% else %>
            <div class="space-y-1">
              <div :for={share <- @shares} class="flex items-center gap-2 text-xs">
                <span class={[
                  "badge badge-xs",
                  if((share[:status] || share["status"]) == "accepted", do: "badge-success", else: "badge-warning")
                ]}>
                  {share[:status] || share["status"] || "pending"}
                </span>
                <span class="text-base-content/70">{share[:custodian_username] || share[:user_id] || "Custodian"}</span>
              </div>
            </div>
          <% end %>
        </div>

        <%!-- Witness button --%>
        <%= if not phase_attested?(@attestations, "preparation") and all_custodians_accepted?(@shares) and not Enum.empty?(@shares) do %>
          {render_witness_form(assigns, "preparation")}
        <% end %>

        <div :if={not phase_attested?(@attestations, "preparation") and (Enum.empty?(@shares) or not all_custodians_accepted?(@shares))} class="text-xs text-base-content/40 italic">
          Waiting for all custodians to accept their shares before witnessing.
        </div>
      </div>
    </div>
    """
  end

  # -- Key Generation phase card --
  defp render_keygen_phase(assigns) do
    ~H"""
    <div class="card bg-base-100 shadow-sm border border-base-300">
      <div class="card-body p-4">
        <div class="flex items-center justify-between mb-3">
          <h3 class="text-sm font-semibold text-base-content flex items-center gap-2">
            <span class="badge badge-sm badge-outline">2</span>
            Key Generation Phase
          </h3>
          <%= if phase_attested?(@attestations, "key_generation") do %>
            <span class="badge badge-success badge-sm gap-1">
              <.icon name="hero-check-circle" class="size-3" />
              Witnessed
            </span>
          <% else %>
            <span class="badge badge-warning badge-sm">Pending</span>
          <% end %>
        </div>

        <%!-- Keygen result display --%>
        <%= if @keygen_result do %>
          <div class="space-y-2 mb-3">
            <div :if={@keygen_result[:fingerprint]} class="text-xs">
              <span class="text-base-content/50">Fingerprint:</span>
              <span class="font-mono text-base-content">{@keygen_result[:fingerprint]}</span>
            </div>
            <div :if={@keygen_result[:algorithm]} class="text-xs">
              <span class="text-base-content/50">Algorithm:</span>
              <span class="font-medium">{@keygen_result[:algorithm]}</span>
            </div>
            <div :if={@keygen_result[:share_count]} class="text-xs">
              <span class="text-base-content/50">Share Count:</span>
              <span class="font-medium">{@keygen_result[:share_count]}</span>
            </div>
          </div>
        <% else %>
          <div class="text-xs text-base-content/40 italic mb-3">
            Key generation details will appear here after the preparation phase is witnessed and keygen completes.
          </div>
        <% end %>

        <%!-- Witness button: only after preparation is attested and keygen result exists --%>
        <%= if not phase_attested?(@attestations, "key_generation") and phase_attested?(@attestations, "preparation") and @keygen_result do %>
          {render_witness_form(assigns, "key_generation")}
        <% end %>
      </div>
    </div>
    """
  end

  # -- Completion phase card --
  defp render_completion_phase(assigns) do
    ~H"""
    <div class="card bg-base-100 shadow-sm border border-base-300">
      <div class="card-body p-4">
        <div class="flex items-center justify-between mb-3">
          <h3 class="text-sm font-semibold text-base-content flex items-center gap-2">
            <span class="badge badge-sm badge-outline">3</span>
            Completion Phase
          </h3>
          <%= if phase_attested?(@attestations, "completion") do %>
            <span class="badge badge-success badge-sm gap-1">
              <.icon name="hero-check-circle" class="size-3" />
              Witnessed
            </span>
          <% else %>
            <span class="badge badge-warning badge-sm">Pending</span>
          <% end %>
        </div>

        <%!-- Ceremony completion details --%>
        <div class="space-y-2 mb-3">
          <div :if={@selected_ceremony[:status] == "completed"} class="text-xs">
            <span class="text-base-content/50">Ceremony completed.</span>
          </div>
          <div :if={@selected_ceremony[:csr_pem]} class="text-xs">
            <span class="text-base-content/50">CSR:</span>
            <span class="badge badge-sm badge-info">Generated</span>
          </div>
          <div :if={@selected_ceremony[:certificate_pem]} class="text-xs">
            <span class="text-base-content/50">Certificate:</span>
            <span class="badge badge-sm badge-success">Present</span>
          </div>
        </div>

        <%!-- Attestation summary --%>
        <div :if={not Enum.empty?(@attestations)} class="mb-3">
          <div class="text-xs text-base-content/50 mb-1">All Attestations</div>
          <div class="space-y-1">
            <div :for={att <- @attestations} class="flex items-center gap-2 text-xs">
              <.icon name="hero-check-circle" class="size-3 text-success" />
              <span class="font-medium">{att[:phase] || att["phase"]}</span>
              <span class="text-base-content/40"><.local_time dt={att[:attested_at] || att[:inserted_at]} /></span>
            </div>
          </div>
        </div>

        <%!-- Witness button: only after key_generation is attested --%>
        <%= if not phase_attested?(@attestations, "completion") and phase_attested?(@attestations, "key_generation") do %>
          {render_witness_form(assigns, "completion")}
        <% end %>
      </div>
    </div>
    """
  end

  # -- Shared witness form with password re-auth --
  defp render_witness_form(assigns, phase) do
    assigns = assign(assigns, :witness_phase, phase)

    ~H"""
    <div class="border-t border-base-300 pt-3 mt-2">
      <form phx-submit="witness_phase" class="flex items-end gap-3">
        <input type="hidden" name="phase" value={@witness_phase} />
        <div class="form-control flex-1">
          <label class="label py-0.5">
            <span class="label-text text-xs">Re-enter your password to attest</span>
          </label>
          <input
            type="password"
            name="password"
            class="input input-bordered input-sm w-full"
            placeholder="Your password"
            required
            autocomplete="current-password"
          />
        </div>
        <button
          type="submit"
          class="btn btn-primary btn-sm gap-1"
          disabled={@attesting}
        >
          <%= if @attesting do %>
            <span class="loading loading-spinner loading-xs"></span>
            Attesting...
          <% else %>
            <.icon name="hero-eye" class="size-4" />
            I Witness {String.replace(@witness_phase, "_", " ") |> String.capitalize()}
          <% end %>
        </button>
      </form>
    </div>
    """
  end
end
