defmodule PkiTenantWeb.Ca.CeremonyWitnessLive do
  @moduledoc """
  Auditor-facing view for witnessing a key ceremony.

  Loads the ceremony, displays custodian attestation state and the
  hash-chained transcript timeline. The auditor confirms presence via
  the "Witness ceremony" button which records an `auditor_witnessed`
  event through CeremonyOrchestrator.

  Full auditor transcript-signing (digital signature on the transcript
  digest) is wired in task E4.2; this scaffold provides the page and the
  placeholder call.
  """

  use PkiTenantWeb, :live_view

  require Logger

  alias PkiCaEngine.CeremonyOrchestrator
  alias PkiMnesia.Repo
  alias PkiMnesia.Structs.{KeyCeremony, CeremonyParticipant, CeremonyTranscript}

  @impl true
  def mount(_params, _session, socket) do
    {:ok,
     assign(socket,
       page_title: "Ceremony Witness",
       ceremony: nil,
       participants: [],
       transcript: nil,
       loading: true,
       witness_error: nil,
       witness_done: false,
       accept_error: nil,
       accept_done: false
     )}
  end

  @impl true
  def handle_params(%{"id" => ceremony_id}, _uri, socket) do
    if connected?(socket) do
      send(self(), {:load_ceremony, ceremony_id})
      Phoenix.PubSub.subscribe(PkiTenantWeb.PubSub, "ceremony:#{ceremony_id}")
    end

    {:noreply, socket}
  end

  def handle_params(_params, _uri, socket) do
    {:noreply,
     socket
     |> put_flash(:error, "No ceremony ID provided.")
     |> push_navigate(to: "/ceremonies")}
  end

  @impl true
  def handle_info({:load_ceremony, ceremony_id}, socket) do
    ceremony =
      case Repo.get(KeyCeremony, ceremony_id) do
        {:ok, c} when not is_nil(c) -> c
        _ -> nil
      end

    if is_nil(ceremony) do
      {:noreply,
       socket
       |> assign(loading: false)
       |> put_flash(:error, "Ceremony not found.")}
    else
      participants =
        case CeremonyOrchestrator.list_participants(ceremony_id) do
          {:ok, ps} -> ps
          _ -> []
        end

      transcript =
        case CeremonyOrchestrator.get_transcript(ceremony_id) do
          {:ok, t} -> t
          _ -> nil
        end

      {:noreply,
       assign(socket,
         ceremony: ceremony,
         participants: participants,
         transcript: transcript,
         loading: false
       )}
    end
  end

  # PubSub: refresh on ceremony state changes
  def handle_info({event, _details}, socket)
      when event in [:ceremony_completed, :phase_changed, :ceremony_failed] do
    if c = socket.assigns.ceremony do
      send(self(), {:load_ceremony, c.id})
    end

    {:noreply, socket}
  end

  def handle_info(_msg, socket), do: {:noreply, socket}

  @impl true
  def handle_event("witness_ceremony", _params, socket) do
    ceremony = socket.assigns.ceremony
    auditor = socket.assigns.current_user

    if is_nil(ceremony) do
      {:noreply, assign(socket, witness_error: "Ceremony not loaded.")}
    else
      case CeremonyOrchestrator.record_auditor_witness(
             ceremony.id,
             auditor[:username] || auditor[:display_name] || "auditor",
             %{user_id: auditor[:id]}
           ) do
        {:ok, _} ->
          PkiTenant.AuditBridge.log("auditor_witnessed", %{
            ceremony_id: ceremony.id,
            auditor: auditor[:username]
          })

          send(self(), {:load_ceremony, ceremony.id})
          {:noreply, assign(socket, witness_done: true, witness_error: nil)}

        {:error, reason} ->
          {:noreply, assign(socket, witness_error: format_error(reason))}
      end
    end
  end

  @impl true
  def handle_event("accept_ceremony", _params, socket) do
    ceremony = socket.assigns.ceremony
    current_user = socket.assigns.current_user

    cond do
      is_nil(ceremony) ->
        {:noreply, assign(socket, accept_error: "Ceremony not loaded.")}

      ceremony.status != "awaiting_auditor_acceptance" ->
        {:noreply, assign(socket, accept_error: "Ceremony is not awaiting auditor acceptance.")}

      current_user[:role] != :auditor and current_user[:role] != "auditor" ->
        {:noreply, assign(socket, accept_error: "Only an auditor may accept this ceremony.")}

      true ->
        auditor_user_id = current_user[:id]

        case CeremonyOrchestrator.accept_auditor_witness(ceremony.id, auditor_user_id) do
          {:ok, _updated} ->
            PkiTenant.AuditBridge.log("auditor_accepted_ceremony", %{
              ceremony_id: ceremony.id,
              auditor_user_id: auditor_user_id
            })

            send(self(), {:load_ceremony, ceremony.id})
            {:noreply, assign(socket, accept_done: true, accept_error: nil)}

          {:error, :auditor_required} ->
            {:noreply, assign(socket, accept_error: "You do not have the auditor role.")}

          {:error, reason} ->
            {:noreply, assign(socket, accept_error: format_error(reason))}
        end
    end
  end

  # ---------------------------------------------------------------------------
  # Render
  # ---------------------------------------------------------------------------

  @impl true
  def render(assigns) do
    ~H"""
    <div id="ceremony-witness-page" class="space-y-6 max-w-3xl mx-auto">
      <div class="flex items-center gap-3">
        <.icon name="hero-eye" class="size-6 text-accent" />
        <h1 class="text-lg font-semibold text-base-content">Auditor Witness View</h1>
      </div>

      <div :if={@loading} class="flex justify-center py-12">
        <span class="loading loading-spinner loading-md text-base-content/40"></span>
      </div>

      <div :if={not @loading and is_nil(@ceremony)} class="alert alert-error text-sm">
        <.icon name="hero-exclamation-circle" class="size-4" />
        <span>Ceremony not found or access denied.</span>
      </div>

      <%= if not @loading and @ceremony do %>
        {render_ceremony_details(assigns)}
        {render_participants(assigns)}
        {render_transcript_timeline(assigns)}
        {render_witness_action(assigns)}
      <% end %>
    </div>
    """
  end

  defp render_ceremony_details(assigns) do
    ~H"""
    <div class="card bg-base-100 shadow-sm border border-base-300">
      <div class="card-body">
        <h2 class="text-sm font-semibold text-base-content mb-3">
          <.icon name="hero-shield-check" class="size-4 inline" /> Ceremony Details
        </h2>
        <div class="bg-base-200/50 rounded-lg p-4 text-sm space-y-1">
          <div class="flex gap-2">
            <span class="text-base-content/50 w-32">Ceremony ID:</span>
            <span class="font-mono">{String.slice(@ceremony.id || "", 0..15)}</span>
          </div>
          <div class="flex gap-2">
            <span class="text-base-content/50 w-32">Algorithm:</span>
            <span class="font-mono font-semibold">{@ceremony.algorithm}</span>
          </div>
          <div class="flex gap-2">
            <span class="text-base-content/50 w-32">Threshold:</span>
            <span>{@ceremony.threshold_k}-of-{@ceremony.threshold_n}</span>
          </div>
          <div class="flex gap-2">
            <span class="text-base-content/50 w-32">Status:</span>
            <span class={"badge badge-sm #{status_badge_class(@ceremony.status)}"}>{@ceremony.status}</span>
          </div>
          <div class="flex gap-2">
            <span class="text-base-content/50 w-32">Initiated by:</span>
            <span>{@ceremony.initiated_by || "—"}</span>
          </div>
          <div class="flex gap-2">
            <span class="text-base-content/50 w-32">Started:</span>
            <span class="text-xs"><.local_time dt={@ceremony.inserted_at} /></span>
          </div>
        </div>
      </div>
    </div>
    """
  end

  defp render_participants(assigns) do
    ~H"""
    <div class="card bg-base-100 shadow-sm border border-base-300">
      <div class="card-body">
        <h2 class="text-sm font-semibold text-base-content mb-3">
          <.icon name="hero-user-group" class="size-4 inline" /> Custodians & Participants
        </h2>
        <div :if={Enum.empty?(@participants)} class="text-sm text-base-content/50 text-center py-4">
          No participants recorded yet.
        </div>
        <table :if={not Enum.empty?(@participants)} class="table table-sm table-fixed w-full">
          <thead>
            <tr class="text-xs uppercase text-base-content/50">
              <th class="w-[40%]">Name</th>
              <th class="w-[20%]">Role</th>
              <th class="w-[20%]">Attestation</th>
              <th class="w-[20%]">Timestamp</th>
            </tr>
          </thead>
          <tbody>
            <tr :for={p <- @participants} class="hover">
              <td class="text-sm font-medium">{p.name}</td>
              <td>
                <span class={"badge badge-sm #{role_badge_class(p.role)}"}>{format_role(p.role)}</span>
              </td>
              <td>
                <span class={"badge badge-sm #{attestation_badge_class(p)}"}>
                  {attestation_label(p)}
                </span>
              </td>
              <td class="text-xs text-base-content/60">
                <.local_time dt={p.share_accepted_at || p.identity_verified_at} />
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
    """
  end

  defp render_transcript_timeline(assigns) do
    ~H"""
    <div class="card bg-base-100 shadow-sm border border-base-300">
      <div class="card-body">
        <h2 class="text-sm font-semibold text-base-content mb-3">
          <.icon name="hero-clock" class="size-4 inline" /> Ceremony Transcript
        </h2>

        <div :if={is_nil(@transcript)} class="text-sm text-base-content/50 text-center py-4">
          No transcript available yet.
        </div>

        <div :if={@transcript} class="space-y-2 max-h-72 overflow-y-auto">
          <div
            :for={{entry, idx} <- Enum.with_index(@transcript.entries || [])}
            class="flex items-start gap-3 text-sm"
          >
            <span class="text-xs font-mono text-base-content/40 shrink-0 w-5 mt-0.5">{idx + 1}.</span>
            <span class="text-xs text-base-content/40 font-mono shrink-0 mt-0.5 w-40">
              {format_entry_time(entry)}
            </span>
            <div class="flex-1 min-w-0">
              <span class="font-medium text-base-content/80">{entry["actor"] || entry[:actor]}</span>
              <span class="text-base-content/50 mx-1">·</span>
              <span class="text-base-content/70">{entry["action"] || entry[:action]}</span>
            </div>
          </div>
          <div :if={Enum.empty?(@transcript.entries || [])} class="text-sm text-base-content/50 text-center py-4">
            No transcript entries yet.
          </div>
        </div>
      </div>
    </div>
    """
  end

  defp render_witness_action(assigns) do
    ~H"""
    <div class="card bg-base-100 shadow-sm border border-base-300">
      <div class="card-body">
        <h2 class="text-sm font-semibold text-base-content mb-2">
          <.icon name="hero-pencil-square" class="size-4 inline" /> Auditor Action
        </h2>

        <p class="text-xs text-base-content/60 mb-4">
          By clicking "Witness ceremony" you confirm that you have observed
          the ceremony in person and attest to the accuracy of the transcript
          above. This action is recorded in the audit log. Digital signature
          of the transcript digest will be added in a future release.
        </p>

        <%!-- Accept-and-witness button: shown only when status is awaiting_auditor_acceptance
            and the current user is an auditor. --%>
        <%= if @ceremony.status == "awaiting_auditor_acceptance" and
               (@current_user[:role] == :auditor or @current_user[:role] == "auditor") do %>
          <div :if={@accept_error} class="alert alert-error text-sm mb-3 py-2">
            <.icon name="hero-exclamation-circle" class="size-4" />
            <span>{@accept_error}</span>
          </div>

          <div :if={@accept_done} class="alert alert-success text-sm mb-3 py-2">
            <.icon name="hero-check-circle" class="size-4" />
            <span>You have accepted the witness role. The ceremony may now proceed.</span>
          </div>

          <button
            phx-click="accept_ceremony"
            disabled={@accept_done}
            class="btn btn-warning btn-sm mb-3"
          >
            <.icon name="hero-shield-check" class="size-4" />
            Accept and witness
          </button>
        <% end %>

        <div :if={@witness_error} class="alert alert-error text-sm mb-3 py-2">
          <.icon name="hero-exclamation-circle" class="size-4" />
          <span>{@witness_error}</span>
        </div>

        <div :if={@witness_done} class="alert alert-success text-sm mb-3 py-2">
          <.icon name="hero-check-circle" class="size-4" />
          <span>Witness attestation recorded successfully.</span>
        </div>

        <button
          phx-click="witness_ceremony"
          disabled={@witness_done or @ceremony.status == "failed"}
          class="btn btn-accent btn-sm"
        >
          <.icon name="hero-eye" class="size-4" />
          Witness ceremony
        </button>
      </div>
    </div>
    """
  end

  # ---------------------------------------------------------------------------
  # Private helpers
  # ---------------------------------------------------------------------------

  defp status_badge_class("initiated"), do: "badge-warning"
  defp status_badge_class("preparing"), do: "badge-warning"
  defp status_badge_class("in_progress"), do: "badge-info"
  defp status_badge_class("generating"), do: "badge-info"
  defp status_badge_class("completed"), do: "badge-success"
  defp status_badge_class("failed"), do: "badge-error"
  defp status_badge_class(_), do: "badge-ghost"

  defp role_badge_class(:auditor), do: "badge-accent"
  defp role_badge_class(:key_manager), do: "badge-info"
  defp role_badge_class(_), do: "badge-ghost"

  defp format_role(:auditor), do: "Auditor"
  defp format_role(:key_manager), do: "Key Manager"
  defp format_role(:custodian), do: "Custodian"
  defp format_role(r), do: to_string(r)

  defp attestation_label(%{share_accepted_at: at}) when not is_nil(at), do: "accepted"
  defp attestation_label(%{identity_verified_at: at}) when not is_nil(at), do: "verified"
  defp attestation_label(%{role: :auditor}), do: "registered"
  defp attestation_label(_), do: "pending"

  defp attestation_badge_class(p) do
    case attestation_label(p) do
      "accepted" -> "badge-success"
      "verified" -> "badge-info"
      "registered" -> "badge-info"
      _ -> "badge-ghost"
    end
  end

  defp format_entry_time(%{"timestamp" => ts}) when is_binary(ts), do: String.slice(ts, 0..18)
  defp format_entry_time(%{timestamp: ts}) when is_binary(ts), do: String.slice(ts, 0..18)
  defp format_entry_time(%{"timestamp" => %DateTime{} = dt}), do: Calendar.strftime(dt, "%Y-%m-%d %H:%M:%S")
  defp format_entry_time(_), do: "—"

  defp format_error(reason) when is_atom(reason), do: to_string(reason) |> String.replace("_", " ")
  defp format_error(reason) when is_binary(reason), do: reason
  defp format_error(_), do: "unexpected error"
end
