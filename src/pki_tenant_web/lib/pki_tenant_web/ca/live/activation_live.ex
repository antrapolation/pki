defmodule PkiTenantWeb.Ca.ActivationLive do
  @moduledoc """
  LiveView page for the activation ceremony.

  ## Views

  - **List view**: All `IssuerKey`s for the current CA instance, each showing
    lease status (active/expired, ops remaining, expires in). Lease status is
    refreshed via PubSub on `"activation:<key_id>"` events.

  - **Activation modal**: Per-key "Start activation ceremony" button. Opens a
    sequential custodian-entry modal that drives the `ActivationCeremony`
    state machine (`start/2` → repeated `submit_auth/4` calls until threshold
    is met → lease granted).

  ## Flows

  1. User clicks "Start activation" for a key
     → `ActivationCeremony.start/2` opens a session
     → modal opens, first custodian entry slot active

  2. Each custodian enters name + password
     → `ActivationCeremony.submit_auth/4` called
     → on success: either advances to next custodian, or (threshold met) lease shown as active

  3. PubSub topic `"activation:<key_id>"` delivers `:lease_granted` /
     `:lease_expired` events; `lease_status/1` is re-fetched and all
     displayed statuses refresh.
  """
  use PkiTenantWeb, :live_view

  require Logger

  alias PkiCaEngine.{CaInstanceManagement, IssuerKeyManagement, KeyActivation, ActivationCeremony}
  alias PkiMnesia.Repo
  alias PkiMnesia.Structs.ThresholdShare

  # ---------------------------------------------------------------------------
  # Mount / params / data loading
  # ---------------------------------------------------------------------------

  @impl true
  def mount(_params, _session, socket) do
    {:ok,
     assign(socket,
       page_title: "Activation Ceremony",
       ca_instances: [],
       issuer_keys: [],
       lease_statuses: %{},
       effective_ca_id: nil,
       selected_ca_id: "",
       loading: true,
       # Activation modal state
       modal_key: nil,
       active_session: nil,
       custodian_count: 0,
       threshold_k: 0,
       custodians_done: 0,
       modal_error: nil,
       modal_busy: false
     )}
  end

  @impl true
  def handle_params(params, _uri, socket) do
    if connected?(socket), do: send(self(), {:load_data, params["ca"]})
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

      issuer_keys = load_keys(effective_ca_id)
      lease_statuses = fetch_lease_statuses(issuer_keys)

      # Subscribe to PubSub for every key so live updates are delivered
      Enum.each(issuer_keys, fn key ->
        Phoenix.PubSub.subscribe(PkiTenantWeb.PubSub, "activation:#{key.id}")
      end)

      {:noreply,
       assign(socket,
         ca_instances: ca_instances,
         issuer_keys: issuer_keys,
         lease_statuses: lease_statuses,
         effective_ca_id: effective_ca_id,
         selected_ca_id: effective_ca_id || "",
         loading: false
       )}
    rescue
      e ->
        Logger.warning("[ActivationLive] Failed to load data: #{Exception.message(e)}")
        {:noreply, assign(socket, loading: false)}
    end
  end

  # PubSub: lease state changed for a key
  def handle_info({:lease_granted, %{key_id: key_id}}, socket) do
    refresh_lease(socket, key_id)
  end

  def handle_info({:lease_expired, %{key_id: key_id}}, socket) do
    refresh_lease(socket, key_id)
  end

  # Generic activation topic messages (forward-compatible)
  def handle_info({:activation_update, %{key_id: key_id}}, socket) do
    refresh_lease(socket, key_id)
  end

  def handle_info(_msg, socket), do: {:noreply, socket}

  # ---------------------------------------------------------------------------
  # Events — list view
  # ---------------------------------------------------------------------------

  @impl true
  def handle_event("select_ca_instance", %{"ca_instance_id" => ca_id}, socket) do
    path = if ca_id == "", do: "/activation", else: "/activation?ca=#{ca_id}"
    {:noreply, push_patch(socket, to: path)}
  end

  def handle_event("refresh_lease", %{"key_id" => key_id}, socket) do
    {:noreply, do_refresh_lease(socket, key_id)}
  end

  # ---------------------------------------------------------------------------
  # Events — start activation modal
  # ---------------------------------------------------------------------------

  def handle_event("start_activation", %{"key_id" => key_id}, socket) do
    if socket.assigns.current_user[:role] not in ["key_manager", "ca_admin"] do
      {:noreply, put_flash(socket, :error, "Only Key Managers and CA Admins can activate keys.")}
    else
      case Enum.find(socket.assigns.issuer_keys, fn k -> k.id == key_id end) do
        nil ->
          {:noreply, put_flash(socket, :error, "Key not found.")}

        key ->
          case ActivationCeremony.start(key_id) do
            {:ok, session} ->
              {k, _n} = resolve_threshold_display(key_id)

              {:noreply,
               assign(socket,
                 modal_key: key,
                 active_session: session,
                 threshold_k: k,
                 custodians_done: 0,
                 modal_error: nil,
                 modal_busy: false
               )}

            {:error, :no_shares_found} ->
              {:noreply,
               put_flash(socket, :error,
                 "No threshold shares found for this key. Run a key ceremony first."
               )}

            {:error, reason} ->
              Logger.warning("[ActivationLive] start/2 failed: #{inspect(reason)}")

              {:noreply,
               put_flash(socket, :error, "Could not start activation session: #{format_error(reason)}")}
          end
      end
    end
  end

  # ---------------------------------------------------------------------------
  # Events — custodian auth submission
  # ---------------------------------------------------------------------------

  def handle_event("submit_custodian_auth", params, socket) do
    session = socket.assigns.active_session
    key = socket.assigns.modal_key
    custodian_name = String.trim(params["custodian_name"] || "")
    auth_token = params["auth_token"] || ""

    cond do
      is_nil(session) or is_nil(key) ->
        {:noreply, socket}

      custodian_name == "" ->
        {:noreply, assign(socket, modal_error: "Enter your name.")}

      auth_token == "" ->
        {:noreply, assign(socket, modal_error: "Enter your password.")}

      true ->
        socket = assign(socket, modal_busy: true, modal_error: nil)

        case ActivationCeremony.submit_auth(session.id, custodian_name, auth_token) do
          {:ok, :lease_granted} ->
            # Threshold met — lease is now active
            new_statuses =
              Map.put(
                socket.assigns.lease_statuses,
                key.id,
                KeyActivation.lease_status(key.id)
              )

            Phoenix.PubSub.broadcast(
              PkiTenantWeb.PubSub,
              "activation:#{key.id}",
              {:lease_granted, %{key_id: key.id}}
            )

            PkiTenant.AuditBridge.log("activation_lease_granted", %{
              key_id: key.id,
              session_id: session.id,
              custodian: custodian_name
            })

            {:noreply,
             socket
             |> assign(
               modal_key: nil,
               active_session: nil,
               custodians_done: 0,
               threshold_k: 0,
               modal_busy: false,
               modal_error: nil,
               lease_statuses: new_statuses
             )
             |> put_flash(:info, "Lease granted for #{key.key_alias || key.id}.")}

          {:ok, %{} = updated_session} ->
            # Auth accepted, more custodians needed
            done = length(updated_session.authenticated_custodians)

            PkiTenant.AuditBridge.log("activation_custodian_authenticated", %{
              key_id: key.id,
              session_id: session.id,
              custodian: custodian_name,
              authenticated_count: done
            })

            {:noreply,
             assign(socket,
               active_session: updated_session,
               custodians_done: done,
               modal_busy: false,
               modal_error: nil
             )}

          {:error, :already_authenticated} ->
            {:noreply,
             assign(socket,
               modal_busy: false,
               modal_error: "#{custodian_name} has already authenticated in this session."
             )}

          {:error, :authentication_failed} ->
            {:noreply,
             assign(socket,
               modal_busy: false,
               modal_error: "Authentication failed — wrong password for #{custodian_name}."
             )}

          {:error, :share_not_found} ->
            {:noreply,
             assign(socket,
               modal_busy: false,
               modal_error: "No threshold share found for custodian '#{custodian_name}'."
             )}

          {:error, :session_closed} ->
            {:noreply,
             socket
             |> assign(modal_key: nil, active_session: nil, modal_busy: false)
             |> put_flash(:error, "Session closed — start a new activation.")}

          {:error, reason} ->
            Logger.warning("[ActivationLive] submit_auth failed: #{inspect(reason)}")

            {:noreply,
             assign(socket,
               modal_busy: false,
               modal_error: "Error: #{format_error(reason)}"
             )}
        end
    end
  end

  # ---------------------------------------------------------------------------
  # Events — cancel modal
  # ---------------------------------------------------------------------------

  def handle_event("cancel_activation", _params, socket) do
    if session = socket.assigns.active_session do
      ActivationCeremony.cancel(session.id, "cancelled_by_user")
    end

    {:noreply,
     assign(socket,
       modal_key: nil,
       active_session: nil,
       custodians_done: 0,
       threshold_k: 0,
       modal_error: nil,
       modal_busy: false
     )}
  end

  # ---------------------------------------------------------------------------
  # Private helpers
  # ---------------------------------------------------------------------------

  defp load_keys(nil), do: []

  defp load_keys(ca_id) do
    case IssuerKeyManagement.list_issuer_keys(ca_id) do
      {:ok, keys} -> keys
      _ -> []
    end
  rescue
    _ -> []
  end

  defp fetch_lease_statuses(keys) do
    Enum.reduce(keys, %{}, fn key, acc ->
      status = KeyActivation.lease_status(key.id)
      Map.put(acc, key.id, status)
    end)
  rescue
    _ -> %{}
  end

  defp refresh_lease(socket, key_id) do
    {:noreply, do_refresh_lease(socket, key_id)}
  end

  defp do_refresh_lease(socket, key_id) do
    status = KeyActivation.lease_status(key_id)
    new_statuses = Map.put(socket.assigns.lease_statuses, key_id, status)
    assign(socket, lease_statuses: new_statuses)
  end

  defp resolve_threshold_display(key_id) do
    case Repo.get_all_by_index(ThresholdShare, :issuer_key_id, key_id) do
      {:ok, [share | _]} -> {share.min_shares, share.total_shares}
      _ -> {2, 3}
    end
  rescue
    _ -> {2, 3}
  end

  defp format_error({:persist_failed, reason}), do: "Persist failed: #{inspect(reason)}"
  defp format_error({:share_lookup_failed, reason}), do: "Share lookup failed: #{inspect(reason)}"
  defp format_error(reason) when is_binary(reason), do: reason
  defp format_error(reason) when is_atom(reason), do: to_string(reason)
  defp format_error(_), do: "an unexpected error occurred"

  defp lease_badge_class(true), do: "badge-success"
  defp lease_badge_class(false), do: "badge-ghost"

  defp format_expires_in(nil), do: "—"

  defp format_expires_in(seconds) when is_integer(seconds) and seconds > 0 do
    hours = div(seconds, 3600)
    minutes = div(rem(seconds, 3600), 60)

    cond do
      hours > 0 -> "#{hours}h #{minutes}m"
      minutes > 0 -> "#{minutes}m"
      true -> "< 1m"
    end
  end

  defp format_expires_in(_), do: "expired"

  defp key_status_badge("active"), do: "badge-success"
  defp key_status_badge("pending"), do: "badge-warning"
  defp key_status_badge("suspended"), do: "badge-error"
  defp key_status_badge("retired"), do: "badge-ghost"
  defp key_status_badge(_), do: "badge-ghost"

  # ---------------------------------------------------------------------------
  # Render
  # ---------------------------------------------------------------------------

  @impl true
  def render(assigns) do
    ~H"""
    <div id="activation-page" class="space-y-6">
      <%= if @modal_key do %>
        {render_activation_modal(assigns)}
      <% end %>
      {render_list_view(assigns)}
    </div>
    """
  end

  defp render_list_view(assigns) do
    ~H"""
    <%!-- Info banner --%>
    <div class="alert border border-info/30 bg-info/5">
      <.icon name="hero-information-circle" class="size-5 text-info shrink-0" />
      <div>
        <p class="text-sm font-medium text-base-content">Key Activation Ceremony</p>
        <p class="text-xs text-base-content/60 mt-0.5">
          Activate an issuer key by having the required custodians authenticate with
          their per-ceremony passwords.  Once the threshold is met, a timed lease
          is granted and the key becomes available for signing operations.
        </p>
      </div>
    </div>

    <%!-- CA Instance selector --%>
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

    <%!-- No CA selected --%>
    <div :if={is_nil(@effective_ca_id) and not @loading} class="card bg-base-100 shadow-sm border border-base-300">
      <div class="card-body text-center py-8 text-base-content/50 text-sm">
        Select a CA instance above to view issuer keys and start an activation ceremony.
      </div>
    </div>

    <%!-- Loading --%>
    <div :if={@loading} class="flex justify-center py-12">
      <span class="loading loading-spinner loading-md text-primary"></span>
    </div>

    <%!-- Keys table --%>
    <div :if={@effective_ca_id and not @loading} class="card bg-base-100 shadow-sm border border-base-300">
      <div class="card-body p-0">
        <div class="px-5 py-4 border-b border-base-300 flex items-center justify-between">
          <h2 class="text-sm font-semibold text-base-content">Issuer Keys</h2>
          <span class="text-xs text-base-content/50">{length(@issuer_keys)} key(s)</span>
        </div>

        <div :if={Enum.empty?(@issuer_keys)} class="p-8 text-center text-base-content/50 text-sm">
          No issuer keys found for this CA instance.
          <br />
          <a href="/ceremonies" class="link link-primary mt-1 inline-block">
            Run a key ceremony to generate one.
          </a>
        </div>

        <div :if={not Enum.empty?(@issuer_keys)}>
          <table class="table table-sm w-full">
            <thead>
              <tr class="text-xs uppercase text-base-content/50">
                <th class="w-[22%]">Key Alias</th>
                <th class="w-[14%]">Algorithm</th>
                <th class="w-[12%]">Status</th>
                <th class="w-[14%]">Lease</th>
                <th class="w-[22%]">Lease Details</th>
                <th class="w-[16%]"></th>
              </tr>
            </thead>
            <tbody>
              <tr :for={key <- @issuer_keys} class="hover" id={"key-row-#{key.id}"}>
                <td class="text-sm font-medium overflow-hidden text-ellipsis whitespace-nowrap" title={key.key_alias}>
                  <%= if key.key_alias && key.key_alias != "" do %>
                    {key.key_alias}
                  <% else %>
                    <span class="text-base-content/40 italic">—</span>
                  <% end %>
                </td>
                <td class="font-mono text-xs text-base-content/70">{key.algorithm}</td>
                <td>
                  <span class={"badge badge-sm #{key_status_badge(key.status)}"}>{key.status}</span>
                </td>
                <% lease = Map.get(@lease_statuses, key.id, %{active: false, expires_in_seconds: nil, ops_remaining: nil}) %>
                <td>
                  <span class={"badge badge-sm #{lease_badge_class(lease.active)}"}>
                    {if lease.active, do: "active", else: "inactive"}
                  </span>
                </td>
                <td class="text-xs text-base-content/60">
                  <%= if lease.active do %>
                    <span class="font-semibold text-success">
                      Expires in: {format_expires_in(lease.expires_in_seconds)}
                    </span>
                    <span class="ml-2 text-base-content/40">
                      | {lease.ops_remaining} ops left
                    </span>
                  <% else %>
                    <span class="text-base-content/30">No active lease</span>
                  <% end %>
                </td>
                <td class="flex items-center gap-1 justify-end">
                  <button
                    phx-click="refresh_lease"
                    phx-value-key_id={key.id}
                    title="Refresh lease status"
                    class="btn btn-ghost btn-xs text-base-content/50"
                  >
                    <.icon name="hero-arrow-path" class="size-3.5" />
                  </button>
                  <button
                    :if={key.status in ["active", "pending"]}
                    phx-click="start_activation"
                    phx-value-key_id={key.id}
                    title="Start activation ceremony"
                    class="btn btn-primary btn-xs"
                  >
                    <.icon name="hero-key" class="size-3.5" />
                    Activate
                  </button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
    """
  end

  defp render_activation_modal(assigns) do
    ~H"""
    <div class="modal modal-open" role="dialog" aria-labelledby="activation-modal-title">
      <div class="modal-box max-w-md">
        <h2 id="activation-modal-title" class="text-base font-semibold mb-1">
          <.icon name="hero-key" class="size-4 inline" />
          Activate: {@modal_key.key_alias || String.slice(@modal_key.id, 0..7)}
        </h2>

        <%!-- Progress indicator --%>
        <div class="mb-4 flex items-center gap-2 text-xs text-base-content/60">
          <span class="badge badge-sm badge-info">{@custodians_done}/{@threshold_k} custodians authenticated</span>
          <span>— threshold to unlock: {@threshold_k}</span>
        </div>

        <p class="text-xs text-base-content/60 mb-4">
          Each custodian enters the name they used during the key ceremony and their
          per-ceremony password. Authentication is verified against the stored
          encrypted share. Once {@threshold_k} custodian(s) have authenticated,
          a lease is granted.
        </p>

        <form phx-submit="submit_custodian_auth" class="space-y-3" autocomplete="off">
          <div>
            <label class="block text-xs font-medium text-base-content/70 mb-1">
              Custodian name (as registered in ceremony)
            </label>
            <input
              type="text"
              name="custodian_name"
              maxlength="128"
              autofocus
              required
              disabled={@modal_busy}
              class="input input-bordered input-sm w-full"
              placeholder="e.g. Jane Roe"
            />
          </div>

          <div>
            <label class="block text-xs font-medium text-base-content/70 mb-1">
              Password (per-ceremony password)
            </label>
            <input
              type="password"
              name="auth_token"
              required
              disabled={@modal_busy}
              class="input input-bordered input-sm w-full font-mono"
            />
          </div>

          <div :if={@modal_error} class="alert alert-error text-sm py-2">
            <.icon name="hero-exclamation-circle" class="size-4" />
            <span>{@modal_error}</span>
          </div>

          <div class="modal-action mt-4 flex items-center justify-between">
            <button
              type="button"
              phx-click="cancel_activation"
              disabled={@modal_busy}
              class="btn btn-ghost btn-sm"
            >
              Cancel
            </button>
            <button type="submit" disabled={@modal_busy} class="btn btn-primary btn-sm">
              <%= if @modal_busy do %>
                <span class="loading loading-spinner loading-xs"></span>
                Verifying…
              <% else %>
                <.icon name="hero-shield-check" class="size-4" />
                Authenticate
              <% end %>
            </button>
          </div>
        </form>
      </div>
    </div>
    """
  end
end
