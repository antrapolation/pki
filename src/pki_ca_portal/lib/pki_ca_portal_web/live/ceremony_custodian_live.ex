defmodule PkiCaPortalWeb.CeremonyCustodianLive do
  use PkiCaPortalWeb, :live_view

  alias PkiCaPortal.CaEngineClient
  alias PkiCaPortal.CustodianPasswordStore
  alias PkiCaPortal.CeremonyNotifications
  import PkiCaPortalWeb.AuditHelpers, only: [audit_log: 5]

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket), do: send(self(), :load_shares)

    {:ok,
     assign(socket,
       page_title: "My Ceremony Shares",
       shares: [],
       selected_ceremony_id: nil,
       key_label: "",
       password: "",
       password_confirmation: "",
       error: nil,
       activity_log: [],
       loading: true
     )}
  end

  @impl true
  def handle_info(:load_shares, socket) do
    user_id = socket.assigns.current_user[:id]
    opts = tenant_opts(socket)

    shares =
      case CaEngineClient.list_my_ceremony_shares(user_id, opts) do
        {:ok, shares} -> shares
        {:error, _} -> []
      end

    # Subscribe to PubSub for each ceremony
    for share <- shares do
      Phoenix.PubSub.subscribe(PkiCaPortal.PubSub, "ceremony:#{share.ceremony_id}")
    end

    {:noreply, assign(socket, shares: shares, loading: false)}
  end

  def handle_info({:custodian_ready, %{user_id: _uid, username: username}}, socket) do
    entry = %{
      time: DateTime.utc_now(),
      message: "#{username} accepted their share"
    }

    activity_log = [entry | socket.assigns.activity_log] |> Enum.take(50)

    # Reload shares to reflect updated statuses
    shares = reload_shares(socket)

    {:noreply, assign(socket, activity_log: activity_log, shares: shares)}
  end

  def handle_info({:ceremony_status_changed, %{status: status, ceremony_id: ceremony_id}}, socket) do
    entry = %{
      time: DateTime.utc_now(),
      message: "Ceremony #{String.slice(ceremony_id, 0, 8)} status changed to #{status}"
    }

    activity_log = [entry | socket.assigns.activity_log] |> Enum.take(50)
    shares = reload_shares(socket)

    {:noreply, assign(socket, activity_log: activity_log, shares: shares)}
  end

  def handle_info(_msg, socket), do: {:noreply, socket}

  # ---------------------------------------------------------------------------
  # Events
  # ---------------------------------------------------------------------------

  @impl true
  def handle_event("select_ceremony", %{"ceremony-id" => ceremony_id}, socket) do
    {:noreply,
     assign(socket,
       selected_ceremony_id: ceremony_id,
       key_label: "",
       password: "",
       password_confirmation: "",
       error: nil
     )}
  end

  def handle_event("validate", params, socket) do
    {:noreply,
     assign(socket,
       key_label: params["key_label"] || socket.assigns.key_label,
       password: params["password"] || socket.assigns.password,
       password_confirmation: params["password_confirmation"] || socket.assigns.password_confirmation,
       error: nil
     )}
  end

  def handle_event("accept_share", params, socket) do
    key_label = String.trim(params["key_label"] || "")
    password = params["password"] || ""
    password_confirmation = params["password_confirmation"] || ""
    ceremony_id = socket.assigns.selected_ceremony_id
    user = socket.assigns.current_user
    opts = tenant_opts(socket)

    with :ok <- validate_key_label(key_label),
         :ok <- validate_password(password, password_confirmation) do
      case CaEngineClient.accept_ceremony_share(ceremony_id, user[:id], key_label, opts) do
        {:ok, _} ->
          # Store password in ETS for later share encryption
          CustodianPasswordStore.store_password(ceremony_id, user[:id], password)

          # Broadcast custodian ready
          Phoenix.PubSub.broadcast(
            PkiCaPortal.PubSub,
            "ceremony:#{ceremony_id}",
            {:custodian_ready, %{user_id: user[:id], username: user[:username]}}
          )

          # Audit log
          audit_log(socket, "ceremony_share_accepted", "ceremony", ceremony_id, %{
            key_label: key_label,
            username: user[:username]
          })

          # Reload shares and check if all custodians are ready
          shares = reload_shares(socket)
          check_all_custodians_ready(ceremony_id, shares, opts)

          {:noreply,
           assign(socket,
             shares: shares,
             password: "",
             password_confirmation: "",
             error: nil
           )}

        {:error, reason} ->
          {:noreply, assign(socket, error: format_error(reason))}
      end
    else
      {:error, msg} ->
        {:noreply, assign(socket, error: msg)}
    end
  end

  # ---------------------------------------------------------------------------
  # Render
  # ---------------------------------------------------------------------------

  @impl true
  def render(assigns) do
    ~H"""
    <div class="p-6">
      <h1 class="text-2xl font-bold mb-6">My Ceremony Shares</h1>

      <div :if={@loading} class="flex justify-center py-12">
        <span class="loading loading-spinner loading-lg"></span>
      </div>

      <div :if={!@loading} class="grid grid-cols-3 gap-6">
        <%!-- Ceremony list --%>
        <div class="col-span-1">
          <h2 class="text-sm font-semibold text-base-content/70 mb-3 uppercase tracking-wide">Assigned Ceremonies</h2>
          <div class="space-y-2">
            <div
              :for={share <- @shares}
              class={[
                "card bg-base-100 shadow-sm cursor-pointer p-4 border-2 transition-colors",
                if(share.ceremony_id == @selected_ceremony_id, do: "border-primary", else: "border-transparent hover:border-base-300")
              ]}
              phx-click="select_ceremony"
              phx-value-ceremony-id={share.ceremony_id}
            >
              <div class="flex items-center justify-between">
                <span class="font-mono text-sm">{String.slice(share.ceremony_id, 0, 8)}</span>
                <span class={["badge badge-sm", share_badge(share.share_status)]}>{share.share_status}</span>
              </div>
              <div class="text-xs text-base-content/60 mt-1">{share.algorithm}</div>
              <div class="text-xs text-base-content/40 mt-1">
                {share.threshold_k}-of-{share.threshold_n} threshold
              </div>
            </div>
            <div :if={@shares == []} class="text-center text-base-content/50 py-8">
              No ceremonies assigned to you.
            </div>
          </div>
        </div>

        <%!-- Detail panel --%>
        <div class="col-span-2">
          <div :if={@selected_ceremony_id == nil} class="flex items-center justify-center h-64 text-base-content/40">
            Select a ceremony from the list to view details.
          </div>

          <%= if @selected_ceremony_id do %>
            <% share = selected_share(@shares, @selected_ceremony_id) %>
            <%= if share do %>
              <%!-- Ceremony details card --%>
              <div class="card bg-base-100 shadow-sm p-6 mb-4">
                <h2 class="text-lg font-semibold mb-4">Ceremony Details</h2>
                <div class="grid grid-cols-2 gap-4 text-sm">
                  <div>
                    <span class="text-base-content/60">Ceremony ID</span>
                    <p class="font-mono">{share.ceremony_id}</p>
                  </div>
                  <div>
                    <span class="text-base-content/60">Algorithm</span>
                    <p class="font-semibold">{share.algorithm}</p>
                  </div>
                  <div>
                    <span class="text-base-content/60">Threshold</span>
                    <p>{share.threshold_k}-of-{share.threshold_n}</p>
                  </div>
                  <div>
                    <span class="text-base-content/60">Share Index</span>
                    <p>#{share.share_index}</p>
                  </div>
                  <div>
                    <span class="text-base-content/60">Ceremony Status</span>
                    <p>
                      <span class={["badge badge-sm", ceremony_badge(share.ceremony_status)]}>{share.ceremony_status}</span>
                    </p>
                  </div>
                  <div>
                    <span class="text-base-content/60">Time Remaining</span>
                    <p class={if time_remaining_urgent?(share.window_expires_at), do: "text-error font-semibold", else: ""}>
                      {format_time_remaining(share.window_expires_at)}
                    </p>
                  </div>
                </div>
              </div>

              <%!-- Accept form (pending) --%>
              <%= if share.share_status == "pending" do %>
                <div class="card bg-base-100 shadow-sm p-6">
                  <h3 class="text-lg font-semibold mb-4">Accept Your Share</h3>
                  <p class="text-sm text-base-content/60 mb-4">
                    Provide a key label and a password to protect your share. The password is stored in memory only
                    and will be used during the ceremony preparation phase.
                  </p>

                  <div :if={@error} class="alert alert-error mb-4">
                    <svg xmlns="http://www.w3.org/2000/svg" class="stroke-current shrink-0 h-5 w-5" fill="none" viewBox="0 0 24 24">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                    <span>{@error}</span>
                  </div>

                  <form phx-submit="accept_share" phx-change="validate" class="space-y-4">
                    <div class="form-control">
                      <label class="label">
                        <span class="label-text">Key Label</span>
                      </label>
                      <input
                        type="text"
                        name="key_label"
                        value={@key_label}
                        placeholder="e.g. my-ceremony-key-1"
                        class="input input-bordered w-full"
                        maxlength="64"
                        required
                      />
                      <label class="label">
                        <span class="label-text-alt text-base-content/50">Alphanumeric and hyphens only, max 64 characters</span>
                      </label>
                    </div>

                    <div class="form-control">
                      <label class="label">
                        <span class="label-text">Password</span>
                      </label>
                      <input
                        type="password"
                        name="password"
                        value={@password}
                        placeholder="Minimum 8 characters"
                        class="input input-bordered w-full"
                        required
                      />
                    </div>

                    <div class="form-control">
                      <label class="label">
                        <span class="label-text">Confirm Password</span>
                      </label>
                      <input
                        type="password"
                        name="password_confirmation"
                        value={@password_confirmation}
                        placeholder="Re-enter password"
                        class="input input-bordered w-full"
                        required
                      />
                    </div>

                    <div class="flex justify-end pt-2">
                      <button type="submit" class="btn btn-primary">
                        Accept Share
                      </button>
                    </div>
                  </form>
                </div>
              <% end %>

              <%!-- Accepted confirmation --%>
              <%= if share.share_status == "accepted" do %>
                <div class="card bg-base-100 shadow-sm p-6">
                  <div class="flex items-center gap-3 mb-4">
                    <svg xmlns="http://www.w3.org/2000/svg" class="h-8 w-8 text-success" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                    <h3 class="text-lg font-semibold text-success">Share Accepted</h3>
                  </div>
                  <div class="grid grid-cols-2 gap-4 text-sm">
                    <div>
                      <span class="text-base-content/60">Key Label</span>
                      <p class="font-mono">{share.key_label}</p>
                    </div>
                    <div>
                      <span class="text-base-content/60">Accepted At</span>
                      <p>{format_datetime(share.accepted_at)}</p>
                    </div>
                  </div>
                  <p class="text-sm text-base-content/50 mt-4">
                    Your password is held in memory. It will be used during the preparation phase and then wiped.
                  </p>
                </div>
              <% end %>

              <%!-- Activity log --%>
              <%= if @activity_log != [] do %>
                <div class="card bg-base-100 shadow-sm p-6 mt-4">
                  <h3 class="text-sm font-semibold text-base-content/70 mb-3 uppercase tracking-wide">Live Activity</h3>
                  <div class="space-y-2 max-h-48 overflow-y-auto">
                    <div :for={entry <- @activity_log} class="flex items-start gap-2 text-sm">
                      <span class="text-base-content/40 font-mono text-xs whitespace-nowrap">
                        {Calendar.strftime(entry.time, "%H:%M:%S")}
                      </span>
                      <span>{entry.message}</span>
                    </div>
                  </div>
                </div>
              <% end %>
            <% end %>
          <% end %>
        </div>
      </div>
    </div>
    """
  end

  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  defp tenant_opts(socket), do: [tenant_id: socket.assigns[:tenant_id]]

  defp reload_shares(socket) do
    user_id = socket.assigns.current_user[:id]

    case CaEngineClient.list_my_ceremony_shares(user_id, tenant_opts(socket)) do
      {:ok, shares} -> shares
      {:error, _} -> socket.assigns.shares
    end
  end

  defp selected_share(shares, ceremony_id) do
    Enum.find(shares, fn s -> s.ceremony_id == ceremony_id end)
  end

  defp check_all_custodians_ready(ceremony_id, shares, opts) do
    ceremony_shares = Enum.filter(shares, fn s -> s.ceremony_id == ceremony_id end)

    # If this user's share is the only one we see, fetch the ceremony to check total
    case CaEngineClient.get_ceremony(ceremony_id, opts) do
      {:ok, ceremony} ->
        total = ceremony[:threshold_n] || ceremony.threshold_n
        accepted_count =
          case CaEngineClient.list_my_ceremony_shares("__all__", opts) do
            _ ->
              # We only see our own shares; use the ceremony data to check
              # Count accepted from ceremony_shares visible to us
              Enum.count(ceremony_shares, fn s -> s.share_status == "accepted" end)
          end

        # The ceremony object may track custodian readiness itself;
        # notify if we can determine all are ready
        if accepted_count >= total do
          CeremonyNotifications.notify_all_custodians_ready(ceremony)
        end

      {:error, _} ->
        :ok
    end
  rescue
    _ -> :ok
  end

  defp validate_key_label(label) do
    cond do
      label == "" ->
        {:error, "Key label is required."}

      String.length(label) > 64 ->
        {:error, "Key label must be at most 64 characters."}

      not Regex.match?(~r/^[a-zA-Z0-9\-]+$/, label) ->
        {:error, "Key label must contain only letters, numbers, and hyphens."}

      true ->
        :ok
    end
  end

  defp validate_password(password, confirmation) do
    cond do
      String.length(password) < 8 ->
        {:error, "Password must be at least 8 characters."}

      password != confirmation ->
        {:error, "Password confirmation does not match."}

      true ->
        :ok
    end
  end

  defp format_error(:not_found), do: "Ceremony or share not found."
  defp format_error(:already_accepted), do: "This share has already been accepted."
  defp format_error(:window_expired), do: "The ceremony window has expired."
  defp format_error(msg) when is_binary(msg), do: msg
  defp format_error(err), do: "An error occurred: #{inspect(err)}"

  defp share_badge("pending"), do: "badge-warning"
  defp share_badge("accepted"), do: "badge-success"
  defp share_badge("completed"), do: "badge-info"
  defp share_badge("failed"), do: "badge-error"
  defp share_badge(_), do: "badge-ghost"

  defp ceremony_badge("preparing"), do: "badge-warning"
  defp ceremony_badge("generating"), do: "badge-info"
  defp ceremony_badge("completed"), do: "badge-success"
  defp ceremony_badge("failed"), do: "badge-error"
  defp ceremony_badge(_), do: "badge-ghost"

  defp format_time_remaining(nil), do: "N/A"

  defp format_time_remaining(expires_at) do
    now = DateTime.utc_now()

    case DateTime.diff(expires_at, now, :second) do
      diff when diff <= 0 ->
        "Expired"

      diff when diff < 3600 ->
        "#{div(diff, 60)} minutes remaining"

      diff ->
        hours = div(diff, 3600)
        minutes = div(rem(diff, 3600), 60)
        "#{hours}h #{minutes}m remaining"
    end
  rescue
    _ -> "N/A"
  end

  defp time_remaining_urgent?(nil), do: false

  defp time_remaining_urgent?(expires_at) do
    case DateTime.diff(expires_at, DateTime.utc_now(), :second) do
      diff when diff <= 3600 -> true
      _ -> false
    end
  rescue
    _ -> false
  end

  defp format_datetime(nil), do: "N/A"

  defp format_datetime(dt) do
    Calendar.strftime(dt, "%Y-%m-%d %H:%M:%S")
  rescue
    _ -> inspect(dt)
  end
end
