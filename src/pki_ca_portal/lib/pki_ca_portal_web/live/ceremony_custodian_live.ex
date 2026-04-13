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
       selected_share: nil,
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
    import PkiCaPortalWeb.SafeEngine, only: [safe_load: 3]

    safe_load(socket, fn ->
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
    end, retry_msg: :load_shares)
  end

  def handle_info({:custodian_ready, %{user_id: _uid, username: username}}, socket) do
    entry = %{time: DateTime.utc_now(), message: "#{username} accepted their share"}
    activity_log = [entry | socket.assigns.activity_log] |> Enum.take(50)
    shares = reload_shares(socket)
    selected = refresh_selected(shares, socket.assigns.selected_ceremony_id)

    {:noreply, assign(socket, activity_log: activity_log, shares: shares, selected_share: selected)}
  end

  def handle_info({:ceremony_status_changed, %{status: status, ceremony_id: ceremony_id}}, socket) do
    entry = %{time: DateTime.utc_now(), message: "Ceremony #{String.slice(ceremony_id, 0, 8)} status changed to #{status}"}
    activity_log = [entry | socket.assigns.activity_log] |> Enum.take(50)
    shares = reload_shares(socket)
    selected = refresh_selected(shares, socket.assigns.selected_ceremony_id)

    {:noreply, assign(socket, activity_log: activity_log, shares: shares, selected_share: selected)}
  end

  def handle_info(_msg, socket), do: {:noreply, socket}

  # ---------------------------------------------------------------------------
  # Events
  # ---------------------------------------------------------------------------

  @impl true
  def handle_event("select_ceremony", %{"ceremony-id" => ceremony_id}, socket) do
    share = Enum.find(socket.assigns.shares, fn s -> s.ceremony_id == ceremony_id end)

    {:noreply,
     assign(socket,
       selected_ceremony_id: ceremony_id,
       selected_share: share,
       key_label: "",
       password: "",
       password_confirmation: "",
       error: nil,
       activity_log: []
     )}
  end

  def handle_event("back_to_list", _params, socket) do
    {:noreply,
     assign(socket,
       selected_ceremony_id: nil,
       selected_share: nil,
       key_label: "",
       password: "",
       password_confirmation: "",
       error: nil,
       activity_log: []
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
      case CaEngineClient.accept_ceremony_share(ceremony_id, user[:id], key_label, [{:password, password} | opts]) do
        {:ok, _} ->
          # Also keep in ETS for fast access during same session
          CustodianPasswordStore.store_password(ceremony_id, user[:id], password)

          Phoenix.PubSub.broadcast(
            PkiCaPortal.PubSub,
            "ceremony:#{ceremony_id}",
            {:custodian_ready, %{user_id: user[:id], username: user[:username]}}
          )

          audit_log(socket, "ceremony_share_accepted", "ceremony", ceremony_id, %{
            key_label: key_label,
            username: user[:username]
          })

          shares = reload_shares(socket)
          check_all_custodians_ready(ceremony_id, shares, opts)
          selected = refresh_selected(shares, ceremony_id)

          {:noreply,
           assign(socket,
             shares: shares,
             selected_share: selected,
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
    <div id="ceremony-custodian-page" class="space-y-6">
      <%= if @selected_share do %>
        {render_detail(assigns)}
      <% else %>
        {render_list(assigns)}
      <% end %>
    </div>
    """
  end

  defp render_list(assigns) do
    ~H"""
    <div class="alert border border-primary/30 bg-primary/5">
      <.icon name="hero-key" class="size-5 text-primary shrink-0" />
      <div>
        <p class="text-sm font-medium text-base-content">Key Custodian Portal</p>
        <p class="text-xs text-base-content/60 mt-0.5">
          As a key custodian, you accept your share of the threshold key and set a password to protect it.
          Select a ceremony below to view your assignment.
        </p>
      </div>
    </div>

    <div :if={@loading} class="flex justify-center py-12">
      <span class="loading loading-spinner loading-md text-primary"></span>
    </div>

    <div :if={not @loading and Enum.empty?(@shares)} class="card bg-base-100 shadow-sm border border-base-300">
      <div class="card-body text-center py-12 text-base-content/50 text-sm">
        <.icon name="hero-key" class="size-8 mx-auto mb-2 opacity-40" />
        <p>No ceremonies assigned to you.</p>
      </div>
    </div>

    <div :if={not @loading and not Enum.empty?(@shares)} class="space-y-3">
      <h2 class="text-sm font-semibold text-base-content">Assigned Ceremonies</h2>

      <div class="grid gap-3">
        <div
          :for={share <- @shares}
          class="card bg-base-100 shadow-sm border border-base-300 cursor-pointer hover:border-primary/40 transition-colors"
          phx-click="select_ceremony"
          phx-value-ceremony-id={share.ceremony_id}
        >
          <div class="card-body p-4">
            <div class="flex items-center justify-between">
              <div class="flex items-center gap-3">
                <div class="text-sm font-mono font-medium text-base-content">
                  {String.slice(share.ceremony_id, 0, 8)}
                </div>
                <span class={"badge badge-sm #{share_badge(share.share_status)}"}>{share.share_status}</span>
                <span class={"badge badge-sm #{ceremony_badge(share.ceremony_status)}"}>{share.ceremony_status}</span>
              </div>
              <div class="flex items-center gap-4 text-xs text-base-content/60">
                <span class="font-medium text-base-content/70">{share.ca_instance_name || "—"}</span>
                <span>{share.algorithm}</span>
                <span>{share.threshold_k}-of-{share.threshold_n}</span>
                <span class={if time_remaining_urgent?(share.window_expires_at), do: "text-error font-semibold", else: ""}>
                  {format_time_remaining(share.window_expires_at)}
                </span>
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
        Ceremony {String.slice(@selected_share.ceremony_id, 0, 8)}
      </h2>
      <span class={"badge badge-sm #{ceremony_badge(@selected_share.ceremony_status)}"}>{@selected_share.ceremony_status}</span>
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
            <div class="font-medium">{@selected_share.ca_instance_name || "—"}</div>
          </div>
          <div>
            <div class="text-xs text-base-content/50">Algorithm</div>
            <div class="font-medium">{@selected_share.algorithm}</div>
          </div>
          <div>
            <div class="text-xs text-base-content/50">Threshold</div>
            <div class="font-medium">{@selected_share.threshold_k}-of-{@selected_share.threshold_n}</div>
          </div>
          <div>
            <div class="text-xs text-base-content/50">Your Share Index</div>
            <div class="font-medium">#{@selected_share.share_index}</div>
          </div>
          <div>
            <div class="text-xs text-base-content/50">Time Remaining</div>
            <div class={["font-medium", if(time_remaining_urgent?(@selected_share.window_expires_at), do: "text-error", else: "")]}>
              {format_time_remaining(@selected_share.window_expires_at)}
            </div>
          </div>
        </div>
      </div>
    </div>

    <%!-- Accept share card (pending) --%>
    <div :if={@selected_share.share_status == "pending"} class="card bg-base-100 shadow-sm border border-base-300">
      <div class="card-body p-4">
        <div class="flex items-center justify-between mb-3">
          <h3 class="text-sm font-semibold text-base-content flex items-center gap-2">
            <.icon name="hero-key" class="size-4 text-primary" />
            Accept Your Share
          </h3>
          <span class="badge badge-warning badge-sm">Action Required</span>
        </div>

        <p class="text-xs text-base-content/60 mb-4">
          Provide a key label and a password to protect your share. The password is stored in memory only
          and will be used during the ceremony preparation phase.
        </p>

        <div :if={@error} class="alert alert-error text-sm mb-4">
          <.icon name="hero-exclamation-circle" class="size-4" />
          <span>{@error}</span>
        </div>

        <form phx-submit="accept_share" phx-change="validate" class="space-y-3">
          <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
            <div class="form-control">
              <label class="label py-0.5">
                <span class="label-text text-xs">Key Label</span>
              </label>
              <input
                type="text"
                name="key_label"
                value={@key_label}
                placeholder="e.g. my-ceremony-key-1"
                class="input input-bordered input-sm w-full"
                maxlength="64"
                required
              />
              <label class="label py-0">
                <span class="label-text-alt text-base-content/40">Alphanumeric and hyphens only</span>
              </label>
            </div>
            <div></div>
            <div class="form-control">
              <label class="label py-0.5">
                <span class="label-text text-xs">Password</span>
              </label>
              <input
                type="password"
                name="password"
                value={@password}
                placeholder="Minimum 8 characters"
                class="input input-bordered input-sm w-full"
                required
              />
            </div>
            <div class="form-control">
              <label class="label py-0.5">
                <span class="label-text text-xs">Confirm Password</span>
              </label>
              <input
                type="password"
                name="password_confirmation"
                value={@password_confirmation}
                placeholder="Re-enter password"
                class="input input-bordered input-sm w-full"
                required
              />
            </div>
          </div>
          <div class="flex justify-end pt-1">
            <button type="submit" class="btn btn-primary btn-sm gap-1">
              <.icon name="hero-check" class="size-4" />
              Accept Share
            </button>
          </div>
        </form>
      </div>
    </div>

    <%!-- Accepted confirmation card --%>
    <div :if={@selected_share.share_status == "accepted"} class="card bg-base-100 shadow-sm border border-success/30">
      <div class="card-body p-4">
        <div class="flex items-center justify-between mb-3">
          <h3 class="text-sm font-semibold text-success flex items-center gap-2">
            <.icon name="hero-check-circle" class="size-4" />
            Share Accepted
          </h3>
          <span class="badge badge-success badge-sm">Done</span>
        </div>

        <div class="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
          <div>
            <div class="text-xs text-base-content/50">Key Label</div>
            <div class="font-mono font-medium">{@selected_share.key_label}</div>
          </div>
          <div>
            <div class="text-xs text-base-content/50">Accepted At</div>
            <div class="font-medium"><.local_time dt={@selected_share.accepted_at} /></div>
          </div>
        </div>

        <p class="text-xs text-base-content/40 mt-3">
          Your password is held in memory. It will be used during the preparation phase and then wiped.
        </p>
      </div>
    </div>

    <%!-- Activity log --%>
    <div :if={not Enum.empty?(@activity_log)} class="card bg-base-100 shadow-sm border border-base-300">
      <div class="card-body p-4">
        <h3 class="text-xs font-semibold text-base-content/60 uppercase tracking-wider mb-3">
          Activity Log
        </h3>
        <div class="space-y-1">
          <div :for={entry <- @activity_log} class="flex items-start gap-2 text-xs">
            <span class="text-base-content/40 font-mono shrink-0"><.local_time dt={entry.time} format="time" /></span>
            <span class="text-base-content/70">{entry.message}</span>
          </div>
        </div>
      </div>
    </div>
    """
  end

  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  defp tenant_opts(socket) do
    opts = [tenant_id: socket.assigns[:tenant_id]]

    case get_in(socket.assigns, [:current_user, :role]) do
      nil -> opts
      role -> [{:user_role, role} | opts]
    end
  end

  defp reload_shares(socket) do
    user_id = socket.assigns.current_user[:id]

    case CaEngineClient.list_my_ceremony_shares(user_id, tenant_opts(socket)) do
      {:ok, shares} -> shares
      {:error, _} -> socket.assigns.shares
    end
  end

  defp refresh_selected(shares, ceremony_id) do
    Enum.find(shares, fn s -> s.ceremony_id == ceremony_id end)
  end

  defp check_all_custodians_ready(ceremony_id, shares, opts) do
    ceremony_shares = Enum.filter(shares, fn s -> s.ceremony_id == ceremony_id end)

    case CaEngineClient.get_ceremony(ceremony_id, opts) do
      {:ok, ceremony} ->
        total = ceremony[:threshold_n] || ceremony.threshold_n
        accepted_count = Enum.count(ceremony_shares, fn s -> s.share_status == "accepted" end)

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
      label == "" -> {:error, "Key label is required."}
      String.length(label) > 64 -> {:error, "Key label must be at most 64 characters."}
      not Regex.match?(~r/^[a-zA-Z0-9\-]+$/, label) -> {:error, "Key label must contain only letters, numbers, and hyphens."}
      true -> :ok
    end
  end

  defp validate_password(password, confirmation) do
    cond do
      String.length(password) < 8 -> {:error, "Password must be at least 8 characters."}
      password != confirmation -> {:error, "Password confirmation does not match."}
      true -> :ok
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
      diff when diff <= 0 -> "Expired"
      diff when diff < 3600 -> "#{div(diff, 60)}m remaining"
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
end
