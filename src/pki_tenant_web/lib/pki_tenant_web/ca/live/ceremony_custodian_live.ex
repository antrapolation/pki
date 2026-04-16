defmodule PkiTenantWeb.Ca.CeremonyCustodianLive do
  use PkiTenantWeb, :live_view

  alias PkiCaEngine.CeremonyOrchestrator
  alias PkiMnesia.Repo
  alias PkiMnesia.Structs.{ThresholdShare, KeyCeremony}

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
    try do
      user_name = socket.assigns.current_user[:username] || socket.assigns.current_user[:display_name]

      shares = load_shares_for_user(user_name)

      # Subscribe to PubSub for each ceremony
      for share <- shares do
        Phoenix.PubSub.subscribe(PkiTenantWeb.PubSub, "ceremony:#{share.ceremony_id}")
      end

      {:noreply, assign(socket, shares: shares, loading: false)}
    rescue
      e ->
        require Logger
        Logger.warning("[CeremonyCustodianLive] Failed to load shares: #{Exception.message(e)}")
        {:noreply, assign(socket, shares: [], loading: false)}
    end
  end

  def handle_info({:custodian_ready, %{username: username}}, socket) do
    entry = %{time: DateTime.utc_now(), message: "#{username} accepted their share"}
    activity_log = [entry | socket.assigns.activity_log] |> Enum.take(50)
    user_name = socket.assigns.current_user[:username] || socket.assigns.current_user[:display_name]
    shares = load_shares_for_user(user_name)
    selected = refresh_selected(shares, socket.assigns.selected_ceremony_id)

    {:noreply, assign(socket, activity_log: activity_log, shares: shares, selected_share: selected)}
  end

  def handle_info({:ceremony_status_changed, %{status: status, ceremony_id: ceremony_id}}, socket) do
    entry = %{time: DateTime.utc_now(), message: "Ceremony #{String.slice(ceremony_id, 0, 8)} status changed to #{status}"}
    activity_log = [entry | socket.assigns.activity_log] |> Enum.take(50)
    user_name = socket.assigns.current_user[:username] || socket.assigns.current_user[:display_name]
    shares = load_shares_for_user(user_name)
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
    custodian_name = user[:username] || user[:display_name]

    with :ok <- validate_key_label(key_label),
         :ok <- validate_password(password, password_confirmation) do
      case CeremonyOrchestrator.accept_share(ceremony_id, custodian_name, password) do
        {:ok, _} ->
          Phoenix.PubSub.broadcast(
            PkiTenantWeb.PubSub,
            "ceremony:#{ceremony_id}",
            {:custodian_ready, %{username: custodian_name}}
          )

          PkiTenant.AuditBridge.log("ceremony_share_accepted", %{
            ceremony_id: ceremony_id,
            key_label: key_label,
            username: custodian_name
          })

          shares = load_shares_for_user(custodian_name)
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
                  {String.slice(share.ceremony_id || "", 0, 8)}
                </div>
                <span class={"badge badge-sm #{share_badge(share.status)}"}>{share.status}</span>
                <span class={"badge badge-sm #{ceremony_badge(share.ceremony_status)}"}>{share.ceremony_status}</span>
              </div>
              <div class="flex items-center gap-4 text-xs text-base-content/60">
                <span>{share.algorithm}</span>
                <span>{share.min_shares}-of-{share.total_shares}</span>
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
        Ceremony {String.slice(@selected_share.ceremony_id || "", 0, 8)}
      </h2>
      <span class={"badge badge-sm #{ceremony_badge(@selected_share.ceremony_status)}"}>{@selected_share.ceremony_status}</span>
    </div>

    <%!-- Ceremony details card --%>
    <div class="card bg-base-100 shadow-sm border border-base-300">
      <div class="card-body p-4">
        <h3 class="text-xs font-semibold text-base-content/60 uppercase tracking-wider mb-3">
          Ceremony Details
        </h3>
        <div class="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
          <div>
            <div class="text-xs text-base-content/50">Algorithm</div>
            <div class="font-medium">{@selected_share.algorithm}</div>
          </div>
          <div>
            <div class="text-xs text-base-content/50">Threshold</div>
            <div class="font-medium">{@selected_share.min_shares}-of-{@selected_share.total_shares}</div>
          </div>
          <div>
            <div class="text-xs text-base-content/50">Your Share Index</div>
            <div class="font-medium">#{@selected_share.share_index}</div>
          </div>
          <div>
            <div class="text-xs text-base-content/50">Custodian</div>
            <div class="font-medium">{@selected_share.custodian_name}</div>
          </div>
        </div>
      </div>
    </div>

    <%!-- Accept share card (pending) --%>
    <div :if={@selected_share.status == "pending"} class="card bg-base-100 shadow-sm border border-base-300">
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
    <div :if={@selected_share.status == "accepted"} class="card bg-base-100 shadow-sm border border-success/30">
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
            <div class="text-xs text-base-content/50">Custodian</div>
            <div class="font-mono font-medium">{@selected_share.custodian_name}</div>
          </div>
          <div>
            <div class="text-xs text-base-content/50">Accepted At</div>
            <div class="font-medium"><.local_time dt={@selected_share.updated_at} /></div>
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
            <span class="text-base-content/40 font-mono shrink-0"><.local_time dt={entry.time} /></span>
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

  defp load_shares_for_user(user_name) do
    # Load all threshold shares for this custodian name, enriched with ceremony data
    case Repo.get_all_by_index(ThresholdShare, :custodian_name, user_name) do
      {:ok, shares} ->
        Enum.map(shares, fn share ->
          ceremony = case Repo.get(KeyCeremony, share.issuer_key_id) do
            {:ok, nil} ->
              # Try looking up by ceremony that references the issuer_key_id
              case Repo.get_all_by_index(KeyCeremony, :issuer_key_id, share.issuer_key_id) do
                {:ok, [c | _]} -> c
                _ -> nil
              end
            {:ok, c} -> c
            _ -> nil
          end

          ceremony_id = if ceremony, do: ceremony.id, else: share.issuer_key_id
          ceremony_status = if ceremony, do: ceremony.status, else: "unknown"
          algorithm = if ceremony, do: ceremony.algorithm, else: "unknown"

          # Enrich share with ceremony info for display
          %{
            id: share.id,
            ceremony_id: ceremony_id,
            issuer_key_id: share.issuer_key_id,
            custodian_name: share.custodian_name,
            share_index: share.share_index,
            status: share.status,
            min_shares: share.min_shares,
            total_shares: share.total_shares,
            ceremony_status: ceremony_status,
            algorithm: algorithm,
            updated_at: share.updated_at
          }
        end)
      _ -> []
    end
  rescue
    _ -> []
  end

  defp refresh_selected(shares, ceremony_id) do
    Enum.find(shares, fn s -> s.ceremony_id == ceremony_id end)
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
  defp format_error(:share_not_found), do: "Share not found for this custodian."
  defp format_error(:invalid_ceremony_status), do: "Ceremony is not in the correct state for this action."
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
end
