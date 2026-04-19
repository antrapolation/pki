defmodule PkiTenantWeb.Ca.CaInstancesLive do
  @moduledoc """
  CA instance hierarchy: list, create, rename, activate/suspend, and
  bring online/offline. Render is a tree that recurses on parent_id.

  Operates on Mnesia-backed `CaInstanceManagement` — the schema-mode
  Ecto path is retired for this view in favor of the per-tenant BEAM
  data model.
  """
  use PkiTenantWeb, :live_view

  require Logger

  alias PkiCaEngine.{CaInstanceManagement, IssuerKeyManagement}

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket), do: send(self(), :load_data)

    {:ok,
     assign(socket,
       page_title: "CA Instances",
       instances: [],
       issuer_key_counts: %{},
       loading: true,
       show_create_modal: false,
       create_name: "",
       create_parent_id: "",
       renaming_id: nil,
       rename_value: ""
     )}
  end

  @impl true
  def handle_info(:load_data, socket) do
    instances = list_instances()
    counts = compute_key_counts(instances)

    {:noreply, assign(socket, instances: instances, issuer_key_counts: counts, loading: false)}
  end

  # --- Create ---

  @impl true
  def handle_event("open_create_modal", params, socket) do
    parent_id = params["parent_id"] || ""

    {:noreply,
     assign(socket,
       show_create_modal: true,
       create_name: "",
       create_parent_id: parent_id
     )}
  end

  def handle_event("close_create_modal", _params, socket) do
    {:noreply, assign(socket, show_create_modal: false)}
  end

  def handle_event("create_instance", %{"name" => name, "parent_id" => parent_id}, socket) do
    if socket.assigns.current_user[:role] != "ca_admin" do
      {:noreply, put_flash(socket, :error, "Only CA admins can create CA instances.")}
    else
      trimmed = String.trim(name || "")

      cond do
        trimmed == "" ->
          {:noreply, put_flash(socket, :error, "Name is required.")}

        true ->
          attrs = build_create_attrs(trimmed, parent_id)

          case CaInstanceManagement.create_ca_instance(attrs) do
            {:ok, instance} ->
              PkiTenant.AuditBridge.log("ca_instance_created", %{
                ca_instance_id: instance.id,
                name: trimmed,
                parent_id: parent_id
              })

              send(self(), :load_data)

              {:noreply,
               socket
               |> assign(show_create_modal: false)
               |> put_flash(:info, "CA instance created.")}

            {:error, reason} ->
              Logger.error("[ca_instances_live] create failed: #{inspect(reason)}")
              {:noreply, put_flash(socket, :error, "Failed to create CA instance.")}
          end
      end
    end
  end

  # --- Rename ---

  def handle_event("start_rename", %{"id" => id, "name" => name}, socket) do
    {:noreply, assign(socket, renaming_id: id, rename_value: name)}
  end

  def handle_event("cancel_rename", _params, socket) do
    {:noreply, assign(socket, renaming_id: nil, rename_value: "")}
  end

  def handle_event("save_rename", %{"name" => name}, socket) do
    if socket.assigns.current_user[:role] != "ca_admin" do
      {:noreply, put_flash(socket, :error, "Only CA admins can rename CA instances.")}
    else
      id = socket.assigns.renaming_id

      case CaInstanceManagement.update_name(id, name) do
        {:ok, _} ->
          PkiTenant.AuditBridge.log("ca_instance_renamed", %{
            ca_instance_id: id,
            new_name: String.trim(name)
          })

          send(self(), :load_data)

          {:noreply,
           socket
           |> assign(renaming_id: nil, rename_value: "")
           |> put_flash(:info, "CA instance renamed.")}

        {:error, :empty_name} ->
          {:noreply, put_flash(socket, :error, "Name cannot be empty.")}

        {:error, reason} ->
          Logger.error("[ca_instances_live] rename failed: #{inspect(reason)}")
          {:noreply, put_flash(socket, :error, "Rename failed.")}
      end
    end
  end

  # --- Status / offline toggles ---

  def handle_event("activate_instance", %{"id" => id}, socket) do
    apply_status_change(socket, id, "active", "CA instance activated.")
  end

  def handle_event("suspend_instance", %{"id" => id}, socket) do
    apply_status_change(socket, id, "suspended", "CA instance suspended.")
  end

  def handle_event("toggle_offline", %{"id" => id, "offline" => offline_str}, socket) do
    if socket.assigns.current_user[:role] != "ca_admin" do
      {:noreply, put_flash(socket, :error, "Only CA admins can change CA online status.")}
    else
      result =
        case offline_str do
          "true" -> CaInstanceManagement.set_offline(id)
          _ -> CaInstanceManagement.set_online(id)
        end

      case result do
        {:ok, _} ->
          action = if offline_str == "true", do: "ca_instance_offline", else: "ca_instance_online"
          PkiTenant.AuditBridge.log(action, %{ca_instance_id: id})
          send(self(), :load_data)

          msg = if offline_str == "true", do: "CA instance taken offline.", else: "CA instance brought online."
          {:noreply, put_flash(socket, :info, msg)}

        {:error, reason} ->
          Logger.error("[ca_instances_live] toggle_offline failed: #{inspect(reason)}")
          {:noreply, put_flash(socket, :error, "Failed to update online status.")}
      end
    end
  end

  defp apply_status_change(socket, id, status, success_msg) do
    if socket.assigns.current_user[:role] != "ca_admin" do
      {:noreply, put_flash(socket, :error, "Only CA admins can change CA status.")}
    else
      case CaInstanceManagement.update_status(id, status) do
        {:ok, _} ->
          PkiTenant.AuditBridge.log("ca_instance_status_changed", %{
            ca_instance_id: id,
            status: status
          })

          send(self(), :load_data)
          {:noreply, put_flash(socket, :info, success_msg)}

        {:error, reason} ->
          Logger.error("[ca_instances_live] status change failed: #{inspect(reason)}")
          {:noreply, put_flash(socket, :error, "Status change failed.")}
      end
    end
  end

  # --- Private helpers ---

  defp list_instances do
    case CaInstanceManagement.list_ca_instances() do
      {:ok, list} -> list
      _ -> []
    end
  end

  defp compute_key_counts(instances) do
    Map.new(instances, fn ca ->
      case IssuerKeyManagement.list_issuer_keys(ca.id) do
        {:ok, keys} -> {ca.id, length(keys)}
        _ -> {ca.id, 0}
      end
    end)
  end

  defp build_create_attrs(name, parent_id) do
    base = %{name: name}

    cond do
      is_nil(parent_id) or parent_id == "" ->
        Map.put(base, :is_root, true)

      true ->
        base |> Map.put(:parent_id, parent_id) |> Map.put(:is_root, false)
    end
  end

  defp roots(instances) do
    Enum.filter(instances, fn i -> is_nil(i.parent_id) or i.parent_id == "" end)
  end

  defp children(instances, parent_id) do
    Enum.filter(instances, fn i -> i.parent_id == parent_id end)
  end

  # Role is derived from hierarchy position:
  #   root        — is_root
  #   intermediate — has children
  #   issuing     — leaf node (no children)
  defp display_role(ca, instances) do
    has_kids? = Enum.any?(instances, fn i -> i.parent_id == ca.id end)

    cond do
      ca.is_root -> "root"
      has_kids? -> "intermediate"
      true -> "issuing"
    end
  end

  defp role_badge_class("root"), do: "badge-primary"
  defp role_badge_class("intermediate"), do: "badge-secondary"
  defp role_badge_class("issuing"), do: "badge-accent"
  defp role_badge_class(_), do: "badge-ghost"

  defp status_badge_class("active"), do: "badge-success"
  defp status_badge_class("inactive"), do: "badge-ghost"
  defp status_badge_class("suspended"), do: "badge-warning"
  defp status_badge_class(_), do: "badge-ghost"

  # --- Render ---

  @impl true
  def render(assigns) do
    ~H"""
    <div id="ca-instances-page" class="space-y-6">
      <% role = @current_user[:role] %>

      <div class="flex items-center justify-between">
        <div>
          <h1 class="text-lg font-semibold text-base-content">CA Instance Hierarchy</h1>
          <p class="text-xs text-base-content/50 mt-0.5">Manage root and subordinate CA instances</p>
        </div>
        <button
          :if={role == "ca_admin"}
          id="btn-new-root-ca"
          class="btn btn-primary btn-sm"
          phx-click="open_create_modal"
          phx-value-parent_id=""
        >
          <.icon name="hero-plus" class="size-4" />
          New Root CA
        </button>
      </div>

      <div id="ca-hierarchy" class="card bg-base-100 shadow-sm border border-base-300">
        <div class="card-body p-0">
          <div class="px-5 py-4 border-b border-base-300">
            <h2 class="text-sm font-semibold text-base-content">Instance Tree</h2>
          </div>

          <div :if={@loading} class="p-8 text-center text-base-content/40 text-sm">Loading…</div>

          <div :if={not @loading and Enum.empty?(@instances)} class="p-8 text-center text-base-content/50 text-sm">
            No CA instances configured. Create a Root CA to get started.
          </div>

          <div :if={not @loading and not Enum.empty?(@instances)} class="p-4 space-y-1">
            <.tree_node
              :for={root <- roots(@instances)}
              instance={root}
              instances={@instances}
              key_counts={@issuer_key_counts}
              depth={0}
              renaming_id={@renaming_id}
              rename_value={@rename_value}
              role={role}
            />
          </div>
        </div>
      </div>

      <%!-- Create CA Instance Modal --%>
      <div
        :if={role == "ca_admin" and @show_create_modal}
        id="create-ca-modal"
        class="modal modal-open"
        phx-window-keydown="close_create_modal"
        phx-key="Escape"
      >
        <div class="modal-box">
          <h3 class="font-bold text-lg">Create CA Instance</h3>
          <form phx-submit="create_instance" class="space-y-4 mt-4">
            <div>
              <label for="ca-name" class="block text-xs font-medium text-base-content/60 mb-1">
                Name <span class="text-error">*</span>
              </label>
              <input
                type="text"
                name="name"
                id="ca-name"
                required
                maxlength="100"
                value={@create_name}
                placeholder="e.g. Root CA, Intermediate CA 1"
                class="input input-bordered input-sm w-full"
              />
            </div>
            <div>
              <label for="ca-parent" class="block text-xs font-medium text-base-content/60 mb-1">
                Parent CA
              </label>
              <select name="parent_id" id="ca-parent" class="select select-bordered select-sm w-full">
                <option value="">None (Root CA)</option>
                <option
                  :for={inst <- @instances}
                  value={inst.id}
                  selected={@create_parent_id == inst.id}
                >
                  {inst.name}
                </option>
              </select>
            </div>
            <div class="modal-action">
              <button type="button" class="btn btn-ghost btn-sm" phx-click="close_create_modal">
                Cancel
              </button>
              <button type="submit" class="btn btn-primary btn-sm">
                <.icon name="hero-plus" class="size-4" />
                Create
              </button>
            </div>
          </form>
        </div>
        <div class="modal-backdrop" phx-click="close_create_modal"></div>
      </div>
    </div>
    """
  end

  defp tree_node(assigns) do
    kids = children(assigns.instances, assigns.instance.id)
    assigns = assign(assigns, :children, kids)
    assigns = assign(assigns, :role_label, display_role(assigns.instance, assigns.instances))
    assigns = assign(assigns, :key_count, Map.get(assigns.key_counts, assigns.instance.id, 0))

    ~H"""
    <div class={"#{if @depth > 0, do: "ml-6 border-l-2 border-base-300 pl-4", else: ""}"}>
      <div class="flex items-center justify-between py-2 px-3 rounded-lg hover:bg-base-200/50 group">
        <div class="flex items-center gap-3">
          <div class="flex items-center justify-center w-8 h-8 rounded-lg bg-primary/10">
            <.icon
              name={if @depth == 0, do: "hero-shield-check", else: "hero-building-office"}
              class="size-4 text-primary"
            />
          </div>
          <div>
            <%= if @role == "ca_admin" and @renaming_id == @instance.id do %>
              <form phx-submit="save_rename" class="flex items-center gap-2">
                <input
                  type="text"
                  name="name"
                  value={@rename_value}
                  maxlength="100"
                  class="input input-bordered input-xs w-48"
                  autofocus
                  phx-keydown="cancel_rename"
                  phx-key="Escape"
                />
                <button type="submit" class="btn btn-success btn-xs">Save</button>
                <button type="button" class="btn btn-ghost btn-xs" phx-click="cancel_rename">
                  Cancel
                </button>
              </form>
            <% else %>
              <p class="text-sm font-medium text-base-content group/name">
                {@instance.name}
                <span :if={@instance.is_offline} class="badge badge-xs badge-warning ml-1">OFFLINE</span>
                <button
                  :if={@role == "ca_admin"}
                  class="btn btn-ghost btn-xs opacity-0 group-hover/name:opacity-100 ml-1"
                  phx-click="start_rename"
                  phx-value-id={@instance.id}
                  phx-value-name={@instance.name}
                  title="Rename"
                >
                  <.icon name="hero-pencil" class="size-3" />
                </button>
              </p>
            <% end %>

            <div class="flex items-center gap-2 mt-0.5">
              <span class={"badge badge-xs #{role_badge_class(@role_label)}"}>{@role_label}</span>
              <span class={"badge badge-xs #{status_badge_class(@instance.status)}"}>
                {@instance.status}
              </span>
              <span class="text-xs text-base-content/40">{@key_count} issuer key(s)</span>
            </div>
          </div>
        </div>

        <div
          :if={@role == "ca_admin"}
          class="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity"
        >
          <button
            phx-click="toggle_offline"
            phx-value-id={@instance.id}
            phx-value-offline={to_string(not @instance.is_offline)}
            data-confirm={
              cond do
                @instance.is_offline and is_nil(@instance.parent_id) ->
                  "Bring this Root CA online? It will go offline automatically once a new key ceremony completes."
                @instance.is_offline ->
                  "Bring this CA online?"
                true ->
                  "Take this CA offline? Certificate signing will be blocked."
              end
            }
            title={if @instance.is_offline, do: "Bring online", else: "Take offline"}
            class={"btn btn-ghost btn-xs #{if @instance.is_offline, do: "text-emerald-400", else: "text-amber-400"}"}
          >
            <.icon name={if @instance.is_offline, do: "hero-signal", else: "hero-signal-slash"} class="size-4" />
          </button>

          <button
            :if={@instance.status != "active"}
            class="btn btn-ghost btn-xs text-success"
            phx-click="activate_instance"
            phx-value-id={@instance.id}
            title="Activate"
          >
            <.icon name="hero-play" class="size-3" />
          </button>

          <button
            :if={@instance.status == "active"}
            class="btn btn-ghost btn-xs text-warning"
            phx-click="suspend_instance"
            phx-value-id={@instance.id}
            title="Suspend"
          >
            <.icon name="hero-pause" class="size-3" />
          </button>

          <button
            class="btn btn-ghost btn-xs"
            phx-click="open_create_modal"
            phx-value-parent_id={@instance.id}
            title="Add sub-CA"
          >
            <.icon name="hero-plus" class="size-3" />
            Sub-CA
          </button>
        </div>
      </div>

      <.tree_node
        :for={child <- @children}
        instance={child}
        instances={@instances}
        key_counts={@key_counts}
        depth={@depth + 1}
        renaming_id={@renaming_id}
        rename_value={@rename_value}
        role={@role}
      />
    </div>
    """
  end
end
