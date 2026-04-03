defmodule PkiCaPortalWeb.CaInstancesLive do
  use PkiCaPortalWeb, :live_view

  require Logger

  alias PkiCaPortal.CaEngineClient
  import PkiCaPortalWeb.AuditHelpers, only: [audit_log: 4, audit_log: 5]
  import PkiCaPortalWeb.ErrorHelpers, only: [sanitize_error: 2]

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket), do: send(self(), :load_data)

    {:ok,
     assign(socket,
       page_title: "CA Instances",
       instances: [],
       loading: true,
       show_create_modal: false,
       create_name: "",
       create_parent_id: "",
       creating: false,
       renaming_id: nil,
       rename_value: ""
     )}
  end

  @impl true
  def handle_info(:load_data, socket) do
    instances = fetch_instances(tenant_opts(socket))
    {:noreply, assign(socket, instances: instances, loading: false)}
  end

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

  @impl true
  def handle_event("close_create_modal", _params, socket) do
    {:noreply, assign(socket, show_create_modal: false)}
  end

  @impl true
  def handle_event("create_instance", %{"name" => name, "parent_id" => parent_id}, socket) do
    attrs =
      %{name: name}
      |> maybe_put_parent_id(parent_id)

    case CaEngineClient.create_ca_instance(attrs, tenant_opts(socket)) do
      {:ok, instance} ->
        audit_log(socket, "ca_instance_created", "ca_instance", instance[:id] || instance["id"], %{name: name, parent_id: parent_id})
        instances = fetch_instances(tenant_opts(socket))

        {:noreply,
         socket
         |> assign(instances: instances, show_create_modal: false)
         |> put_flash(:info, "CA instance created successfully")}

      {:error, reason} ->
        Logger.error("[ca_instances] Failed to create CA instance: #{inspect(reason)}")
        {:noreply, put_flash(socket, :error, sanitize_error("Failed to create CA instance", reason))}
    end
  end

  @impl true
  def handle_event("start_rename", %{"id" => id, "name" => name}, socket) do
    {:noreply, assign(socket, renaming_id: id, rename_value: name)}
  end

  @impl true
  def handle_event("cancel_rename", _params, socket) do
    {:noreply, assign(socket, renaming_id: nil, rename_value: "")}
  end

  @impl true
  def handle_event("save_rename", %{"name" => name}, socket) do
    id = socket.assigns.renaming_id
    name = String.trim(name)

    if name == "" do
      {:noreply, put_flash(socket, :error, "Name cannot be empty")}
    else
      case CaEngineClient.update_ca_instance(id, %{"name" => name}, tenant_opts(socket)) do
        {:ok, _} ->
          audit_log(socket, "ca_instance_renamed", "ca_instance", id, %{new_name: name})
          instances = fetch_instances(tenant_opts(socket))
          {:noreply,
           socket
           |> assign(instances: instances, renaming_id: nil, rename_value: "")
           |> put_flash(:info, "CA instance renamed")}

        {:error, reason} ->
          Logger.error("[ca_instances] Rename failed: #{inspect(reason)}")
          {:noreply, put_flash(socket, :error, sanitize_error("Rename failed", reason))}
      end
    end
  end

  @impl true
  def handle_event("activate_instance", %{"id" => id}, socket) do
    case CaEngineClient.update_ca_instance(id, %{"status" => "active"}, tenant_opts(socket)) do
      {:ok, _} ->
        audit_log(socket, "ca_instance_activated", "ca_instance", id)
        instances = fetch_instances(tenant_opts(socket))
        {:noreply, socket |> assign(instances: instances) |> put_flash(:info, "CA instance activated")}
      {:error, {:parent_suspended, _}} ->
        {:noreply, put_flash(socket, :error, "Cannot activate: parent CA is suspended. Activate the parent first.")}
      {:error, _reason} ->
        {:noreply, put_flash(socket, :error, "Failed to activate CA instance.")}
    end
  end

  @impl true
  def handle_event("suspend_instance", %{"id" => id}, socket) do
    case CaEngineClient.update_ca_instance(id, %{"status" => "suspended"}, tenant_opts(socket)) do
      {:ok, _} ->
        audit_log(socket, "ca_instance_suspended", "ca_instance", id)
        instances = fetch_instances(tenant_opts(socket))
        {:noreply, socket |> assign(instances: instances) |> put_flash(:info, "CA instance suspended. All child CAs have also been suspended.")}
      {:error, _reason} ->
        {:noreply, put_flash(socket, :error, "Failed to suspend CA instance.")}
    end
  end

  defp maybe_put_parent_id(attrs, ""), do: attrs
  defp maybe_put_parent_id(attrs, nil), do: attrs
  defp maybe_put_parent_id(attrs, parent_id), do: Map.put(attrs, :parent_id, parent_id)

  defp fetch_instances(opts) do
    case CaEngineClient.list_ca_instances(opts) do
      {:ok, instances} -> instances
      {:error, _} -> []
    end
  end

  defp tenant_opts(socket) do
    opts = case socket.assigns[:tenant_id] do
      nil -> []
      tid -> [tenant_id: tid]
    end

    case socket.assigns[:current_user] do
      %{id: id, role: role} -> Keyword.put(opts, :actor, %{actor_did: id, actor_role: role})
      _ -> opts
    end
  end

  defp roots(instances) do
    Enum.filter(instances, fn i -> is_nil(i[:parent_id]) or i[:parent_id] == "" end)
  end

  defp children(instances, parent_id) do
    Enum.filter(instances, fn i -> i[:parent_id] == parent_id end)
  end

  defp role_badge_class(role) do
    case role do
      "root" -> "badge-primary"
      "intermediate" -> "badge-secondary"
      "issuing" -> "badge-accent"
      _ -> "badge-ghost"
    end
  end

  defp status_badge_class(status) do
    case status do
      "active" -> "badge-success"
      "inactive" -> "badge-ghost"
      "suspended" -> "badge-warning"
      _ -> "badge-ghost"
    end
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div id="ca-instances-page" class="space-y-6">
      <% role = @current_user[:role] %>
      <%!-- Header with New Root CA button --%>
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

      <%!-- Hierarchy tree --%>
      <div id="ca-hierarchy" class="card bg-base-100 shadow-sm border border-base-300">
        <div class="card-body p-0">
          <div class="px-5 py-4 border-b border-base-300">
            <h2 class="text-sm font-semibold text-base-content">Instance Tree</h2>
          </div>
          <div :if={Enum.empty?(@instances)} class="p-8 text-center text-base-content/50 text-sm">
            No CA instances configured. Create a Root CA to get started.
          </div>
          <div :if={not Enum.empty?(@instances)} class="p-4 space-y-1">
            <.tree_node
              :for={root <- roots(@instances)}
              instance={root}
              instances={@instances}
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
        :if={role == "ca_admin" && @show_create_modal}
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
    children = children(assigns.instances, assigns.instance.id)
    assigns = assign(assigns, :children, children)

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
            <%= if @role == "ca_admin" && @renaming_id == @instance[:id] do %>
              <form phx-submit="save_rename" class="flex items-center gap-2">
                <input
                  type="text"
                  name="name"
                  value={@rename_value}
                  class="input input-bordered input-xs w-48"
                  autofocus
                  phx-keydown="cancel_rename"
                  phx-key="Escape"
                />
                <button type="submit" class="btn btn-success btn-xs">Save</button>
                <button type="button" class="btn btn-ghost btn-xs" phx-click="cancel_rename">Cancel</button>
              </form>
            <% else %>
              <p class="text-sm font-medium text-base-content group/name">
                {@instance.name}
                <button
                  :if={@role == "ca_admin"}
                  class="btn btn-ghost btn-xs opacity-0 group-hover/name:opacity-100 ml-1"
                  phx-click="start_rename"
                  phx-value-id={@instance[:id]}
                  phx-value-name={@instance.name}
                  title="Rename"
                >
                  <.icon name="hero-pencil" class="size-3" />
                </button>
              </p>
            <% end %>
            <div class="flex items-center gap-2 mt-0.5">
              <span class={"badge badge-xs #{role_badge_class(@instance[:role] || "root")}"}>
                {@instance[:role] || "root"}
              </span>
              <span class={"badge badge-xs #{status_badge_class(@instance[:status] || "active")}"}>
                {@instance[:status] || "active"}
              </span>
              <span class="text-xs text-base-content/40">
                {Map.get(@instance, :issuer_key_count, 0)} issuer key(s)
              </span>
            </div>
          </div>
        </div>
        <div :if={@role == "ca_admin"} class="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
          <button
            :if={@instance[:status] != "active"}
            class="btn btn-ghost btn-xs text-success"
            phx-click="activate_instance"
            phx-value-id={@instance.id}
            title="Activate"
          >
            <.icon name="hero-play" class="size-3" />
          </button>
          <button
            :if={@instance[:status] == "active"}
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
            title="Add Sub-CA"
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
        depth={@depth + 1}
        renaming_id={@renaming_id}
        rename_value={@rename_value}
        role={@role}
      />
    </div>
    """
  end
end
