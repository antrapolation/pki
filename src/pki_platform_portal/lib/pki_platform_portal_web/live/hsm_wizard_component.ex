defmodule PkiPlatformPortalWeb.HsmWizardComponent do
  @moduledoc """
  4-step LiveComponent modal for platform admins to register a physical HSM
  device and assign it to tenants.

  Rendered from HsmDevicesLive when @live_action is :new_device.

  Steps:
    :device_info — label, PKCS#11 library path, slot ID
    :probe       — register & probe the device (spinner while running)
    :assign      — multi-select tenant assignment (skippable)
    :done        — summary card with link to device detail
  """
  use PkiPlatformPortalWeb, :live_component

  require Logger

  alias PkiPlatformEngine.{HsmManagement, PlatformRepo, TenantLifecycle}

  @impl true
  def mount(socket) do
    {:ok,
     assign(socket,
       step: :device_info,
       label_input: "",
       lib_path_input: "",
       slot_id_input: "0",
       device: nil,
       tenants: [],
       selected_tenant_ids: MapSet.new(),
       error: nil,
       busy: false
     )}
  end

  @impl true
  def update(assigns, socket) do
    socket = assign(socket, assigns)

    socket =
      if socket.assigns.step == :assign and Enum.empty?(socket.assigns.tenants) do
        tenants = list_tenants()
        assign(socket, tenants: tenants)
      else
        socket
      end

    {:ok, socket}
  end

  # ---------------------------------------------------------------------------
  # Events
  # ---------------------------------------------------------------------------

  @impl true
  def handle_event("next_device_info", params, socket) do
    label = String.trim(params["label"] || "")
    lib_path = String.trim(params["pkcs11_lib_path"] || "")
    slot_id = parse_int(params["slot_id"])

    cond do
      label == "" ->
        {:noreply, assign(socket, error: "Label is required.")}

      lib_path == "" ->
        {:noreply, assign(socket, error: "PKCS#11 library path is required.")}

      true ->
        {:noreply,
         assign(socket,
           label_input: label,
           lib_path_input: lib_path,
           slot_id_input: to_string(slot_id),
           step: :probe,
           error: nil,
           busy: true
         )
         |> tap(fn _ -> send_update(__MODULE__, id: socket.assigns.id, action: :do_probe) end)}
    end
  end

  @impl true
  def handle_event("do_probe", _params, socket) do
    attrs = %{
      label: socket.assigns.label_input,
      pkcs11_lib_path: socket.assigns.lib_path_input,
      slot_id: parse_int(socket.assigns.slot_id_input)
    }

    case HsmManagement.register_device(attrs) do
      {:ok, device} ->
        {:noreply, assign(socket, device: device, busy: false, step: :assign, error: nil)}

      {:error, {:pkcs11_unreachable, reason}} ->
        Logger.error("[hsm_wizard_component] PKCS#11 unreachable: #{inspect(reason)}")
        {:noreply, assign(socket, busy: false, error: "Cannot reach PKCS#11 library. Check the path and try again.")}

      {:error, reason} ->
        {:noreply, assign(socket, busy: false, error: format_error(reason))}
    end
  end

  @impl true
  def handle_event("retry_probe", _params, socket) do
    {:noreply, assign(socket, step: :device_info, error: nil, device: nil)}
  end

  @impl true
  def handle_event("toggle_tenant", %{"tenant_id" => tid}, socket) do
    selected =
      if MapSet.member?(socket.assigns.selected_tenant_ids, tid) do
        MapSet.delete(socket.assigns.selected_tenant_ids, tid)
      else
        MapSet.put(socket.assigns.selected_tenant_ids, tid)
      end

    {:noreply, assign(socket, selected_tenant_ids: selected)}
  end

  @impl true
  def handle_event("assign_tenants", _params, socket) do
    device = socket.assigns.device

    Enum.each(socket.assigns.selected_tenant_ids, fn tid ->
      case HsmManagement.grant_tenant_access(device.id, tid) do
        {:ok, _} -> :ok
        {:error, reason} -> Logger.warning("[hsm_wizard] grant_tenant_access failed: #{inspect(reason)}")
      end
    end)

    {:noreply, assign(socket, step: :done, error: nil)}
  end

  @impl true
  def handle_event("skip_assign", _params, socket) do
    {:noreply, assign(socket, step: :done, error: nil)}
  end

  @impl true
  def handle_event("close", _params, socket) do
    send(self(), {:hsm_wizard_done, socket.assigns.device})
    {:noreply, socket}
  end

  # ---------------------------------------------------------------------------
  # Render
  # ---------------------------------------------------------------------------

  @impl true
  def render(assigns) do
    ~H"""
    <div id={@id} class="modal modal-open">
      <div class="modal-box max-w-lg">
        <button phx-click="close" phx-target={@myself} class="btn btn-sm btn-circle btn-ghost absolute right-2 top-2">
          <.icon name="hero-x-mark" class="size-4" />
        </button>

        <h3 class="font-semibold text-base mb-1">Register HSM Device</h3>

        <%!-- Step indicator --%>
        <div class="flex gap-1 mb-5">
          <.step_dot label="Info" active={@step == :device_info} done={@step in [:probe, :assign, :done]} />
          <div class="flex-1 flex items-center"><div class="h-px bg-base-300 w-full"></div></div>
          <.step_dot label="Probe" active={@step == :probe} done={@step in [:assign, :done]} />
          <div class="flex-1 flex items-center"><div class="h-px bg-base-300 w-full"></div></div>
          <.step_dot label="Assign" active={@step == :assign} done={@step == :done} />
          <div class="flex-1 flex items-center"><div class="h-px bg-base-300 w-full"></div></div>
          <.step_dot label="Done" active={@step == :done} done={false} />
        </div>

        <%!-- Error --%>
        <div :if={@error} class="alert alert-error mb-4 text-sm">
          <.icon name="hero-exclamation-circle" class="size-5 shrink-0" />
          <span>{@error}</span>
        </div>

        <%= case @step do %>
          <% :device_info -> %>
            <.step_device_info myself={@myself} />
          <% :probe -> %>
            <.step_probe busy={@busy} error={@error} myself={@myself} />
          <% :assign -> %>
            <.step_assign tenants={@tenants} selected={@selected_tenant_ids} myself={@myself} />
          <% :done -> %>
            <.step_done device={@device} myself={@myself} />
        <% end %>
      </div>
    </div>
    """
  end

  # ---------------------------------------------------------------------------
  # Step components
  # ---------------------------------------------------------------------------

  attr :label, :string, required: true
  attr :active, :boolean, required: true
  attr :done, :boolean, required: true

  defp step_dot(assigns) do
    ~H"""
    <div class="flex flex-col items-center gap-0.5">
      <div class={[
        "size-6 rounded-full flex items-center justify-center text-xs font-semibold",
        @active && "bg-primary text-primary-content",
        @done && not @active && "bg-success text-success-content",
        not @active and not @done && "bg-base-300 text-base-content/40"
      ]}>
        <%= if @done do %>
          <.icon name="hero-check" class="size-3" />
        <% else %>
          <span class="text-xs">·</span>
        <% end %>
      </div>
      <span class="text-xs text-base-content/50">{@label}</span>
    </div>
    """
  end

  attr :myself, :any, required: true

  defp step_device_info(assigns) do
    ~H"""
    <form phx-submit="next_device_info" phx-target={@myself} class="space-y-4">
      <div>
        <label class="block text-xs font-medium text-base-content/60 mb-1">Label</label>
        <input type="text" name="label" required placeholder="e.g. Thales Luna Network HSM" class="input input-bordered input-sm w-full" />
      </div>
      <div>
        <label class="block text-xs font-medium text-base-content/60 mb-1">PKCS#11 Library Path</label>
        <input type="text" name="pkcs11_lib_path" required
          placeholder="/usr/lib/libckteec.so"
          class="input input-bordered input-sm w-full font-mono text-xs" />
      </div>
      <div>
        <label class="block text-xs font-medium text-base-content/60 mb-1">Slot ID</label>
        <input type="number" name="slot_id" value="0" min="0" class="input input-bordered input-sm w-24" />
      </div>
      <div class="modal-action mt-4">
        <button type="submit" class="btn btn-primary btn-sm">Probe Device</button>
      </div>
    </form>
    """
  end

  attr :busy, :boolean, required: true
  attr :error, :string, required: true
  attr :myself, :any, required: true

  defp step_probe(assigns) do
    ~H"""
    <div class="text-center py-4 space-y-3">
      <%= if @busy do %>
        <span class="loading loading-spinner loading-lg text-primary"></span>
        <p class="text-sm text-base-content/60">Probing PKCS#11 device…</p>
      <% else %>
        <.icon name="hero-exclamation-triangle" class="size-10 text-error mx-auto" />
        <p class="text-sm text-error">{@error}</p>
        <button phx-click="retry_probe" phx-target={@myself} class="btn btn-ghost btn-sm">
          ← Back to device info
        </button>
      <% end %>
    </div>
    """
  end

  attr :tenants, :list, required: true
  attr :selected, :any, required: true
  attr :myself, :any, required: true

  defp step_assign(assigns) do
    ~H"""
    <div>
      <p class="text-xs text-base-content/50 mb-3">Select tenants to grant access to this device. You can change this later.</p>

      <div class="space-y-1 max-h-48 overflow-y-auto border border-base-300 rounded p-2">
        <div :if={Enum.empty?(@tenants)} class="text-xs text-base-content/40 p-2">
          No tenants provisioned yet.
        </div>
        <label :for={t <- @tenants} class="flex items-center gap-2 p-1.5 hover:bg-base-200 rounded cursor-pointer">
          <input
            type="checkbox"
            checked={MapSet.member?(@selected, t.id)}
            phx-click="toggle_tenant"
            phx-value-tenant_id={t.id}
            phx-target={@myself}
            class="checkbox checkbox-sm checkbox-primary"
          />
          <span class="text-sm">{t.name || t.id}</span>
        </label>
      </div>

      <div class="modal-action mt-4 gap-2">
        <button phx-click="skip_assign" phx-target={@myself} class="btn btn-ghost btn-sm">
          Assign later
        </button>
        <button phx-click="assign_tenants" phx-target={@myself} class="btn btn-primary btn-sm">
          Assign & Continue
        </button>
      </div>
    </div>
    """
  end

  attr :device, :map, required: true
  attr :myself, :any, required: true

  defp step_done(assigns) do
    ~H"""
    <div class="text-center py-4 space-y-3">
      <div class="text-success flex justify-center">
        <.icon name="hero-check-circle" class="size-12" />
      </div>
      <h4 class="font-semibold">{@device && @device.label}</h4>
      <div :if={@device} class="text-xs text-base-content/50 space-y-0.5">
        <div>Manufacturer: {@device.manufacturer || "—"}</div>
        <div>Slot: {@device.slot_id}</div>
        <div>Status: <span class="badge badge-sm badge-success">{@device.status}</span></div>
      </div>
      <div class="modal-action mt-4">
        <button phx-click="close" phx-target={@myself} class="btn btn-primary btn-sm">Done</button>
      </div>
    </div>
    """
  end

  # ---------------------------------------------------------------------------
  # Private helpers
  # ---------------------------------------------------------------------------

  defp list_tenants do
    try do
      PlatformRepo.all(PkiPlatformEngine.Tenant)
    rescue
      _ -> []
    end
  end

  defp parse_int(nil), do: 0
  defp parse_int(""), do: 0
  defp parse_int(v) when is_integer(v), do: v

  defp parse_int(v) when is_binary(v) do
    case Integer.parse(String.trim(v)) do
      {n, ""} -> n
      _ -> 0
    end
  end

  defp format_error(%Ecto.Changeset{} = cs) do
    cs
    |> Ecto.Changeset.traverse_errors(fn {msg, _} -> msg end)
    |> Enum.map_join(", ", fn {field, msgs} -> "#{field}: #{Enum.join(msgs, ", ")}" end)
  end

  defp format_error({:validation_error, errors}), do: inspect(errors)
  defp format_error(atom) when is_atom(atom), do: Atom.to_string(atom) |> String.replace("_", " ")
  defp format_error(bin) when is_binary(bin), do: bin
  defp format_error(other), do: inspect(other)
end
