defmodule PkiTenantWeb.Ca.HsmWizardLive do
  @moduledoc """
  5-step LiveView wizard for CA admins to connect an HSM Go agent.

  Steps:
    :gateway  — gateway port + TLS cert mode (generate vs upload)
    :token    — agent ID + one-time auth token
    :waiting  — poll for agent registration via HsmGateway.agent_connected?/1
    :keys     — select a key label advertised by the agent
    :keystore — review summary + create keystore
    :done     — success
  """
  use PkiTenantWeb, :live_view

  require Logger

  alias PkiCaEngine.{HsmAgentSetup, HsmGateway, KeystoreManagement}
  alias PkiTenant.AuditBridge

  @poll_interval_ms 3_000

  @steps [:gateway, :token, :waiting, :keys, :keystore, :done]

  @impl true
  def mount(params, _session, socket) do
    if socket.assigns.current_user[:role] not in ["ca_admin"] do
      {:ok,
       socket
       |> put_flash(:error, "Only CA Admins can configure HSM devices.")
       |> push_navigate(to: "/")}
    else
      setup_id = params["setup_id"]
      ca_instance_id = socket.assigns[:current_user][:ca_instance_id] || PkiTenant.ca_instance_id()
      tenant_id = socket.assigns[:tenant_id] || PkiTenant.tenant_id()

      socket =
        socket
        |> assign(
          page_title: "Connect HSM Agent",
          step: :gateway,
          setup_id: nil,
          setup: nil,
          ca_instance_id: ca_instance_id,
          tenant_id: tenant_id,
          cert_mode: :generate,
          port_input: "8443",
          agent_id_input: "",
          token_plaintext: nil,
          agent_config_yaml: nil,
          error: nil,
          busy: false
        )

      socket =
        if setup_id do
          resume_from_id(socket, setup_id)
        else
          socket
        end

      {:ok, socket}
    end
  end

  # ---------------------------------------------------------------------------
  # handle_params
  # ---------------------------------------------------------------------------

  @impl true
  def handle_params(%{"setup_id" => id}, _uri, socket) when socket.assigns.setup_id != id do
    {:noreply, resume_from_id(socket, id)}
  end

  def handle_params(_params, _uri, socket), do: {:noreply, socket}

  # ---------------------------------------------------------------------------
  # Agent polling
  # ---------------------------------------------------------------------------

  @impl true
  def handle_info(:poll_agent, %{assigns: %{step: :waiting}} = socket) do
    if HsmGateway.agent_connected?() do
      key_labels = HsmGateway.available_keys()

      if socket.assigns.setup_id do
        HsmAgentSetup.mark_agent_connected(socket.assigns.setup_id, key_labels)
      end

      {:noreply,
       socket
       |> assign(step: :keys, error: nil)
       |> update(:setup, fn s -> s && %{s | key_labels: key_labels, status: "agent_connected"} end)}
    else
      Process.send_after(self(), :poll_agent, @poll_interval_ms)
      {:noreply, socket}
    end
  end

  def handle_info(:poll_agent, socket), do: {:noreply, socket}

  # PubSub: agent connected while viewing a different page and resumed
  def handle_info({:agent_connected, agent_id, key_labels}, socket) do
    Logger.info("HsmWizardLive: agent #{agent_id} connected via PubSub")

    if socket.assigns.setup_id do
      HsmAgentSetup.mark_agent_connected(socket.assigns.setup_id, key_labels)
    end

    {:noreply,
     socket
     |> assign(step: :keys, error: nil)
     |> update(:setup, fn s -> s && %{s | key_labels: key_labels, status: "agent_connected"} end)}
  end

  def handle_info(_msg, socket), do: {:noreply, socket}

  # ---------------------------------------------------------------------------
  # Events — :gateway step
  # ---------------------------------------------------------------------------

  @impl true
  def handle_event("set_cert_mode", %{"mode" => mode}, socket) do
    {:noreply, assign(socket, cert_mode: String.to_existing_atom(mode), error: nil)}
  end

  @impl true
  def handle_event("next_gateway", params, socket) do
    port = parse_port(params["port"])
    cert_mode = params["cert_mode"] || "generate"

    with {:ok, port} <- validate_port(port),
         {:ok, cert_data} <- resolve_certs(cert_mode, params, socket.assigns.ca_instance_id),
         {:ok, setup} <- get_or_create_draft(socket),
         {:ok, setup} <-
           HsmAgentSetup.save_gateway(
             setup.id,
             port,
             cert_mode,
             cert_data.server_cert_pem,
             cert_data.server_key_pem,
             cert_data.ca_cert_pem
           ) do
      {:noreply,
       assign(socket,
         step: :token,
         setup: setup,
         setup_id: setup.id,
         error: nil,
         busy: false
       )}
    else
      {:error, reason} ->
        {:noreply, assign(socket, error: format_error(reason), busy: false)}
    end
  end

  # ---------------------------------------------------------------------------
  # Events — :token step
  # ---------------------------------------------------------------------------

  @impl true
  def handle_event("next_token", %{"agent_id" => agent_id}, socket) do
    agent_id = String.trim(agent_id)

    if agent_id == "" do
      {:noreply, assign(socket, error: "Agent ID is required.")}
    else
      token = HsmAgentSetup.generate_token()
      setup_id = socket.assigns.setup_id

      case HsmAgentSetup.save_token(setup_id, agent_id, token) do
        {:ok, setup} ->
          yaml = HsmAgentSetup.build_agent_config_yaml(setup, token)

          {:noreply,
           assign(socket,
             step: :waiting,
             setup: setup,
             token_plaintext: token,
             agent_config_yaml: yaml,
             error: nil
           )
           |> tap(fn _ -> Process.send_after(self(), :poll_agent, @poll_interval_ms) end)}

        {:error, reason} ->
          {:noreply, assign(socket, error: format_error(reason))}
      end
    end
  end

  # ---------------------------------------------------------------------------
  # Events — :waiting step
  # ---------------------------------------------------------------------------

  @impl true
  def handle_event("save_and_exit", _params, socket) do
    # Mark status pending_agent (already is) and redirect to HSM Devices page
    {:noreply, push_navigate(socket, to: "/hsm-devices")}
  end

  # ---------------------------------------------------------------------------
  # Events — :keys step
  # ---------------------------------------------------------------------------

  @impl true
  def handle_event("next_keys", %{"key_label" => label}, socket) do
    if label == "" do
      {:noreply, assign(socket, error: "Select a key label.")}
    else
      setup = socket.assigns.setup && %{socket.assigns.setup | selected_key_label: label}
      {:noreply, assign(socket, step: :keystore, setup: setup, error: nil)}
    end
  end

  # ---------------------------------------------------------------------------
  # Events — :keystore step
  # ---------------------------------------------------------------------------

  @impl true
  def handle_event("create_keystore", _params, socket) do
    setup = socket.assigns.setup

    keystore_attrs = %{
      type: "remote_hsm",
      config: %{
        agent_id: setup.agent_id,
        key_label: setup.selected_key_label,
        expected_agent_id: setup.expected_agent_id
      }
    }

    case KeystoreManagement.configure_keystore(socket.assigns.ca_instance_id, keystore_attrs) do
      {:ok, _keystore} ->
        HsmAgentSetup.complete(setup.id, setup.selected_key_label)

        AuditBridge.log("hsm_wizard_completed", %{
          agent_id: setup.agent_id,
          key_label: setup.selected_key_label
        })

        {:noreply, assign(socket, step: :done, error: nil)}

      {:error, reason} ->
        {:noreply, assign(socket, error: format_error(reason))}
    end
  end

  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  defp get_or_create_draft(%{assigns: %{setup_id: nil, ca_instance_id: ca_id, tenant_id: tid}}) do
    HsmAgentSetup.create_draft(ca_id, tid)
  end

  defp get_or_create_draft(%{assigns: %{setup_id: id}}) do
    HsmAgentSetup.get_draft(id)
  end

  defp resume_from_id(socket, id) do
    case HsmAgentSetup.get_draft(id) do
      {:ok, setup} ->
        step =
          case setup.status do
            "agent_connected" -> :keys
            "complete" -> :done
            _ -> :waiting
          end

        if step == :waiting do
          Process.send_after(self(), :poll_agent, @poll_interval_ms)
        end

        assign(socket, setup: setup, setup_id: id, step: step, error: nil)

      {:error, _} ->
        assign(socket, error: "Setup record not found.")
    end
  end

  defp resolve_certs("generate", _params, ca_instance_id) do
    case HsmAgentSetup.generate_certs(ca_instance_id) do
      {:ok, certs} -> {:ok, certs}
      {:error, reason} -> {:error, reason}
    end
  end

  defp resolve_certs("upload", params, _ca_instance_id) do
    server_cert = params["server_cert_pem"] || ""
    server_key = params["server_key_pem"] || ""
    ca_cert = params["ca_cert_pem"] || ""

    if server_cert == "" or server_key == "" do
      {:error, :missing_upload_certs}
    else
      {:ok,
       %{
         server_cert_pem: server_cert,
         server_key_pem: server_key,
         ca_cert_pem: if(ca_cert == "", do: nil, else: ca_cert)
       }}
    end
  end

  defp validate_port(port) when is_integer(port) and port >= 1024 and port <= 65535,
    do: {:ok, port}

  defp validate_port(_), do: {:error, :invalid_port}

  defp parse_port(nil), do: 0
  defp parse_port(""), do: 0

  defp parse_port(v) do
    case Integer.parse(String.trim(v)) do
      {n, ""} -> n
      _ -> 0
    end
  end

  defp step_index(step), do: Enum.find_index(@steps, &(&1 == step)) || 0

  defp format_error(:invalid_port), do: "Port must be between 1024 and 65535."
  defp format_error(:missing_upload_certs), do: "Server cert and server key are required."
  defp format_error(:not_found), do: "Setup record not found."
  defp format_error(atom) when is_atom(atom), do: Atom.to_string(atom) |> String.replace("_", " ")
  defp format_error(bin) when is_binary(bin), do: bin
  defp format_error(other), do: inspect(other)

  # ---------------------------------------------------------------------------
  # Render
  # ---------------------------------------------------------------------------

  @impl true
  def render(assigns) do
    assigns = assign(assigns, :step_index, step_index(assigns.step))

    ~H"""
    <div id="hsm-wizard" class="max-w-4xl mx-auto">
      <div class="flex gap-6">
        <%!-- Left sidebar: step list --%>
        <div class="w-48 shrink-0">
          <div class="card bg-base-100 border border-base-300 shadow-sm">
            <div class="card-body p-4 space-y-1">
              <.wizard_step_item step={:gateway} label="Gateway & TLS" current={@step} index={0} done_index={@step_index} />
              <.wizard_step_item step={:token} label="Agent Token" current={@step} index={1} done_index={@step_index} />
              <.wizard_step_item step={:waiting} label="Wait for Agent" current={@step} index={2} done_index={@step_index} />
              <.wizard_step_item step={:keys} label="Select Key" current={@step} index={3} done_index={@step_index} />
              <.wizard_step_item step={:keystore} label="Create Keystore" current={@step} index={4} done_index={@step_index} />
            </div>
          </div>
        </div>

        <%!-- Right panel: step content --%>
        <div class="flex-1">
          <div class="card bg-base-100 border border-base-300 shadow-sm">
            <div class="card-body p-6">
              <%!-- Error banner --%>
              <div :if={@error} class="alert alert-error mb-4 text-sm">
                <.icon name="hero-exclamation-circle" class="size-5 shrink-0" />
                <span>{@error}</span>
              </div>

              <%= case @step do %>
                <% :gateway -> %>
                  <.step_gateway cert_mode={@cert_mode} port_input={@port_input} />
                <% :token -> %>
                  <.step_token agent_id_input={@agent_id_input} />
                <% :waiting -> %>
                  <.step_waiting setup={@setup} agent_config_yaml={@agent_config_yaml} />
                <% :keys -> %>
                  <.step_keys setup={@setup} />
                <% :keystore -> %>
                  <.step_keystore setup={@setup} />
                <% :done -> %>
                  <.step_done />
              <% end %>
            </div>
          </div>
        </div>
      </div>
    </div>
    """
  end

  # ---------------------------------------------------------------------------
  # Step components
  # ---------------------------------------------------------------------------

  attr :step, :atom, required: true
  attr :label, :string, required: true
  attr :current, :atom, required: true
  attr :index, :integer, required: true
  attr :done_index, :integer, required: true

  defp wizard_step_item(assigns) do
    assigns =
      assign(assigns,
        active: assigns.step == assigns.current,
        done: assigns.index < assigns.done_index
      )

    ~H"""
    <div class={[
      "flex items-center gap-2 px-2 py-1.5 rounded text-xs font-medium",
      @active && "bg-primary/10 text-primary",
      @done && not @active && "text-success",
      not @active and not @done && "text-base-content/40"
    ]}>
      <span :if={@done} class="text-success"><.icon name="hero-check-circle" class="size-4" /></span>
      <span :if={@active} class="text-primary"><.icon name="hero-arrow-right-circle" class="size-4" /></span>
      <span :if={not @done and not @active} class="text-base-content/30"><.icon name="hero-ellipsis-horizontal-circle" class="size-4" /></span>
      <span>{@label}</span>
    </div>
    """
  end

  # -- Step: Gateway & TLS --

  attr :cert_mode, :atom, required: true
  attr :port_input, :string, required: true

  defp step_gateway(assigns) do
    ~H"""
    <div>
      <h2 class="text-base font-semibold text-base-content mb-1">Gateway Port & TLS</h2>
      <p class="text-xs text-base-content/50 mb-4">
        Configure the port the HSM agent will connect to and how TLS certificates are provisioned.
      </p>

      <form phx-submit="next_gateway" class="space-y-5">
        <div>
          <label class="block text-xs font-medium text-base-content/60 mb-1">Gateway Port</label>
          <input
            type="number"
            name="port"
            value={@port_input}
            min="1024"
            max="65535"
            required
            class="input input-bordered input-sm w-40"
          />
          <p class="text-xs text-base-content/40 mt-1">Port the agent WebSocket connects to (1024–65535).</p>
        </div>

        <div>
          <label class="block text-xs font-medium text-base-content/60 mb-2">TLS Certificates</label>
          <div class="flex gap-3">
            <label class="flex items-center gap-2 cursor-pointer">
              <input
                type="radio"
                name="cert_mode"
                value="generate"
                checked={@cert_mode == :generate}
                phx-click="set_cert_mode"
                phx-value-mode="generate"
                class="radio radio-sm radio-primary"
              />
              <span class="text-sm">Generate for me</span>
            </label>
            <label class="flex items-center gap-2 cursor-pointer">
              <input
                type="radio"
                name="cert_mode"
                value="upload"
                checked={@cert_mode == :upload}
                phx-click="set_cert_mode"
                phx-value-mode="upload"
                class="radio radio-sm radio-primary"
              />
              <span class="text-sm">Upload my own certs</span>
            </label>
          </div>
        </div>

        <div :if={@cert_mode == :upload} class="space-y-3">
          <div>
            <label class="block text-xs font-medium text-base-content/60 mb-1">Server Certificate (PEM)</label>
            <textarea name="server_cert_pem" rows="4" placeholder="-----BEGIN CERTIFICATE-----" class="textarea textarea-bordered textarea-sm w-full font-mono text-xs" />
          </div>
          <div>
            <label class="block text-xs font-medium text-base-content/60 mb-1">Server Private Key (PEM)</label>
            <textarea name="server_key_pem" rows="4" placeholder="-----BEGIN EC PRIVATE KEY-----" class="textarea textarea-bordered textarea-sm w-full font-mono text-xs" />
          </div>
          <div>
            <label class="block text-xs font-medium text-base-content/60 mb-1">CA Certificate (PEM, given to agent operator)</label>
            <textarea name="ca_cert_pem" rows="4" placeholder="-----BEGIN CERTIFICATE-----" class="textarea textarea-bordered textarea-sm w-full font-mono text-xs" />
          </div>
        </div>

        <div class="pt-2">
          <button type="submit" class="btn btn-primary btn-sm">
            Next <.icon name="hero-arrow-right" class="size-4" />
          </button>
        </div>
      </form>
    </div>
    """
  end

  # -- Step: Agent Token --

  attr :agent_id_input, :string, required: true

  defp step_token(assigns) do
    ~H"""
    <div>
      <h2 class="text-base font-semibold text-base-content mb-1">Agent Token</h2>
      <p class="text-xs text-base-content/50 mb-4">
        Choose an agent ID and generate a one-time auth token. The token is shown once — give it to the HSM operator along with the agent config YAML.
      </p>

      <form phx-submit="next_token" class="space-y-4">
        <div>
          <label class="block text-xs font-medium text-base-content/60 mb-1">Agent ID</label>
          <input
            type="text"
            name="agent_id"
            value={@agent_id_input}
            placeholder="e.g. prod-hsm-01"
            required
            class="input input-bordered input-sm w-64"
          />
          <p class="text-xs text-base-content/40 mt-1">A unique identifier for this agent connection.</p>
        </div>

        <div class="pt-2">
          <button type="submit" class="btn btn-primary btn-sm">
            Generate Token <.icon name="hero-key" class="size-4" />
          </button>
        </div>
      </form>
    </div>
    """
  end

  # -- Step: Wait for Agent --

  attr :setup, :map, required: true
  attr :agent_config_yaml, :string, required: true

  defp step_waiting(assigns) do
    ~H"""
    <div>
      <h2 class="text-base font-semibold text-base-content mb-1">Waiting for Agent</h2>
      <p class="text-xs text-base-content/50 mb-4">
        Send the config below to your HSM operator. This page polls every 3 seconds — it will advance automatically when the agent connects.
      </p>

      <div class="flex items-center gap-3 mb-5 p-3 bg-base-200 rounded">
        <span class="loading loading-spinner loading-sm text-primary"></span>
        <span class="text-sm text-base-content/70">Waiting for agent <strong>{@setup && @setup.agent_id}</strong>…</span>
      </div>

      <div :if={@setup && @setup.ca_cert_pem} class="mb-4">
        <div class="flex items-center justify-between mb-1">
          <label class="text-xs font-medium text-base-content/60">CA Certificate (give to agent operator)</label>
          <a href={"data:text/plain;charset=utf-8,#{URI.encode(@setup.ca_cert_pem)}"} download="ca-cert.pem" class="btn btn-ghost btn-xs text-sky-400">
            <.icon name="hero-arrow-down-tray" class="size-4" /> Download
          </a>
        </div>
        <pre class="bg-base-200 rounded p-2 text-xs font-mono overflow-x-auto max-h-32 overflow-y-auto"><%= @setup.ca_cert_pem %></pre>
      </div>

      <div :if={@agent_config_yaml} class="mb-5">
        <div class="flex items-center justify-between mb-1">
          <label class="text-xs font-medium text-base-content/60">agent-config.yaml</label>
          <a href={"data:text/yaml;charset=utf-8,#{URI.encode(@agent_config_yaml)}"} download="agent-config.yaml" class="btn btn-ghost btn-xs text-sky-400">
            <.icon name="hero-arrow-down-tray" class="size-4" /> Download
          </a>
        </div>
        <pre class="bg-base-200 rounded p-2 text-xs font-mono overflow-x-auto"><%= @agent_config_yaml %></pre>
      </div>

      <div class="pt-2">
        <button phx-click="save_and_exit" class="btn btn-ghost btn-sm text-base-content/50">
          Save progress and come back later
        </button>
      </div>
    </div>
    """
  end

  # -- Step: Key Selection --

  attr :setup, :map, required: true

  defp step_keys(assigns) do
    ~H"""
    <div>
      <h2 class="text-base font-semibold text-base-content mb-1">Select Key</h2>
      <p class="text-xs text-base-content/50 mb-4">
        The agent has connected and advertised the following key labels. Select the key to use for signing.
      </p>

      <form phx-submit="next_keys" class="space-y-4">
        <div class="space-y-2">
          <%= for label <- (@setup && @setup.key_labels || []) do %>
            <label class="flex items-center gap-3 p-3 border border-base-300 rounded cursor-pointer hover:bg-base-200">
              <input type="radio" name="key_label" value={label} required class="radio radio-sm radio-primary" />
              <span class="font-mono text-sm">{label}</span>
            </label>
          <% end %>
          <div :if={Enum.empty?(@setup && @setup.key_labels || [])} class="text-sm text-base-content/50 p-3 border border-base-300 rounded">
            No key labels were advertised by the agent.
          </div>
        </div>

        <div class="pt-2">
          <button type="submit" class="btn btn-primary btn-sm">
            Next <.icon name="hero-arrow-right" class="size-4" />
          </button>
        </div>
      </form>
    </div>
    """
  end

  # -- Step: Create Keystore --

  attr :setup, :map, required: true

  defp step_keystore(assigns) do
    ~H"""
    <div>
      <h2 class="text-base font-semibold text-base-content mb-1">Create Keystore</h2>
      <p class="text-xs text-base-content/50 mb-4">
        Review the configuration below and click Create to register the remote HSM keystore.
      </p>

      <div class="bg-base-200 rounded p-4 space-y-2 mb-5 text-sm">
        <div class="flex gap-2">
          <span class="text-base-content/50 w-36 shrink-0">Agent ID</span>
          <span class="font-mono">{@setup && @setup.agent_id}</span>
        </div>
        <div class="flex gap-2">
          <span class="text-base-content/50 w-36 shrink-0">Gateway Port</span>
          <span class="font-mono">{@setup && @setup.gateway_port}</span>
        </div>
        <div class="flex gap-2">
          <span class="text-base-content/50 w-36 shrink-0">TLS Mode</span>
          <span>{@setup && @setup.cert_mode}</span>
        </div>
        <div class="flex gap-2">
          <span class="text-base-content/50 w-36 shrink-0">Key Label</span>
          <span class="font-mono">{@setup && @setup.selected_key_label}</span>
        </div>
      </div>

      <button phx-click="create_keystore" class="btn btn-primary btn-sm">
        <.icon name="hero-cpu-chip" class="size-4" /> Create Keystore
      </button>
    </div>
    """
  end

  # -- Step: Done --

  defp step_done(assigns) do
    ~H"""
    <div class="text-center py-4 space-y-3">
      <div class="text-success flex justify-center">
        <.icon name="hero-check-circle" class="size-12" />
      </div>
      <h2 class="text-base font-semibold text-base-content">HSM agent connected</h2>
      <p class="text-xs text-base-content/50">
        The keystore has been created. You can now use it during a key ceremony to generate keys on the HSM.
      </p>
      <div class="pt-2">
        <.link navigate="/keystores" class="btn btn-primary btn-sm">
          View Keystores <.icon name="hero-arrow-right" class="size-4" />
        </.link>
      </div>
    </div>
    """
  end
end
