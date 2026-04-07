defmodule PkiRaPortalWeb.SetupWizardLive do
  use PkiRaPortalWeb, :live_view

  require Logger

  alias PkiRaPortal.RaEngineClient

  @templates %{
    "tls_server" => %{
      label: "TLS Server",
      icon: "hero-globe-alt",
      desc: "HTTPS server certificates with domain validation",
      key_usage: "digitalSignature,keyEncipherment",
      ext_key_usage: "serverAuth",
      digest_algo: "SHA-256",
      validity_days: 365,
      dn_required: "CN",
      dn_optional: "O,OU,L,ST,C",
      require_dcv: true
    },
    "tls_client" => %{
      label: "TLS Client",
      icon: "hero-user",
      desc: "Client authentication certificates",
      key_usage: "digitalSignature",
      ext_key_usage: "clientAuth",
      digest_algo: "SHA-256",
      validity_days: 365,
      dn_required: "CN",
      dn_optional: "O,OU,E",
      require_dcv: false
    },
    "code_signing" => %{
      label: "Code Signing",
      icon: "hero-code-bracket",
      desc: "Sign executables and software packages",
      key_usage: "digitalSignature",
      ext_key_usage: "codeSigning",
      digest_algo: "SHA-256",
      validity_days: 365,
      dn_required: "CN,O",
      dn_optional: "OU,L,ST,C",
      require_dcv: false
    },
    "email_smime" => %{
      label: "Email / S-MIME",
      icon: "hero-envelope",
      desc: "Secure email signing and encryption",
      key_usage: "digitalSignature,keyEncipherment",
      ext_key_usage: "emailProtection",
      digest_algo: "SHA-256",
      validity_days: 365,
      dn_required: "CN,E",
      dn_optional: "O,OU",
      require_dcv: false
    },
    "custom" => %{
      label: "Custom",
      icon: "hero-cog-6-tooth",
      desc: "Build a profile from scratch",
      key_usage: "",
      ext_key_usage: "",
      digest_algo: "SHA-256",
      validity_days: 365,
      dn_required: "",
      dn_optional: "",
      require_dcv: false
    }
  }

  @step_labels [
    {1, "Connect to CA"},
    {2, "Certificate Profiles"},
    {3, "Invite Team"},
    {4, "Services"},
    {5, "API Keys"}
  ]

  # ---------------------------------------------------------------------------
  # Mount
  # ---------------------------------------------------------------------------

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket), do: send(self(), :load_data)

    {:ok,
     assign(socket,
       page_title: "Setup Wizard",
       step: 1,
       # Step 1
       available_keys: [],
       connected_keys: [],
       # Step 2
       templates: @templates,
       selected_template: nil,
       profile_form: %{},
       created_profiles: [],
       connected_key_options: [],
       # Step 3
       invited_users: [],
       # Step 4
       configured_services: [],
       # Step 5
       created_api_keys: [],
       raw_key_display: nil,
       # General
       loading: true,
       error: nil
     )}
  end

  # ---------------------------------------------------------------------------
  # Data loading
  # ---------------------------------------------------------------------------

  @impl true
  def handle_info(:load_data, socket) do
    import PkiRaPortalWeb.SafeEngine, only: [safe_load: 3]

    safe_load(socket, fn ->
      opts = tenant_opts(socket)

      connections =
        case RaEngineClient.list_ca_connections([], opts) do
          {:ok, c} -> c
          {:error, _} -> []
        end

      available =
        case RaEngineClient.available_issuer_keys(opts) do
          {:ok, k} -> k
          {:error, _} -> []
        end

      connected_ids = MapSet.new(connections, & &1.issuer_key_id)

      filtered =
        Enum.reject(available, fn key ->
          kid = Map.get(key, :id) || Map.get(key, "id")
          MapSet.member?(connected_ids, kid)
        end)

      profiles =
        case RaEngineClient.list_cert_profiles(opts) do
          {:ok, p} -> p
          {:error, _} -> []
        end

      users =
        case RaEngineClient.list_portal_users(opts) do
          {:ok, u} -> u
          {:error, _} -> []
        end

      services =
        case RaEngineClient.list_service_configs(opts) do
          {:ok, s} -> s
          {:error, _} -> []
        end

      api_keys =
        case RaEngineClient.list_api_keys([], opts) do
          {:ok, k} -> k
          {:error, _} -> []
        end

      key_options =
        Enum.map(connections, fn c ->
          %{id: c.issuer_key_id, label: "#{c.issuer_key_name} (#{c.algorithm})"}
        end)

      {:noreply,
       assign(socket,
         available_keys: filtered,
         connected_keys: connections,
         created_profiles: profiles,
         connected_key_options: key_options,
         invited_users: users,
         configured_services: services,
         created_api_keys: api_keys,
         loading: false
       )}
    end, retry_msg: :load_data)
  end

  # ---------------------------------------------------------------------------
  # Navigation events
  # ---------------------------------------------------------------------------

  @impl true
  def handle_event("go_step", %{"step" => step_str}, socket) do
    case Integer.parse(step_str) do
      {step, ""} when step >= 1 and step <= 6 ->
        handle_go_step(step, socket)
      _ ->
        {:noreply, socket}
    end
  end

  defp handle_go_step(step, socket) do
    cond do
      step < 1 or step > 6 ->
        {:noreply, socket}

      step > 1 and Enum.empty?(socket.assigns.connected_keys) ->
        {:noreply, put_flash(socket, :error, "Connect at least one CA key first")}

      step > 2 and Enum.empty?(socket.assigns.created_profiles) ->
        {:noreply, put_flash(socket, :error, "Create at least one certificate profile first")}

      true ->
        {:noreply, assign(socket, step: step, error: nil)}
    end
  end

  def handle_event("next_step", _params, socket) do
    next = socket.assigns.step + 1
    handle_event("go_step", %{"step" => to_string(next)}, socket)
  end

  def handle_event("prev_step", _params, socket) do
    prev = max(socket.assigns.step - 1, 1)
    {:noreply, assign(socket, step: prev, error: nil)}
  end

  def handle_event("skip_step", _params, socket) do
    next = min(socket.assigns.step + 1, 6)
    {:noreply, assign(socket, step: next, error: nil)}
  end

  # ---------------------------------------------------------------------------
  # Step 1: Connect to CA
  # ---------------------------------------------------------------------------

  def handle_event("connect_key", params, socket) do
    key_id = params["key-id"] || params["key_id"]
    attrs = %{
      issuer_key_id: key_id,
      issuer_key_name: params["key-name"] || params["key_name"] || "",
      algorithm: params["algorithm"] || "",
      ca_instance_name: params["ca-instance"] || params["ca_instance"] || ""
    }

    case RaEngineClient.create_ca_connection(attrs, tenant_opts(socket)) do
      {:ok, _conn} ->
        send(self(), :load_data)
        {:noreply, put_flash(socket, :info, "Key connected successfully")}

      {:error, reason} ->
        Logger.error("[setup_wizard] connect_key failed: #{inspect(reason)}")
        {:noreply, put_flash(socket, :error, "Failed to connect key")}
    end
  end

  # ---------------------------------------------------------------------------
  # Step 2: Certificate Profiles
  # ---------------------------------------------------------------------------

  def handle_event("select_template", %{"template" => name}, socket) do
    tpl = Map.get(@templates, name, %{})

    form = %{
      "name" => "",
      "key_usage" => Map.get(tpl, :key_usage, ""),
      "ext_key_usage" => Map.get(tpl, :ext_key_usage, ""),
      "digest_algo" => Map.get(tpl, :digest_algo, "SHA-256"),
      "validity_days" => to_string(Map.get(tpl, :validity_days, 365)),
      "dn_required" => Map.get(tpl, :dn_required, ""),
      "dn_optional" => Map.get(tpl, :dn_optional, ""),
      "require_dcv" => Map.get(tpl, :require_dcv, false),
      "issuer_key_id" => ""
    }

    {:noreply, assign(socket, selected_template: name, profile_form: form)}
  end

  def handle_event("cancel_template", _params, socket) do
    {:noreply, assign(socket, selected_template: nil, profile_form: %{})}
  end

  def handle_event("create_profile", params, socket) do
    attrs = %{
      name: params["name"],
      key_usage: params["key_usage"],
      ext_key_usage: params["ext_key_usage"],
      digest_algo: params["digest_algo"],
      validity_days: parse_int(params["validity_days"], 365),
      issuer_key_id: params["issuer_key_id"],
      subject_dn_policy: %{
        required_fields: params["dn_required"] || "",
        optional_fields: params["dn_optional"] || "",
        require_dcv: params["require_dcv"] == "true"
      }
    }

    case RaEngineClient.create_cert_profile(attrs, tenant_opts(socket)) do
      {:ok, profile} ->
        profiles = [profile | socket.assigns.created_profiles]

        {:noreply,
         socket
         |> assign(created_profiles: profiles, selected_template: nil, profile_form: %{})
         |> put_flash(:info, "Certificate profile created")}

      {:error, reason} ->
        Logger.error("[setup_wizard] create_profile failed: #{inspect(reason)}")
        {:noreply, put_flash(socket, :error, "Failed to create profile")}
    end
  end

  # ---------------------------------------------------------------------------
  # Step 3: Invite Team
  # ---------------------------------------------------------------------------

  def handle_event("invite_user", params, socket) do
    attrs = %{
      username: params["username"],
      display_name: params["display_name"],
      email: params["email"],
      role: params["role"]
    }

    case RaEngineClient.create_portal_user(attrs, tenant_opts(socket)) do
      {:ok, user} ->
        users = [user | socket.assigns.invited_users]
        {:noreply, socket |> assign(invited_users: users) |> put_flash(:info, "User invited")}

      {:error, reason} ->
        Logger.error("[setup_wizard] invite_user failed: #{inspect(reason)}")
        {:noreply, put_flash(socket, :error, "Failed to invite user")}
    end
  end

  # ---------------------------------------------------------------------------
  # Step 4: Service Configuration
  # ---------------------------------------------------------------------------

  def handle_event("configure_service", params, socket) do
    attrs = %{
      service_type: params["service_type"],
      port: parse_int(params["port"], 8080),
      url: params["url"]
    }

    case RaEngineClient.configure_service(attrs, tenant_opts(socket)) do
      {:ok, config} ->
        services = [config | socket.assigns.configured_services]

        {:noreply,
         socket |> assign(configured_services: services) |> put_flash(:info, "Service configured")}

      {:error, reason} ->
        Logger.error("[setup_wizard] configure_service failed: #{inspect(reason)}")
        {:noreply, put_flash(socket, :error, "Failed to configure service")}
    end
  end

  # ---------------------------------------------------------------------------
  # Step 5: API Keys
  # ---------------------------------------------------------------------------

  def handle_event("create_api_key", params, socket) do
    user_id =
      get_in(socket.assigns, [:current_user, "id"]) ||
        get_in(socket.assigns, [:current_user, :id])

    attrs = %{name: params["label"], ra_user_id: user_id}

    case RaEngineClient.create_api_key(attrs, tenant_opts(socket)) do
      {:ok, key} ->
        raw = key[:raw_key] || key["raw_key"]
        keys = [key | socket.assigns.created_api_keys]

        {:noreply,
         socket
         |> assign(created_api_keys: keys, raw_key_display: raw)
         |> put_flash(:info, "API key created. Copy the key now!")}

      {:error, reason} ->
        Logger.error("[setup_wizard] create_api_key failed: #{inspect(reason)}")
        {:noreply, put_flash(socket, :error, "Failed to create API key")}
    end
  end

  def handle_event("dismiss_raw_key", _params, socket) do
    {:noreply, assign(socket, raw_key_display: nil)}
  end

  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  defp parse_int(val, default) when is_binary(val) do
    case Integer.parse(val) do
      {n, _} -> n
      :error -> default
    end
  end

  defp parse_int(_, default), do: default

  defp key_get(key, field) do
    Map.get(key, field) || Map.get(key, to_string(field))
  end

  defp algorithm_badge_class(algorithm) do
    algo = to_string(algorithm)

    cond do
      algo in ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"] -> "badge-primary"
      algo == "KAZ-SIGN" -> "badge-secondary"
      String.starts_with?(algo, "RSA") -> "badge-warning"
      String.starts_with?(algo, "EC") -> "badge-info"
      true -> "badge-ghost"
    end
  end

  defp step_status(current, step_num, connected_keys, created_profiles) do
    cond do
      step_num == current -> :current
      step_num < current -> :completed
      step_num == 2 and Enum.empty?(connected_keys) -> :locked
      step_num > 2 and Enum.empty?(created_profiles) -> :locked
      true -> :upcoming
    end
  end

  # ---------------------------------------------------------------------------
  # Render
  # ---------------------------------------------------------------------------

  @impl true
  def render(assigns) do
    assigns = assign(assigns, step_labels: @step_labels)

    ~H"""
    <div id="setup-wizard" class="fixed inset-0 z-50 bg-base-200 overflow-y-auto">
      <div class="max-w-4xl mx-auto py-8 px-4">
        <%!-- Header --%>
        <div class="text-center mb-6">
          <h1 class="text-2xl font-bold">RA Setup Wizard</h1>
          <p class="text-sm text-base-content/60 mt-1">Configure your Registration Authority in a few steps</p>
        </div>

        <%!-- Step Indicator --%>
        <div class="flex items-center justify-center gap-1 mb-8">
          <%= for {num, label} <- @step_labels do %>
            <% status = step_status(@step, num, @connected_keys, @created_profiles) %>
            <button
              phx-click="go_step"
              phx-value-step={num}
              disabled={status == :locked}
              class={[
                "flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-medium transition-colors",
                status == :current && "bg-primary text-primary-content",
                status == :completed && "bg-success/20 text-success cursor-pointer hover:bg-success/30",
                status == :upcoming && "bg-base-300 text-base-content/60 cursor-pointer hover:bg-base-300/80",
                status == :locked && "bg-base-300/50 text-base-content/30 cursor-not-allowed"
              ]}
            >
              <span :if={status == :completed} class="text-success">
                <.icon name="hero-check-circle-solid" class="size-4" />
              </span>
              <span :if={status != :completed} class={[
                "flex items-center justify-center w-5 h-5 rounded-full text-[10px] font-bold",
                status == :current && "bg-primary-content/20",
                status in [:upcoming, :locked] && "bg-base-content/10"
              ]}>
                {num}
              </span>
              <span class="hidden sm:inline">{label}</span>
            </button>
            <.icon :if={num < 5} name="hero-chevron-right-mini" class="size-3 text-base-content/30" />
          <% end %>
        </div>

        <%!-- Loading state --%>
        <div :if={@loading} class="flex flex-col items-center justify-center py-20">
          <span class="loading loading-spinner loading-lg text-primary"></span>
          <p class="mt-3 text-sm text-base-content/60">Loading configuration...</p>
        </div>

        <%!-- Step content --%>
        <div :if={not @loading}>
          {render_current_step(assigns)}
        </div>
      </div>
    </div>
    """
  end

  defp render_current_step(%{step: 1} = assigns), do: render_step_1(assigns)
  defp render_current_step(%{step: 2} = assigns), do: render_step_2(assigns)
  defp render_current_step(%{step: 3} = assigns), do: render_step_3(assigns)
  defp render_current_step(%{step: 4} = assigns), do: render_step_4(assigns)
  defp render_current_step(%{step: 5} = assigns), do: render_step_5(assigns)
  defp render_current_step(%{step: 6} = assigns), do: render_step_6(assigns)
  defp render_current_step(assigns), do: render_step_1(assigns)

  # ---------------------------------------------------------------------------
  # Step 1: Connect to CA
  # ---------------------------------------------------------------------------

  defp render_step_1(assigns) do
    ~H"""
    <div class="space-y-6">
      <div class="text-center">
        <h2 class="text-lg font-semibold">Step 1: Connect to CA</h2>
        <p class="text-sm text-base-content/60 mt-1">
          Link your RA to issuer keys from the Certificate Authority
        </p>
      </div>

      <%!-- Connected keys --%>
      <div :if={not Enum.empty?(@connected_keys)} class="card bg-base-100 shadow-sm border border-success/30">
        <div class="card-body p-4">
          <h3 class="text-sm font-semibold flex items-center gap-2">
            <.icon name="hero-check-circle" class="size-4 text-success" />
            Connected Keys
            <span class="badge badge-sm badge-success">{length(@connected_keys)}</span>
          </h3>
          <div class="divide-y divide-base-200 mt-2">
            <div :for={conn <- @connected_keys} class="flex items-center justify-between py-2">
              <div class="flex items-center gap-2">
                <.icon name="hero-key" class="size-4 text-primary" />
                <span class="text-sm font-medium">{conn.issuer_key_name}</span>
                <span class={"badge badge-xs #{algorithm_badge_class(conn.algorithm)}"}>{conn.algorithm}</span>
              </div>
              <span class="text-xs text-base-content/50">{conn.ca_instance_name}</span>
            </div>
          </div>
        </div>
      </div>

      <%!-- Available keys --%>
      <div :if={Enum.empty?(@available_keys) and Enum.empty?(@connected_keys)} class="alert alert-warning">
        <.icon name="hero-exclamation-triangle" class="size-5" />
        <span>No CA issuer keys available. Ensure the CA engine is running and has active keys.</span>
      </div>

      <div :if={not Enum.empty?(@available_keys)}>
        <h3 class="text-sm font-semibold mb-3 flex items-center gap-2">
          <.icon name="hero-key" class="size-4 text-primary" />
          Available Keys
          <span class="badge badge-sm badge-ghost">{length(@available_keys)}</span>
        </h3>
        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
          <div
            :for={key <- @available_keys}
            class="card bg-base-100 shadow-sm border border-base-300 hover:border-primary/40 transition-colors"
          >
            <div class="card-body p-4 space-y-2">
              <div class="flex items-center justify-between">
                <span class="text-sm font-medium">{key_get(key, :name)}</span>
                <span class={"badge badge-xs #{algorithm_badge_class(key_get(key, :algorithm))}"}>{key_get(key, :algorithm)}</span>
              </div>
              <p class="text-xs text-base-content/50">CA: {key_get(key, :ca_instance_name)}</p>
              <button
                class="btn btn-primary btn-xs btn-block"
                phx-click="connect_key"
                phx-value-key-id={key_get(key, :id)}
                phx-value-key-name={key_get(key, :name)}
                phx-value-algorithm={key_get(key, :algorithm)}
                phx-value-ca-instance={key_get(key, :ca_instance_name)}
              >
                <.icon name="hero-plus" class="size-3" /> Connect
              </button>
            </div>
          </div>
        </div>
      </div>

      <%!-- Navigation --%>
      <div class="flex justify-end pt-4 border-t border-base-300">
        <button
          class="btn btn-primary"
          phx-click="next_step"
          disabled={Enum.empty?(@connected_keys)}
        >
          Next: Certificate Profiles <.icon name="hero-arrow-right" class="size-4" />
        </button>
      </div>
    </div>
    """
  end

  # ---------------------------------------------------------------------------
  # Step 2: Certificate Profiles
  # ---------------------------------------------------------------------------

  defp render_step_2(assigns) do
    ~H"""
    <div class="space-y-6">
      <div class="text-center">
        <h2 class="text-lg font-semibold">Step 2: Certificate Profiles</h2>
        <p class="text-sm text-base-content/60 mt-1">
          Define what types of certificates this RA can issue
        </p>
      </div>

      <%!-- Created profiles --%>
      <div :if={not Enum.empty?(@created_profiles)} class="card bg-base-100 shadow-sm border border-success/30">
        <div class="card-body p-4">
          <h3 class="text-sm font-semibold flex items-center gap-2">
            <.icon name="hero-check-circle" class="size-4 text-success" />
            Created Profiles
            <span class="badge badge-sm badge-success">{length(@created_profiles)}</span>
          </h3>
          <div class="divide-y divide-base-200 mt-2">
            <div :for={p <- @created_profiles} class="flex items-center justify-between py-2">
              <span class="text-sm font-medium">{p.name || Map.get(p, "name")}</span>
              <span class="text-xs text-base-content/50">{p.key_usage || Map.get(p, "key_usage")}</span>
            </div>
          </div>
        </div>
      </div>

      <%!-- Template picker (when no template selected) --%>
      <div :if={@selected_template == nil}>
        <h3 class="text-sm font-semibold mb-3">Choose a Template</h3>
        <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
          <%= for {key, tpl} <- @templates do %>
            <button
              phx-click="select_template"
              phx-value-template={key}
              class="card bg-base-100 shadow-sm border border-base-300 hover:border-primary/40 transition-colors text-left"
            >
              <div class="card-body p-4 space-y-2">
                <div class="flex items-center gap-2">
                  <.icon name={tpl.icon} class="size-5 text-primary" />
                  <span class="font-semibold text-sm">{tpl.label}</span>
                </div>
                <p class="text-xs text-base-content/60">{tpl.desc}</p>
              </div>
            </button>
          <% end %>
        </div>
      </div>

      <%!-- Profile form (when template selected) --%>
      <div :if={@selected_template != nil} class="card bg-base-100 shadow-sm border border-primary/30">
        <div class="card-body">
          <div class="flex items-center justify-between mb-4">
            <h3 class="text-sm font-semibold">
              New Profile: {Map.get(@templates[@selected_template] || %{}, :label, "Custom")}
            </h3>
            <button phx-click="cancel_template" class="btn btn-ghost btn-xs">Cancel</button>
          </div>

          <form phx-submit="create_profile" class="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label class="label text-xs font-medium">Profile Name <span class="text-error">*</span></label>
              <input
                type="text"
                name="name"
                required
                maxlength="255"
                placeholder="e.g. Production TLS"
                class="input input-sm input-bordered w-full"
              />
            </div>

            <div>
              <label class="label text-xs font-medium">Issuer Key <span class="text-error">*</span></label>
              <select name="issuer_key_id" required class="select select-sm select-bordered w-full">
                <option value="">Select issuer key</option>
                <option :for={k <- @connected_key_options} value={k.id}>{k.label}</option>
              </select>
            </div>

            <div>
              <label class="label text-xs font-medium">Key Usage</label>
              <input
                type="text"
                name="key_usage"
                value={@profile_form["key_usage"]}
                maxlength="255"
                class="input input-sm input-bordered w-full"
              />
            </div>

            <div>
              <label class="label text-xs font-medium">Extended Key Usage</label>
              <input
                type="text"
                name="ext_key_usage"
                value={@profile_form["ext_key_usage"]}
                maxlength="255"
                class="input input-sm input-bordered w-full"
              />
            </div>

            <div>
              <label class="label text-xs font-medium">Digest Algorithm</label>
              <select name="digest_algo" class="select select-sm select-bordered w-full">
                <option value="SHA-256" selected={@profile_form["digest_algo"] == "SHA-256"}>SHA-256</option>
                <option value="SHA-384" selected={@profile_form["digest_algo"] == "SHA-384"}>SHA-384</option>
                <option value="SHA-512" selected={@profile_form["digest_algo"] == "SHA-512"}>SHA-512</option>
              </select>
            </div>

            <div>
              <label class="label text-xs font-medium">Validity (days)</label>
              <input
                type="number"
                name="validity_days"
                value={@profile_form["validity_days"]}
                min="1"
                class="input input-sm input-bordered w-full"
              />
            </div>

            <div>
              <label class="label text-xs font-medium">Required DN Fields</label>
              <input
                type="text"
                name="dn_required"
                value={@profile_form["dn_required"]}
                maxlength="255"
                placeholder="CN,O,OU"
                class="input input-sm input-bordered w-full"
              />
            </div>

            <div>
              <label class="label text-xs font-medium">Optional DN Fields</label>
              <input
                type="text"
                name="dn_optional"
                value={@profile_form["dn_optional"]}
                maxlength="255"
                placeholder="L,ST,C"
                class="input input-sm input-bordered w-full"
              />
            </div>

            <div class="flex items-center gap-2">
              <input
                type="checkbox"
                name="require_dcv"
                value="true"
                checked={@profile_form["require_dcv"] == true}
                class="checkbox checkbox-sm checkbox-primary"
              />
              <label class="text-xs font-medium">Require Domain Control Validation</label>
            </div>

            <div class="flex items-end">
              <button type="submit" class="btn btn-primary btn-sm">Create Profile</button>
            </div>
          </form>
        </div>
      </div>

      <%!-- Navigation --%>
      <div class="flex justify-between pt-4 border-t border-base-300">
        <button class="btn btn-ghost" phx-click="prev_step">
          <.icon name="hero-arrow-left" class="size-4" /> Back
        </button>
        <button
          class="btn btn-primary"
          phx-click="next_step"
          disabled={Enum.empty?(@created_profiles)}
        >
          Next: Invite Team <.icon name="hero-arrow-right" class="size-4" />
        </button>
      </div>
    </div>
    """
  end

  # ---------------------------------------------------------------------------
  # Step 3: Invite Team
  # ---------------------------------------------------------------------------

  defp render_step_3(assigns) do
    ~H"""
    <div class="space-y-6">
      <div class="text-center">
        <h2 class="text-lg font-semibold">Step 3: Invite Team</h2>
        <p class="text-sm text-base-content/60 mt-1">
          Add RA officers and auditors to your team (optional)
        </p>
      </div>

      <%!-- Invited users --%>
      <div :if={not Enum.empty?(@invited_users)} class="card bg-base-100 shadow-sm border border-success/30">
        <div class="card-body p-4">
          <h3 class="text-sm font-semibold flex items-center gap-2">
            <.icon name="hero-check-circle" class="size-4 text-success" />
            Team Members
            <span class="badge badge-sm badge-success">{length(@invited_users)}</span>
          </h3>
          <div class="divide-y divide-base-200 mt-2">
            <div :for={u <- @invited_users} class="flex items-center justify-between py-2">
              <div>
                <span class="text-sm font-medium">{u.display_name || u.username || Map.get(u, "username")}</span>
                <span class="text-xs text-base-content/50 ml-2">{u.email || Map.get(u, "email")}</span>
              </div>
              <span class="badge badge-xs badge-outline">{u.role || Map.get(u, "role")}</span>
            </div>
          </div>
        </div>
      </div>

      <%!-- Invite form --%>
      <div class="card bg-base-100 shadow-sm border border-base-300">
        <div class="card-body">
          <h3 class="text-sm font-semibold mb-3">Invite a User</h3>
          <form phx-submit="invite_user" class="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label class="label text-xs font-medium">Username <span class="text-error">*</span></label>
              <input type="text" name="username" required maxlength="50" class="input input-sm input-bordered w-full" />
            </div>
            <div>
              <label class="label text-xs font-medium">Display Name</label>
              <input type="text" name="display_name" maxlength="100" class="input input-sm input-bordered w-full" />
            </div>
            <div>
              <label class="label text-xs font-medium">Email <span class="text-error">*</span></label>
              <input type="email" name="email" required maxlength="254" class="input input-sm input-bordered w-full" />
            </div>
            <div>
              <label class="label text-xs font-medium">Role <span class="text-error">*</span></label>
              <select name="role" required class="select select-sm select-bordered w-full">
                <option value="">Select role</option>
                <option value="ra_officer">RA Officer</option>
                <option value="auditor">Auditor</option>
              </select>
            </div>
            <div class="flex items-end">
              <button type="submit" class="btn btn-primary btn-sm">
                <.icon name="hero-user-plus" class="size-4" /> Invite
              </button>
            </div>
          </form>
        </div>
      </div>

      <%!-- Navigation --%>
      <div class="flex justify-between pt-4 border-t border-base-300">
        <button class="btn btn-ghost" phx-click="prev_step">
          <.icon name="hero-arrow-left" class="size-4" /> Back
        </button>
        <div class="flex gap-2">
          <button class="btn btn-ghost" phx-click="skip_step">Skip</button>
          <button class="btn btn-primary" phx-click="next_step">
            Next: Services <.icon name="hero-arrow-right" class="size-4" />
          </button>
        </div>
      </div>
    </div>
    """
  end

  # ---------------------------------------------------------------------------
  # Step 4: Service Configuration
  # ---------------------------------------------------------------------------

  defp render_step_4(assigns) do
    ~H"""
    <div class="space-y-6">
      <div class="text-center">
        <h2 class="text-lg font-semibold">Step 4: Service Configuration</h2>
        <p class="text-sm text-base-content/60 mt-1">
          Configure validation and distribution services (optional)
        </p>
      </div>

      <%!-- Configured services --%>
      <div :if={not Enum.empty?(@configured_services)} class="card bg-base-100 shadow-sm border border-success/30">
        <div class="card-body p-4">
          <h3 class="text-sm font-semibold flex items-center gap-2">
            <.icon name="hero-check-circle" class="size-4 text-success" />
            Configured Services
            <span class="badge badge-sm badge-success">{length(@configured_services)}</span>
          </h3>
          <div class="divide-y divide-base-200 mt-2">
            <div :for={s <- @configured_services} class="flex items-center justify-between py-2">
              <div>
                <span class="text-sm font-medium">{s.service_type || Map.get(s, "service_type")}</span>
                <span class="text-xs text-base-content/50 ml-2">Port: {s.port || Map.get(s, "port")}</span>
              </div>
              <span class="text-xs text-base-content/50 font-mono">{s.url || Map.get(s, "url")}</span>
            </div>
          </div>
        </div>
      </div>

      <%!-- Configure form --%>
      <div class="card bg-base-100 shadow-sm border border-base-300">
        <div class="card-body">
          <h3 class="text-sm font-semibold mb-3">Add a Service</h3>
          <form phx-submit="configure_service" class="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label class="label text-xs font-medium">Service Type <span class="text-error">*</span></label>
              <select name="service_type" required class="select select-sm select-bordered w-full">
                <option value="">Select service</option>
                <option value="ocsp_responder">OCSP Responder</option>
                <option value="crl_distribution">CRL Distribution</option>
                <option value="tsa">Time Stamping Authority (TSA)</option>
              </select>
            </div>
            <div>
              <label class="label text-xs font-medium">Port</label>
              <input type="number" name="port" value="8080" min="1" max="65535" class="input input-sm input-bordered w-full" />
            </div>
            <div class="md:col-span-2">
              <label class="label text-xs font-medium">URL</label>
              <input type="url" name="url" placeholder="https://ocsp.example.com" maxlength="255" class="input input-sm input-bordered w-full" />
            </div>
            <div class="flex items-end">
              <button type="submit" class="btn btn-primary btn-sm">
                <.icon name="hero-cog-6-tooth" class="size-4" /> Configure
              </button>
            </div>
          </form>
        </div>
      </div>

      <%!-- Navigation --%>
      <div class="flex justify-between pt-4 border-t border-base-300">
        <button class="btn btn-ghost" phx-click="prev_step">
          <.icon name="hero-arrow-left" class="size-4" /> Back
        </button>
        <div class="flex gap-2">
          <button class="btn btn-ghost" phx-click="skip_step">Skip</button>
          <button class="btn btn-primary" phx-click="next_step">
            Next: API Keys <.icon name="hero-arrow-right" class="size-4" />
          </button>
        </div>
      </div>
    </div>
    """
  end

  # ---------------------------------------------------------------------------
  # Step 5: API Keys
  # ---------------------------------------------------------------------------

  defp render_step_5(assigns) do
    ~H"""
    <div class="space-y-6">
      <div class="text-center">
        <h2 class="text-lg font-semibold">Step 5: API Keys</h2>
        <p class="text-sm text-base-content/60 mt-1">
          Create API keys for programmatic access (optional)
        </p>
      </div>

      <%!-- Raw key display --%>
      <div :if={@raw_key_display} class="alert alert-warning shadow-sm">
        <div class="flex flex-col gap-2 w-full">
          <div class="flex items-center justify-between">
            <h3 class="font-semibold text-sm flex items-center gap-1">
              <.icon name="hero-exclamation-triangle" class="size-4" />
              Copy this key now -- it will not be shown again!
            </h3>
            <button phx-click="dismiss_raw_key" class="btn btn-ghost btn-xs">Dismiss</button>
          </div>
          <code class="font-mono text-sm bg-black/10 rounded px-3 py-2 break-all select-all">
            {@raw_key_display}
          </code>
        </div>
      </div>

      <%!-- Created keys --%>
      <div :if={not Enum.empty?(@created_api_keys)} class="card bg-base-100 shadow-sm border border-success/30">
        <div class="card-body p-4">
          <h3 class="text-sm font-semibold flex items-center gap-2">
            <.icon name="hero-check-circle" class="size-4 text-success" />
            API Keys
            <span class="badge badge-sm badge-success">{length(@created_api_keys)}</span>
          </h3>
          <div class="divide-y divide-base-200 mt-2">
            <div :for={k <- @created_api_keys} class="flex items-center justify-between py-2">
              <span class="text-sm font-medium">{k[:name] || k[:label] || k["name"] || k["label"]}</span>
              <span class="badge badge-xs badge-success">Created</span>
            </div>
          </div>
        </div>
      </div>

      <%!-- Create form --%>
      <div class="card bg-base-100 shadow-sm border border-base-300">
        <div class="card-body">
          <h3 class="text-sm font-semibold mb-3">Create an API Key</h3>
          <form phx-submit="create_api_key" class="flex items-end gap-4">
            <div class="flex-1">
              <label class="label text-xs font-medium">Label <span class="text-error">*</span></label>
              <input type="text" name="label" required maxlength="100" placeholder="e.g. CI/CD Pipeline" class="input input-sm input-bordered w-full" />
            </div>
            <button type="submit" class="btn btn-primary btn-sm">
              <.icon name="hero-key" class="size-4" /> Create Key
            </button>
          </form>
        </div>
      </div>

      <%!-- Navigation --%>
      <div class="flex justify-between pt-4 border-t border-base-300">
        <button class="btn btn-ghost" phx-click="prev_step">
          <.icon name="hero-arrow-left" class="size-4" /> Back
        </button>
        <div class="flex gap-2">
          <button class="btn btn-ghost" phx-click="skip_step">Skip</button>
          <button class="btn btn-primary" phx-click="go_step" phx-value-step="6">
            Finish <.icon name="hero-check" class="size-4" />
          </button>
        </div>
      </div>
    </div>
    """
  end

  # ---------------------------------------------------------------------------
  # Step 6: Summary
  # ---------------------------------------------------------------------------

  defp render_step_6(assigns) do
    ~H"""
    <div class="space-y-6">
      <div class="text-center">
        <div class="flex justify-center mb-3">
          <div class="flex items-center justify-center w-16 h-16 rounded-full bg-success/20">
            <.icon name="hero-check-circle" class="size-10 text-success" />
          </div>
        </div>
        <h2 class="text-lg font-semibold">Setup Complete</h2>
        <p class="text-sm text-base-content/60 mt-1">
          Your Registration Authority is configured and ready to go
        </p>
      </div>

      <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
        <%!-- CA Connections --%>
        <div class="card bg-base-100 shadow-sm border border-base-300">
          <div class="card-body p-4">
            <h3 class="text-sm font-semibold flex items-center gap-2">
              <.icon name="hero-link" class="size-4 text-primary" />
              CA Connections
              <span class="badge badge-sm badge-primary">{length(@connected_keys)}</span>
            </h3>
            <div class="mt-2 space-y-1">
              <div :for={c <- @connected_keys} class="text-xs flex items-center gap-1">
                <.icon name="hero-check" class="size-3 text-success" />
                {c.issuer_key_name}
                <span class={"badge badge-xs #{algorithm_badge_class(c.algorithm)}"}>{c.algorithm}</span>
              </div>
              <p :if={Enum.empty?(@connected_keys)} class="text-xs text-base-content/50">None</p>
            </div>
          </div>
        </div>

        <%!-- Certificate Profiles --%>
        <div class="card bg-base-100 shadow-sm border border-base-300">
          <div class="card-body p-4">
            <h3 class="text-sm font-semibold flex items-center gap-2">
              <.icon name="hero-document-text" class="size-4 text-primary" />
              Certificate Profiles
              <span class="badge badge-sm badge-primary">{length(@created_profiles)}</span>
            </h3>
            <div class="mt-2 space-y-1">
              <div :for={p <- @created_profiles} class="text-xs flex items-center gap-1">
                <.icon name="hero-check" class="size-3 text-success" />
                {p.name || Map.get(p, "name")}
              </div>
              <p :if={Enum.empty?(@created_profiles)} class="text-xs text-base-content/50">None</p>
            </div>
          </div>
        </div>

        <%!-- Team Members --%>
        <div class="card bg-base-100 shadow-sm border border-base-300">
          <div class="card-body p-4">
            <h3 class="text-sm font-semibold flex items-center gap-2">
              <.icon name="hero-users" class="size-4 text-primary" />
              Team Members
              <span class="badge badge-sm badge-primary">{length(@invited_users)}</span>
            </h3>
            <div class="mt-2 space-y-1">
              <div :for={u <- @invited_users} class="text-xs flex items-center gap-1">
                <.icon name="hero-check" class="size-3 text-success" />
                {u.display_name || u.username || Map.get(u, "username")}
                <span class="badge badge-xs badge-outline">{u.role || Map.get(u, "role")}</span>
              </div>
              <p :if={Enum.empty?(@invited_users)} class="text-xs text-base-content/50">Skipped</p>
            </div>
          </div>
        </div>

        <%!-- Services --%>
        <div class="card bg-base-100 shadow-sm border border-base-300">
          <div class="card-body p-4">
            <h3 class="text-sm font-semibold flex items-center gap-2">
              <.icon name="hero-server" class="size-4 text-primary" />
              Services
              <span class="badge badge-sm badge-primary">{length(@configured_services)}</span>
            </h3>
            <div class="mt-2 space-y-1">
              <div :for={s <- @configured_services} class="text-xs flex items-center gap-1">
                <.icon name="hero-check" class="size-3 text-success" />
                {s.service_type || Map.get(s, "service_type")}
              </div>
              <p :if={Enum.empty?(@configured_services)} class="text-xs text-base-content/50">Skipped</p>
            </div>
          </div>
        </div>

        <%!-- API Keys --%>
        <div class="card bg-base-100 shadow-sm border border-base-300 md:col-span-2">
          <div class="card-body p-4">
            <h3 class="text-sm font-semibold flex items-center gap-2">
              <.icon name="hero-key" class="size-4 text-primary" />
              API Keys
              <span class="badge badge-sm badge-primary">{length(@created_api_keys)}</span>
            </h3>
            <div class="mt-2 space-y-1">
              <div :for={k <- @created_api_keys} class="text-xs flex items-center gap-1">
                <.icon name="hero-check" class="size-3 text-success" />
                {k[:name] || k[:label] || k["name"] || k["label"]}
              </div>
              <p :if={Enum.empty?(@created_api_keys)} class="text-xs text-base-content/50">Skipped</p>
            </div>
          </div>
        </div>
      </div>

      <%!-- Go to Dashboard --%>
      <div class="flex justify-center pt-4 border-t border-base-300">
        <.link navigate="/" class="btn btn-primary btn-lg">
          <.icon name="hero-home" class="size-5" /> Go to Dashboard
        </.link>
      </div>
    </div>
    """
  end
end
