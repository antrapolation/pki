defmodule PkiCaPortalWeb.QuickSetupLive do
  @moduledoc """
  Dev/test helper: one-click CA hierarchy setup.
  Creates Root CA → Sub-CA with keystores and key ceremonies in a single flow.
  """
  use PkiCaPortalWeb, :live_view

  alias PkiCaPortal.CaEngineClient

  @algorithms [
    {"ECC-P256", "Classical — fast, widely supported"},
    {"ECC-P384", "Classical — stronger, slightly slower"},
    {"RSA-2048", "Classical — legacy compatibility"},
    {"RSA-4096", "Classical — legacy, stronger"},
    {"KAZ-SIGN-128", "Post-Quantum — Malaysia local PQC"},
    {"KAZ-SIGN-192", "Post-Quantum — KAZ-Sign level 3"},
    {"KAZ-SIGN-256", "Post-Quantum — KAZ-Sign level 5"},
    {"ML-DSA-44", "Post-Quantum — NIST FIPS 204 level 2"},
    {"ML-DSA-65", "Post-Quantum — NIST FIPS 204 level 3"},
    {"ML-DSA-87", "Post-Quantum — NIST FIPS 204 level 5"}
  ]

  @impl true
  def mount(_params, _session, socket) do
    {:ok,
     assign(socket,
       page_title: "Quick Setup",
       root_name: "Root CA",
       sub_name: "Issuing CA",
       root_algo: "ECC-P256",
       sub_algo: "ECC-P256",
       algorithms: @algorithms,
       log: [],
       running: false,
       done: false
     )}
  end

  @impl true
  def handle_event("run_setup", params, socket) do
    root_name = String.trim(params["root_name"] || "Root CA")
    sub_name = String.trim(params["sub_name"] || "Issuing CA")
    root_algo = params["root_algo"] || "ECC-P256"
    sub_algo = params["sub_algo"] || "ECC-P256"

    socket = assign(socket, running: true, done: false, log: [], root_name: root_name, sub_name: sub_name, root_algo: root_algo, sub_algo: sub_algo)

    send(self(), {:run, root_name, sub_name, root_algo, sub_algo})
    {:noreply, socket}
  end

  @impl true
  def handle_info({:run, root_name, sub_name, root_algo, sub_algo}, socket) do
    _ca_id = socket.assigns.current_user[:ca_instance_id] || "default"
    log = []

    # Step 1: Create Root CA
    {log, root_id} =
      case CaEngineClient.create_ca_instance(%{"name" => root_name, "created_by" => "quick-setup"}) do
        {:ok, root} ->
          {log ++ [{:ok, "Created Root CA: #{root_name} (#{root["id"] || root[:id]})"}], root["id"] || root[:id]}
        {:error, reason} ->
          {log ++ [{:error, "Failed to create Root CA: #{inspect(reason)}"}], nil}
      end

    # Step 2: Configure keystore for Root CA
    {log, root_ks_id} =
      if root_id do
        case CaEngineClient.configure_keystore(root_id, %{type: "software"}) do
          {:ok, ks} ->
            {log ++ [{:ok, "Configured software keystore for Root CA"}], ks["id"] || ks[:id]}
          {:error, reason} ->
            {log ++ [{:error, "Failed to configure Root keystore: #{inspect(reason)}"}], nil}
        end
      else
        {log ++ [{:skip, "Skipped Root keystore (no Root CA)"}], nil}
      end

    # Step 3: Run ceremony for Root CA
    {log, _root_key} =
      if root_id && root_ks_id do
        case CaEngineClient.initiate_ceremony(root_id, %{
          algorithm: root_algo,
          keystore_id: root_ks_id,
          key_alias: "#{String.downcase(String.replace(root_name, " ", "-"))}-key",
          is_root: true,
          threshold_k: 2,
          threshold_n: 3,
          initiated_by: "quick-setup"
        }) do
          {:ok, result} ->
            key_info = result["issuer_key"] || result[:issuer_key] || %{}
            {log ++ [{:ok, "Root CA key ceremony complete — #{root_algo}, key: #{key_info["key_alias"] || key_info[:key_alias]}"}], key_info}
          {:error, reason} ->
            {log ++ [{:error, "Root key ceremony failed: #{inspect(reason)}"}], nil}
        end
      else
        {log ++ [{:skip, "Skipped Root ceremony"}], nil}
      end

    # Step 4: Create Sub-CA
    {log, sub_id} =
      if root_id do
        case CaEngineClient.create_ca_instance(%{"name" => sub_name, "parent_id" => root_id, "created_by" => "quick-setup"}) do
          {:ok, sub} ->
            {log ++ [{:ok, "Created Sub-CA: #{sub_name} under #{root_name}"}], sub["id"] || sub[:id]}
          {:error, reason} ->
            {log ++ [{:error, "Failed to create Sub-CA: #{inspect(reason)}"}], nil}
        end
      else
        {log ++ [{:skip, "Skipped Sub-CA (no Root CA)"}], nil}
      end

    # Step 5: Configure keystore for Sub-CA
    {log, sub_ks_id} =
      if sub_id do
        case CaEngineClient.configure_keystore(sub_id, %{type: "software"}) do
          {:ok, ks} ->
            {log ++ [{:ok, "Configured software keystore for Sub-CA"}], ks["id"] || ks[:id]}
          {:error, reason} ->
            {log ++ [{:error, "Failed to configure Sub-CA keystore: #{inspect(reason)}"}], nil}
        end
      else
        {log ++ [{:skip, "Skipped Sub-CA keystore"}], nil}
      end

    # Step 6: Run ceremony for Sub-CA
    log =
      if sub_id && sub_ks_id do
        case CaEngineClient.initiate_ceremony(sub_id, %{
          algorithm: sub_algo,
          keystore_id: sub_ks_id,
          key_alias: "#{String.downcase(String.replace(sub_name, " ", "-"))}-key",
          is_root: false,
          threshold_k: 2,
          threshold_n: 3,
          initiated_by: "quick-setup"
        }) do
          {:ok, result} ->
            key_info = result["issuer_key"] || result[:issuer_key] || %{}
            log ++ [{:ok, "Sub-CA key ceremony complete — #{sub_algo}, key: #{key_info["key_alias"] || key_info[:key_alias]}"}]
          {:error, reason} ->
            log ++ [{:error, "Sub-CA key ceremony failed: #{inspect(reason)}"}]
        end
      else
        log ++ [{:skip, "Skipped Sub-CA ceremony"}]
      end

    has_errors = Enum.any?(log, fn {status, _} -> status == :error end)
    log = if has_errors do
      log ++ [{:error, "Setup completed with errors. Check above."}]
    else
      log ++ [{:ok, "Setup complete! Go to CA Instances to see your hierarchy."}]
    end

    {:noreply, assign(socket, log: log, running: false, done: true)}
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div id="quick-setup" class="max-w-2xl mx-auto space-y-6">
      <div class="alert alert-warning text-sm">
        <.icon name="hero-beaker" class="size-4" />
        <span><strong>Dev/Test Only</strong> — This page runs a full CA hierarchy setup in one click. Not for production use.</span>
      </div>

      <div class="card bg-base-100 shadow-sm border border-base-300">
        <div class="card-body space-y-4">
          <h2 class="text-base font-semibold">Quick CA Hierarchy Setup</h2>
          <p class="text-sm text-base-content/60">Creates: Root CA → Issuing Sub-CA, each with a software keystore and key ceremony.</p>

          <form phx-submit="run_setup" class="space-y-4">
            <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label class="block text-xs font-medium text-base-content/60 mb-1">Root CA Name</label>
                <input type="text" name="root_name" value={@root_name} required class="input input-bordered input-sm w-full" />
              </div>
              <div>
                <label class="block text-xs font-medium text-base-content/60 mb-1">Root CA Algorithm</label>
                <select name="root_algo" class="select select-bordered select-sm w-full">
                  <%= for {algo, desc} <- @algorithms do %>
                    <option value={algo} selected={algo == @root_algo}>{algo} — {desc}</option>
                  <% end %>
                </select>
              </div>
            </div>

            <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label class="block text-xs font-medium text-base-content/60 mb-1">Sub-CA Name</label>
                <input type="text" name="sub_name" value={@sub_name} required class="input input-bordered input-sm w-full" />
              </div>
              <div>
                <label class="block text-xs font-medium text-base-content/60 mb-1">Sub-CA Algorithm</label>
                <select name="sub_algo" class="select select-bordered select-sm w-full">
                  <%= for {algo, desc} <- @algorithms do %>
                    <option value={algo} selected={algo == @sub_algo}>{algo} — {desc}</option>
                  <% end %>
                </select>
              </div>
            </div>

            <button type="submit" class="btn btn-primary btn-sm" disabled={@running}>
              <%= if @running do %>
                <span class="loading loading-spinner loading-xs"></span>
                Running...
              <% else %>
                <.icon name="hero-bolt" class="size-4" />
                Run Quick Setup
              <% end %>
            </button>
          </form>
        </div>
      </div>

      <%= if @log != [] do %>
        <div class="card bg-base-100 shadow-sm border border-base-300">
          <div class="card-body p-0">
            <div class="px-5 py-3 border-b border-base-300">
              <h3 class="text-sm font-semibold">Setup Log</h3>
            </div>
            <div class="p-4 space-y-1 font-mono text-xs">
              <%= for {status, msg} <- @log do %>
                <div class={[
                  "flex items-start gap-2 py-1",
                  status == :error && "text-error",
                  status == :ok && "text-success",
                  status == :skip && "text-base-content/40"
                ]}>
                  <span class="shrink-0 mt-0.5">
                    <%= case status do %>
                      <% :ok -> %><.icon name="hero-check-circle" class="size-3.5" />
                      <% :error -> %><.icon name="hero-x-circle" class="size-3.5" />
                      <% :skip -> %><.icon name="hero-minus-circle" class="size-3.5" />
                    <% end %>
                  </span>
                  <span>{msg}</span>
                </div>
              <% end %>
            </div>
          </div>
        </div>

        <%= if @done and not Enum.any?(@log, fn {s, _} -> s == :error end) do %>
          <div class="flex gap-3">
            <.link navigate="/ca-instances" class="btn btn-primary btn-sm">
              <.icon name="hero-server-stack" class="size-4" />
              View CA Instances
            </.link>
            <.link navigate="/ceremony" class="btn btn-ghost btn-sm">
              <.icon name="hero-shield-check" class="size-4" />
              View Ceremonies
            </.link>
          </div>
        <% end %>
      <% end %>
    </div>
    """
  end
end
