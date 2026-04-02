defmodule PkiCaPortalWeb.CeremonyLive do
  use PkiCaPortalWeb, :live_view

  alias PkiCaPortal.CaEngineClient

  @algorithms [
    {"KAZ-SIGN-128", "Post-Quantum — KAZ-Sign level 1"},
    {"KAZ-SIGN-192", "Post-Quantum — KAZ-Sign level 3"},
    {"KAZ-SIGN-256", "Post-Quantum — KAZ-Sign level 5"},
    {"ML-DSA-44", "Post-Quantum — NIST FIPS 204 level 2"},
    {"ML-DSA-65", "Post-Quantum — NIST FIPS 204 level 3"},
    {"ML-DSA-87", "Post-Quantum — NIST FIPS 204 level 5"},
    {"SLH-DSA-SHA2-128f", "Post-Quantum — NIST FIPS 205 fast"},
    {"SLH-DSA-SHA2-128s", "Post-Quantum — NIST FIPS 205 small"},
    {"SLH-DSA-SHA2-192f", "Post-Quantum — NIST FIPS 205 L3 fast"},
    {"SLH-DSA-SHA2-192s", "Post-Quantum — NIST FIPS 205 L3 small"},
    {"SLH-DSA-SHA2-256f", "Post-Quantum — NIST FIPS 205 L5 fast"},
    {"SLH-DSA-SHA2-256s", "Post-Quantum — NIST FIPS 205 L5 small"},
    {"ECC-P256", "Classical — fast, widely supported"},
    {"ECC-P384", "Classical — stronger"},
    {"RSA-2048", "Classical — legacy compatibility"},
    {"RSA-4096", "Classical — legacy, stronger"}
  ]

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket), do: send(self(), :load_data)

    {:ok,
     assign(socket,
       page_title: "Key Ceremony",
       ceremonies: [],
       keystores: [],
       ca_instances: [],
       algorithms: @algorithms,
       effective_ca_id: nil,
       selected_ca_id: "",
       loading: true,
       page: 1,
       per_page: 10,
       # Wizard state
       wizard_step: nil,
       active_ceremony: nil,
       private_key: nil,
       public_key: nil,
       public_key_fingerprint: nil,
       is_root: true,
       subject_dn: "",
       key_managers: [],
       custodians: [],
       custodian_passwords: [],
       csr_pem: nil,
       wizard_error: nil,
       wizard_busy: false
     )}
  end

  @impl true
  def handle_info(:load_data, socket) do
    ca_id = socket.assigns.current_user[:ca_instance_id]
    opts = tenant_opts(socket)

    ca_instances =
      case CaEngineClient.list_ca_instances(opts) do
        {:ok, instances} -> instances
        {:error, _} -> []
      end

    effective_ca_id = ca_id || case ca_instances do
      [first | _] -> first[:id]
      [] -> nil
    end

    {ceremonies, keystores} = load_for_ca(effective_ca_id, opts)

    key_managers = load_key_managers(opts)

    {:noreply,
     assign(socket,
       ceremonies: ceremonies,
       keystores: keystores,
       ca_instances: ca_instances,
       effective_ca_id: effective_ca_id,
       selected_ca_id: effective_ca_id || "",
       key_managers: key_managers,
       loading: false
     )}
  end

  def handle_info(:wipe_private_key, socket) do
    # Safety net: discard private key if still held after error timeout
    if socket.assigns.private_key do
      {:noreply, assign(socket, private_key: nil, public_key: nil, wizard_error: "Private key discarded (timeout). Please restart the ceremony.")}
    else
      {:noreply, socket}
    end
  end

  # ---------------------------------------------------------------------------
  # List view events
  # ---------------------------------------------------------------------------

  @impl true
  def handle_event("select_ca_instance", %{"ca_instance_id" => ca_instance_id}, socket) do
    ca_id = if ca_instance_id == "", do: nil, else: ca_instance_id
    {ceremonies, keystores} = load_for_ca(ca_id, tenant_opts(socket))

    {:noreply,
     assign(socket,
       ceremonies: ceremonies,
       keystores: keystores,
       effective_ca_id: ca_id,
       selected_ca_id: ca_instance_id,
       page: 1
     )}
  end

  def handle_event("change_page", %{"page" => page}, socket) do
    {:noreply, assign(socket, page: parse_int(page) || 1)}
  end

  def handle_event("cancel_ceremony_record", %{"id" => ceremony_id}, socket) do
    opts = tenant_opts(socket)

    case CaEngineClient.cancel_ceremony(ceremony_id, opts) do
      {:ok, _} ->
        {ceremonies, _} = load_for_ca(socket.assigns.effective_ca_id, opts)
        {:noreply,
         socket
         |> assign(ceremonies: ceremonies)
         |> put_flash(:info, "Ceremony cancelled.")}

      {:error, reason} ->
        {:noreply, put_flash(socket, :error, "Cancel failed: #{format_error(reason)}")}
    end
  end

  def handle_event("delete_ceremony_record", %{"id" => ceremony_id}, socket) do
    opts = tenant_opts(socket)

    case CaEngineClient.delete_ceremony(ceremony_id, opts) do
      :ok ->
        {ceremonies, _} = load_for_ca(socket.assigns.effective_ca_id, opts)
        {:noreply,
         socket
         |> assign(ceremonies: ceremonies)
         |> put_flash(:info, "Ceremony deleted.")}

      {:error, reason} ->
        {:noreply, put_flash(socket, :error, "Delete failed: #{format_error(reason)}")}
    end
  end

  def handle_event("start_wizard", _params, socket) do
    {:noreply,
     assign(socket,
       wizard_step: 1,
       active_ceremony: nil,
       private_key: nil,
       public_key: nil,
       public_key_fingerprint: nil,
       is_root: true,
       subject_dn: "",
       custodians: [],
       custodian_passwords: [],
       csr_pem: nil,
       wizard_error: nil,
       wizard_busy: false
     )}
  end

  def handle_event("cancel_wizard", _params, socket) do
    # Discard private key from memory
    {:noreply,
     assign(socket,
       wizard_step: nil,
       active_ceremony: nil,
       private_key: nil,
       public_key: nil,
       public_key_fingerprint: nil,
       csr_pem: nil,
       wizard_error: nil,
       wizard_busy: false
     )}
  end

  # Resume wizard for an existing ceremony that's still in progress
  def handle_event("resume_ceremony", %{"id" => ceremony_id}, socket) do
    opts = tenant_opts(socket)

    case CaEngineClient.get_ceremony(ceremony_id, opts) do
      {:ok, ceremony} ->
        step = case ceremony[:status] do
          "initiated" -> 2
          "in_progress" -> 4
          _ -> nil
        end

        if step do
          n = ceremony[:threshold_n] || 3
          {:noreply,
           assign(socket,
             wizard_step: step,
             active_ceremony: ceremony,
             is_root: get_in(ceremony, [:domain_info, "is_root"]) != false,
             subject_dn: get_in(ceremony, [:domain_info, "subject_dn"]) || "",
             custodians: List.duplicate(nil, n),
             custodian_passwords: List.duplicate("", n),
             private_key: nil,
             public_key: nil,
             public_key_fingerprint: nil,
             csr_pem: nil,
             wizard_error: nil,
             wizard_busy: false
           )}
        else
          {:noreply, put_flash(socket, :info, "Ceremony already completed.")}
        end

      {:error, _} ->
        {:noreply, put_flash(socket, :error, "Ceremony not found.")}
    end
  end

  # ---------------------------------------------------------------------------
  # Step 1: Initiate ceremony
  # ---------------------------------------------------------------------------

  def handle_event("initiate_ceremony", params, socket) do
    ca_id = params["ca_instance_id"]
    opts = tenant_opts(socket)

    cond do
      is_nil(ca_id) or ca_id == "" ->
        {:noreply, assign(socket, wizard_error: "Please select a CA Instance.")}

      is_nil(params["keystore_id"]) or params["keystore_id"] == "" ->
        {:noreply, assign(socket, wizard_error: "Please select a Keystore.")}

      true ->
        is_root = params["is_root"] == "true"
        threshold_n = parse_int(params["threshold_n"]) || 3

        ceremony_params = %{
          algorithm: params["algorithm"],
          keystore_id: params["keystore_id"],
          threshold_k: params["threshold_k"],
          threshold_n: params["threshold_n"],
          domain_info: %{"is_root" => is_root},
          initiated_by: socket.assigns.current_user[:id],
          is_root: is_root,
          key_alias: params["key_alias"]
        }

        case CaEngineClient.initiate_ceremony(ca_id, ceremony_params, opts) do
          {:ok, ceremony} ->
            {ceremonies, keystores} = load_for_ca(ca_id, opts)
            n = threshold_n || 3

            {:noreply,
             socket
             |> assign(
               ceremonies: ceremonies,
               keystores: keystores,
               effective_ca_id: ca_id,
               active_ceremony: ceremony,
               is_root: is_root,
               subject_dn: "",
               wizard_step: 2,
               wizard_error: nil,
               custodians: List.duplicate(nil, n),
               custodian_passwords: List.duplicate("", n)
             )}

          {:error, reason} ->
            {:noreply, assign(socket, wizard_error: "Failed to initiate: #{format_error(reason)}")}
        end
    end
  end

  # ---------------------------------------------------------------------------
  # Step 2: Generate keypair
  # ---------------------------------------------------------------------------

  def handle_event("generate_keypair", _params, socket) do
    # Return immediately to show spinner, then do keygen async
    send(self(), :do_generate_keypair)
    {:noreply, assign(socket, wizard_busy: true, wizard_error: nil)}
  end

  def handle_info(:do_generate_keypair, socket) do
    ceremony = socket.assigns.active_ceremony
    opts = tenant_opts(socket)

    case CaEngineClient.generate_ceremony_keypair(ceremony[:algorithm], opts) do
      {:ok, %{public_key: pub, private_key: priv}} ->
        fingerprint = :crypto.hash(:sha256, pub) |> Base.encode16(case: :lower) |> format_fingerprint()

        {:noreply,
         assign(socket,
           private_key: priv,
           public_key: pub,
           public_key_fingerprint: fingerprint,
           wizard_step: 3,
           wizard_busy: false,
           wizard_error: nil
         )}

      {:error, reason} ->
        {:noreply, assign(socket, wizard_busy: false, wizard_error: "Keypair generation failed: #{format_error(reason)}")}
    end
  end

  # ---------------------------------------------------------------------------
  # Step 3: Distribute shares
  # ---------------------------------------------------------------------------

  def handle_event("update_custodian_password", params, socket) do
    idx = parse_int(params["index"]) || 0
    value = params["value"] || ""
    passwords = List.replace_at(socket.assigns.custodian_passwords, idx, value)
    {:noreply, assign(socket, custodian_passwords: passwords)}
  end

  def handle_event("select_custodian", params, socket) do
    idx = parse_int(params["index"]) || 0
    user_id = params["custodian_#{idx}"] || ""
    custodian = if user_id == "", do: nil, else: Enum.find(socket.assigns.key_managers, &(&1.id == user_id))
    custodians = List.replace_at(socket.assigns.custodians, idx, custodian)
    {:noreply, assign(socket, custodians: custodians)}
  end

  def handle_event("distribute_shares", params, socket) do
    # Pick up passwords and custodian selections from form params
    n = length(socket.assigns.custodian_passwords)
    passwords =
      Enum.map(0..(n - 1), fn idx ->
        params["password_#{idx}"] || Enum.at(socket.assigns.custodian_passwords, idx, "")
      end)

    custodians =
      Enum.map(0..(n - 1), fn idx ->
        user_id = params["custodian_#{idx}"]
        if user_id && user_id != "" do
          Enum.find(socket.assigns.key_managers, &(&1.id == user_id))
        else
          Enum.at(socket.assigns.custodians, idx)
        end
      end)

    socket = assign(socket, custodian_passwords: passwords, custodians: custodians)
    ceremony = socket.assigns.active_ceremony
    private_key = socket.assigns.private_key
    opts = tenant_opts(socket)

    cond do
      Enum.any?(custodians, &is_nil/1) ->
        {:noreply, assign(socket, wizard_error: "Please select a key manager for each share.")}

      length(Enum.uniq_by(custodians, & &1.id)) != n ->
        {:noreply, assign(socket, wizard_error: "Each share must be assigned to a different key manager.")}

      Enum.any?(passwords, &(String.trim(&1) == "")) ->
        {:noreply, assign(socket, wizard_error: "All custodian passwords are required.")}

      true ->
        socket = assign(socket, wizard_busy: true, wizard_error: nil)

        custodian_tuples =
          Enum.zip(custodians, passwords)
          |> Enum.map(fn {custodian, pw} -> {custodian.id, pw} end)

        case CaEngineClient.distribute_ceremony_shares(ceremony[:id], private_key, custodian_tuples, opts) do
          {:ok, _count} ->
            {:noreply,
             assign(socket,
               wizard_step: 4,
               wizard_busy: false,
               wizard_error: nil
             )}

          {:error, reason} ->
            {:noreply, assign(socket, wizard_busy: false, wizard_error: "Share distribution failed: #{format_error(reason)}")}
        end
    end
  end

  # ---------------------------------------------------------------------------
  # Step 4: Complete ceremony
  # ---------------------------------------------------------------------------

  def handle_event("update_subject_dn", %{"value" => value}, socket) do
    {:noreply, assign(socket, subject_dn: value)}
  end

  def handle_event("complete_ceremony", _params, socket) do
    ceremony = socket.assigns.active_ceremony
    private_key = socket.assigns.private_key
    opts = tenant_opts(socket)

    socket = assign(socket, wizard_busy: true, wizard_error: nil)

    result =
      if socket.assigns.is_root do
        subject_dn = socket.assigns.subject_dn
        subject = if subject_dn == "", do: "/CN=Root-CA-#{ceremony[:id]}", else: subject_dn
        root_opts = Keyword.put(opts, :public_key, socket.assigns.public_key)
        CaEngineClient.complete_ceremony_root(ceremony[:id], private_key, subject, root_opts)
      else
        CaEngineClient.complete_ceremony_sub_ca(ceremony[:id], private_key, opts)
      end

    case result do
      {:ok, {updated_ceremony, csr_pem}} ->
        {ceremonies, _} = load_for_ca(socket.assigns.effective_ca_id, opts)
        {:noreply,
         assign(socket,
           active_ceremony: updated_ceremony,
           csr_pem: csr_pem,
           ceremonies: ceremonies,
           wizard_step: :done,
           wizard_busy: false,
           wizard_error: nil,
           private_key: nil
         )}

      {:ok, updated_ceremony} ->
        {ceremonies, _} = load_for_ca(socket.assigns.effective_ca_id, opts)
        {:noreply,
         assign(socket,
           active_ceremony: updated_ceremony,
           ceremonies: ceremonies,
           wizard_step: :done,
           wizard_busy: false,
           wizard_error: nil,
           private_key: nil
         )}

      {:error, reason} ->
        # Schedule key wipe — don't hold key in memory indefinitely on error
        if socket.assigns.private_key, do: Process.send_after(self(), :wipe_private_key, 60_000)
        {:noreply, assign(socket, wizard_busy: false, wizard_error: "Completion failed: #{format_error(reason)}")}
    end
  end

  def handle_event("finish_wizard", _params, socket) do
    {:noreply,
     assign(socket,
       wizard_step: nil,
       active_ceremony: nil,
       private_key: nil,
       public_key: nil,
       public_key_fingerprint: nil,
       csr_pem: nil,
       wizard_error: nil,
       wizard_busy: false
     )}
  end

  # ---------------------------------------------------------------------------
  # Private helpers
  # ---------------------------------------------------------------------------

  defp load_key_managers(opts) do
    case CaEngineClient.list_portal_users(opts) do
      {:ok, users} ->
        users
        |> Enum.filter(fn u -> u[:role] == "key_manager" and u[:status] == "active" end)
        |> Enum.map(fn u -> %{id: u[:id], username: u[:username], display_name: u[:display_name]} end)

      {:error, _} -> []
    end
  end

  defp load_for_ca(nil, _opts), do: {[], []}
  defp load_for_ca(ca_id, opts) do
    ceremonies = case CaEngineClient.list_ceremonies(ca_id, opts) do
      {:ok, c} -> c
      {:error, _} -> []
    end
    keystores = case CaEngineClient.list_keystores(ca_id, opts) do
      {:ok, ks} -> ks
      {:error, _} -> []
    end
    {ceremonies, keystores}
  end

  defp tenant_opts(socket) do
    case socket.assigns[:tenant_id] do
      nil -> []
      tid -> [tenant_id: tid]
    end
  end

  defp keystore_display(ks) do
    config = if ks[:config], do: PkiCaEngine.Schema.Keystore.decode_config(ks.config), else: nil
    label = if config, do: config["label"], else: nil

    case {ks.type, label} do
      {"hsm", l} when is_binary(l) -> "HSM — #{l}"
      {"hsm", _} -> "HSM"
      {"software", _} -> "Software"
      {type, _} -> type
    end
  end

  defp format_fingerprint(hex) do
    hex
    |> String.graphemes()
    |> Enum.chunk_every(2)
    |> Enum.map(&Enum.join/1)
    |> Enum.take(16)
    |> Enum.join(":")
  end

  defp format_error({:validation_error, errors}) when is_map(errors) do
    errors
    |> Enum.map(fn {k, v} -> "#{k}: #{inspect(v)}" end)
    |> Enum.join(", ")
  end
  defp format_error(reason), do: inspect(reason)

  defp parse_int(v) when is_integer(v), do: v
  defp parse_int(v) when is_binary(v) do
    case Integer.parse(v) do
      {n, _} -> n
      :error -> nil
    end
  end
  defp parse_int(_), do: nil

  defp format_datetime(nil), do: "-"
  defp format_datetime(%NaiveDateTime{} = dt) do
    Calendar.strftime(dt, "%d %b %Y, %H:%M")
  end
  defp format_datetime(%DateTime{} = dt) do
    Calendar.strftime(dt, "%d %b %Y, %H:%M")
  end
  defp format_datetime(%{year: _, month: _, day: _, hour: _, minute: _} = dt) do
    Calendar.strftime(dt, "%d %b %Y, %H:%M")
  end
  defp format_datetime(_), do: "-"

  defp status_badge_class("initiated"), do: "badge-warning"
  defp status_badge_class("in_progress"), do: "badge-info"
  defp status_badge_class("completed"), do: "badge-success"
  defp status_badge_class("failed"), do: "badge-error"
  defp status_badge_class(_), do: "badge-ghost"

  defp ceremony_resumable?(ceremony) do
    ceremony[:status] in ["initiated", "in_progress"]
  end

  # ---------------------------------------------------------------------------
  # Render
  # ---------------------------------------------------------------------------

  @impl true
  def render(assigns) do
    ~H"""
    <div id="ceremony-page" class="space-y-6">
      <%!-- Wizard overlay --%>
      <%= if @wizard_step do %>
        {render_wizard(assigns)}
      <% else %>
        {render_list_view(assigns)}
      <% end %>
    </div>
    """
  end

  defp render_list_view(assigns) do
    ~H"""
    <%!-- Server-side HSM disclaimer --%>
    <div class="alert border border-info/30 bg-info/5">
      <.icon name="hero-information-circle" class="size-5 text-info shrink-0" />
      <div>
        <p class="text-sm font-medium text-base-content">Server-Side HSM Only</p>
        <p class="text-xs text-base-content/60 mt-0.5">
          Key ceremonies use server-side HSM devices managed by the platform. Keys are generated and stored on the server's HSM hardware via PKCS#11.
          Client-side HSM (e.g., USB tokens on your laptop) is not supported in this version.
        </p>
      </div>
    </div>

    <%!-- CA Instance selector + New Ceremony button --%>
    <div class="flex items-center justify-between">
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
      <button
        :if={@effective_ca_id && not Enum.empty?(@keystores)}
        phx-click="start_wizard"
        class="btn btn-primary btn-sm"
      >
        <.icon name="hero-shield-check" class="size-4" />
        New Key Ceremony
      </button>
    </div>

    <%!-- No CA instance selected --%>
    <div :if={is_nil(@effective_ca_id) and not @loading} class="card bg-base-100 shadow-sm border border-base-300">
      <div class="card-body text-center py-8 text-base-content/50 text-sm">
        Select a CA instance above to view ceremonies and initiate new ones.
      </div>
    </div>

    <%!-- No keystores warning --%>
    <div :if={@effective_ca_id && Enum.empty?(@keystores)} class="alert alert-warning text-sm">
      <.icon name="hero-exclamation-triangle" class="size-4" />
      <span>No keystores configured for this CA instance. <a href="/keystores" class="link link-primary">Configure one first.</a></span>
    </div>

    <%!-- Ceremony history table --%>
    <div :if={@effective_ca_id} id="ceremony-table" class="card bg-base-100 shadow-sm border border-base-300">
      <div class="card-body p-0">
        <div class="px-5 py-4 border-b border-base-300">
          <h2 class="text-sm font-semibold text-base-content">Ceremony History</h2>
        </div>
        <% paginated = @ceremonies |> Enum.drop((@page - 1) * @per_page) |> Enum.take(@per_page) %>
        <% total = length(@ceremonies) %>
        <% total_pages = max(ceil(total / @per_page), 1) %>
        <div :if={Enum.empty?(@ceremonies)} class="p-8 text-center text-base-content/50 text-sm">
          No ceremonies yet for this CA instance.
        </div>
        <div :if={not Enum.empty?(@ceremonies)} class="overflow-x-auto">
          <table class="table table-sm">
            <thead>
              <tr class="text-xs uppercase text-base-content/50">
                <th>ID</th>
                <th>Type</th>
                <th>Algorithm</th>
                <th>Status</th>
                <th>Created</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              <tr :for={c <- paginated} class="hover">
                <td class="font-mono text-xs">{String.slice(c[:id] || "", 0..7)}</td>
                <td class="text-sm">{c[:ceremony_type]}</td>
                <td class="font-mono text-sm">{c[:algorithm]}</td>
                <td>
                  <span class={"badge badge-sm #{status_badge_class(c[:status])}"}>{c[:status]}</span>
                </td>
                <td class="text-xs text-base-content/60">{format_datetime(c[:inserted_at])}</td>
                <td class="flex items-center gap-1">
                  <button
                    :if={ceremony_resumable?(c)}
                    phx-click="resume_ceremony"
                    phx-value-id={c[:id]}
                    class="btn btn-ghost btn-xs"
                  >
                    Resume
                  </button>
                  <button
                    :if={c[:status] in ["initiated", "in_progress"]}
                    phx-click="cancel_ceremony_record"
                    phx-value-id={c[:id]}
                    data-confirm="Cancel this ceremony? The pending issuer key will be removed."
                    class="btn btn-ghost btn-xs text-warning"
                  >
                    Cancel
                  </button>
                  <button
                    :if={c[:status] in ["failed"]}
                    phx-click="delete_ceremony_record"
                    phx-value-id={c[:id]}
                    data-confirm="Permanently delete this ceremony record?"
                    class="btn btn-ghost btn-xs text-error"
                  >
                    Delete
                  </button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <div :if={total > @per_page} class="flex items-center justify-between px-5 py-3 border-t border-base-300 text-sm">
          <span class="text-base-content/60">
            Showing {min((@page - 1) * @per_page + 1, total)}–{min(@page * @per_page, total)} of {total}
          </span>
          <div class="join">
            <button class="join-item btn btn-sm" phx-click="change_page" phx-value-page={@page - 1} disabled={@page == 1}>«</button>
            <button class="join-item btn btn-sm btn-active">{@page}</button>
            <button class="join-item btn btn-sm" phx-click="change_page" phx-value-page={@page + 1} disabled={@page >= total_pages}>»</button>
          </div>
        </div>
      </div>
    </div>
    """
  end

  # ---------------------------------------------------------------------------
  # Wizard renderer
  # ---------------------------------------------------------------------------

  defp render_wizard(assigns) do
    ~H"""
    <div id="ceremony-wizard">
      <%!-- Step indicator --%>
      <ul class="steps steps-horizontal w-full mb-8">
        <li class={"step #{if @wizard_step == :done or (is_integer(@wizard_step) and @wizard_step >= 1), do: "step-primary"}"}>
          <span class="text-xs">Initiate</span>
        </li>
        <li class={"step #{if @wizard_step == :done or (is_integer(@wizard_step) and @wizard_step >= 2), do: "step-primary"}"}>
          <span class="text-xs">Generate Key</span>
        </li>
        <li class={"step #{if @wizard_step == :done or (is_integer(@wizard_step) and @wizard_step >= 3), do: "step-primary"}"}>
          <span class="text-xs">Distribute Shares</span>
        </li>
        <li class={"step #{if @wizard_step == :done or (is_integer(@wizard_step) and @wizard_step >= 4), do: "step-primary"}"}>
          <span class="text-xs">Complete</span>
        </li>
      </ul>

      <%!-- Error banner --%>
      <div :if={@wizard_error} class="alert alert-error mb-4 text-sm">
        <.icon name="hero-exclamation-circle" class="size-4" />
        <span>{@wizard_error}</span>
      </div>

      <%!-- Step content --%>
      <%= case @wizard_step do %>
        <% 1 -> %>
          {render_step_initiate(assigns)}
        <% 2 -> %>
          {render_step_generate(assigns)}
        <% 3 -> %>
          {render_step_distribute(assigns)}
        <% 4 -> %>
          {render_step_complete(assigns)}
        <% :done -> %>
          {render_step_done(assigns)}
        <% _ -> %>
          <div></div>
      <% end %>

      <%!-- Cancel button (not shown on done) --%>
      <div :if={@wizard_step != :done} class="mt-6 flex justify-end">
        <button phx-click="cancel_wizard" class="btn btn-ghost btn-sm">Cancel Ceremony</button>
      </div>
    </div>
    """
  end

  # Step 1: Initiate
  defp render_step_initiate(assigns) do
    ~H"""
    <div class="card bg-base-100 shadow-sm border border-base-300">
      <div class="card-body">
        <h2 class="text-sm font-semibold text-base-content mb-4">
          <.icon name="hero-shield-check" class="size-4 inline" /> Step 1 — Initiate Key Ceremony
        </h2>

        <form phx-submit="initiate_ceremony" class="space-y-4">
          <input type="hidden" name="ca_instance_id" value={@effective_ca_id} />

          <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label class="block text-xs font-medium text-base-content/60 mb-1">Algorithm</label>
              <select name="algorithm" class="select select-bordered select-sm w-full">
                <%= for {algo, desc} <- @algorithms do %>
                  <option value={algo}>{algo} — {desc}</option>
                <% end %>
              </select>
            </div>
            <div>
              <label class="block text-xs font-medium text-base-content/60 mb-1">Keystore</label>
              <select name="keystore_id" class="select select-bordered select-sm w-full" required>
                <option value="" disabled selected>Select Keystore</option>
                <option :for={ks <- @keystores} value={ks.id}>{keystore_display(ks)}</option>
              </select>
            </div>
            <div>
              <label class="block text-xs font-medium text-base-content/60 mb-1">Key Alias</label>
              <input type="text" name="key_alias" placeholder="e.g. root-key-2026" class="input input-bordered input-sm w-full" />
            </div>
            <div>
              <label class="block text-xs font-medium text-base-content/60 mb-1">Certificate Type</label>
              <select name="is_root" class="select select-bordered select-sm w-full">
                <option value="true" selected={@is_root}>Root CA (self-signed)</option>
                <option value="false" selected={not @is_root}>Sub-CA (generates CSR)</option>
              </select>
            </div>
            <div>
              <label class="block text-xs font-medium text-base-content/60 mb-1">Threshold K (min. to reconstruct)</label>
              <input type="number" name="threshold_k" min="2" value="2" class="input input-bordered input-sm w-full" />
            </div>
            <div>
              <label class="block text-xs font-medium text-base-content/60 mb-1">Threshold N (total key custodians)</label>
              <input type="number" name="threshold_n" min="2" value="3" class="input input-bordered input-sm w-full" />
            </div>
          </div>

          <div class="pt-2">
            <button type="submit" class="btn btn-primary btn-sm">
              <.icon name="hero-arrow-right" class="size-4" />
              Initiate & Continue
            </button>
          </div>
        </form>
      </div>
    </div>
    """
  end

  # Step 2: Generate Keypair
  defp render_step_generate(assigns) do
    ~H"""
    <div class="card bg-base-100 shadow-sm border border-base-300">
      <div class="card-body">
        <h2 class="text-sm font-semibold text-base-content mb-4">
          <.icon name="hero-key" class="size-4 inline" /> Step 2 — Generate Keypair
        </h2>

        <div class="bg-base-200/50 rounded-lg p-4 mb-4 text-sm space-y-1">
          <div class="flex gap-2">
            <span class="text-base-content/50 w-28">Ceremony ID:</span>
            <span class="font-mono">{String.slice(@active_ceremony[:id] || "", 0..7)}</span>
          </div>
          <div class="flex gap-2">
            <span class="text-base-content/50 w-28">Algorithm:</span>
            <span class="font-mono font-semibold">{@active_ceremony[:algorithm]}</span>
          </div>
          <div class="flex gap-2">
            <span class="text-base-content/50 w-28">Threshold:</span>
            <span>{@active_ceremony[:threshold_k]}-of-{@active_ceremony[:threshold_n]}</span>
          </div>
        </div>

        <div class="alert border border-warning/30 bg-warning/5 mb-4">
          <.icon name="hero-exclamation-triangle" class="size-5 text-warning shrink-0" />
          <div class="text-sm">
            <p class="font-medium">Security Notice</p>
            <p class="text-xs text-base-content/60 mt-0.5">
              The private key will be generated and held in server memory only. It is never written to disk or database.
              After the ceremony completes, only encrypted Shamir shares will persist.
            </p>
          </div>
        </div>

        <button
          phx-click="generate_keypair"
          class="btn btn-primary btn-sm"
          disabled={@wizard_busy}
        >
          <%= if @wizard_busy do %>
            <span class="loading loading-spinner loading-xs"></span> Generating...
          <% else %>
            <.icon name="hero-key" class="size-4" /> Generate Keypair
          <% end %>
        </button>
      </div>
    </div>
    """
  end

  # Step 3: Distribute Shares
  defp render_step_distribute(assigns) do
    ~H"""
    <div class="card bg-base-100 shadow-sm border border-base-300">
      <div class="card-body">
        <h2 class="text-sm font-semibold text-base-content mb-4">
          <.icon name="hero-lock-closed" class="size-4 inline" /> Step 3 — Distribute Key Shares
        </h2>

        <%!-- Public key fingerprint --%>
        <div :if={@public_key_fingerprint} class="bg-success/5 border border-success/20 rounded-lg p-4 mb-4">
          <div class="flex items-center gap-2 mb-1">
            <.icon name="hero-check-circle" class="size-4 text-success" />
            <span class="text-sm font-medium">Keypair Generated Successfully</span>
          </div>
          <p class="text-xs text-base-content/60">
            Public Key Fingerprint: <span class="font-mono">{@public_key_fingerprint}</span>
          </p>
        </div>

        <p class="text-sm text-base-content/70 mb-2">
          Assign each share to a key manager and have them enter a secret password.
          The private key will be split into
          <strong>{length(@custodian_passwords)}</strong> shares using Shamir's Secret Sharing.
          At least <strong>{@active_ceremony[:threshold_k]}</strong> shares are needed to reconstruct the key.
        </p>

        <div :if={Enum.empty?(@key_managers)} class="alert alert-warning text-sm mb-4">
          <.icon name="hero-exclamation-triangle" class="size-4" />
          <span>No active key managers found. <a href="/users" class="link link-primary">Add key manager users first.</a></span>
        </div>

        <div :if={length(@key_managers) < length(@custodian_passwords)} class="alert alert-warning text-sm mb-4">
          <.icon name="hero-exclamation-triangle" class="size-4" />
          <span>
            Need at least {length(@custodian_passwords)} key managers but only {length(@key_managers)} available.
            <a href="/users" class="link link-primary">Add more key manager users.</a>
          </span>
        </div>

        <form :if={length(@key_managers) >= length(@custodian_passwords)} phx-submit="distribute_shares" class="space-y-3">
          <div :for={{_pw, idx} <- Enum.with_index(@custodian_passwords)} class="flex items-center gap-3">
            <span class="text-sm font-medium text-base-content/60 w-16 shrink-0">Share {idx + 1}</span>
            <select
              name={"custodian_#{idx}"}
              class="select select-bordered select-sm w-48"
              phx-change="select_custodian"
              phx-value-index={idx}
            >
              <option value="">Select key manager</option>
              <option
                :for={km <- @key_managers}
                value={km.id}
                selected={Enum.at(@custodians, idx) && Enum.at(@custodians, idx).id == km.id}
              >
                {km.display_name || km.username}
              </option>
            </select>
            <input
              type="password"
              name={"password_#{idx}"}
              value={Enum.at(@custodian_passwords, idx)}
              phx-keyup="update_custodian_password"
              phx-value-index={idx}
              placeholder="Custodian's secret password"
              class="input input-bordered input-sm flex-1"
              autocomplete="off"
            />
          </div>

          <div class="pt-2">
            <button
              type="submit"
              class="btn btn-primary btn-sm"
              disabled={@wizard_busy}
            >
              <%= if @wizard_busy do %>
                <span class="loading loading-spinner loading-xs"></span> Distributing...
              <% else %>
                <.icon name="hero-lock-closed" class="size-4" /> Encrypt & Store Shares
              <% end %>
            </button>
          </div>
        </form>
      </div>
    </div>
    """
  end

  # Step 4: Complete
  defp render_step_complete(assigns) do
    ~H"""
    <div class="card bg-base-100 shadow-sm border border-base-300">
      <div class="card-body">
        <h2 class="text-sm font-semibold text-base-content mb-4">
          <.icon name="hero-check-badge" class="size-4 inline" /> Step 4 — Complete Ceremony
        </h2>

        <div class="bg-success/5 border border-success/20 rounded-lg p-4 mb-4">
          <div class="flex items-center gap-2 mb-1">
            <.icon name="hero-check-circle" class="size-4 text-success" />
            <span class="text-sm font-medium">Key Shares Distributed</span>
          </div>
          <p class="text-xs text-base-content/60">
            All {length(@custodian_passwords)} shares have been encrypted and stored securely.
          </p>
        </div>

        <%!-- Subject DN input — needed for both root cert and sub-CA CSR --%>
        <div class="mb-4">
          <label class="block text-xs font-medium text-base-content/60 mb-1">Subject DN</label>
          <input
            type="text"
            value={@subject_dn}
            phx-keyup="update_subject_dn"
            phx-debounce="300"
            placeholder="/CN=My Root CA/O=Organization/C=MY"
            class="input input-bordered input-sm w-full"
          />
          <p class="text-xs text-base-content/40 mt-1">
            The identity on the certificate. Example: <span class="font-mono">/CN=My Root CA/O=Antrapolation Technology/C=MY</span>
            <br/>If left blank, a default will be generated from the CA instance ID.
          </p>
        </div>

        <%= if @is_root do %>
          <div class="mb-4">
            <p class="text-sm text-base-content/70 mb-2">
              This will generate a <strong>self-signed root certificate</strong> and activate the issuer key.
            </p>
            <div class="bg-base-200/50 rounded-lg p-3 text-sm">
              <div class="flex gap-2">
                <span class="text-base-content/50 w-24">Validity:</span>
                <span>10 years (3650 days)</span>
              </div>
            </div>
          </div>

          <button
            phx-click="complete_ceremony"
            class="btn btn-success btn-sm"
            disabled={@wizard_busy}
          >
            <%= if @wizard_busy do %>
              <span class="loading loading-spinner loading-xs"></span> Signing...
            <% else %>
              <.icon name="hero-check-badge" class="size-4" /> Self-Sign & Activate
            <% end %>
          </button>
        <% else %>
          <div class="mb-4">
            <p class="text-sm text-base-content/70">
              This will generate a <strong>PKCS#10 Certificate Signing Request (CSR)</strong> for submission to the parent CA.
              The issuer key will remain in <em>pending</em> status until a certificate is uploaded.
            </p>
          </div>

          <button
            phx-click="complete_ceremony"
            class="btn btn-primary btn-sm"
            disabled={@wizard_busy}
          >
            <%= if @wizard_busy do %>
              <span class="loading loading-spinner loading-xs"></span> Generating CSR...
            <% else %>
              <.icon name="hero-document-arrow-down" class="size-4" /> Generate CSR & Complete
            <% end %>
          </button>
        <% end %>
      </div>
    </div>
    """
  end

  # Done
  defp render_step_done(assigns) do
    ~H"""
    <div class="card bg-base-100 shadow-sm border border-base-300">
      <div class="card-body text-center py-10">
        <div class="flex items-center justify-center w-16 h-16 rounded-full bg-success/10 mx-auto mb-4">
          <.icon name="hero-check-badge" class="size-10 text-success" />
        </div>
        <h2 class="text-lg font-bold text-base-content mb-1">Ceremony Complete</h2>
        <p class="text-sm text-base-content/60 mb-4">
          Ceremony <span class="font-mono">{String.slice(@active_ceremony[:id] || "", 0..7)}</span> has been completed successfully.
        </p>

        <%!-- CSR download for sub-CA --%>
        <div :if={@csr_pem} class="mb-6 text-left max-w-xl mx-auto">
          <label class="block text-xs font-medium text-base-content/60 mb-1">Certificate Signing Request (CSR)</label>
          <textarea class="textarea textarea-bordered w-full font-mono text-xs h-40" readonly>{@csr_pem}</textarea>
          <p class="text-xs text-base-content/40 mt-1">Copy this CSR and submit it to the parent CA for signing.</p>
        </div>

        <%!-- Custodian summary --%>
        <div :if={Enum.any?(@custodians, & &1)} class="mb-6 text-left max-w-xl mx-auto">
          <label class="block text-xs font-medium text-base-content/60 mb-2">Key Share Custodians</label>
          <div class="bg-base-200/50 rounded-lg p-3 space-y-1">
            <div :for={{custodian, idx} <- Enum.with_index(@custodians)} class="flex gap-2 text-sm">
              <span class="text-base-content/50 w-16">Share {idx + 1}:</span>
              <span :if={custodian} class="font-medium">{custodian.display_name || custodian.username}</span>
            </div>
          </div>
        </div>

        <div class="alert border border-info/30 bg-info/5 text-left max-w-xl mx-auto mb-6">
          <.icon name="hero-information-circle" class="size-5 text-info shrink-0" />
          <div class="text-sm">
            <p>The private key has been securely discarded from memory.</p>
            <p class="text-xs text-base-content/60">Only the encrypted Shamir shares remain in the database.</p>
          </div>
        </div>

        <button phx-click="finish_wizard" class="btn btn-primary btn-sm">
          <.icon name="hero-arrow-left" class="size-4" /> Back to Ceremony List
        </button>
      </div>
    </div>
    """
  end
end
