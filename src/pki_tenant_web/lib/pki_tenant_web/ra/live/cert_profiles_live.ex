defmodule PkiTenantWeb.Ra.CertProfilesLive do
  use PkiTenantWeb, :live_view

  require Logger

  alias PkiRaEngine.CertProfileConfig
  alias PkiMnesia.{Repo, Structs.RaInstance, Structs.RaCaConnection}

  @templates %{
    "tls_server" => %{
      label: "TLS Server",
      description: "HTTPS server certificates",
      key_usage: "digitalSignature, keyEncipherment",
      ext_key_usage: "serverAuth",
      digest_algo: "SHA-256",
      validity_days: 365,
      subject_dn_policy: %{"required" => ["CN"], "optional" => ["O", "OU", "L", "ST", "C"], "require_dcv" => true}
    },
    "tls_client" => %{
      label: "TLS Client",
      description: "Client authentication certificates",
      key_usage: "digitalSignature",
      ext_key_usage: "clientAuth",
      digest_algo: "SHA-256",
      validity_days: 365,
      subject_dn_policy: %{"required" => ["CN"], "optional" => ["O", "OU", "E"], "require_dcv" => false}
    },
    "code_signing" => %{
      label: "Code Signing",
      description: "Software code signing certificates",
      key_usage: "digitalSignature",
      ext_key_usage: "codeSigning",
      digest_algo: "SHA-256",
      validity_days: 365,
      subject_dn_policy: %{"required" => ["CN", "O"], "optional" => ["OU", "L", "ST", "C"], "require_dcv" => false}
    },
    "email" => %{
      label: "Email / S-MIME",
      description: "Email encryption and signing",
      key_usage: "digitalSignature, keyEncipherment",
      ext_key_usage: "emailProtection",
      digest_algo: "SHA-256",
      validity_days: 365,
      subject_dn_policy: %{"required" => ["CN", "E"], "optional" => ["O", "OU"], "require_dcv" => false}
    },
    "custom" => %{
      label: "Custom",
      description: "Configure all fields manually",
      key_usage: "",
      ext_key_usage: "",
      digest_algo: "SHA-256",
      validity_days: 365,
      subject_dn_policy: %{"required" => ["CN"], "optional" => [], "require_dcv" => false}
    }
  }

  @template_order ~w(tls_server tls_client code_signing email custom)

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket), do: send(self(), :load_data)

    {:ok,
     socket
     |> assign(
       page_title: "Certificate Profiles",
       profiles: [],
       ra_instances: [],
       issuer_keys: [],
       connected_keys: [],
       loading: true,
       editing: nil,
       show_template_picker: false,
       show_create_form: false,
       selected_template: nil,
       selected_issuer_key_algo: nil,
       form_values: %{},
       template_defaults: %{},
       page: 1,
       per_page: 50
     )
     |> apply_pagination()}
  end

  @impl true
  def handle_info(:load_data, socket) do
    {profiles, socket} = case CertProfileConfig.list_profiles() do
      {:ok, p} -> {p, socket}
      {:error, _} -> {[], put_flash(socket, :error, "Failed to load data. Try refreshing.")}
    end

    ra_instances =
      case Repo.all(RaInstance) do
        {:ok, instances} -> instances
        {:error, _} -> []
      end

    issuer_keys =
      case PkiMnesia.Repo.where(PkiMnesia.Structs.IssuerKey, fn k ->
        k.status == "active" and k.certificate_pem != nil
      end) do
        {:ok, keys} -> keys
        {:error, _} -> []
      end

    connections =
      case Repo.all(RaCaConnection) do
        {:ok, conns} -> conns
        {:error, _} -> []
      end

    # Filter issuer keys to only those with an active CA connection
    connected_key_ids = MapSet.new(connections, & &1.issuer_key_id)

    connected_keys =
      Enum.filter(issuer_keys, fn key ->
        key_id = Map.get(key, :id) || Map.get(key, "id")
        MapSet.member?(connected_key_ids, key_id)
      end)

    {:noreply,
     socket
     |> assign(
       profiles: profiles,
       ra_instances: ra_instances,
       issuer_keys: issuer_keys,
       connected_keys: connected_keys,
       loading: false
     )
     |> apply_pagination()}
  end

  @impl true
  def handle_event("show_create_form", _params, socket) do
    {:noreply, assign(socket, show_template_picker: true, show_create_form: false, selected_template: nil, template_defaults: %{})}
  end

  @impl true
  def handle_event("select_template", %{"template" => key}, socket) do
    template = Map.get(@templates, key, %{})

    {:noreply,
     assign(socket,
       show_template_picker: false,
       show_create_form: true,
       selected_template: key,
       template_defaults: template
     )}
  end

  @impl true
  def handle_event("cancel_template", _params, socket) do
    {:noreply, assign(socket, show_template_picker: false, show_create_form: false, selected_template: nil, template_defaults: %{})}
  end

  @impl true
  def handle_event("cancel_create", _params, socket) do
    {:noreply, assign(socket, show_create_form: false, selected_template: nil, selected_issuer_key_algo: nil, form_values: %{}, template_defaults: %{})}
  end

  @impl true
  def handle_event("form_change", params, socket) do
    issuer_key_id = params["issuer_key_id"]

    algo = case Enum.find(socket.assigns.connected_keys, &(to_string(&1.id) == issuer_key_id)) do
      nil -> nil
      key -> key.algorithm
    end

    # Preserve all form values so they survive re-renders
    form_values = %{
      name: params["name"],
      ra_instance_id: params["ra_instance_id"],
      issuer_key_id: issuer_key_id,
      key_usage: params["key_usage"],
      ext_key_usage: params["ext_key_usage"],
      digest_algo: params["digest_algo"],
      validity_days: params["validity_days"]
    }

    {:noreply, assign(socket, selected_issuer_key_algo: algo, form_values: form_values)}
  end

  @impl true
  def handle_event("create_profile", params, socket) do
    if get_role(socket) == "ra_admin" do
      # Join checkbox array into comma-separated string
      key_usage = case params["key_usage"] do
        list when is_list(list) -> Enum.join(list, ", ")
        str when is_binary(str) -> str
        _ -> ""
      end

      # For PQC algorithms, digest is built-in; disabled field won't submit, so default it
      digest_algo = case params["digest_algo"] do
        nil -> if is_pqc_algorithm?(socket.assigns.selected_issuer_key_algo), do: "algorithm-default", else: "SHA-256"
        "" -> "SHA-256"
        val -> val
      end

      attrs = %{
        name: params["name"],
        key_usage: key_usage,
        ext_key_usage: params["ext_key_usage"],
        digest_algo: digest_algo,
        validity_days: parse_int(params["validity_days"], 365),
        ra_instance_id: params["ra_instance_id"],
        issuer_key_id: params["issuer_key_id"],
        approval_mode: params["approval_mode"] || "manual"
      }

      case CertProfileConfig.create_profile(attrs) do
        {:ok, profile} ->
          profiles = [profile | socket.assigns.profiles]

          {:noreply,
           socket
           |> assign(profiles: profiles, show_create_form: false, selected_template: nil, selected_issuer_key_algo: nil, form_values: %{}, template_defaults: %{})
           |> apply_pagination()
           |> put_flash(:info, "Certificate profile created")}

        {:error, reason} ->
          Logger.error("[cert_profiles] Failed to create profile: #{inspect(reason)}")
          {:noreply, put_flash(socket, :error, PkiTenantWeb.ErrorHelpers.sanitize_error("Failed to create profile", reason))}
      end
    else
      {:noreply, put_flash(socket, :error, "Unauthorized")}
    end
  end

  @impl true
  def handle_event("edit_profile", %{"id" => id}, socket) do
    profile = Enum.find(socket.assigns.profiles, &(&1.id == id))

    # Detect issuer key algorithm for PQC digest logic
    algo = case Enum.find(socket.assigns.connected_keys, &(&1.id == Map.get(profile, :issuer_key_id))) do
      nil -> nil
      key -> key.algorithm
    end

    {:noreply, assign(socket, editing: profile, selected_issuer_key_algo: algo)}
  end

  @impl true
  def handle_event("cancel_edit", _params, socket) do
    {:noreply, assign(socket, editing: nil)}
  end

  @impl true
  def handle_event("update_profile", params, socket) do
    if get_role(socket) == "ra_admin" do
      profile_id = params["profile_id"]

      attrs = %{
        name: params["name"],
        key_usage: params["key_usage"],
        ext_key_usage: params["ext_key_usage"],
        digest_algo: params["digest_algo"],
        validity_days: parse_int(params["validity_days"], 365),
        ra_instance_id: params["ra_instance_id"],
        issuer_key_id: params["issuer_key_id"],
        approval_mode: params["approval_mode"] || "manual"
      }

      case CertProfileConfig.update_profile(profile_id, attrs) do
        {:ok, updated} ->
          profiles =
            Enum.map(socket.assigns.profiles, fn p ->
              if p.id == profile_id, do: Map.merge(p, updated), else: p
            end)

          {:noreply,
           socket
           |> assign(profiles: profiles, editing: nil)
           |> apply_pagination()
           |> put_flash(:info, "Profile updated")}

        {:error, reason} ->
          Logger.error("[cert_profiles] Failed to update profile: #{inspect(reason)}")
          {:noreply, put_flash(socket, :error, PkiTenantWeb.ErrorHelpers.sanitize_error("Failed to update profile", reason))}
      end
    else
      {:noreply, put_flash(socket, :error, "Unauthorized")}
    end
  end

  @impl true
  def handle_event("delete_profile", %{"id" => id}, socket) do
    if get_role(socket) == "ra_admin" do
      case CertProfileConfig.delete_profile(id) do
        :ok ->
          profiles = Enum.reject(socket.assigns.profiles, &(&1.id == id))

          {:noreply,
           socket
           |> assign(profiles: profiles)
           |> apply_pagination()
           |> put_flash(:info, "Profile deleted")}

        {:error, reason} ->
          Logger.error("[cert_profiles] Failed to delete profile: #{inspect(reason)}")
          {:noreply, put_flash(socket, :error, PkiTenantWeb.ErrorHelpers.sanitize_error("Failed to delete profile", reason))}
      end
    else
      {:noreply, put_flash(socket, :error, "Unauthorized")}
    end
  end

  @impl true
  def handle_event("change_page", %{"page" => page}, socket) do
    case Integer.parse(page) do
      {p, ""} when p > 0 -> {:noreply, socket |> assign(page: p) |> apply_pagination()}
      _ -> {:noreply, socket}
    end
  end

  defp get_role(socket) do
    user = socket.assigns[:current_user]
    user[:role] || user["role"]
  end

  defp key_usage_options do
    ~w(digitalSignature nonRepudiation keyEncipherment dataEncipherment keyAgreement keyCertSign cRLSign encipherOnly decipherOnly)
  end

  defp ext_key_usage_options do
    [
      {"Server Authentication (TLS)", "serverAuth"},
      {"Client Authentication", "clientAuth"},
      {"Code Signing", "codeSigning"},
      {"Email Protection (S/MIME)", "emailProtection"},
      {"Time Stamping", "timeStamping"},
      {"OCSP Signing", "OCSPSigning"}
    ]
  end

  @pqc_algorithms ~w(KAZ-SIGN KAZ-SIGN-128 KAZ-SIGN-192 KAZ-SIGN-256 ML-DSA-44 ML-DSA-65 ML-DSA-87 Ed25519 Ed448)

  defp is_pqc_algorithm?(nil), do: false
  defp is_pqc_algorithm?(algo) when is_binary(algo), do: algo in @pqc_algorithms
  defp is_pqc_algorithm?(_), do: false

  defp parse_key_usage(nil), do: []
  defp parse_key_usage(str) when is_binary(str) do
    str |> String.split(",") |> Enum.map(&String.trim/1) |> Enum.reject(&(&1 == ""))
  end
  defp parse_key_usage(_), do: []

  defp get_validity_days(profile) do
    get_in(profile, [:validity_policy, "days"]) ||
      get_in(profile, [:validity_policy, :days]) ||
      Map.get(profile, :validity_days) ||
      Map.get(profile, "validity_days")
  end

  defp parse_int(val, default) when is_binary(val) do
    case Integer.parse(val) do
      {int, _} -> int
      :error -> default
    end
  end

  defp parse_int(_, default), do: default

  defp ra_instance_name(profile, ra_instances) do
    ra_id = Map.get(profile, :ra_instance_id)
    case Enum.find(ra_instances, &(&1.id == ra_id)) do
      nil -> "-"
      inst -> inst.name
    end
  end

  defp issuer_key_label(profile, issuer_keys) do
    key_id = Map.get(profile, :issuer_key_id)
    case Enum.find(issuer_keys, &(&1.id == key_id)) do
      nil -> "-"
      key -> "#{key[:name] || key[:key_alias] || key[:alias] || key.id} (#{key.algorithm})"
    end
  end

  defp template_order, do: @template_order

  defp template_label(key) do
    case Map.get(@templates, key) do
      nil -> key
      t -> t.label
    end
  end

  defp template_description(key) do
    case Map.get(@templates, key) do
      nil -> ""
      t -> t.description
    end
  end

  defp apply_pagination(socket) do
    items = socket.assigns.profiles
    total = length(items)
    per_page = socket.assigns.per_page
    total_pages = max(ceil(total / per_page), 1)
    page = min(socket.assigns.page, total_pages)
    start_idx = (page - 1) * per_page
    paged = items |> Enum.drop(start_idx) |> Enum.take(per_page)

    assign(socket, paged_profiles: paged, total_pages: total_pages, page: page)
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div id="cert-profiles-page" class="space-y-6">
      <div class="flex items-center justify-between">
        <h1 class="text-2xl font-bold tracking-tight">Certificate Profiles</h1>
        <button :if={!@show_template_picker and !@show_create_form} phx-click="show_create_form" class="btn btn-sm btn-primary">
          <.icon name="hero-plus" class="size-4 mr-1" /> Create Profile
        </button>
      </div>

      <%!-- Profiles Table --%>
      <section id="profile-table" class="card bg-base-100 shadow-sm border border-base-300">
        <div class="card-body">
          <div>
            <table class="table table-sm table-fixed w-full">
              <thead>
                <tr class="border-base-300">
                  <th class="font-semibold text-xs uppercase tracking-wider w-[15%]">Name</th>
                  <th class="font-semibold text-xs uppercase tracking-wider w-[15%]">RA Instance</th>
                  <th class="font-semibold text-xs uppercase tracking-wider w-[18%]">Issuer Key</th>
                  <th class="font-semibold text-xs uppercase tracking-wider w-[15%]">Key Usage</th>
                  <th class="font-semibold text-xs uppercase tracking-wider w-[10%]">Digest</th>
                  <th class="font-semibold text-xs uppercase tracking-wider w-[8%]">Validity</th>
                  <th class="font-semibold text-xs uppercase tracking-wider w-[7%]">Status</th>
                  <th class="font-semibold text-xs uppercase tracking-wider w-[7%]">Mode</th>
                  <th class="font-semibold text-xs uppercase tracking-wider w-[9%]">Actions</th>
                </tr>
              </thead>
              <tbody id="profile-list">
                <tr :for={profile <- @paged_profiles} id={"profile-#{profile.id}"} class="hover:bg-base-200/50 border-base-300">
                  <td class="font-medium overflow-hidden text-ellipsis whitespace-nowrap">{profile.name}</td>
                  <td class="text-xs overflow-hidden text-ellipsis whitespace-nowrap">{ra_instance_name(profile, @ra_instances)}</td>
                  <td class="text-xs overflow-hidden text-ellipsis whitespace-nowrap">{issuer_key_label(profile, @issuer_keys)}</td>
                  <td class="font-mono text-xs overflow-hidden text-ellipsis whitespace-nowrap">{profile.key_usage}</td>
                  <td class="font-mono text-xs">{profile.digest_algo}</td>
                  <td><%= case get_validity_days(profile) do nil -> "-"; days -> "#{days}d" end %></td>
                  <td>
                    <span class={[
                      "badge badge-xs",
                      (profile[:status] || "active") == "active" && "badge-success",
                      (profile[:status] || "active") == "archived" && "badge-ghost"
                    ]}>
                      {profile[:status] || "active"}
                    </span>
                  </td>
                  <td>
                    <span class={[
                      "badge badge-xs",
                      (profile[:approval_mode] || "manual") == "auto" && "badge-info",
                      (profile[:approval_mode] || "manual") == "manual" && "badge-ghost"
                    ]}>
                      {profile[:approval_mode] || "manual"}
                    </span>
                  </td>
                  <td class="flex gap-1">
                    <button phx-click="edit_profile" phx-value-id={profile.id} title="Edit" class="btn btn-ghost btn-xs text-sky-400">
                      <.icon name="hero-pencil" class="size-4" />
                    </button>
                    <button
                      :if={(profile[:status] || "active") == "active"}
                      phx-click="delete_profile"
                      phx-value-id={profile.id}
                      title="Archive this profile"
                      class="btn btn-ghost btn-xs text-amber-500"
                      data-confirm="Archive this profile? It will no longer be available for new CSRs, but existing certificates retain their audit trail."
                    >
                      <.icon name="hero-archive-box" class="size-4" />
                    </button>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
          <div :if={@total_pages > 1} class="flex justify-center mt-4">
            <div class="join">
              <button
                :for={p <- 1..@total_pages}
                phx-click="change_page"
                phx-value-page={p}
                class={["join-item btn btn-sm", p == @page && "btn-active"]}
              >
                {p}
              </button>
            </div>
          </div>
        </div>
      </section>

      <%!-- Edit Profile Form (mirrors create form) --%>
      <section :if={@editing} id="edit-profile-form" class="card bg-base-100 shadow-sm border border-primary/30">
        <div class="card-body">
          <div class="flex items-center justify-between">
            <h2 class="card-title text-sm font-semibold uppercase tracking-wide text-base-content/60">Edit Profile</h2>
            <button phx-click="cancel_edit" class="btn btn-ghost btn-xs">Cancel</button>
          </div>
          <form phx-submit="update_profile" phx-change="form_change" class="grid grid-cols-1 md:grid-cols-2 gap-4 mt-2">
            <input type="hidden" name="profile_id" value={@editing.id} />
            <div>
              <label for="edit-name" class="label text-xs font-medium">Name <span class="text-error">*</span></label>
              <input type="text" name="name" id="edit-name" value={@editing.name} required maxlength="100" class="input input-sm input-bordered w-full" />
              <p class="text-xs text-base-content/40 mt-0.5">Max 100 characters</p>
            </div>
            <div>
              <label for="edit-ra-instance" class="label text-xs font-medium">RA Instance <span class="text-error">*</span></label>
              <select name="ra_instance_id" id="edit-ra-instance" required class="select select-sm select-bordered w-full">
                <option value="">Select RA Instance</option>
                <option :for={inst <- @ra_instances} value={inst.id} selected={Map.get(@editing, :ra_instance_id) == inst.id}>
                  {inst.name}
                </option>
              </select>
            </div>
            <div>
              <label for="edit-issuer-key" class="label text-xs font-medium">Issuer Key <span class="text-error">*</span></label>
              <select name="issuer_key_id" id="edit-issuer-key" required class="select select-sm select-bordered w-full">
                <option value="">Select Issuer Key</option>
                <option :for={key <- @connected_keys} value={key.id} selected={Map.get(@editing, :issuer_key_id) == key.id}>
                  {key[:name] || key[:key_alias] || key[:alias] || key.id} ({key.algorithm})
                </option>
              </select>
              <p :if={@connected_keys == []} class="text-xs text-warning mt-1">No connected CA keys found. Connect a CA key first.</p>
            </div>
            <div>
              <label class="label text-xs font-medium">Key Usage</label>
              <div class="flex flex-wrap gap-3 mt-1">
                <label :for={ku <- key_usage_options()} class="flex items-center gap-1.5 cursor-pointer">
                  <input
                    type="checkbox"
                    name="key_usage[]"
                    value={ku}
                    checked={ku in parse_key_usage(Map.get(@editing, :key_usage, ""))}
                    class="checkbox checkbox-xs checkbox-primary"
                  />
                  <span class="text-xs">{ku}</span>
                </label>
              </div>
            </div>
            <div>
              <label for="edit-ext-key-usage" class="label text-xs font-medium">Extended Key Usage</label>
              <select name="ext_key_usage" id="edit-ext-key-usage" class="select select-sm select-bordered w-full">
                <option value="" selected={(@editing.ext_key_usage || "") == ""}>-- Select --</option>
                <option :for={{label, value} <- ext_key_usage_options()} value={value} selected={@editing.ext_key_usage == value}>
                  {label}
                </option>
              </select>
            </div>
            <div>
              <label for="edit-digest-algo" class="label text-xs font-medium">Digest Algorithm</label>
              <%= if is_pqc_algorithm?(@selected_issuer_key_algo) do %>
                <select name="digest_algo" id="edit-digest-algo" class="select select-sm select-bordered w-full select-disabled" disabled>
                  <option value="algorithm-default" selected>Algorithm Default</option>
                </select>
                <p class="text-xs text-info mt-1">PQC algorithms use a built-in digest.</p>
              <% else %>
                <select name="digest_algo" id="edit-digest-algo" class="select select-sm select-bordered w-full">
                  <option value="SHA-256" selected={@editing.digest_algo == "SHA-256"}>SHA-256</option>
                  <option value="SHA-384" selected={@editing.digest_algo == "SHA-384"}>SHA-384</option>
                  <option value="SHA-512" selected={@editing.digest_algo == "SHA-512"}>SHA-512</option>
                  <option value="algorithm-default" selected={@editing.digest_algo == "algorithm-default"}>Algorithm Default</option>
                </select>
              <% end %>
            </div>
            <div>
              <label for="edit-validity" class="label text-xs font-medium">Validity (days)</label>
              <input type="number" name="validity_days" id="edit-validity" value={get_validity_days(@editing) || 365} min="1" max="3650" class="input input-sm input-bordered w-full" />
            </div>
            <div>
              <label class="label text-xs font-medium">Approval Mode</label>
              <div class="flex gap-4 mt-1">
                <label class="flex items-center gap-2 cursor-pointer">
                  <input type="radio" name="approval_mode" value="manual"
                         checked={Map.get(@editing, :approval_mode, "manual") == "manual"}
                         class="radio radio-sm radio-primary" />
                  <div>
                    <span class="text-sm font-medium">Manual Review</span>
                    <p class="text-xs text-base-content/50">Officer must approve each CSR</p>
                  </div>
                </label>
                <label class="flex items-center gap-2 cursor-pointer">
                  <input type="radio" name="approval_mode" value="auto"
                         checked={Map.get(@editing, :approval_mode, "manual") == "auto"}
                         class="radio radio-sm radio-primary" />
                  <div>
                    <span class="text-sm font-medium">Auto-Approve</span>
                    <p class="text-xs text-base-content/50">Automatically issue if all validations pass</p>
                  </div>
                </label>
              </div>
            </div>
            <div class="flex items-end gap-2">
              <button type="submit" phx-disable-with="Saving..." class="btn btn-sm btn-primary">Update Profile</button>
              <button type="button" phx-click="cancel_edit" class="btn btn-sm btn-ghost">Cancel</button>
            </div>
          </form>
        </div>
      </section>

      <%!-- Template Picker --%>
      <section :if={@show_template_picker} id="template-picker" class="card bg-base-100 shadow-sm border border-primary/30">
        <div class="card-body">
          <div class="flex items-center justify-between">
            <h2 class="card-title text-sm font-semibold uppercase tracking-wide text-base-content/60">Choose a Template</h2>
            <button phx-click="cancel_template" class="btn btn-ghost btn-xs">Cancel</button>
          </div>
          <p class="text-xs text-base-content/50 mt-1">Select a certificate profile template to pre-fill the form, or choose Custom to configure manually.</p>
          <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5 gap-4 mt-4">
            <div
              :for={key <- template_order()}
              class="card bg-base-200/50 border border-base-300 hover:border-primary/50 transition-colors cursor-pointer"
              phx-click="select_template"
              phx-value-template={key}
            >
              <div class="card-body p-4">
                <h3 class="font-semibold text-sm">{template_label(key)}</h3>
                <p class="text-xs text-base-content/60 mt-1">{template_description(key)}</p>
                <div class="card-actions justify-end mt-3">
                  <button class="btn btn-xs btn-primary btn-outline">Select</button>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      <%!-- Create Profile Form (shown after template selection) --%>
      <section :if={@show_create_form} id="create-profile-form" class="card bg-base-100 shadow-sm border border-primary/30">
        <div class="card-body">
          <div class="flex items-center justify-between">
            <h2 class="card-title text-sm font-semibold uppercase tracking-wide text-base-content/60">
              Create Profile
              <span :if={@selected_template && @selected_template != "custom"} class="badge badge-sm badge-primary ml-2">
                {template_label(@selected_template)}
              </span>
            </h2>
            <button phx-click="cancel_create" class="btn btn-ghost btn-xs">Cancel</button>
          </div>
          <form phx-submit="create_profile" phx-change="form_change" class="grid grid-cols-1 md:grid-cols-2 gap-4 mt-2">
            <div>
              <label for="profile-name" class="label text-xs font-medium">Name <span class="text-error">*</span></label>
              <input type="text" name="name" id="profile-name" required maxlength="100" value={@form_values[:name] || ""} class="input input-sm input-bordered w-full" />
              <p class="text-xs text-base-content/40 mt-0.5">Max 100 characters</p>
            </div>
            <div>
              <label for="profile-ra-instance" class="label text-xs font-medium">RA Instance <span class="text-error">*</span></label>
              <select name="ra_instance_id" id="profile-ra-instance" required class="select select-sm select-bordered w-full">
                <option value="">Select RA Instance</option>
                <option :for={inst <- @ra_instances} value={inst.id} selected={@form_values[:ra_instance_id] == to_string(inst.id)}>
                  {inst.name}
                </option>
              </select>
            </div>
            <div>
              <label for="profile-issuer-key" class="label text-xs font-medium">Issuer Key <span class="text-error">*</span></label>
              <select name="issuer_key_id" id="profile-issuer-key" required class="select select-sm select-bordered w-full">
                <option value="">Select Issuer Key</option>
                <option :for={key <- @connected_keys} value={key.id} selected={@form_values[:issuer_key_id] == to_string(key.id)}>
                  {key[:name] || key[:key_alias] || key[:alias] || key.id} ({key.algorithm})
                </option>
              </select>
              <p :if={@connected_keys == []} class="text-xs text-warning mt-1">No connected CA keys found. Connect a CA key first.</p>
            </div>
            <div>
              <label class="label text-xs font-medium">Key Usage</label>
              <div class="flex flex-wrap gap-3 mt-1">
                <label :for={ku <- key_usage_options()} class="flex items-center gap-1.5 cursor-pointer">
                  <input
                    type="checkbox"
                    name="key_usage[]"
                    value={ku}
                    checked={
                      case @form_values[:key_usage] do
                        list when is_list(list) -> ku in list
                        _ -> ku in parse_key_usage(Map.get(@template_defaults, :key_usage, ""))
                      end
                    }
                    class="checkbox checkbox-xs checkbox-primary"
                  />
                  <span class="text-xs">{ku}</span>
                </label>
              </div>
            </div>
            <div>
              <label for="profile-ext-key-usage" class="label text-xs font-medium">Extended Key Usage</label>
              <% current_eku = @form_values[:ext_key_usage] || Map.get(@template_defaults, :ext_key_usage, "") %>
              <select name="ext_key_usage" id="profile-ext-key-usage" class="select select-sm select-bordered w-full">
                <option value="" selected={current_eku == ""}>- Select -</option>
                <option :for={{label, value} <- ext_key_usage_options()} value={value} selected={current_eku == value}>
                  {label}
                </option>
              </select>
            </div>
            <div>
              <label for="profile-digest-algo" class="label text-xs font-medium">Digest Algorithm</label>
              <%= if is_pqc_algorithm?(@selected_issuer_key_algo) do %>
                <select name="digest_algo" id="profile-digest-algo" class="select select-sm select-bordered w-full select-disabled" disabled>
                  <option value="algorithm-default" selected>Algorithm Default</option>
                </select>
                <p class="text-xs text-info mt-1">PQC algorithms use a built-in digest -- no separate selection needed.</p>
              <% else %>
                <select name="digest_algo" id="profile-digest-algo" class="select select-sm select-bordered w-full">
                  <option value="SHA-256" selected={Map.get(@template_defaults, :digest_algo, "SHA-256") == "SHA-256"}>SHA-256</option>
                  <option value="SHA-384" selected={Map.get(@template_defaults, :digest_algo) == "SHA-384"}>SHA-384</option>
                  <option value="SHA-512" selected={Map.get(@template_defaults, :digest_algo) == "SHA-512"}>SHA-512</option>
                </select>
              <% end %>
            </div>
            <div>
              <label for="profile-validity" class="label text-xs font-medium">Validity (days)</label>
              <input type="number" name="validity_days" id="profile-validity" value={@form_values[:validity_days] || Map.get(@template_defaults, :validity_days, 365)} min="1" max="3650" class="input input-sm input-bordered w-full" />
            </div>
            <div>
              <label class="label text-xs font-medium">Approval Mode</label>
              <div class="flex gap-4 mt-1">
                <label class="flex items-center gap-2 cursor-pointer">
                  <input type="radio" name="approval_mode" value="manual"
                         checked={Map.get(@template_defaults, :approval_mode, "manual") == "manual"}
                         class="radio radio-sm radio-primary" />
                  <div>
                    <span class="text-sm font-medium">Manual Review</span>
                    <p class="text-xs text-base-content/50">Officer must approve each CSR</p>
                  </div>
                </label>
                <label class="flex items-center gap-2 cursor-pointer">
                  <input type="radio" name="approval_mode" value="auto"
                         checked={Map.get(@template_defaults, :approval_mode, "manual") == "auto"}
                         class="radio radio-sm radio-primary" />
                  <div>
                    <span class="text-sm font-medium">Auto-Approve</span>
                    <p class="text-xs text-base-content/50">Automatically issue if all validations pass</p>
                  </div>
                </label>
              </div>
            </div>
            <div class="flex items-end gap-2">
              <button type="submit" phx-disable-with="Saving..." class="btn btn-sm btn-primary">Create Profile</button>
              <button type="button" phx-click="cancel_create" class="btn btn-sm btn-ghost">Cancel</button>
            </div>
          </form>
        </div>
      </section>
    </div>
    """
  end
end
