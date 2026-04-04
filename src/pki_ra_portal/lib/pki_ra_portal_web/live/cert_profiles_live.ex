defmodule PkiRaPortalWeb.CertProfilesLive do
  use PkiRaPortalWeb, :live_view

  require Logger

  alias PkiRaPortal.RaEngineClient

  @templates %{
    "tls_server" => %{
      label: "TLS Server",
      description: "HTTPS server certificates",
      key_usage: "digitalSignature, keyEncipherment",
      ext_key_usage: "serverAuth",
      digest_algo: "sha256",
      validity_days: 365,
      subject_dn_policy: %{"required" => ["CN"], "optional" => ["O", "OU", "L", "ST", "C"], "require_dcv" => true}
    },
    "tls_client" => %{
      label: "TLS Client",
      description: "Client authentication certificates",
      key_usage: "digitalSignature",
      ext_key_usage: "clientAuth",
      digest_algo: "sha256",
      validity_days: 365,
      subject_dn_policy: %{"required" => ["CN"], "optional" => ["O", "OU", "E"], "require_dcv" => false}
    },
    "code_signing" => %{
      label: "Code Signing",
      description: "Software code signing certificates",
      key_usage: "digitalSignature",
      ext_key_usage: "codeSigning",
      digest_algo: "sha256",
      validity_days: 365,
      subject_dn_policy: %{"required" => ["CN", "O"], "optional" => ["OU", "L", "ST", "C"], "require_dcv" => false}
    },
    "email" => %{
      label: "Email / S-MIME",
      description: "Email encryption and signing",
      key_usage: "digitalSignature, keyEncipherment",
      ext_key_usage: "emailProtection",
      digest_algo: "sha256",
      validity_days: 365,
      subject_dn_policy: %{"required" => ["CN", "E"], "optional" => ["O", "OU"], "require_dcv" => false}
    },
    "custom" => %{
      label: "Custom",
      description: "Configure all fields manually",
      key_usage: "",
      ext_key_usage: "",
      digest_algo: "sha256",
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
       template_defaults: %{},
       page: 1,
       per_page: 50
     )
     |> apply_pagination()}
  end

  @impl true
  def handle_info(:load_data, socket) do
    opts = tenant_opts(socket)

    profiles = case RaEngineClient.list_cert_profiles(opts) do
      {:ok, p} -> p
      {:error, _} -> []
    end

    ra_instances =
      case RaEngineClient.list_ra_instances(opts) do
        {:ok, instances} -> instances
        {:error, _} -> []
      end

    issuer_keys =
      case RaEngineClient.available_issuer_keys(opts) do
        {:ok, keys} -> keys
        {:error, _} -> []
      end

    connections =
      case RaEngineClient.list_ca_connections([], opts) do
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
    {:noreply, assign(socket, show_create_form: false, selected_template: nil, template_defaults: %{})}
  end

  @impl true
  def handle_event("create_profile", params, socket) do
    if get_role(socket) != "ra_admin" do
      {:noreply, put_flash(socket, :error, "Unauthorized")}
    else
      attrs = %{
        name: params["name"],
        key_usage: params["key_usage"],
        ext_key_usage: params["ext_key_usage"],
        digest_algo: params["digest_algo"],
        validity_days: parse_int(params["validity_days"], 365),
        ra_instance_id: params["ra_instance_id"],
        issuer_key_id: params["issuer_key_id"]
      }

      case RaEngineClient.create_cert_profile(attrs, tenant_opts(socket)) do
        {:ok, profile} ->
          profiles = [profile | socket.assigns.profiles]

          {:noreply,
           socket
           |> assign(profiles: profiles, show_create_form: false, selected_template: nil, template_defaults: %{})
           |> apply_pagination()
           |> put_flash(:info, "Certificate profile created")}

        {:error, reason} ->
          Logger.error("[cert_profiles] Failed to create profile: #{inspect(reason)}")
          {:noreply, put_flash(socket, :error, PkiRaPortalWeb.ErrorHelpers.sanitize_error("Failed to create profile", reason))}
      end
    end
  end

  @impl true
  def handle_event("edit_profile", %{"id" => id}, socket) do
    profile = Enum.find(socket.assigns.profiles, &(&1.id == id))
    {:noreply, assign(socket, editing: profile)}
  end

  @impl true
  def handle_event("cancel_edit", _params, socket) do
    {:noreply, assign(socket, editing: nil)}
  end

  @impl true
  def handle_event("update_profile", params, socket) do
    if get_role(socket) != "ra_admin" do
      {:noreply, put_flash(socket, :error, "Unauthorized")}
    else
      profile_id = params["profile_id"]

      attrs = %{
        name: params["name"],
        key_usage: params["key_usage"],
        ext_key_usage: params["ext_key_usage"],
        digest_algo: params["digest_algo"],
        validity_days: parse_int(params["validity_days"], 365),
        ra_instance_id: params["ra_instance_id"],
        issuer_key_id: params["issuer_key_id"]
      }

      case RaEngineClient.update_cert_profile(profile_id, attrs, tenant_opts(socket)) do
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
          {:noreply, put_flash(socket, :error, PkiRaPortalWeb.ErrorHelpers.sanitize_error("Failed to update profile", reason))}
      end
    end
  end

  @impl true
  def handle_event("delete_profile", %{"id" => id}, socket) do
    if get_role(socket) != "ra_admin" do
      {:noreply, put_flash(socket, :error, "Unauthorized")}
    else
      case RaEngineClient.delete_cert_profile(id, tenant_opts(socket)) do
        {:ok, _} ->
          profiles = Enum.reject(socket.assigns.profiles, &(&1.id == id))

          {:noreply,
           socket
           |> assign(profiles: profiles)
           |> apply_pagination()
           |> put_flash(:info, "Profile deleted")}

        {:error, reason} ->
          Logger.error("[cert_profiles] Failed to delete profile: #{inspect(reason)}")
          {:noreply, put_flash(socket, :error, PkiRaPortalWeb.ErrorHelpers.sanitize_error("Failed to delete profile", reason))}
      end
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
      key -> "#{key.alias} (#{key.algorithm})"
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
      <h1 class="text-2xl font-bold tracking-tight">Certificate Profiles</h1>

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
                  <th class="font-semibold text-xs uppercase tracking-wider w-[10%]">Validity (days)</th>
                  <th class="font-semibold text-xs uppercase tracking-wider w-[17%]">Actions</th>
                </tr>
              </thead>
              <tbody id="profile-list">
                <tr :for={profile <- @paged_profiles} id={"profile-#{profile.id}"} class="hover:bg-base-200/50 border-base-300">
                  <td class="font-medium overflow-hidden text-ellipsis whitespace-nowrap">{profile.name}</td>
                  <td class="text-xs overflow-hidden text-ellipsis whitespace-nowrap">{ra_instance_name(profile, @ra_instances)}</td>
                  <td class="text-xs overflow-hidden text-ellipsis whitespace-nowrap">{issuer_key_label(profile, @issuer_keys)}</td>
                  <td class="font-mono text-xs overflow-hidden text-ellipsis whitespace-nowrap">{profile.key_usage}</td>
                  <td class="font-mono text-xs">{profile.digest_algo}</td>
                  <td>{profile.validity_days}</td>
                  <td class="flex gap-1">
                    <button phx-click="edit_profile" phx-value-id={profile.id} title="Edit" class="btn btn-ghost btn-xs text-sky-400">
                      <.icon name="hero-pencil" class="size-4" />
                    </button>
                    <button phx-click="delete_profile" phx-value-id={profile.id} title="Delete" class="btn btn-ghost btn-xs text-rose-400">
                      <.icon name="hero-trash" class="size-4" />
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

      <%!-- Edit Profile Form --%>
      <section :if={@editing} id="edit-profile-form" class="card bg-base-100 shadow-sm border border-primary/30">
        <div class="card-body">
          <h2 class="card-title text-sm font-semibold uppercase tracking-wide text-base-content/60">Edit Profile</h2>
          <form phx-submit="update_profile" class="grid grid-cols-1 md:grid-cols-2 gap-4 mt-2">
            <input type="hidden" name="profile_id" value={@editing.id} />
            <div>
              <label for="edit-name" class="label text-xs font-medium">Name</label>
              <input type="text" name="name" id="edit-name" value={@editing.name} required class="input input-sm input-bordered w-full" />
            </div>
            <div>
              <label for="edit-ra-instance" class="label text-xs font-medium">RA Instance <span class="text-error">*</span></label>
              <select name="ra_instance_id" id="edit-ra-instance" required class="select select-sm select-bordered w-full">
                <option value="">Select RA Instance</option>
                <option
                  :for={inst <- @ra_instances}
                  value={inst.id}
                  selected={Map.get(@editing, :ra_instance_id) == inst.id}
                >
                  {inst.name}
                </option>
              </select>
            </div>
            <div>
              <label for="edit-issuer-key" class="label text-xs font-medium">Issuer Key <span class="text-error">*</span></label>
              <select name="issuer_key_id" id="edit-issuer-key" required class="select select-sm select-bordered w-full">
                <option value="">Select Issuer Key</option>
                <option
                  :for={key <- @issuer_keys}
                  value={key.id}
                  selected={Map.get(@editing, :issuer_key_id) == key.id}
                >
                  {key.alias} ({key.ca_instance_name} — {key.algorithm})
                </option>
              </select>
            </div>
            <div>
              <label for="edit-key-usage" class="label text-xs font-medium">Key Usage</label>
              <input type="text" name="key_usage" id="edit-key-usage" value={@editing.key_usage} class="input input-sm input-bordered w-full" />
            </div>
            <div>
              <label for="edit-ext-key-usage" class="label text-xs font-medium">Extended Key Usage</label>
              <input type="text" name="ext_key_usage" id="edit-ext-key-usage" value={@editing.ext_key_usage} class="input input-sm input-bordered w-full" />
            </div>
            <div>
              <label for="edit-digest-algo" class="label text-xs font-medium">Digest Algorithm</label>
              <select name="digest_algo" id="edit-digest-algo" class="select select-sm select-bordered w-full">
                <option value="SHA-256" selected={@editing.digest_algo == "SHA-256"}>SHA-256</option>
                <option value="SHA-384" selected={@editing.digest_algo == "SHA-384"}>SHA-384</option>
                <option value="SHA-512" selected={@editing.digest_algo == "SHA-512"}>SHA-512</option>
              </select>
            </div>
            <div>
              <label for="edit-validity" class="label text-xs font-medium">Validity (days)</label>
              <input type="number" name="validity_days" id="edit-validity" value={@editing.validity_days} min="1" class="input input-sm input-bordered w-full" />
            </div>
            <div class="flex items-end gap-2">
              <button type="submit" class="btn btn-sm btn-primary">Update</button>
              <button type="button" phx-click="cancel_edit" class="btn btn-sm btn-ghost">Cancel</button>
            </div>
          </form>
        </div>
      </section>

      <%!-- Create Profile Button --%>
      <div :if={!@show_template_picker and !@show_create_form} class="flex justify-end">
        <button phx-click="show_create_form" class="btn btn-sm btn-primary">
          <.icon name="hero-plus" class="size-4 mr-1" /> Create Profile
        </button>
      </div>

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
          <form phx-submit="create_profile" class="grid grid-cols-1 md:grid-cols-2 gap-4 mt-2">
            <div>
              <label for="profile-name" class="label text-xs font-medium">Name <span class="text-error">*</span></label>
              <input type="text" name="name" id="profile-name" required class="input input-sm input-bordered w-full" />
            </div>
            <div>
              <label for="profile-ra-instance" class="label text-xs font-medium">RA Instance <span class="text-error">*</span></label>
              <select name="ra_instance_id" id="profile-ra-instance" required class="select select-sm select-bordered w-full">
                <option value="">Select RA Instance</option>
                <option :for={inst <- @ra_instances} value={inst.id}>
                  {inst.name}
                </option>
              </select>
            </div>
            <div>
              <label for="profile-issuer-key" class="label text-xs font-medium">Issuer Key <span class="text-error">*</span></label>
              <select name="issuer_key_id" id="profile-issuer-key" required class="select select-sm select-bordered w-full">
                <option value="">Select Issuer Key</option>
                <option :for={key <- @connected_keys} value={key.id}>
                  {key.alias} ({key.algorithm})
                </option>
              </select>
              <p :if={@connected_keys == []} class="text-xs text-warning mt-1">No connected CA keys found. Connect a CA key first.</p>
            </div>
            <div>
              <label for="profile-key-usage" class="label text-xs font-medium">Key Usage</label>
              <input type="text" name="key_usage" id="profile-key-usage" value={Map.get(@template_defaults, :key_usage, "")} class="input input-sm input-bordered w-full" />
            </div>
            <div>
              <label for="profile-ext-key-usage" class="label text-xs font-medium">Extended Key Usage</label>
              <input type="text" name="ext_key_usage" id="profile-ext-key-usage" value={Map.get(@template_defaults, :ext_key_usage, "")} class="input input-sm input-bordered w-full" />
            </div>
            <div>
              <label for="profile-digest-algo" class="label text-xs font-medium">Digest Algorithm</label>
              <select name="digest_algo" id="profile-digest-algo" class="select select-sm select-bordered w-full">
                <option value="SHA-256" selected={Map.get(@template_defaults, :digest_algo, "sha256") == "sha256"}>SHA-256</option>
                <option value="SHA-384" selected={Map.get(@template_defaults, :digest_algo) == "sha384"}>SHA-384</option>
                <option value="SHA-512" selected={Map.get(@template_defaults, :digest_algo) == "sha512"}>SHA-512</option>
              </select>
            </div>
            <div>
              <label for="profile-validity" class="label text-xs font-medium">Validity (days)</label>
              <input type="number" name="validity_days" id="profile-validity" value={Map.get(@template_defaults, :validity_days, 365)} min="1" class="input input-sm input-bordered w-full" />
            </div>
            <div class="flex items-end gap-2">
              <button type="submit" class="btn btn-sm btn-primary">Create Profile</button>
              <button type="button" phx-click="cancel_create" class="btn btn-sm btn-ghost">Cancel</button>
            </div>
          </form>
        </div>
      </section>
    </div>
    """
  end
end
