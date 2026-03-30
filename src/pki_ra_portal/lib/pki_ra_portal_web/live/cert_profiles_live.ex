defmodule PkiRaPortalWeb.CertProfilesLive do
  use PkiRaPortalWeb, :live_view

  alias PkiRaPortal.RaEngineClient

  @impl true
  def mount(_params, _session, socket) do
    {:ok, profiles} = RaEngineClient.list_cert_profiles()

    ra_instances =
      case RaEngineClient.list_ra_instances() do
        {:ok, instances} -> instances
        {:error, _} -> []
      end

    issuer_keys =
      case RaEngineClient.available_issuer_keys() do
        {:ok, keys} -> keys
        {:error, _} -> []
      end

    {:ok,
     socket
     |> assign(
       page_title: "Certificate Profiles",
       profiles: profiles,
       ra_instances: ra_instances,
       issuer_keys: issuer_keys,
       editing: nil,
       page: 1,
       per_page: 50
     )
     |> apply_pagination()}
  end

  @impl true
  def handle_event("create_profile", params, socket) do
    attrs = %{
      name: params["name"],
      key_usage: params["key_usage"],
      ext_key_usage: params["ext_key_usage"],
      digest_algo: params["digest_algo"],
      validity_days: parse_int(params["validity_days"], 365),
      ra_instance_id: params["ra_instance_id"],
      issuer_key_id: params["issuer_key_id"]
    }

    case RaEngineClient.create_cert_profile(attrs) do
      {:ok, profile} ->
        profiles = [profile | socket.assigns.profiles]

        {:noreply,
         socket
         |> assign(profiles: profiles)
         |> apply_pagination()
         |> put_flash(:info, "Certificate profile created")}

      {:error, reason} ->
        {:noreply, put_flash(socket, :error, "Failed to create profile: #{inspect(reason)}")}
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

    case RaEngineClient.update_cert_profile(profile_id, attrs) do
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
        {:noreply, put_flash(socket, :error, "Failed to update profile: #{inspect(reason)}")}
    end
  end

  @impl true
  def handle_event("delete_profile", %{"id" => id}, socket) do
    case RaEngineClient.delete_cert_profile(id) do
      {:ok, _} ->
        profiles = Enum.reject(socket.assigns.profiles, &(&1.id == id))

        {:noreply,
         socket
         |> assign(profiles: profiles)
         |> apply_pagination()
         |> put_flash(:info, "Profile deleted")}

      {:error, reason} ->
        {:noreply, put_flash(socket, :error, "Failed to delete profile: #{inspect(reason)}")}
    end
  end

  @impl true
  def handle_event("change_page", %{"page" => page}, socket) do
    {:noreply, socket |> assign(page: String.to_integer(page)) |> apply_pagination()}
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
          <div class="overflow-x-auto">
            <table class="table table-sm">
              <thead>
                <tr class="border-base-300">
                  <th class="font-semibold text-xs uppercase tracking-wider">Name</th>
                  <th class="font-semibold text-xs uppercase tracking-wider">RA Instance</th>
                  <th class="font-semibold text-xs uppercase tracking-wider">Issuer Key</th>
                  <th class="font-semibold text-xs uppercase tracking-wider">Key Usage</th>
                  <th class="font-semibold text-xs uppercase tracking-wider">Digest</th>
                  <th class="font-semibold text-xs uppercase tracking-wider">Validity (days)</th>
                  <th class="font-semibold text-xs uppercase tracking-wider">Actions</th>
                </tr>
              </thead>
              <tbody id="profile-list">
                <tr :for={profile <- @paged_profiles} id={"profile-#{profile.id}"} class="hover:bg-base-200/50 border-base-300">
                  <td class="font-medium">{profile.name}</td>
                  <td class="text-xs">{ra_instance_name(profile, @ra_instances)}</td>
                  <td class="text-xs">{issuer_key_label(profile, @issuer_keys)}</td>
                  <td class="font-mono text-xs">{profile.key_usage}</td>
                  <td class="font-mono text-xs">{profile.digest_algo}</td>
                  <td>{profile.validity_days}</td>
                  <td class="flex gap-1">
                    <button phx-click="edit_profile" phx-value-id={profile.id} class="btn btn-xs btn-ghost">
                      Edit
                    </button>
                    <button phx-click="delete_profile" phx-value-id={profile.id} class="btn btn-xs btn-error btn-outline">
                      Delete
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

      <%!-- Create Profile Form --%>
      <section id="create-profile-form" class="card bg-base-100 shadow-sm border border-base-300">
        <div class="card-body">
          <h2 class="card-title text-sm font-semibold uppercase tracking-wide text-base-content/60">Create Profile</h2>
          <form phx-submit="create_profile" class="grid grid-cols-1 md:grid-cols-2 gap-4 mt-2">
            <div>
              <label for="profile-name" class="label text-xs font-medium">Name</label>
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
                <option :for={key <- @issuer_keys} value={key.id}>
                  {key.alias} ({key.ca_instance_name} — {key.algorithm})
                </option>
              </select>
            </div>
            <div>
              <label for="profile-key-usage" class="label text-xs font-medium">Key Usage</label>
              <input type="text" name="key_usage" id="profile-key-usage" class="input input-sm input-bordered w-full" />
            </div>
            <div>
              <label for="profile-ext-key-usage" class="label text-xs font-medium">Extended Key Usage</label>
              <input type="text" name="ext_key_usage" id="profile-ext-key-usage" class="input input-sm input-bordered w-full" />
            </div>
            <div>
              <label for="profile-digest-algo" class="label text-xs font-medium">Digest Algorithm</label>
              <select name="digest_algo" id="profile-digest-algo" class="select select-sm select-bordered w-full">
                <option value="SHA-256">SHA-256</option>
                <option value="SHA-384">SHA-384</option>
                <option value="SHA-512">SHA-512</option>
              </select>
            </div>
            <div>
              <label for="profile-validity" class="label text-xs font-medium">Validity (days)</label>
              <input type="number" name="validity_days" id="profile-validity" value="365" min="1" class="input input-sm input-bordered w-full" />
            </div>
            <div class="flex items-end">
              <button type="submit" class="btn btn-sm btn-primary">Create Profile</button>
            </div>
          </form>
        </div>
      </section>
    </div>
    """
  end
end
