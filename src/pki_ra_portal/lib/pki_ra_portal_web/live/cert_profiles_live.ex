defmodule PkiRaPortalWeb.CertProfilesLive do
  use PkiRaPortalWeb, :live_view

  alias PkiRaPortal.RaEngineClient

  @impl true
  def mount(_params, _session, socket) do
    {:ok, profiles} = RaEngineClient.list_cert_profiles()

    {:ok,
     assign(socket,
       page_title: "Certificate Profiles",
       profiles: profiles,
       editing: nil
     )}
  end

  @impl true
  def handle_event("create_profile", params, socket) do
    attrs = %{
      name: params["name"],
      key_usage: params["key_usage"],
      ext_key_usage: params["ext_key_usage"],
      digest_algo: params["digest_algo"],
      validity_days: parse_int(params["validity_days"], 365)
    }

    case RaEngineClient.create_cert_profile(attrs) do
      {:ok, profile} ->
        profiles = socket.assigns.profiles ++ [profile]

        {:noreply,
         socket
         |> assign(profiles: profiles)
         |> put_flash(:info, "Certificate profile created")}

      {:error, reason} ->
        {:noreply, put_flash(socket, :error, "Failed to create profile: #{inspect(reason)}")}
    end
  end

  @impl true
  def handle_event("edit_profile", %{"id" => id}, socket) do
    profile_id = String.to_integer(id)
    profile = Enum.find(socket.assigns.profiles, &(&1.id == profile_id))
    {:noreply, assign(socket, editing: profile)}
  end

  @impl true
  def handle_event("cancel_edit", _params, socket) do
    {:noreply, assign(socket, editing: nil)}
  end

  @impl true
  def handle_event("update_profile", params, socket) do
    profile_id = String.to_integer(params["profile_id"])

    attrs = %{
      name: params["name"],
      key_usage: params["key_usage"],
      ext_key_usage: params["ext_key_usage"],
      digest_algo: params["digest_algo"],
      validity_days: parse_int(params["validity_days"], 365)
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
         |> put_flash(:info, "Profile updated")}

      {:error, reason} ->
        {:noreply, put_flash(socket, :error, "Failed to update profile: #{inspect(reason)}")}
    end
  end

  @impl true
  def handle_event("delete_profile", %{"id" => id}, socket) do
    profile_id = String.to_integer(id)

    case RaEngineClient.delete_cert_profile(profile_id) do
      {:ok, _} ->
        profiles = Enum.reject(socket.assigns.profiles, &(&1.id == profile_id))

        {:noreply,
         socket
         |> assign(profiles: profiles)
         |> put_flash(:info, "Profile deleted")}

      {:error, reason} ->
        {:noreply, put_flash(socket, :error, "Failed to delete profile: #{inspect(reason)}")}
    end
  end

  defp parse_int(val, default) when is_binary(val) do
    case Integer.parse(val) do
      {int, _} -> int
      :error -> default
    end
  end

  defp parse_int(_, default), do: default

  @impl true
  def render(assigns) do
    ~H"""
    <div id="cert-profiles-page">
      <h1>Certificate Profiles</h1>

      <section id="profile-table">
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Key Usage</th>
              <th>Ext Key Usage</th>
              <th>Digest</th>
              <th>Validity (days)</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody id="profile-list">
            <tr :for={profile <- @profiles} id={"profile-#{profile.id}"}>
              <td>{profile.name}</td>
              <td>{profile.key_usage}</td>
              <td>{profile.ext_key_usage}</td>
              <td>{profile.digest_algo}</td>
              <td>{profile.validity_days}</td>
              <td>
                <button phx-click="edit_profile" phx-value-id={profile.id}>Edit</button>
                <button phx-click="delete_profile" phx-value-id={profile.id}>Delete</button>
              </td>
            </tr>
          </tbody>
        </table>
      </section>

      <section :if={@editing} id="edit-profile-form">
        <h2>Edit Profile</h2>
        <form phx-submit="update_profile">
          <input type="hidden" name="profile_id" value={@editing.id} />
          <div>
            <label for="edit-name">Name:</label>
            <input type="text" name="name" id="edit-name" value={@editing.name} required />
          </div>
          <div>
            <label for="edit-key-usage">Key Usage:</label>
            <input type="text" name="key_usage" id="edit-key-usage" value={@editing.key_usage} />
          </div>
          <div>
            <label for="edit-ext-key-usage">Extended Key Usage:</label>
            <input
              type="text"
              name="ext_key_usage"
              id="edit-ext-key-usage"
              value={@editing.ext_key_usage}
            />
          </div>
          <div>
            <label for="edit-digest-algo">Digest Algorithm:</label>
            <select name="digest_algo" id="edit-digest-algo">
              <option value="SHA-256" selected={@editing.digest_algo == "SHA-256"}>SHA-256</option>
              <option value="SHA-384" selected={@editing.digest_algo == "SHA-384"}>SHA-384</option>
              <option value="SHA-512" selected={@editing.digest_algo == "SHA-512"}>SHA-512</option>
            </select>
          </div>
          <div>
            <label for="edit-validity">Validity (days):</label>
            <input
              type="number"
              name="validity_days"
              id="edit-validity"
              value={@editing.validity_days}
              min="1"
            />
          </div>
          <button type="submit">Update</button>
          <button type="button" phx-click="cancel_edit">Cancel</button>
        </form>
      </section>

      <section id="create-profile-form">
        <h2>Create Profile</h2>
        <form phx-submit="create_profile">
          <div>
            <label for="profile-name">Name:</label>
            <input type="text" name="name" id="profile-name" required />
          </div>
          <div>
            <label for="profile-key-usage">Key Usage:</label>
            <input type="text" name="key_usage" id="profile-key-usage" />
          </div>
          <div>
            <label for="profile-ext-key-usage">Extended Key Usage:</label>
            <input type="text" name="ext_key_usage" id="profile-ext-key-usage" />
          </div>
          <div>
            <label for="profile-digest-algo">Digest Algorithm:</label>
            <select name="digest_algo" id="profile-digest-algo">
              <option value="SHA-256">SHA-256</option>
              <option value="SHA-384">SHA-384</option>
              <option value="SHA-512">SHA-512</option>
            </select>
          </div>
          <div>
            <label for="profile-validity">Validity (days):</label>
            <input type="number" name="validity_days" id="profile-validity" value="365" min="1" />
          </div>
          <button type="submit">Create Profile</button>
        </form>
      </section>
    </div>
    """
  end
end
