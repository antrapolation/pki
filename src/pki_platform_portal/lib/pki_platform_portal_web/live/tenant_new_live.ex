defmodule PkiPlatformPortalWeb.TenantNewLive do
  use PkiPlatformPortalWeb, :live_view

  alias PkiPlatformEngine.{Provisioner, EmailVerification, Mailer, EmailTemplates}

  @impl true
  def mount(_params, _session, socket) do
    {:ok,
     assign(socket,
       page_title: "New Tenant",
       step: 1,
       name: "",
       slug: "",
       email: "",
       form_error: nil,
       created_tenant: nil,
       verification_sent: false
     )}
  end

  @impl true
  def handle_event("next_step", params, socket) do
    name = String.trim(params["name"] || "")
    slug = String.trim(params["slug"] || "")
    email = String.trim(params["email"] || "")

    with :ok <- validate_name(name),
         :ok <- validate_slug(slug),
         :ok <- validate_email(email) do
      socket =
        socket
        |> assign(
          step: 2,
          name: name,
          slug: slug,
          email: email,
          form_error: nil,
          verification_sent: false
        )

      send(self(), :send_verification)

      {:noreply, socket}
    else
      {:error, msg} ->
        {:noreply, assign(socket, form_error: msg)}
    end
  end

  def handle_event("back_to_step1", _params, socket) do
    {:noreply, assign(socket, step: 1, form_error: nil)}
  end

  def handle_event("resend_code", _params, socket) do
    send(self(), :send_verification)
    {:noreply, assign(socket, form_error: nil, verification_sent: false)}
  end

  def handle_event("verify_code", %{"code" => code}, socket) do
    code = String.trim(code)

    if String.length(code) != 6 do
      {:noreply, assign(socket, form_error: "Please enter the 6-digit verification code.")}
    else
      case EmailVerification.verify_code(socket.assigns.email, code) do
        :ok ->
          send(self(), :provision_tenant)
          {:noreply, assign(socket, step: 3, form_error: nil)}

        {:error, :expired} ->
          {:noreply, assign(socket, form_error: "Verification code has expired. Please resend.")}

        {:error, :invalid_code} ->
          {:noreply, assign(socket, form_error: "Invalid verification code. Please try again.")}

        {:error, :no_code} ->
          {:noreply, assign(socket, form_error: "No verification code found. Please resend.")}
      end
    end
  end

  @impl true
  def handle_info(:send_verification, socket) do
    email = socket.assigns.email
    code = EmailVerification.generate_code(email)
    html = EmailTemplates.verification_code(code)

    case Mailer.send_email(email, "Your verification code", html) do
      {:ok, _} ->
        {:noreply, assign(socket, verification_sent: true)}

      {:error, reason} ->
        {:noreply, assign(socket, form_error: "Failed to send verification email: #{inspect(reason)}")}
    end
  end

  def handle_info(:provision_tenant, socket) do
    %{name: name, slug: slug, email: email} = socket.assigns

    if email == "" or slug == "" do
      {:noreply, assign(socket, step: 1, form_error: "Session expired. Please start again.")}
    else

    ca_password = :crypto.strong_rand_bytes(12) |> Base.url_encode64()
    ra_password = :crypto.strong_rand_bytes(12) |> Base.url_encode64()
    ca_username = "#{slug}-ca-admin"
    ra_username = "#{slug}-ra-admin"

    opts = [email: email]

    errors = []

    {tenant, errors} =
      case Provisioner.create_tenant(name, slug, opts) do
        {:ok, tenant} ->
          {tenant, errors}

        {:error, %Ecto.Changeset{} = changeset} ->
          err =
            Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
              Regex.replace(~r"%{(\w+)}", msg, fn _, key ->
                opts |> Keyword.get(String.to_existing_atom(key), key) |> to_string()
              end)
            end)
            |> Enum.map(fn {k, v} -> "#{k}: #{Enum.join(v, ", ")}" end)
            |> Enum.join("; ")

          {nil, ["Tenant creation failed: #{err}" | errors]}

        {:error, reason} ->
          {nil, ["Tenant creation failed: #{inspect(reason)}" | errors]}
      end

    if tenant == nil do
      {:noreply,
       assign(socket,
         form_error: Enum.join(Enum.reverse(errors), "\n"),
         step: 3
       )}
    else
      secret = System.get_env("INTERNAL_API_SECRET", "")
      expires_at = DateTime.utc_now() |> DateTime.add(24, :hour) |> DateTime.truncate(:second)

      errors =
        errors ++
          create_ca_admin(ca_username, ca_password, name, secret, expires_at) ++
          create_ra_admin(ra_username, ra_password, name, tenant.id, secret, expires_at)

      ca_host = System.get_env("CA_PORTAL_HOST", "ca.straptrust.com")
      ra_host = System.get_env("RA_PORTAL_HOST", "ra.straptrust.com")
      ca_portal_url = "https://#{ca_host}"
      ra_portal_url = "https://#{ra_host}"

      html =
        EmailTemplates.admin_credentials(
          name,
          ca_username,
          ca_password,
          ra_username,
          ra_password,
          ca_portal_url,
          ra_portal_url
        )

      errors =
        if errors == [] do
          # Only send credentials email if both admins were created successfully
          case Mailer.send_email(email, "Your #{name} admin credentials", html) do
            {:ok, _} -> []
            {:error, reason} -> ["Failed to send credentials email: #{inspect(reason)}"]
          end
        else
          errors ++ ["Credentials email not sent due to admin creation errors."]
        end

      error_msg = if errors == [], do: nil, else: Enum.join(errors, "\n")

      {:noreply,
       assign(socket,
         created_tenant: tenant,
         form_error: error_msg
       )}
    end
    end
  end

  defp create_ca_admin(username, password, display_name, secret, expires_at) do
    body = %{
      username: username,
      password: password,
      role: "ca_admin",
      display_name: "#{display_name} CA Admin",
      ca_instance_id: "default",
      must_change_password: true,
      credential_expires_at: DateTime.to_iso8601(expires_at)
    }

    case Req.post("http://127.0.0.1:4001/api/v1/users",
           json: body,
           headers: [{"authorization", "Bearer #{secret}"}]
         ) do
      {:ok, %{status: status}} when status in 200..299 -> []
      {:ok, %{status: status}} -> ["CA admin creation failed (HTTP #{status})"]
      {:error, reason} -> ["CA admin creation failed: #{inspect(reason)}"]
    end
  end

  defp create_ra_admin(username, password, display_name, tenant_id, secret, expires_at) do
    body = %{
      username: username,
      password: password,
      role: "ra_admin",
      display_name: "#{display_name} RA Admin",
      tenant_id: tenant_id,
      must_change_password: true,
      credential_expires_at: DateTime.to_iso8601(expires_at)
    }

    case Req.post("http://127.0.0.1:4003/api/v1/users",
           json: body,
           headers: [{"authorization", "Bearer #{secret}"}]
         ) do
      {:ok, %{status: status}} when status in 200..299 -> []
      {:ok, %{status: status}} -> ["RA admin creation failed (HTTP #{status})"]
      {:error, reason} -> ["RA admin creation failed: #{inspect(reason)}"]
    end
  end

  defp validate_name(""), do: {:error, "Name is required."}
  defp validate_name(_), do: :ok

  defp validate_slug(""), do: {:error, "Slug is required."}

  defp validate_slug(slug) do
    if Regex.match?(~r/^[a-z0-9][a-z0-9-]*[a-z0-9]$/, slug) do
      :ok
    else
      {:error, "Slug must contain only lowercase letters, numbers, and hyphens, and must start and end with a letter or number."}
    end
  end

  defp validate_email(""), do: {:error, "Email is required."}

  defp validate_email(email) do
    if Regex.match?(~r/^[^\s@]+@[^\s@]+\.[^\s@]+$/, email) do
      :ok
    else
      {:error, "Please enter a valid email address."}
    end
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div id="tenant-new-page" class="max-w-2xl mx-auto space-y-6">
      <%!-- Back link --%>
      <div>
        <.link navigate="/tenants" class="inline-flex items-center gap-1 text-sm text-base-content/60 hover:text-base-content transition-colors">
          <.icon name="hero-arrow-left" class="size-4" />
          Back to Tenants
        </.link>
      </div>

      <%!-- Step indicator --%>
      <div class="flex items-center justify-center gap-0">
        <%!-- Step 1 --%>
        <div class="flex items-center gap-2">
          <div class={[
            "flex items-center justify-center w-8 h-8 rounded-full text-sm font-semibold border-2 transition-colors",
            if(@step >= 1, do: "bg-primary text-primary-content border-primary", else: "bg-base-200 text-base-content/40 border-base-300")
          ]}>
            <%= if @step > 1 do %>
              <.icon name="hero-check-mini" class="size-4" />
            <% else %>
              1
            <% end %>
          </div>
          <span class={["text-xs font-medium", if(@step >= 1, do: "text-base-content", else: "text-base-content/40")]}>
            Tenant Info
          </span>
        </div>

        <div class={["w-12 h-0.5 mx-2", if(@step >= 2, do: "bg-primary", else: "bg-base-300")]}></div>

        <%!-- Step 2 --%>
        <div class="flex items-center gap-2">
          <div class={[
            "flex items-center justify-center w-8 h-8 rounded-full text-sm font-semibold border-2 transition-colors",
            if(@step >= 2, do: "bg-primary text-primary-content border-primary", else: "bg-base-200 text-base-content/40 border-base-300")
          ]}>
            <%= if @step > 2 do %>
              <.icon name="hero-check-mini" class="size-4" />
            <% else %>
              2
            <% end %>
          </div>
          <span class={["text-xs font-medium", if(@step >= 2, do: "text-base-content", else: "text-base-content/40")]}>
            Verify Email
          </span>
        </div>

        <div class={["w-12 h-0.5 mx-2", if(@step >= 3, do: "bg-primary", else: "bg-base-300")]}></div>

        <%!-- Step 3 --%>
        <div class="flex items-center gap-2">
          <div class={[
            "flex items-center justify-center w-8 h-8 rounded-full text-sm font-semibold border-2 transition-colors",
            if(@step >= 3, do: "bg-primary text-primary-content border-primary", else: "bg-base-200 text-base-content/40 border-base-300")
          ]}>
            3
          </div>
          <span class={["text-xs font-medium", if(@step >= 3, do: "text-base-content", else: "text-base-content/40")]}>
            Complete
          </span>
        </div>
      </div>

      <%!-- Step 1: Tenant Info --%>
      <%= if @step == 1 do %>
        <div class="card bg-base-100 shadow-sm border border-base-300">
          <div class="card-body p-6 space-y-5">
            <div>
              <h2 class="text-base font-semibold text-base-content">Tenant Information</h2>
              <p class="text-sm text-base-content/60 mt-0.5">Enter the details for the new Certificate Authority tenant.</p>
            </div>

            <%= if @form_error do %>
              <div class="alert alert-error text-sm">
                <.icon name="hero-exclamation-circle" class="size-4 shrink-0" />
                <span>{@form_error}</span>
              </div>
            <% end %>

            <form id="step1-form" phx-submit="next_step" class="space-y-4">
              <div>
                <label for="tenant-name" class="block text-xs font-medium text-base-content/60 mb-1">
                  Name <span class="text-error">*</span>
                </label>
                <input
                  type="text"
                  name="name"
                  id="tenant-name"
                  required
                  value={@name}
                  class="input input-bordered w-full"
                  placeholder="Acme Corporation"
                />
              </div>

              <div>
                <label for="tenant-slug" class="block text-xs font-medium text-base-content/60 mb-1">
                  Slug <span class="text-error">*</span>
                </label>
                <input
                  type="text"
                  name="slug"
                  id="tenant-slug"
                  required
                  value={@slug}
                  class="input input-bordered w-full font-mono"
                  placeholder="acme-corp"
                  pattern="[a-z0-9][a-z0-9-]*[a-z0-9]"
                  title="Lowercase letters, numbers, and hyphens only. Must start and end with a letter or number."
                />
                <p class="text-xs text-base-content/50 mt-1">Lowercase alphanumeric with hyphens (e.g. <code class="font-mono">acme-corp</code>)</p>
              </div>

              <div>
                <label for="tenant-email" class="block text-xs font-medium text-base-content/60 mb-1">
                  Email <span class="text-error">*</span>
                </label>
                <input
                  type="email"
                  name="email"
                  id="tenant-email"
                  required
                  value={@email}
                  class="input input-bordered w-full"
                  placeholder="admin@acme-corp.com"
                />
                <p class="text-xs text-base-content/50 mt-1">Admin credentials will be sent to this email after verification.</p>
              </div>

              <div class="flex justify-end gap-3 pt-2">
                <.link navigate="/tenants" class="btn btn-ghost btn-sm">
                  Cancel
                </.link>
                <button type="submit" class="btn btn-primary btn-sm" phx-disable-with="Validating...">
                  Next
                  <.icon name="hero-arrow-right" class="size-4" />
                </button>
              </div>
            </form>
          </div>
        </div>
      <% end %>

      <%!-- Step 2: Email Verification --%>
      <%= if @step == 2 do %>
        <div class="card bg-base-100 shadow-sm border border-base-300">
          <div class="card-body p-6 space-y-5">
            <div>
              <h2 class="text-base font-semibold text-base-content">Verify Email</h2>
              <p class="text-sm text-base-content/60 mt-0.5">
                We sent a 6-digit verification code to <strong class="text-base-content">{@email}</strong>.
              </p>
            </div>

            <%= if @verification_sent do %>
              <div class="alert alert-success text-sm">
                <.icon name="hero-check-circle" class="size-4 shrink-0" />
                <span>Verification code sent to {@email}.</span>
              </div>
            <% end %>

            <%= if @form_error do %>
              <div class="alert alert-error text-sm">
                <.icon name="hero-exclamation-circle" class="size-4 shrink-0" />
                <span>{@form_error}</span>
              </div>
            <% end %>

            <form id="step2-form" phx-submit="verify_code" class="space-y-4">
              <div>
                <label for="verification-code" class="block text-xs font-medium text-base-content/60 mb-1">
                  Verification Code <span class="text-error">*</span>
                </label>
                <input
                  type="text"
                  name="code"
                  id="verification-code"
                  required
                  maxlength="6"
                  class="input input-bordered w-full font-mono text-center text-lg tracking-[0.5em]"
                  placeholder="000000"
                  autocomplete="one-time-code"
                  inputmode="numeric"
                />
              </div>

              <div class="flex items-center justify-between pt-2">
                <div class="flex items-center gap-3">
                  <button type="button" phx-click="back_to_step1" class="btn btn-ghost btn-sm">
                    <.icon name="hero-arrow-left" class="size-4" />
                    Back
                  </button>
                  <button type="button" phx-click="resend_code" class="btn btn-ghost btn-sm text-primary">
                    <.icon name="hero-arrow-path" class="size-4" />
                    Resend Code
                  </button>
                </div>
                <button type="submit" class="btn btn-primary btn-sm" phx-disable-with="Verifying...">
                  Verify
                  <.icon name="hero-arrow-right" class="size-4" />
                </button>
              </div>
            </form>
          </div>
        </div>
      <% end %>

      <%!-- Step 3: Complete --%>
      <%= if @step == 3 do %>
        <%= if @created_tenant do %>
          <div class="card bg-base-100 shadow-sm border border-success/40">
            <div class="card-body p-6 space-y-5">
              <div class="flex items-center gap-3">
                <div class="flex items-center justify-center w-10 h-10 rounded-lg bg-success/10">
                  <.icon name="hero-check-circle" class="size-6 text-success" />
                </div>
                <div>
                  <h2 class="text-base font-semibold text-base-content">Tenant Created</h2>
                  <p class="text-sm text-base-content/60">
                    <span class="font-medium text-base-content">{@created_tenant.name}</span>
                    has been provisioned successfully.
                  </p>
                </div>
              </div>

              <%= if @form_error do %>
                <div class="alert alert-warning text-sm whitespace-pre-line">
                  <.icon name="hero-exclamation-triangle" class="size-4 shrink-0" />
                  <span>{@form_error}</span>
                </div>
              <% end %>

              <div class="divider my-0"></div>

              <div class="space-y-3">
                <div>
                  <p class="text-xs font-semibold uppercase tracking-wider text-base-content/50">What happens next</p>
                  <p class="text-sm text-base-content/70 mt-1">
                    Admin credentials for both the CA and RA portals have been generated and emailed to
                    <strong class="text-base-content">{@email}</strong>.
                    The credentials expire in 24 hours and must be changed on first login.
                  </p>
                </div>

                <div class="alert alert-info text-xs">
                  <.icon name="hero-information-circle" class="size-4" />
                  <span>The tenant must be <strong>activated</strong> from the tenant detail page before the admin accounts can log in.</span>
                </div>
              </div>

              <div class="flex gap-3 pt-1">
                <.link navigate={"/tenants/#{@created_tenant.id}"} class="btn btn-primary btn-sm">
                  <.icon name="hero-building-office" class="size-4" />
                  View Tenant
                </.link>
                <.link navigate="/tenants" class="btn btn-ghost btn-sm">
                  <.icon name="hero-list-bullet" class="size-4" />
                  Back to List
                </.link>
              </div>
            </div>
          </div>
        <% else %>
          <%!-- Provisioning failed completely --%>
          <div class="card bg-base-100 shadow-sm border border-error/40">
            <div class="card-body p-6 space-y-5">
              <div class="flex items-center gap-3">
                <div class="flex items-center justify-center w-10 h-10 rounded-lg bg-error/10">
                  <.icon name="hero-x-circle" class="size-6 text-error" />
                </div>
                <div>
                  <h2 class="text-base font-semibold text-base-content">Provisioning Failed</h2>
                  <p class="text-sm text-base-content/60">The tenant could not be created.</p>
                </div>
              </div>

              <%= if @form_error do %>
                <div class="alert alert-error text-sm whitespace-pre-line">
                  <.icon name="hero-exclamation-circle" class="size-4 shrink-0" />
                  <span>{@form_error}</span>
                </div>
              <% end %>

              <div class="flex gap-3 pt-1">
                <button phx-click="back_to_step1" class="btn btn-primary btn-sm">
                  <.icon name="hero-arrow-left" class="size-4" />
                  Try Again
                </button>
                <.link navigate="/tenants" class="btn btn-ghost btn-sm">
                  <.icon name="hero-list-bullet" class="size-4" />
                  Back to List
                </.link>
              </div>
            </div>
          </div>
        <% end %>
      <% end %>
    </div>
    """
  end
end
