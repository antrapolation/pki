defmodule PkiRaPortal.RaEngineClient.Http do
  @moduledoc """
  HTTP implementation of the RA engine client.

  Communicates with the RA Engine REST API over HTTP using the Req library.
  Auth endpoints (login, register, needs-setup) are public.
  All other endpoints require a Bearer token (INTERNAL_API_SECRET).
  """

  @behaviour PkiRaPortal.RaEngineClient

  require Logger

  # --- Auth endpoints (public, no Bearer token) ---

  @impl true
  def authenticate(username, password) do
    case post("/api/v1/auth/login", %{username: username, password: password}) do
      {:ok, %{status: 200, body: body}} ->
        {:ok, atomize_keys(body)}

      {:ok, %{status: 401}} ->
        {:error, :invalid_credentials}

      {:ok, %{status: status, body: body}} ->
        {:error, {:unexpected_status, status, body}}

      {:error, reason} ->
        {:error, {:http_error, reason}}
    end
  end

  @impl true
  def authenticate_with_session(username, password) do
    case post("/api/v1/auth/login", %{username: username, password: password}) do
      {:ok, %{status: 200, body: body}} ->
        user = atomize_keys(body)
        session = %{
          session_key: decode_session_value(Map.get(body, "session_key")),
          session_salt: decode_session_value(Map.get(body, "session_salt"))
        }
        {:ok, user, session}

      {:ok, %{status: 401}} ->
        {:error, :invalid_credentials}

      {:ok, %{status: status, body: body}} ->
        {:error, {:unexpected_status, status, body}}

      {:error, reason} ->
        {:error, {:http_error, reason}}
    end
  end

  @impl true
  def register_user(attrs) do
    payload = stringify_keys(attrs)

    case post("/api/v1/auth/register", payload) do
      {:ok, %{status: status, body: body}} when status in [200, 201] ->
        {:ok, atomize_keys(body)}

      {:ok, %{status: 409}} ->
        {:error, :setup_already_complete}

      {:ok, %{status: 422, body: %{"details" => details}}} ->
        {:error, {:validation_error, details}}

      {:ok, %{status: status, body: body}} ->
        {:error, {:unexpected_status, status, body}}

      {:error, reason} ->
        {:error, {:http_error, reason}}
    end
  end

  @impl true
  def needs_setup? do
    case get("/api/v1/auth/needs-setup") do
      {:ok, %{status: 200, body: %{"needs_setup" => value}}} ->
        value

      {:ok, %{status: 404}} ->
        true

      {:ok, _} ->
        true

      {:error, reason} ->
        Logger.error("Failed to check needs_setup: #{inspect(reason)}")
        true
    end
  end

  @impl true
  def needs_setup?(tenant_id) do
    case get("/api/v1/auth/needs-setup?tenant_id=#{tenant_id}") do
      {:ok, %{status: 200, body: %{"needs_setup" => value}}} ->
        value

      {:ok, %{status: 404}} ->
        true

      {:ok, _} ->
        true

      {:error, reason} ->
        Logger.error("Failed to check needs_setup for tenant #{tenant_id}: #{inspect(reason)}")
        true
    end
  end

  @impl true
  def get_user_by_username(username) do
    case auth_get("/api/v1/users/by-username/#{URI.encode(username)}") do
      {:ok, %{status: 200, body: body}} ->
        {:ok, atomize_keys(body)}

      {:ok, %{status: status, body: body}} ->
        {:error, {:unexpected_status, status, body}}

      {:error, reason} ->
        {:error, {:http_error, reason}}
    end
  end

  # --- User management ---

  @impl true
  def list_users do
    case auth_get("/api/v1/users") do
      {:ok, %{status: 200, body: body}} when is_list(body) ->
        {:ok, Enum.map(body, &atomize_keys/1)}

      {:ok, %{status: status, body: body}} ->
        {:error, {:unexpected_status, status, body}}

      {:error, reason} ->
        {:error, {:http_error, reason}}
    end
  end

  @impl true
  def create_user(attrs) do
    payload = stringify_keys(attrs)

    case auth_post("/api/v1/users", payload) do
      {:ok, %{status: status, body: body}} when status in [200, 201] ->
        {:ok, atomize_keys(body)}

      {:ok, %{status: 422, body: %{"details" => details}}} ->
        {:error, {:validation_error, details}}

      {:ok, %{status: status, body: body}} ->
        {:error, {:unexpected_status, status, body}}

      {:error, reason} ->
        {:error, {:http_error, reason}}
    end
  end

  @impl true
  def create_user(attrs, admin_context) do
    payload =
      attrs
      |> stringify_keys()
      |> Map.put("admin_user_id", admin_context[:user_id] || admin_context["user_id"])
      |> Map.put("admin_password", admin_context[:password] || admin_context["password"])

    case auth_post("/api/v1/users", payload) do
      {:ok, %{status: status, body: body}} when status in [200, 201] ->
        {:ok, atomize_keys(body)}

      {:ok, %{status: 422, body: %{"details" => details}}} ->
        {:error, {:validation_error, details}}

      {:ok, %{status: status, body: body}} ->
        {:error, {:unexpected_status, status, body}}

      {:error, reason} ->
        {:error, {:http_error, reason}}
    end
  end

  @impl true
  def delete_user(id) do
    case auth_delete("/api/v1/users/#{id}") do
      {:ok, %{status: 200, body: body}} ->
        {:ok, atomize_keys(body)}

      {:ok, %{status: 404}} ->
        {:error, :not_found}

      {:ok, %{status: status, body: body}} ->
        {:error, {:unexpected_status, status, body}}

      {:error, reason} ->
        {:error, {:http_error, reason}}
    end
  end

  # --- CSR management (implemented on RA Engine) ---

  @impl true
  def list_csrs(filters) do
    params =
      filters
      |> Enum.map(fn {k, v} -> {to_string(k), v} end)

    case auth_get("/api/v1/csr", params: params) do
      {:ok, %{status: 200, body: body}} when is_list(body) ->
        {:ok, Enum.map(body, &atomize_keys/1)}

      {:ok, %{status: status, body: body}} ->
        {:error, {:unexpected_status, status, body}}

      {:error, reason} ->
        {:error, {:http_error, reason}}
    end
  end

  @impl true
  def get_csr(id) do
    case auth_get("/api/v1/csr/#{id}") do
      {:ok, %{status: 200, body: body}} ->
        {:ok, atomize_keys(body)}

      {:ok, %{status: 404}} ->
        {:error, :not_found}

      {:ok, %{status: status, body: body}} ->
        {:error, {:unexpected_status, status, body}}

      {:error, reason} ->
        {:error, {:http_error, reason}}
    end
  end

  @impl true
  def approve_csr(id, meta) do
    payload = stringify_keys(meta)

    case auth_post("/api/v1/csr/#{id}/approve", payload) do
      {:ok, %{status: 200, body: body}} ->
        {:ok, atomize_keys(body)}

      {:ok, %{status: 404}} ->
        {:error, :not_found}

      {:ok, %{status: status, body: body}} ->
        {:error, {:unexpected_status, status, body}}

      {:error, reason} ->
        {:error, {:http_error, reason}}
    end
  end

  @impl true
  def reject_csr(id, reason, meta) do
    payload =
      meta
      |> stringify_keys()
      |> Map.put("reason", reason)

    case auth_post("/api/v1/csr/#{id}/reject", payload) do
      {:ok, %{status: 200, body: body}} ->
        {:ok, atomize_keys(body)}

      {:ok, %{status: 404}} ->
        {:error, :not_found}

      {:ok, %{status: status, body: body}} ->
        {:error, {:unexpected_status, status, body}}

      {:error, reason_err} ->
        {:error, {:http_error, reason_err}}
    end
  end

  # --- Cert profiles ---

  @impl true
  def list_cert_profiles do
    case auth_get("/api/v1/cert-profiles") do
      {:ok, %{status: 200, body: body}} when is_list(body) ->
        {:ok, Enum.map(body, &atomize_keys/1)}

      {:ok, %{status: status, body: body}} ->
        {:error, {:unexpected_status, status, body}}

      {:error, reason} ->
        {:error, {:http_error, reason}}
    end
  end

  @impl true
  def create_cert_profile(attrs) do
    payload = stringify_keys(attrs)

    case auth_post("/api/v1/cert-profiles", payload) do
      {:ok, %{status: status, body: body}} when status in [200, 201] ->
        {:ok, atomize_keys(body)}

      {:ok, %{status: status, body: body}} ->
        {:error, {:unexpected_status, status, body}}

      {:error, reason} ->
        {:error, {:http_error, reason}}
    end
  end

  @impl true
  def update_cert_profile(id, attrs) do
    payload = stringify_keys(attrs)

    case auth_put("/api/v1/cert-profiles/#{id}", payload) do
      {:ok, %{status: 200, body: body}} ->
        {:ok, atomize_keys(body)}

      {:ok, %{status: 404}} ->
        {:error, :not_found}

      {:ok, %{status: status, body: body}} ->
        {:error, {:unexpected_status, status, body}}

      {:error, reason} ->
        {:error, {:http_error, reason}}
    end
  end

  @impl true
  def delete_cert_profile(id) do
    case auth_delete("/api/v1/cert-profiles/#{id}") do
      {:ok, %{status: 200, body: body}} ->
        {:ok, atomize_keys(body)}

      {:ok, %{status: 404}} ->
        {:error, :not_found}

      {:ok, %{status: status, body: body}} ->
        {:error, {:unexpected_status, status, body}}

      {:error, reason} ->
        {:error, {:http_error, reason}}
    end
  end

  # --- Service configs ---

  @impl true
  def list_service_configs do
    case auth_get("/api/v1/service-configs") do
      {:ok, %{status: 200, body: body}} when is_list(body) ->
        {:ok, Enum.map(body, &atomize_keys/1)}

      {:ok, %{status: status, body: body}} ->
        {:error, {:unexpected_status, status, body}}

      {:error, reason} ->
        {:error, {:http_error, reason}}
    end
  end

  @impl true
  def configure_service(attrs) do
    payload = stringify_keys(attrs)

    case auth_post("/api/v1/service-configs", payload) do
      {:ok, %{status: status, body: body}} when status in [200, 201] ->
        {:ok, atomize_keys(body)}

      {:ok, %{status: status, body: body}} ->
        {:error, {:unexpected_status, status, body}}

      {:error, reason} ->
        {:error, {:http_error, reason}}
    end
  end

  # --- RA instances ---

  @impl true
  def list_ra_instances do
    case auth_get("/api/v1/ra-instances") do
      {:ok, %{status: 200, body: body}} when is_list(body) ->
        {:ok, Enum.map(body, &atomize_keys/1)}

      {:ok, %{status: status, body: body}} ->
        {:error, {:unexpected_status, status, body}}

      {:error, reason} ->
        {:error, {:http_error, reason}}
    end
  end

  @impl true
  def create_ra_instance(attrs) do
    payload = stringify_keys(attrs)

    case auth_post("/api/v1/ra-instances", payload) do
      {:ok, %{status: status, body: body}} when status in [200, 201] ->
        {:ok, atomize_keys(body)}

      {:ok, %{status: status, body: body}} ->
        {:error, {:unexpected_status, status, body}}

      {:error, reason} ->
        {:error, {:http_error, reason}}
    end
  end

  @impl true
  def available_issuer_keys do
    case auth_get("/api/v1/available-issuer-keys") do
      {:ok, %{status: 200, body: body}} when is_list(body) ->
        {:ok, Enum.map(body, &atomize_keys/1)}

      {:ok, %{status: status, body: body}} ->
        {:error, {:unexpected_status, status, body}}

      {:error, reason} ->
        {:error, {:http_error, reason}}
    end
  end

  # --- API keys ---

  @impl true
  def list_api_keys(filters) do
    params =
      filters
      |> Enum.map(fn {k, v} -> {to_string(k), v} end)

    case auth_get("/api/v1/api-keys", params: params) do
      {:ok, %{status: 200, body: body}} when is_list(body) ->
        {:ok, Enum.map(body, &atomize_keys/1)}

      {:ok, %{status: status, body: body}} ->
        {:error, {:unexpected_status, status, body}}

      {:error, reason} ->
        {:error, {:http_error, reason}}
    end
  end

  @impl true
  def create_api_key(attrs) do
    payload = stringify_keys(attrs)

    case auth_post("/api/v1/api-keys", payload) do
      {:ok, %{status: status, body: body}} when status in [200, 201] ->
        {:ok, atomize_keys(body)}

      {:ok, %{status: status, body: body}} ->
        {:error, {:unexpected_status, status, body}}

      {:error, reason} ->
        {:error, {:http_error, reason}}
    end
  end

  @impl true
  def revoke_api_key(id) do
    case auth_post("/api/v1/api-keys/#{id}/revoke", %{}) do
      {:ok, %{status: 200, body: body}} ->
        {:ok, atomize_keys(body)}

      {:ok, %{status: 404}} ->
        {:error, :not_found}

      {:ok, %{status: status, body: body}} ->
        {:error, {:unexpected_status, status, body}}

      {:error, reason} ->
        {:error, {:http_error, reason}}
    end
  end

  # --- Private helpers ---

  defp base_url do
    Application.get_env(:pki_ra_portal, :ra_engine_url) ||
      raise "Missing :ra_engine_url configuration for :pki_ra_portal"
  end

  defp api_secret do
    Application.get_env(:pki_ra_portal, :internal_api_secret) ||
      raise "Missing :internal_api_secret configuration for :pki_ra_portal"
  end

  defp get(path, opts \\ []) do
    url = base_url() <> path
    params = Keyword.get(opts, :params, [])

    Req.get(url, params: params, decode_body: :json)
  rescue
    e -> {:error, Exception.message(e)}
  end

  defp post(path, body) do
    url = base_url() <> path

    Req.post(url, json: body, decode_body: :json)
  rescue
    e -> {:error, Exception.message(e)}
  end

  defp auth_get(path, opts \\ []) do
    url = base_url() <> path
    params = Keyword.get(opts, :params, [])

    Req.get(url,
      params: params,
      headers: [{"authorization", "Bearer #{api_secret()}"}],
      decode_body: :json
    )
  rescue
    e -> {:error, Exception.message(e)}
  end

  defp auth_post(path, body) do
    url = base_url() <> path

    Req.post(url,
      json: body,
      headers: [{"authorization", "Bearer #{api_secret()}"}],
      decode_body: :json
    )
  rescue
    e -> {:error, Exception.message(e)}
  end

  defp auth_put(path, body) do
    url = base_url() <> path

    Req.put(url,
      json: body,
      headers: [{"authorization", "Bearer #{api_secret()}"}],
      decode_body: :json
    )
  rescue
    e -> {:error, Exception.message(e)}
  end

  defp auth_delete(path) do
    url = base_url() <> path

    Req.delete(url,
      headers: [{"authorization", "Bearer #{api_secret()}"}],
      decode_body: :json
    )
  rescue
    e -> {:error, Exception.message(e)}
  end

  defp atomize_keys(map) when is_map(map) do
    Map.new(map, fn
      {k, v} when is_binary(k) -> {safe_to_atom(k), atomize_value(v)}
      {k, v} -> {k, atomize_value(v)}
    end)
  end

  defp atomize_keys(other), do: other

  defp atomize_value(v) when is_map(v), do: atomize_keys(v)
  defp atomize_value(v) when is_list(v), do: Enum.map(v, &atomize_value/1)
  defp atomize_value(v), do: v

  defp safe_to_atom(key) when is_binary(key) do
    String.to_existing_atom(key)
  rescue
    ArgumentError -> key
  end

  defp stringify_keys(map) when is_map(map) do
    Map.new(map, fn
      {k, v} when is_atom(k) -> {Atom.to_string(k), v}
      {k, v} -> {k, v}
    end)
  end

  defp stringify_keys(other), do: other

  defp decode_session_value(nil), do: nil
  defp decode_session_value(val) when is_binary(val) do
    case Base.decode64(val) do
      {:ok, bin} -> bin
      :error -> val  # return as-is if not base64
    end
  end
end
