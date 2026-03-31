defmodule PkiCaPortal.CaEngineClient.Http do
  @moduledoc """
  HTTP implementation of the CA engine client.

  Communicates with the CA Engine REST API over HTTP using the Req library.
  Auth endpoints (login, register, needs-setup) are public.
  All other endpoints require a Bearer token (INTERNAL_API_SECRET).
  """

  @behaviour PkiCaPortal.CaEngineClient

  require Logger

  # --- Public auth endpoints (no Bearer token) ---

  @impl true
  def authenticate(username, password, opts \\ []) do
    case post("/api/v1/auth/login", %{username: username, password: password}, opts) do
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
  def authenticate_with_session(username, password, opts \\ []) do
    case post("/api/v1/auth/login", %{username: username, password: password}, opts) do
      {:ok, %{status: 200, body: body}} ->
        user = atomize_keys(Map.drop(body, ["session_key", "session_salt"]))

        session_info = %{
          session_key: decode_session_value(body["session_key"]),
          session_salt: decode_session_value(body["session_salt"])
        }

        {:ok, user, session_info}

      {:ok, %{status: 401}} ->
        {:error, :invalid_credentials}

      {:ok, %{status: status, body: body}} ->
        {:error, {:unexpected_status, status, body}}

      {:error, reason} ->
        {:error, {:http_error, reason}}
    end
  end

  defp decode_session_value(nil), do: nil
  defp decode_session_value(val) when is_binary(val) do
    case Base.decode64(val) do
      {:ok, bin} -> bin
      :error -> val
    end
  end
  defp decode_session_value(val), do: val

  @impl true
  def register_user(ca_instance_id, attrs, opts \\ []) do
    payload =
      attrs
      |> stringify_keys()
      |> Map.put("ca_instance_id", ca_instance_id)

    case post("/api/v1/auth/register", payload, opts) do
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
  def needs_setup?(ca_instance_id, opts \\ []) do
    case get("/api/v1/auth/needs-setup", params: [ca_instance_id: ca_instance_id], tenant_id: opts[:tenant_id]) do
      {:ok, %{status: 200, body: %{"needs_setup" => value}}} ->
        value

      {:ok, _} ->
        true

      {:error, reason} ->
        Logger.error("Failed to check needs_setup: #{inspect(reason)}")
        true
    end
  end

  @impl true
  def get_user_by_username(username, ca_instance_id, opts \\ []) do
    case auth_get("/api/v1/users/by-username/#{URI.encode(username)}", params: [ca_instance_id: ca_instance_id], tenant_id: opts[:tenant_id]) do
      {:ok, %{status: 200, body: body}} ->
        {:ok, atomize_keys(body)}

      {:ok, %{status: status, body: body}} ->
        {:error, {:unexpected_status, status, body}}

      {:error, reason} ->
        {:error, {:http_error, reason}}
    end
  end

  @impl true
  def update_user_profile(user_id, attrs, opts \\ []) do
    case auth_put("/api/v1/users/#{user_id}/profile", attrs, opts) do
      {:ok, %{status: status, body: body}} when status in 200..299 -> {:ok, atomize_keys(body)}
      {:ok, %{status: 404}} -> {:error, :not_found}
      {:ok, %{status: status, body: body}} -> {:error, {:unexpected_status, status, body}}
      {:error, reason} -> {:error, {:http_error, reason}}
    end
  end

  @impl true
  def verify_and_change_password(user_id, current_password, new_password, opts \\ []) do
    payload = %{current_password: current_password, new_password: new_password}
    case auth_put("/api/v1/users/#{user_id}/password/change", payload, opts) do
      {:ok, %{status: status, body: body}} when status in 200..299 -> {:ok, atomize_keys(body)}
      {:ok, %{status: 401}} -> {:error, :invalid_current_password}
      {:ok, %{status: 404}} -> {:error, :not_found}
      {:ok, %{status: status, body: body}} -> {:error, {:unexpected_status, status, body}}
      {:error, reason} -> {:error, {:http_error, reason}}
    end
  end

  @impl true
  def reset_password(user_id, new_password, opts \\ []) do
    case auth_put("/api/v1/users/#{user_id}/password", %{password: new_password, must_change_password: false}, opts) do
      {:ok, %{status: status}} when status in 200..299 -> :ok
      {:ok, %{status: status, body: body}} -> {:error, {:unexpected_status, status, body}}
      {:error, reason} -> {:error, {:http_error, reason}}
    end
  end

  # --- Authenticated endpoints (Bearer token required) ---

  @impl true
  def list_users(ca_instance_id, opts \\ []) do
    case auth_get("/api/v1/users", params: [ca_instance_id: ca_instance_id], tenant_id: opts[:tenant_id]) do
      {:ok, %{status: 200, body: body}} when is_list(body) ->
        {:ok, Enum.map(body, &atomize_keys/1)}

      {:ok, %{status: status, body: body}} ->
        {:error, {:unexpected_status, status, body}}

      {:error, reason} ->
        {:error, {:http_error, reason}}
    end
  end

  @impl true
  def create_user(ca_instance_id, attrs, opts \\ []) do
    payload =
      attrs
      |> stringify_keys()
      |> Map.put("ca_instance_id", ca_instance_id)

    case auth_post("/api/v1/users", payload, opts) do
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
  def create_user_with_admin(ca_instance_id, attrs, admin_context, opts \\ []) do
    payload =
      attrs
      |> stringify_keys()
      |> Map.put("ca_instance_id", ca_instance_id)
      |> Map.put("admin_user_id", admin_context[:user_id] || admin_context["user_id"])
      |> Map.put("admin_password", admin_context[:password] || admin_context["password"])

    case auth_post("/api/v1/users", payload, opts) do
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
  def get_user(id, opts \\ []) do
    case auth_get("/api/v1/users/#{id}", opts) do
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
  def delete_user(id, opts \\ []) do
    case auth_delete("/api/v1/users/#{id}", opts) do
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
  def list_keystores(ca_instance_id, opts \\ []) do
    case auth_get("/api/v1/keystores", params: [ca_instance_id: ca_instance_id], tenant_id: opts[:tenant_id]) do
      {:ok, %{status: 200, body: body}} when is_list(body) ->
        {:ok, Enum.map(body, &atomize_keys/1)}

      {:ok, %{status: status, body: body}} ->
        {:error, {:unexpected_status, status, body}}

      {:error, reason} ->
        {:error, {:http_error, reason}}
    end
  end

  @impl true
  def configure_keystore(ca_instance_id, attrs, opts \\ []) do
    payload =
      attrs
      |> stringify_keys()
      |> Map.put("ca_instance_id", ca_instance_id)

    case auth_post("/api/v1/keystores", payload, opts) do
      {:ok, %{status: status, body: body}} when status in [200, 201] ->
        {:ok, atomize_keys(body)}

      {:ok, %{status: status, body: body}} ->
        {:error, {:unexpected_status, status, body}}

      {:error, reason} ->
        {:error, {:http_error, reason}}
    end
  end

  @impl true
  def list_issuer_keys(ca_instance_id, opts \\ []) do
    case auth_get("/api/v1/issuer-keys", params: [ca_instance_id: ca_instance_id], tenant_id: opts[:tenant_id]) do
      {:ok, %{status: 200, body: body}} when is_list(body) ->
        {:ok, Enum.map(body, &atomize_keys/1)}

      {:ok, %{status: status, body: body}} ->
        {:error, {:unexpected_status, status, body}}

      {:error, reason} ->
        {:error, {:http_error, reason}}
    end
  end

  @impl true
  def get_engine_status(ca_instance_id, opts \\ []) do
    case auth_get("/api/v1/status", params: [ca_instance_id: ca_instance_id], tenant_id: opts[:tenant_id]) do
      {:ok, %{status: 200, body: body}} ->
        status = atomize_keys(body)
        {:ok, Map.put(status, :active_keys, get_in(status, [:issuer_keys, :active]) || 0)}

      {:ok, %{status: status, body: body}} ->
        {:error, {:unexpected_status, status, body}}

      {:error, reason} ->
        {:error, {:http_error, reason}}
    end
  end

  @impl true
  def initiate_ceremony(ca_instance_id, params, opts \\ []) do
    payload =
      params
      |> stringify_keys()
      |> Map.put("ca_instance_id", ca_instance_id)

    case auth_post("/api/v1/ceremonies", payload, opts) do
      {:ok, %{status: status, body: %{"ceremony" => ceremony}}} when status in [200, 201] ->
        {:ok, atomize_keys(ceremony)}

      {:ok, %{status: status, body: body}} when status in [200, 201] ->
        {:ok, atomize_keys(body)}

      {:ok, %{status: status, body: body}} ->
        {:error, {:unexpected_status, status, body}}

      {:error, reason} ->
        {:error, {:http_error, reason}}
    end
  end

  @impl true
  def list_ceremonies(ca_instance_id, opts \\ []) do
    case auth_get("/api/v1/ceremonies", params: [ca_instance_id: ca_instance_id], tenant_id: opts[:tenant_id]) do
      {:ok, %{status: 200, body: body}} when is_list(body) ->
        {:ok, Enum.map(body, &atomize_keys/1)}

      {:ok, %{status: status, body: body}} ->
        {:error, {:unexpected_status, status, body}}

      {:error, reason} ->
        {:error, {:http_error, reason}}
    end
  end

  @impl true
  def list_ca_instances(opts \\ []) do
    case auth_get("/api/v1/ca-instances", opts) do
      {:ok, %{status: 200, body: body}} when is_list(body) ->
        {:ok, Enum.map(body, &atomize_keys/1)}

      {:ok, %{status: status, body: body}} ->
        {:error, {:unexpected_status, status, body}}

      {:error, reason} ->
        {:error, {:http_error, reason}}
    end
  end

  @impl true
  def create_ca_instance(attrs, opts \\ []) do
    payload = stringify_keys(attrs)

    case auth_post("/api/v1/ca-instances", payload, opts) do
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
  def query_audit_log(filters, opts \\ []) do
    params =
      filters
      |> Enum.map(fn {k, v} -> {to_string(k), v} end)

    case auth_get("/api/v1/audit-log", params: params, tenant_id: opts[:tenant_id]) do
      {:ok, %{status: 200, body: body}} when is_list(body) ->
        {:ok, Enum.map(body, &atomize_keys/1)}

      {:ok, %{status: status, body: body}} ->
        {:error, {:unexpected_status, status, body}}

      {:error, reason} ->
        {:error, {:http_error, reason}}
    end
  end

  # --- Private helpers ---

  defp base_url do
    Application.get_env(:pki_ca_portal, :ca_engine_url) ||
      raise "Missing :ca_engine_url configuration for :pki_ca_portal"
  end

  defp api_secret do
    Application.get_env(:pki_ca_portal, :internal_api_secret) ||
      raise "Missing :internal_api_secret configuration for :pki_ca_portal"
  end

  defp get(path, opts) do
    url = base_url() <> path
    params = Keyword.get(opts, :params, [])

    Req.get(url,
      params: params,
      headers: tenant_headers(opts),
      decode_body: :json
    )
  rescue
    e -> {:error, Exception.message(e)}
  end

  defp post(path, body, opts) do
    url = base_url() <> path

    Req.post(url,
      json: body,
      headers: tenant_headers(opts),
      decode_body: :json
    )
  rescue
    e -> {:error, Exception.message(e)}
  end

  defp auth_get(path, opts) do
    url = base_url() <> path
    params = Keyword.get(opts, :params, [])

    Req.get(url,
      params: params,
      headers: auth_headers(opts),
      decode_body: :json
    )
  rescue
    e -> {:error, Exception.message(e)}
  end

  defp auth_post(path, body, opts) do
    url = base_url() <> path

    Req.post(url,
      json: body,
      headers: auth_headers(opts),
      decode_body: :json
    )
  rescue
    e -> {:error, Exception.message(e)}
  end

  defp auth_put(path, body, opts) do
    url = base_url() <> path

    Req.put(url,
      json: body,
      headers: auth_headers(opts),
      decode_body: :json
    )
  rescue
    e -> {:error, Exception.message(e)}
  end

  defp auth_delete(path, opts) do
    url = base_url() <> path

    Req.delete(url,
      headers: auth_headers(opts),
      decode_body: :json
    )
  rescue
    e -> {:error, Exception.message(e)}
  end

  defp auth_headers(opts) do
    [{"authorization", "Bearer #{api_secret()}"} | tenant_headers(opts)]
  end

  defp tenant_headers(opts) do
    case Keyword.get(opts, :tenant_id) do
      nil -> []
      tenant_id -> [{"x-tenant-id", to_string(tenant_id)}]
    end
  end

  defp atomize_keys(map) when is_map(map) do
    Map.new(map, fn
      {k, v} when is_binary(k) -> {safe_to_atom(k), atomize_value(v)}
      {k, v} -> {k, atomize_value(v)}
    end)
  end

  defp atomize_keys(other), do: other

  @impl true
  def update_ca_instance(id, attrs, opts \\ []) do
    url = base_url() <> "/api/v1/ca-instances/#{id}"

    case Req.patch(url,
           json: stringify_keys(attrs),
           headers: auth_headers(opts),
           receive_timeout: 10_000
         ) do
      {:ok, %{status: 200, body: body}} ->
        {:ok, atomize_keys(body)}
      {:ok, %{status: _status, body: body}} ->
        {:error, body}
      {:error, reason} ->
        {:error, {:http_error, reason}}
    end
  end

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

  defp stringify_keys(kw) when is_list(kw) do
    Map.new(kw, fn
      {k, v} when is_atom(k) -> {Atom.to_string(k), v}
      {k, v} -> {k, v}
    end)
  end

  defp stringify_keys(other), do: other
end
