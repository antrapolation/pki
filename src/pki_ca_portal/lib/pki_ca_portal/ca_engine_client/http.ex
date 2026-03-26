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
  defp decode_session_value(val) when is_binary(val), do: Base.decode64!(val)
  defp decode_session_value(val), do: val

  @impl true
  def register_user(ca_instance_id, attrs) do
    payload =
      attrs
      |> stringify_keys()
      |> Map.put("ca_instance_id", ca_instance_id)

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
  def needs_setup?(ca_instance_id) do
    case get("/api/v1/auth/needs-setup", params: [ca_instance_id: ca_instance_id]) do
      {:ok, %{status: 200, body: %{"needs_setup" => value}}} ->
        value

      {:ok, _} ->
        true

      {:error, reason} ->
        Logger.error("Failed to check needs_setup: #{inspect(reason)}")
        true
    end
  end

  # --- Authenticated endpoints (Bearer token required) ---

  @impl true
  def list_users(ca_instance_id) do
    case auth_get("/api/v1/users", params: [ca_instance_id: ca_instance_id]) do
      {:ok, %{status: 200, body: body}} when is_list(body) ->
        {:ok, Enum.map(body, &atomize_keys/1)}

      {:ok, %{status: status, body: body}} ->
        {:error, {:unexpected_status, status, body}}

      {:error, reason} ->
        {:error, {:http_error, reason}}
    end
  end

  @impl true
  def create_user(ca_instance_id, attrs) do
    payload =
      attrs
      |> stringify_keys()
      |> Map.put("ca_instance_id", ca_instance_id)

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
  def get_user(id) do
    case auth_get("/api/v1/users/#{id}") do
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

  @impl true
  def list_keystores(ca_instance_id) do
    case auth_get("/api/v1/keystores", params: [ca_instance_id: ca_instance_id]) do
      {:ok, %{status: 200, body: body}} when is_list(body) ->
        {:ok, Enum.map(body, &atomize_keys/1)}

      {:ok, %{status: status, body: body}} ->
        {:error, {:unexpected_status, status, body}}

      {:error, reason} ->
        {:error, {:http_error, reason}}
    end
  end

  @impl true
  def configure_keystore(ca_instance_id, attrs) do
    payload =
      attrs
      |> stringify_keys()
      |> Map.put("ca_instance_id", ca_instance_id)

    case auth_post("/api/v1/keystores", payload) do
      {:ok, %{status: status, body: body}} when status in [200, 201] ->
        {:ok, atomize_keys(body)}

      {:ok, %{status: status, body: body}} ->
        {:error, {:unexpected_status, status, body}}

      {:error, reason} ->
        {:error, {:http_error, reason}}
    end
  end

  @impl true
  def list_issuer_keys(ca_instance_id) do
    case auth_get("/api/v1/issuer-keys", params: [ca_instance_id: ca_instance_id]) do
      {:ok, %{status: 200, body: body}} when is_list(body) ->
        {:ok, Enum.map(body, &atomize_keys/1)}

      {:ok, %{status: status, body: body}} ->
        {:error, {:unexpected_status, status, body}}

      {:error, reason} ->
        {:error, {:http_error, reason}}
    end
  end

  @impl true
  def get_engine_status(ca_instance_id) do
    case auth_get("/api/v1/status", params: [ca_instance_id: ca_instance_id]) do
      {:ok, %{status: 200, body: body}} ->
        {:ok, atomize_keys(body)}

      {:ok, %{status: status, body: body}} ->
        {:error, {:unexpected_status, status, body}}

      {:error, reason} ->
        {:error, {:http_error, reason}}
    end
  end

  @impl true
  def initiate_ceremony(ca_instance_id, params) do
    payload =
      params
      |> stringify_keys()
      |> Map.put("ca_instance_id", ca_instance_id)

    case auth_post("/api/v1/ceremonies", payload) do
      {:ok, %{status: status, body: body}} when status in [200, 201] ->
        {:ok, atomize_keys(body)}

      {:ok, %{status: status, body: body}} ->
        {:error, {:unexpected_status, status, body}}

      {:error, reason} ->
        {:error, {:http_error, reason}}
    end
  end

  @impl true
  def list_ceremonies(ca_instance_id) do
    case auth_get("/api/v1/ceremonies", params: [ca_instance_id: ca_instance_id]) do
      {:ok, %{status: 200, body: body}} when is_list(body) ->
        {:ok, Enum.map(body, &atomize_keys/1)}

      {:ok, %{status: status, body: body}} ->
        {:error, {:unexpected_status, status, body}}

      {:error, reason} ->
        {:error, {:http_error, reason}}
    end
  end

  @impl true
  def query_audit_log(filters) do
    params =
      filters
      |> Enum.map(fn {k, v} -> {to_string(k), v} end)

    case auth_get("/api/v1/audit-log", params: params) do
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
      {k, v} when is_binary(k) -> {String.to_atom(k), atomize_value(v)}
      {k, v} -> {k, atomize_value(v)}
    end)
  end

  defp atomize_keys(other), do: other

  defp atomize_value(v) when is_map(v), do: atomize_keys(v)
  defp atomize_value(v) when is_list(v), do: Enum.map(v, &atomize_value/1)
  defp atomize_value(v), do: v

  defp stringify_keys(map) when is_map(map) do
    Map.new(map, fn
      {k, v} when is_atom(k) -> {Atom.to_string(k), v}
      {k, v} -> {k, v}
    end)
  end

  defp stringify_keys(other), do: other
end
