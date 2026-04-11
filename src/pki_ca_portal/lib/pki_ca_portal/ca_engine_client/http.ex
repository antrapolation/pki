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

  @impl true
  def list_portal_users(opts \\ []) do
    case auth_get("/api/v1/portal-users", opts) do
      {:ok, %{status: 200, body: body}} when is_list(body) -> {:ok, Enum.map(body, &atomize_keys/1)}
      {:ok, %{status: status, body: body}} -> {:error, {:unexpected_status, status, body}}
      {:error, reason} -> {:error, {:http_error, reason}}
    end
  end

  @impl true
  def create_portal_user(attrs, opts \\ []) do
    case auth_post("/api/v1/portal-users", stringify_keys(attrs), opts) do
      {:ok, %{status: status, body: body}} when status in [200, 201] -> {:ok, atomize_keys(body)}
      {:ok, %{status: 422, body: %{"details" => details}}} -> {:error, {:validation_error, details}}
      {:ok, %{status: status, body: body}} -> {:error, {:unexpected_status, status, body}}
      {:error, reason} -> {:error, {:http_error, reason}}
    end
  end

  @impl true
  def suspend_user_role(role_id, opts \\ []) do
    case auth_put("/api/v1/portal-users/roles/#{role_id}/suspend", %{}, opts) do
      {:ok, %{status: status, body: body}} when status in 200..299 -> {:ok, atomize_keys(body)}
      {:ok, %{status: status, body: body}} -> {:error, {:unexpected_status, status, body}}
      {:error, reason} -> {:error, {:http_error, reason}}
    end
  end

  @impl true
  def activate_user_role(role_id, opts \\ []) do
    case auth_put("/api/v1/portal-users/roles/#{role_id}/activate", %{}, opts) do
      {:ok, %{status: status, body: body}} when status in 200..299 -> {:ok, atomize_keys(body)}
      {:ok, %{status: status, body: body}} -> {:error, {:unexpected_status, status, body}}
      {:error, reason} -> {:error, {:http_error, reason}}
    end
  end

  @impl true
  def delete_user_role(role_id, opts \\ []) do
    case auth_delete("/api/v1/portal-users/roles/#{role_id}", opts) do
      {:ok, %{status: status, body: body}} when status in 200..299 -> {:ok, atomize_keys(body)}
      {:ok, %{status: status, body: body}} -> {:error, {:unexpected_status, status, body}}
      {:error, reason} -> {:error, {:http_error, reason}}
    end
  end

  @impl true
  def reset_user_password(user_id, opts \\ []) do
    case auth_post("/api/v1/portal-users/#{user_id}/reset-password", %{}, opts) do
      {:ok, %{status: status}} when status in 200..299 -> :ok
      {:ok, %{status: status, body: body}} -> {:error, {:unexpected_status, status, body}}
      {:error, reason} -> {:error, {:http_error, reason}}
    end
  end

  @impl true
  def resend_invitation(user_id, opts \\ []) do
    case auth_post("/api/v1/portal-users/#{user_id}/resend-invitation", %{}, opts) do
      {:ok, %{status: status}} when status in 200..299 -> :ok
      {:ok, %{status: status, body: body}} -> {:error, {:unexpected_status, status, body}}
      {:error, reason} -> {:error, {:http_error, reason}}
    end
  end

  @impl true
  def list_audit_events(filters, opts \\ []) do
    params = Enum.map(filters, fn {k, v} -> {to_string(k), v} end)
    case auth_get("/api/v1/platform-audit-events", params: params, tenant_id: opts[:tenant_id]) do
      {:ok, %{status: 200, body: body}} when is_list(body) -> {:ok, Enum.map(body, &atomize_keys/1)}
      {:ok, %{status: status, body: body}} -> {:error, {:unexpected_status, status, body}}
      {:error, reason} -> {:error, {:http_error, reason}}
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
    e ->
      Logger.error("[ca_engine_http] GET #{path} failed: #{Exception.message(e)}")
      {:error, "service unavailable"}
  end

  defp post(path, body, opts) do
    url = base_url() <> path

    Req.post(url,
      json: body,
      headers: tenant_headers(opts),
      decode_body: :json
    )
  rescue
    e ->
      Logger.error("[ca_engine_http] POST #{path} failed: #{Exception.message(e)}")
      {:error, "service unavailable"}
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
    e ->
      Logger.error("[ca_engine_http] auth_get #{path} failed: #{Exception.message(e)}")
      {:error, "service unavailable"}
  end

  defp auth_post(path, body, opts) do
    url = base_url() <> path

    Req.post(url,
      json: body,
      headers: auth_headers(opts),
      decode_body: :json
    )
  rescue
    e ->
      Logger.error("[ca_engine_http] auth_post #{path} failed: #{Exception.message(e)}")
      {:error, "service unavailable"}
  end

  defp auth_put(path, body, opts) do
    url = base_url() <> path

    Req.put(url,
      json: body,
      headers: auth_headers(opts),
      decode_body: :json
    )
  rescue
    e ->
      Logger.error("[ca_engine_http] auth_put #{path} failed: #{Exception.message(e)}")
      {:error, "service unavailable"}
  end

  defp auth_delete(path, opts) do
    url = base_url() <> path

    Req.delete(url,
      headers: auth_headers(opts),
      decode_body: :json
    )
  rescue
    e ->
      Logger.error("[ca_engine_http] auth_delete #{path} failed: #{Exception.message(e)}")
      {:error, "service unavailable"}
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

  @impl true
  def list_active_ceremonies do
    # TODO: implement HTTP endpoint for listing active ceremonies
    {:ok, []}
  end

  @impl true
  def fail_ceremony(_ceremony_id, _reason) do
    # TODO: implement HTTP endpoint for failing a ceremony
    {:ok, %{status: "failed"}}
  end

  @impl true
  def initiate_witnessed_ceremony(_ca_instance_id, _params, _opts \\ []) do
    # TODO: implement HTTP endpoint
    {:ok, %{id: "stub", status: "preparing"}}
  end

  @impl true
  def accept_ceremony_share(_ceremony_id, _user_id, _key_label, _opts \\ []) do
    # TODO: implement HTTP endpoint
    :ok
  end

  @impl true
  def attest_ceremony(_ceremony_id, _auditor_user_id, _phase, _details \\ %{}, _opts \\ []) do
    # TODO: implement HTTP endpoint
    :ok
  end

  @impl true
  def check_ceremony_readiness(_ceremony_id, _opts \\ []) do
    # TODO: implement HTTP endpoint
    {:ok, %{ready: false, missing: []}}
  end

  @impl true
  def execute_ceremony_keygen(_ceremony_id, _custodian_passwords, _opts \\ []) do
    # TODO: implement HTTP endpoint
    {:ok, %{status: "completed"}}
  end

  @impl true
  def list_ceremony_attestations(_ceremony_id, _opts \\ []) do
    # TODO: implement HTTP endpoint
    {:ok, []}
  end

  @impl true
  def list_my_ceremony_shares(_user_id, _opts \\ []) do
    # TODO: implement HTTP endpoint
    {:ok, []}
  end

  @impl true
  def list_my_witness_ceremonies(_auditor_user_id, _opts \\ []) do
    # TODO: implement HTTP endpoint
    {:ok, []}
  end

  @impl true
  def list_certificates(_issuer_key_id, _opts \\ []) do
    # TODO: implement HTTP endpoint
    {:ok, []}
  end

  @impl true
  def list_certificates_by_ca(_ca_instance_id, _opts \\ []) do
    # TODO: implement HTTP endpoint
    {:ok, []}
  end

  @impl true
  def get_certificate(_serial_number, _opts \\ []) do
    # TODO: implement HTTP endpoint
    {:ok, %{}}
  end

  @impl true
  def revoke_certificate(_serial_number, _reason, _opts \\ []) do
    # TODO: implement HTTP endpoint
    {:ok, %{status: "revoked"}}
  end

  @impl true
  def suspend_issuer_key(_id, _opts) do
    # TODO: implement HTTP endpoint
    {:ok, %{status: "suspended"}}
  end

  @impl true
  def reactivate_issuer_key(_id, _opts) do
    # TODO: implement HTTP endpoint
    {:ok, %{status: "active"}}
  end

  @impl true
  def retire_issuer_key(_id, _opts) do
    # TODO: implement HTTP endpoint
    {:ok, %{status: "retired"}}
  end

  @impl true
  def archive_issuer_key(_id, _opts) do
    # TODO: implement HTTP endpoint
    {:ok, %{status: "archived"}}
  end

  # ── HSM Device Management (HTTP stubs) ──────────────────────────

  @impl true
  def list_hsm_devices(_opts \\ []) do
    # TODO: implement HTTP endpoint for HSM device listing
    {:ok, []}
  end

  @impl true
  def register_hsm_device(_params, _opts \\ []) do
    # TODO: implement HTTP endpoint for HSM device registration
    {:error, :not_implemented}
  end

  @impl true
  def probe_hsm_device(_device_id, _opts \\ []) do
    # TODO: implement HTTP endpoint for HSM device probing
    {:error, :not_implemented}
  end

  @impl true
  def deactivate_hsm_device(_device_id, _opts \\ []) do
    # TODO: implement HTTP endpoint for HSM device deactivation
    {:error, :not_implemented}
  end

  # ── Ceremony Management (HTTP stubs) ────────────────────────────

  @impl true
  def get_ceremony(_ceremony_id, _opts \\ []) do
    # TODO: implement HTTP endpoint for ceremony retrieval
    {:error, :not_implemented}
  end

  @impl true
  def generate_ceremony_keypair(_ceremony_id, _opts \\ []) do
    # TODO: implement HTTP endpoint for ceremony keypair generation
    {:error, :not_implemented}
  end

  @impl true
  def distribute_ceremony_shares(_ceremony_id, _private_key, _custodian_passwords, _opts \\ []) do
    # TODO: implement HTTP endpoint for ceremony share distribution
    {:error, :not_implemented}
  end

  @impl true
  def complete_ceremony_root(_ceremony_id, _private_key, _subject_dn, _opts \\ []) do
    # TODO: implement HTTP endpoint for root ceremony completion
    {:error, :not_implemented}
  end

  @impl true
  def complete_ceremony_sub_ca(_ceremony_id, _private_key, _opts \\ []) do
    # TODO: implement HTTP endpoint for sub-CA ceremony completion
    {:error, :not_implemented}
  end

  @impl true
  def cancel_ceremony(_ceremony_id, _opts \\ []) do
    # TODO: implement HTTP endpoint for ceremony cancellation
    {:error, :not_implemented}
  end

  # ── Issuer Key & Signing (HTTP stubs) ───────────────────────────

  @impl true
  def delete_ceremony(_ceremony_id, _opts \\ []) do
    # TODO: implement HTTP endpoint
    {:error, :not_implemented}
  end

  @impl true
  def get_issuer_key(_issuer_key_id, _opts \\ []) do
    # TODO: implement HTTP endpoint
    {:error, :not_implemented}
  end

  @impl true
  def list_threshold_shares(_issuer_key_id, _opts \\ []) do
    # TODO: implement HTTP endpoint
    {:ok, []}
  end

  @impl true
  def reconstruct_key(_issuer_key_id, _custodian_shares, _opts \\ []) do
    # TODO: implement HTTP endpoint
    {:error, :not_implemented}
  end

  @impl true
  def sign_csr(_issuer_key_id, _csr_pem, _subject_dn, _cert_profile, _opts \\ []) do
    # TODO: implement HTTP endpoint
    {:error, :not_implemented}
  end

  @impl true
  def activate_issuer_key(_issuer_key_id, _cert_data, _opts \\ []) do
    # TODO: implement HTTP endpoint
    {:error, :not_implemented}
  end
end
