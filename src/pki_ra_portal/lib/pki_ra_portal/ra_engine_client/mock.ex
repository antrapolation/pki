defmodule PkiRaPortal.RaEngineClient.Mock do
  @moduledoc """
  Mock implementation of the RA engine client.

  Uses an Agent for stateful storage so that create/delete/update operations
  affect subsequent list operations. This enables realistic Playwright e2e testing.
  """

  @behaviour PkiRaPortal.RaEngineClient

  # Fixed UUIDv7 constants for deterministic test data
  @user1_id "019577b0-0001-7000-8000-000000000001"
  @user2_id "019577b0-0002-7000-8000-000000000002"
  @user3_id "019577b0-0003-7000-8000-000000000003"
  @csr1_id "019577b0-0010-7000-8000-000000000010"
  @csr2_id "019577b0-0011-7000-8000-000000000011"
  @csr3_id "019577b0-0012-7000-8000-000000000012"
  @csr4_id "019577b0-0013-7000-8000-000000000013"
  @csr5_id "019577b0-0014-7000-8000-000000000014"
  @profile1_id "019577b0-0020-7000-8000-000000000020"
  @profile2_id "019577b0-0021-7000-8000-000000000021"
  @svc1_id "019577b0-0030-7000-8000-000000000030"
  @svc2_id "019577b0-0031-7000-8000-000000000031"
  @svc3_id "019577b0-0032-7000-8000-000000000032"
  @apikey1_id "019577b0-0040-7000-8000-000000000040"
  @apikey2_id "019577b0-0041-7000-8000-000000000041"
  @ra_instance1_id "019577b0-0050-7000-8000-000000000050"
  @ra_instance2_id "019577b0-0051-7000-8000-000000000051"

  # --- Agent helpers ---

  defp initial_state do
    %{
      users: [
        %{
          id: @user1_id,
          username: "raadmin1",
          display_name: "RA Admin One",
          role: "ra_admin",
          status: "active",
          has_credentials: true
        },
        %{
          id: @user2_id,
          username: "raofficer1",
          display_name: "RA Officer One",
          role: "ra_officer",
          status: "active",
          has_credentials: true
        },
        %{
          id: @user3_id,
          username: "auditor1",
          display_name: "Auditor One",
          role: "auditor",
          status: "active",
          has_credentials: false
        }
      ],
      csrs: [
        %{
          id: @csr1_id,
          subject: "CN=example.com,O=Example Corp",
          status: "pending",
          profile_name: "TLS Server",
          submitted_at: ~U[2026-03-15 10:00:00Z],
          requestor: "requester1",
          public_key_algorithm: "RSA-2048",
          extensions: %{san: ["example.com", "www.example.com"]}
        },
        %{
          id: @csr2_id,
          subject: "CN=api.example.com,O=Example Corp",
          status: "approved",
          profile_name: "TLS Server",
          submitted_at: ~U[2026-03-14 08:30:00Z],
          requestor: "requester2",
          public_key_algorithm: "RSA-2048",
          extensions: %{san: ["api.example.com"]}
        },
        %{
          id: @csr3_id,
          subject: "CN=John Doe,O=Example Corp",
          status: "rejected",
          profile_name: "Client Auth",
          submitted_at: ~U[2026-03-13 14:20:00Z],
          requestor: "requester3",
          public_key_algorithm: "RSA-2048",
          extensions: %{}
        },
        %{
          id: @csr4_id,
          subject: "CN=mail.example.com,O=Example Corp",
          status: "pending",
          profile_name: "TLS Server",
          submitted_at: ~U[2026-03-12 11:00:00Z],
          requestor: "requester4",
          public_key_algorithm: "RSA-2048",
          extensions: %{san: ["mail.example.com"]}
        },
        %{
          id: @csr5_id,
          subject: "CN=verified.example.com,O=Example Corp",
          status: "verified",
          profile_name: "TLS Server",
          submitted_at: ~U[2026-03-12 09:00:00Z],
          requestor: "requester5",
          public_key_algorithm: "ML-DSA-65",
          extensions: %{san: ["verified.example.com"]}
        }
      ],
      cert_profiles: [
        %{
          id: @profile1_id,
          name: "TLS Server",
          key_usage: "digitalSignature,keyEncipherment",
          ext_key_usage: "serverAuth",
          digest_algo: "SHA-256",
          validity_days: 365
        },
        %{
          id: @profile2_id,
          name: "Client Auth",
          key_usage: "digitalSignature",
          ext_key_usage: "clientAuth",
          digest_algo: "SHA-256",
          validity_days: 730
        }
      ],
      service_configs: [
        %{
          id: @svc1_id,
          service_type: "OCSP Responder",
          port: 8080,
          url: "http://ocsp.example.com",
          rate_limit: 1000,
          ip_whitelist: "10.0.0.0/8",
          ip_blacklist: "",
          status: "active"
        },
        %{
          id: @svc2_id,
          service_type: "CRL Distribution",
          port: 8081,
          url: "http://crl.example.com",
          rate_limit: 500,
          ip_whitelist: "",
          ip_blacklist: "",
          status: "active"
        },
        %{
          id: @svc3_id,
          service_type: "TSA",
          port: 8082,
          url: "http://tsa.example.com",
          rate_limit: 200,
          ip_whitelist: "",
          ip_blacklist: "",
          status: "active"
        }
      ],
      ra_instances: [
        %{
          id: @ra_instance1_id,
          name: "Production RA",
          status: "active",
          cert_profile_count: 2,
          api_key_count: 1
        },
        %{
          id: @ra_instance2_id,
          name: "Staging RA",
          status: "active",
          cert_profile_count: 1,
          api_key_count: 1
        }
      ],
      available_issuer_keys: [
        %{
          id: "019577b0-0060-7000-8000-000000000060",
          alias: "gov-kaz-128",
          ca_instance_name: "PQC Issuing CA",
          algorithm: "KAZ-Sign-128",
          status: "active"
        },
        %{
          id: "019577b0-0061-7000-8000-000000000061",
          alias: "tls-rsa-2048",
          ca_instance_name: "Classic Issuing CA",
          algorithm: "RSA-2048",
          status: "active"
        },
        %{
          id: "019577b0-0062-7000-8000-000000000062",
          alias: "ml-dsa-65",
          ca_instance_name: "PQC Issuing CA",
          algorithm: "ML-DSA-65",
          status: "active"
        }
      ],
      api_keys: [
        %{
          id: @apikey1_id,
          name: "Production API Key",
          prefix: "ra_prod_",
          created_at: ~U[2026-01-15 10:00:00Z],
          status: "active",
          last_used_at: ~U[2026-03-15 09:00:00Z]
        },
        %{
          id: @apikey2_id,
          name: "Staging API Key",
          prefix: "ra_stg_",
          created_at: ~U[2026-02-01 08:00:00Z],
          status: "revoked",
          last_used_at: ~U[2026-02-28 12:00:00Z]
        }
      ]
    }
  end

  defp ensure_started do
    case Agent.start(fn -> initial_state() end, name: __MODULE__) do
      {:ok, _pid} -> :ok
      {:error, {:already_started, _pid}} -> :ok
    end
  end

  defp get_state(key) do
    ensure_started()
    Agent.get(__MODULE__, &Map.get(&1, key))
  end

  defp update_state(key, fun) do
    ensure_started()
    Agent.update(__MODULE__, &Map.update!(&1, key, fun))
  end

  @doc "Reset mock state to initial values. Use in test setup to avoid cross-test contamination."
  def reset! do
    ensure_started()
    Agent.update(__MODULE__, fn _ -> initial_state() end)
  end

  # --- Behaviour implementation ---

  @impl true
  def list_users(_opts \\ []) do
    {:ok, get_state(:users)}
  end

  @impl true
  def create_user(attrs, opts \\ [])

  def create_user(attrs, opts) when is_list(opts) do
    has_creds = Map.has_key?(attrs, :password) or Map.has_key?(attrs, "password")
    user = attrs
      |> Map.drop([:password, "password"])
      |> Map.merge(%{id: Uniq.UUID.uuid7(), status: "active", has_credentials: has_creds})
    update_state(:users, fn users -> users ++ [user] end)
    {:ok, user}
  end

  def create_user(attrs, admin_context) when is_map(admin_context) do
    create_user(attrs, admin_context, [])
  end

  @impl true
  def create_user(attrs, _admin_context, _opts) do
    has_creds = Map.has_key?(attrs, :password) or Map.has_key?(attrs, "password")
    user = attrs
      |> Map.drop([:password, "password"])
      |> Map.merge(%{id: Uniq.UUID.uuid7(), status: "active", has_credentials: has_creds})
    update_state(:users, fn users -> users ++ [user] end)
    {:ok, user}
  end

  @impl true
  def delete_user(id, _opts \\ []) do
    update_state(:users, fn users -> Enum.reject(users, &(&1.id == id)) end)
    {:ok, %{id: id, status: "suspended"}}
  end

  @impl true
  def list_csrs(filters, _opts \\ []) do
    csrs = get_state(:csrs)

    filtered =
      case Keyword.get(filters, :status) do
        nil -> csrs
        status -> Enum.filter(csrs, &(&1.status == status))
      end

    {:ok, filtered}
  end

  @impl true
  def get_csr(id, _opts \\ []) do
    csrs = get_state(:csrs)

    case Enum.find(csrs, &(&1.id == id)) do
      nil ->
        {:ok,
         %{
           id: id,
           subject: "CN=example.com,O=Example Corp",
           status: "pending",
           profile_name: "TLS Server",
           submitted_at: ~U[2026-03-15 10:00:00Z],
           requestor: "requester1",
           public_key_algorithm: "RSA-2048",
           extensions: %{san: ["example.com", "www.example.com"]}
         }}

      csr ->
        {:ok, csr}
    end
  end

  @impl true
  def approve_csr(id, _meta, _opts \\ []) do
    update_state(:csrs, fn csrs ->
      Enum.map(csrs, fn
        %{id: ^id} = csr -> Map.merge(csr, %{status: "approved", approved_at: DateTime.utc_now()})
        csr -> csr
      end)
    end)

    {:ok, %{id: id, status: "approved", approved_at: DateTime.utc_now()}}
  end

  @impl true
  def reject_csr(id, reason, _meta, _opts \\ []) do
    update_state(:csrs, fn csrs ->
      Enum.map(csrs, fn
        %{id: ^id} = csr ->
          Map.merge(csr, %{status: "rejected", rejection_reason: reason, rejected_at: DateTime.utc_now()})

        csr ->
          csr
      end)
    end)

    {:ok, %{id: id, status: "rejected", rejection_reason: reason, rejected_at: DateTime.utc_now()}}
  end

  @impl true
  def list_cert_profiles(_opts \\ []) do
    {:ok, get_state(:cert_profiles)}
  end

  @impl true
  def create_cert_profile(attrs, _opts \\ []) do
    profile = Map.merge(%{id: Uniq.UUID.uuid7()}, attrs)
    update_state(:cert_profiles, fn profiles -> profiles ++ [profile] end)
    {:ok, profile}
  end

  @impl true
  def update_cert_profile(id, attrs, _opts \\ []) do
    update_state(:cert_profiles, fn profiles ->
      Enum.map(profiles, fn
        %{id: ^id} = profile -> Map.merge(profile, attrs)
        profile -> profile
      end)
    end)

    {:ok, Map.merge(%{id: id}, attrs)}
  end

  @impl true
  def delete_cert_profile(id, _opts \\ []) do
    update_state(:cert_profiles, fn profiles -> Enum.reject(profiles, &(&1.id == id)) end)
    {:ok, %{id: id, deleted: true}}
  end

  @impl true
  def list_service_configs(_opts \\ []) do
    {:ok, get_state(:service_configs)}
  end

  @impl true
  def configure_service(attrs, _opts \\ []) do
    service_type = attrs[:service_type] || attrs["service_type"]

    update_state(:service_configs, fn configs ->
      case Enum.find_index(configs, &(&1.service_type == service_type)) do
        nil ->
          # New service - append
          new_config = Map.merge(%{id: Uniq.UUID.uuid7(), status: "active"}, attrs)
          configs ++ [new_config]

        idx ->
          # Existing service - replace (upsert)
          existing = Enum.at(configs, idx)
          updated = Map.merge(existing, attrs)
          List.replace_at(configs, idx, updated)
      end
    end)

    {:ok, Map.merge(%{id: Uniq.UUID.uuid7(), status: "active"}, attrs)}
  end

  @impl true
  def list_api_keys(_filters, _opts \\ []) do
    {:ok, get_state(:api_keys)}
  end

  @impl true
  def create_api_key(attrs, _opts \\ []) do
    raw_key = "ra_" <> Base.encode64(:crypto.strong_rand_bytes(32), padding: false)

    api_key =
      Map.merge(
        %{
          id: Uniq.UUID.uuid7(),
          raw_key: raw_key,
          prefix: String.slice(raw_key, 0, 8),
          created_at: DateTime.utc_now(),
          status: "active"
        },
        attrs
      )

    update_state(:api_keys, fn keys -> keys ++ [api_key] end)
    {:ok, api_key}
  end

  @impl true
  def revoke_api_key(id, _opts \\ []) do
    update_state(:api_keys, fn keys ->
      Enum.map(keys, fn
        %{id: ^id} = key -> Map.merge(key, %{status: "revoked", revoked_at: DateTime.utc_now()})
        key -> key
      end)
    end)

    {:ok, %{id: id, status: "revoked", revoked_at: DateTime.utc_now()}}
  end

  @impl true
  def list_ra_instances(_opts \\ []) do
    {:ok, get_state(:ra_instances)}
  end

  @impl true
  def create_ra_instance(attrs, _opts \\ []) do
    instance =
      Map.merge(
        %{
          id: Uniq.UUID.uuid7(),
          status: "active",
          cert_profile_count: 0,
          api_key_count: 0
        },
        attrs
      )

    update_state(:ra_instances, fn instances -> instances ++ [instance] end)
    {:ok, instance}
  end

  @impl true
  def available_issuer_keys(_opts \\ []) do
    {:ok, get_state(:available_issuer_keys)}
  end

  @impl true
  def authenticate(username, _password) do
    {:ok, %{id: @user1_id, username: username, role: "ra_admin", display_name: "Mock RA Admin"}}
  end

  @impl true
  def authenticate_with_session(username, _password) do
    user = %{id: @user1_id, username: username, role: "ra_admin", display_name: "Mock RA Admin"}
    session = %{session_key: "mock_session_key_#{System.unique_integer([:positive])}", session_salt: "mock_salt"}
    {:ok, user, session}
  end

  @impl true
  def register_user(attrs) do
    user = Map.merge(%{id: Uniq.UUID.uuid7(), status: "active", role: "ra_admin"}, attrs)
    update_state(:users, fn users -> users ++ [user] end)
    {:ok, user}
  end

  @impl true
  def needs_setup? do
    users = get_state(:users)
    Enum.empty?(users)
  end

  @impl true
  def needs_setup?(_tenant_id) do
    users = get_state(:users)
    Enum.empty?(users)
  end

  @impl true
  def get_user_by_username(_username, _opts \\ []) do
    {:ok, %{id: "mock-user-id", email: "test@example.com", tenant_id: "mock-tenant"}}
  end

  @impl true
  def list_portal_users(_opts \\ []) do
    {:ok, get_state(:users) |> Enum.map(fn u ->
      Map.merge(u, %{role_id: "role-#{u.id}", email: "#{u.username}@example.com"})
    end)}
  end

  @impl true
  def create_portal_user(attrs, _opts \\ []) do
    user = %{
      id: Uniq.UUID.uuid7(),
      username: attrs[:username] || attrs["username"],
      display_name: attrs[:display_name] || attrs["display_name"],
      email: attrs[:email] || attrs["email"],
      role: attrs[:role] || attrs["role"],
      status: "active",
      role_id: Uniq.UUID.uuid7()
    }
    update_state(:users, fn users -> users ++ [user] end)
    {:ok, user}
  end

  @impl true
  def suspend_user_role(role_id, _opts \\ []) do
    update_state(:users, fn users ->
      Enum.map(users, fn u ->
        if Map.get(u, :role_id) == role_id, do: Map.put(u, :status, "suspended"), else: u
      end)
    end)
    {:ok, %{id: role_id, status: "suspended"}}
  end

  @impl true
  def activate_user_role(role_id, _opts \\ []) do
    update_state(:users, fn users ->
      Enum.map(users, fn u ->
        if Map.get(u, :role_id) == role_id, do: Map.put(u, :status, "active"), else: u
      end)
    end)
    {:ok, %{id: role_id, status: "active"}}
  end

  @impl true
  def delete_user_role(role_id, _opts \\ []) do
    update_state(:users, fn users ->
      Enum.reject(users, fn u -> Map.get(u, :role_id) == role_id end)
    end)
    {:ok, %{id: role_id}}
  end

  @impl true
  def reset_user_password(_user_id, _opts \\ []), do: :ok

  @impl true
  def resend_invitation(_user_id, _opts \\ []), do: :ok

  @impl true
  def list_audit_events(_filters, _opts \\ []) do
    {:ok, [
      %{id: "evt-1", timestamp: DateTime.utc_now(), action: "user_created", actor_username: "raadmin1", target_type: "user_profile", details: %{}},
      %{id: "evt-2", timestamp: DateTime.utc_now(), action: "login", actor_username: "raadmin1", target_type: nil, details: %{}}
    ]}
  end

  @impl true
  def update_user_profile(user_id, attrs, _opts \\ []) do
    update_state(:users, fn users ->
      Enum.map(users, fn
        %{id: ^user_id} = user ->
          user
          |> Map.merge(Map.take(attrs, [:display_name, :email, "display_name", "email"]))

        user ->
          user
      end)
    end)

    {:ok, %{id: user_id, display_name: attrs[:display_name] || attrs["display_name"], email: attrs[:email] || attrs["email"]}}
  end

  @impl true
  def verify_and_change_password(_user_id, _current_password, _new_password, _opts \\ []) do
    {:ok, %{}}
  end

  @impl true
  def reset_password(_user_id, _new_password, _opts \\ []), do: :ok
end
