defmodule PkiCaPortal.CaEngineClient.StatefulMock do
  @moduledoc """
  Stateful mock implementation of the CA engine client.

  Stores data in an Agent process, allowing integration tests to verify
  that user actions (form submits, button clicks) produce the expected
  state changes through the full LiveView -> Client -> State round-trip.

  Unlike the static Mock, this implementation accumulates state --
  a created user will appear in subsequent list_users calls.
  """

  @behaviour PkiCaPortal.CaEngineClient

  use Agent

  def start_link(_opts \\ []) do
    Agent.start_link(&initial_state/0, name: __MODULE__)
  end

  def reset! do
    Agent.update(__MODULE__, fn _state -> initial_state() end)
  end

  defp initial_state do
    %{
      users: [],
      keystores: [],
      ceremonies: [],
      issuer_keys: [
        %{id: Uniq.UUID.uuid7(), key_alias: "root-1", algorithm: "ML-DSA-65", status: "active", is_root: true}
      ],
      audit_events: [],
      id_counter: 100
    }
  end

  defp next_id do
    Uniq.UUID.uuid7()
  end

  # -- Callbacks --

  @impl true
  def list_users(_ca_instance_id, _opts \\ []) do
    {:ok, Agent.get(__MODULE__, & &1.users)}
  end

  @impl true
  def create_user(_ca_instance_id, attrs, _opts \\ []) do
    id = next_id()

    user =
      %{id: id, status: "active"}
      |> Map.merge(attrs)

    Agent.update(__MODULE__, fn state ->
      event = %{
        event_id: "evt-#{System.unique_integer([:positive])}",
        action: "user_created",
        actor: Map.get(attrs, :username, "system"),
        timestamp: DateTime.utc_now()
      }

      %{state | users: state.users ++ [user], audit_events: state.audit_events ++ [event]}
    end)

    {:ok, user}
  end

  @impl true
  def create_user_with_admin(ca_instance_id, attrs, _admin_context, opts \\ []) do
    create_user(ca_instance_id, attrs, opts)
  end

  @impl true
  def get_user(id, _opts \\ []) do
    case Agent.get(__MODULE__, fn state -> Enum.find(state.users, &(&1.id == id)) end) do
      nil -> {:error, :not_found}
      user -> {:ok, user}
    end
  end

  @impl true
  def delete_user(id, _opts \\ []) do
    Agent.update(__MODULE__, fn state ->
      %{state | users: Enum.reject(state.users, &(&1.id == id))}
    end)

    {:ok, %{id: id, status: "suspended"}}
  end

  @impl true
  def list_keystores(_ca_instance_id, _opts \\ []) do
    {:ok, Agent.get(__MODULE__, & &1.keystores)}
  end

  @impl true
  def configure_keystore(_ca_instance_id, attrs, _opts \\ []) do
    id = next_id()

    keystore =
      %{id: id, status: "active", provider_name: provider_for_type(Map.get(attrs, :type, "software"))}
      |> Map.merge(attrs)

    Agent.update(__MODULE__, fn state ->
      event = %{
        event_id: "evt-#{System.unique_integer([:positive])}",
        action: "keystore_configured",
        actor: "system",
        timestamp: DateTime.utc_now()
      }

      %{state | keystores: state.keystores ++ [keystore], audit_events: state.audit_events ++ [event]}
    end)

    {:ok, keystore}
  end

  @impl true
  def list_issuer_keys(_ca_instance_id, _opts \\ []) do
    {:ok, Agent.get(__MODULE__, & &1.issuer_keys)}
  end

  @impl true
  def get_engine_status(_ca_instance_id, _opts \\ []) do
    keys_count = Agent.get(__MODULE__, fn state -> length(state.issuer_keys) end)
    {:ok, %{status: "running", active_keys: keys_count, uptime_seconds: 3600}}
  end

  @impl true
  def initiate_ceremony(_ca_instance_id, params, _opts \\ []) do
    id = next_id()
    algorithm = params[:algorithm] || Keyword.get(params, "algorithm", "ML-DSA-65")

    ceremony = %{
      id: id,
      ceremony_type: "sync",
      status: "initiated",
      algorithm: algorithm
    }

    Agent.update(__MODULE__, fn state ->
      event = %{
        event_id: "evt-#{System.unique_integer([:positive])}",
        action: "ceremony_initiated",
        actor: "system",
        timestamp: DateTime.utc_now()
      }

      %{state | ceremonies: state.ceremonies ++ [ceremony], audit_events: state.audit_events ++ [event]}
    end)

    {:ok, ceremony}
  end

  @impl true
  def list_ceremonies(_ca_instance_id, _opts \\ []) do
    {:ok, Agent.get(__MODULE__, & &1.ceremonies)}
  end

  @impl true
  def authenticate(username, _password, _opts \\ []) do
    {:ok, %{id: Uniq.UUID.uuid7(), username: username, role: "ca_admin", display_name: "Mock Admin"}}
  end

  @impl true
  def authenticate_with_session(username, _password, _opts \\ []) do
    user = %{id: Uniq.UUID.uuid7(), username: username, role: "ca_admin", display_name: "Mock Admin"}
    session_info = %{session_key: :crypto.strong_rand_bytes(32), session_salt: :crypto.strong_rand_bytes(32)}
    {:ok, user, session_info}
  end

  @impl true
  def register_user(_ca_instance_id, attrs, _opts \\ []) do
    id = next_id()
    user = Map.merge(%{id: id, status: "active", role: "ca_admin",
      credentials: [
        %{credential_type: "signing", algorithm: "ECC-P256", status: "active"},
        %{credential_type: "kem", algorithm: "ECDH-P256", status: "active"}
      ]}, attrs)

    Agent.update(__MODULE__, fn state ->
      %{state | users: state.users ++ [user]}
    end)

    {:ok, user}
  end

  @impl true
  def needs_setup?(_ca_instance_id, _opts \\ []) do
    users = Agent.get(__MODULE__, & &1.users)
    Enum.empty?(users)
  end

  @impl true
  def list_ca_instances(_opts \\ []) do
    {:ok, Agent.get(__MODULE__, fn state -> Map.get(state, :ca_instances, []) end)}
  end

  @impl true
  def create_ca_instance(attrs, _opts \\ []) do
    id = next_id()

    role =
      if attrs[:parent_id] || attrs["parent_id"],
        do: "intermediate",
        else: "root"

    instance =
      Map.merge(
        %{id: id, status: "active", role: role, issuer_key_count: 0},
        attrs
      )

    Agent.update(__MODULE__, fn state ->
      instances = Map.get(state, :ca_instances, [])
      Map.put(state, :ca_instances, instances ++ [instance])
    end)

    {:ok, instance}
  end

  @impl true
  def update_ca_instance(id, attrs, _opts \\ []) do
    Agent.update(__MODULE__, fn state ->
      instances = Map.get(state, :ca_instances, [])
      updated = Enum.map(instances, fn i ->
        if (i[:id] || i["id"]) == id, do: Map.merge(i, attrs), else: i
      end)
      Map.put(state, :ca_instances, updated)
    end)

    {:ok, %{id: id}}
  end

  @impl true
  def query_audit_log(_filters, _opts \\ []) do
    {:ok, Agent.get(__MODULE__, & &1.audit_events)}
  end

  @impl true
  def get_user_by_username(_username, _ca_instance_id, _opts \\ []) do
    {:ok, %{id: "mock-user-id", email: "test@example.com"}}
  end

  @impl true
  def update_user_profile(user_id, attrs, _opts \\ []) do
    Agent.update(__MODULE__, fn state ->
      updated_users = Enum.map(state.users, fn
        %{id: ^user_id} = user ->
          Map.merge(user, Map.take(attrs, [:display_name, :email, "display_name", "email"]))
        user -> user
      end)
      %{state | users: updated_users}
    end)

    {:ok, %{id: user_id, display_name: attrs[:display_name] || attrs["display_name"], email: attrs[:email] || attrs["email"]}}
  end

  @impl true
  def verify_and_change_password(_user_id, _current_password, _new_password, _opts \\ []) do
    {:ok, %{}}
  end

  @impl true
  def reset_password(_user_id, _new_password, _opts \\ []), do: :ok

  @impl true
  def list_portal_users(_opts \\ []) do
    {:ok, Agent.get(__MODULE__, & &1.users) |> Enum.map(fn u ->
      Map.merge(u, %{role_id: Map.get(u, :role_id, "role-#{u.id}"), email: Map.get(u, :email, "#{u.id}@example.com")})
    end)}
  end

  @impl true
  def create_portal_user(attrs, _opts \\ []) do
    id = next_id()
    user = %{
      id: id,
      username: attrs[:username] || attrs["username"],
      display_name: attrs[:display_name] || attrs["display_name"],
      email: attrs[:email] || attrs["email"],
      role: attrs[:role] || attrs["role"],
      status: "active",
      role_id: next_id()
    }
    Agent.update(__MODULE__, fn state -> %{state | users: state.users ++ [user]} end)
    {:ok, user}
  end

  @impl true
  def suspend_user_role(role_id, _opts \\ []) do
    Agent.update(__MODULE__, fn state ->
      updated = Enum.map(state.users, fn u ->
        if Map.get(u, :role_id) == role_id, do: Map.put(u, :status, "suspended"), else: u
      end)
      %{state | users: updated}
    end)
    {:ok, %{id: role_id, status: "suspended"}}
  end

  @impl true
  def activate_user_role(role_id, _opts \\ []) do
    Agent.update(__MODULE__, fn state ->
      updated = Enum.map(state.users, fn u ->
        if Map.get(u, :role_id) == role_id, do: Map.put(u, :status, "active"), else: u
      end)
      %{state | users: updated}
    end)
    {:ok, %{id: role_id, status: "active"}}
  end

  @impl true
  def delete_user_role(role_id, _opts \\ []) do
    Agent.update(__MODULE__, fn state ->
      updated = Enum.reject(state.users, fn u -> Map.get(u, :role_id) == role_id end)
      %{state | users: updated}
    end)
    {:ok, %{id: role_id}}
  end

  @impl true
  def reset_user_password(_user_id, _opts \\ []), do: :ok

  @impl true
  def resend_invitation(_user_id, _opts \\ []), do: :ok

  @impl true
  def list_hsm_devices(_opts \\ []), do: {:ok, []}

  @impl true
  def register_hsm_device(_attrs, _opts \\ []), do: {:error, :not_permitted}

  @impl true
  def probe_hsm_device(_id, _opts \\ []), do: {:error, :not_found}

  @impl true
  def deactivate_hsm_device(_id, _opts \\ []), do: {:error, :not_permitted}

  @impl true
  def list_audit_events(_filters, _opts \\ []) do
    {:ok, Agent.get(__MODULE__, & &1.audit_events)}
  end

  @impl true
  def get_ceremony(ceremony_id, _opts \\ []) do
    case Agent.get(__MODULE__, fn s -> Enum.find(s.ceremonies, &(&1.id == ceremony_id)) end) do
      nil -> {:error, :not_found}
      c -> {:ok, c}
    end
  end

  @impl true
  def generate_ceremony_keypair(_algorithm, _opts \\ []) do
    {:ok, %{public_key: :crypto.strong_rand_bytes(32), private_key: :crypto.strong_rand_bytes(64)}}
  end

  @impl true
  def distribute_ceremony_shares(ceremony_id, _private_key, custodian_passwords, _opts \\ []) do
    Agent.update(__MODULE__, fn state ->
      updated = Enum.map(state.ceremonies, fn c ->
        if c.id == ceremony_id, do: Map.put(c, :status, "in_progress"), else: c
      end)
      %{state | ceremonies: updated}
    end)
    {:ok, length(custodian_passwords)}
  end

  @impl true
  def complete_ceremony_root(ceremony_id, _private_key, _subject_dn, _opts \\ []) do
    Agent.update(__MODULE__, fn state ->
      updated = Enum.map(state.ceremonies, fn c ->
        if c.id == ceremony_id, do: Map.put(c, :status, "completed"), else: c
      end)
      %{state | ceremonies: updated}
    end)
    {:ok, %{id: ceremony_id, status: "completed"}}
  end

  @impl true
  def cancel_ceremony(ceremony_id, _opts \\ []) do
    Agent.update(__MODULE__, fn state ->
      updated = Enum.map(state.ceremonies, fn c ->
        if c.id == ceremony_id, do: Map.put(c, :status, "failed"), else: c
      end)
      %{state | ceremonies: updated}
    end)
    {:ok, %{id: ceremony_id, status: "failed"}}
  end

  @impl true
  def delete_ceremony(ceremony_id, _opts \\ []) do
    Agent.update(__MODULE__, fn state ->
      updated = Enum.reject(state.ceremonies, &(&1.id == ceremony_id))
      %{state | ceremonies: updated}
    end)
    :ok
  end

  @impl true
  def get_issuer_key(id, _opts \\ []) do
    case Agent.get(__MODULE__, fn s -> Enum.find(s.issuer_keys, &(&1.id == id)) end) do
      nil -> {:error, :not_found}
      key -> {:ok, key}
    end
  end

  @impl true
  def list_threshold_shares(_issuer_key_id, _opts \\ []), do: {:ok, []}

  @impl true
  def reconstruct_key(_issuer_key_id, _custodian_passwords, _opts \\ []) do
    {:ok, :crypto.strong_rand_bytes(64)}
  end

  @impl true
  def sign_csr(_issuer_key_id, _private_key, _csr_pem, _cert_profile, _opts \\ []) do
    {:ok, %{certificate_der: "mock", certificate_pem: "-----BEGIN CERTIFICATE-----\nMOCK\n-----END CERTIFICATE-----\n", serial: "0001", algorithm: "ECC-P256"}}
  end

  @impl true
  def activate_issuer_key(id, _cert_attrs, _opts \\ []) do
    Agent.update(__MODULE__, fn state ->
      updated = Enum.map(state.issuer_keys, fn k ->
        if k.id == id, do: Map.put(k, :status, "active"), else: k
      end)
      %{state | issuer_keys: updated}
    end)
    {:ok, %{id: id, status: "active"}}
  end

  @impl true
  def complete_ceremony_sub_ca(ceremony_id, _private_key, _opts \\ []) do
    Agent.update(__MODULE__, fn state ->
      updated = Enum.map(state.ceremonies, fn c ->
        if c.id == ceremony_id, do: Map.put(c, :status, "completed"), else: c
      end)
      %{state | ceremonies: updated}
    end)
    {:ok, {%{id: ceremony_id, status: "completed"}, "-----BEGIN CERTIFICATE REQUEST-----\nMOCK\n-----END CERTIFICATE REQUEST-----\n"}}
  end

  # -- Private --

  @impl true
  def list_active_ceremonies do
    ceremonies = Agent.get(__MODULE__, fn state -> state.ceremonies end)

    active =
      Enum.filter(ceremonies, fn c ->
        c[:status] in ["preparing", "generating"]
      end)

    {:ok, active}
  end

  @impl true
  def fail_ceremony(ceremony_id, _reason) do
    Agent.update(__MODULE__, fn state ->
      updated =
        Enum.map(state.ceremonies, fn c ->
          if c.id == ceremony_id, do: Map.put(c, :status, "failed"), else: c
        end)

      %{state | ceremonies: updated}
    end)

    {:ok, %{id: ceremony_id, status: "failed"}}
  end

  @impl true
  def initiate_witnessed_ceremony(_ca_instance_id, _params, _opts \\ []) do
    {:ok, %{id: Uniq.UUID.uuid7(), status: "preparing"}}
  end

  @impl true
  def accept_ceremony_share(_ceremony_id, _user_id, _key_label, _opts \\ []) do
    :ok
  end

  @impl true
  def attest_ceremony(_ceremony_id, _auditor_user_id, _phase, _details \\ %{}, _opts \\ []) do
    :ok
  end

  @impl true
  def check_ceremony_readiness(_ceremony_id, _opts \\ []) do
    {:ok, %{ready: false, missing: []}}
  end

  @impl true
  def execute_ceremony_keygen(_ceremony_id, _custodian_passwords, _opts \\ []) do
    {:ok, %{status: "completed"}}
  end

  @impl true
  def list_ceremony_attestations(_ceremony_id, _opts \\ []) do
    {:ok, []}
  end

  @impl true
  def list_my_ceremony_shares(_user_id, _opts \\ []) do
    {:ok, []}
  end

  @impl true
  def list_my_witness_ceremonies(_auditor_user_id, _opts \\ []) do
    {:ok, []}
  end

  @impl true
  def list_certificates(_issuer_key_id, _opts \\ []), do: {:ok, []}

  @impl true
  def get_certificate(_serial_number, _opts \\ []), do: {:ok, %{}}

  @impl true
  def revoke_certificate(_serial_number, _reason, _opts \\ []), do: {:ok, %{status: "revoked"}}

  @impl true
  def suspend_issuer_key(id, _opts) do
    Agent.update(__MODULE__, fn state ->
      updated = Enum.map(state.issuer_keys, fn k ->
        if k.id == id, do: Map.put(k, :status, "suspended"), else: k
      end)
      %{state | issuer_keys: updated}
    end)
    {:ok, %{id: id, status: "suspended"}}
  end

  @impl true
  def reactivate_issuer_key(id, _opts) do
    Agent.update(__MODULE__, fn state ->
      updated = Enum.map(state.issuer_keys, fn k ->
        if k.id == id, do: Map.put(k, :status, "active"), else: k
      end)
      %{state | issuer_keys: updated}
    end)
    {:ok, %{id: id, status: "active"}}
  end

  @impl true
  def archive_issuer_key(id, _opts) do
    Agent.update(__MODULE__, fn state ->
      updated = Enum.map(state.issuer_keys, fn k ->
        if k.id == id, do: Map.put(k, :status, "archived"), else: k
      end)
      %{state | issuer_keys: updated}
    end)
    {:ok, %{id: id, status: "archived"}}
  end

  defp provider_for_type("software"), do: "StrapSoftPrivKeyStoreProvider"
  defp provider_for_type("hsm"), do: "StrapSofthsmPrivKeyStoreProvider"
  defp provider_for_type(_), do: "UnknownProvider"
end
