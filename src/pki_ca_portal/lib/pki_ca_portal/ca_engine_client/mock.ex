defmodule PkiCaPortal.CaEngineClient.Mock do
  @moduledoc """
  Mock implementation of the CA engine client.

  Uses an Agent for stateful storage so that create/delete/update operations
  affect subsequent list operations. This enables realistic Playwright e2e testing.
  """

  @behaviour PkiCaPortal.CaEngineClient

  # Fixed UUIDv7 constants for deterministic test data
  @user1_id "019577a0-0001-7000-8000-000000000001"
  @user2_id "019577a0-0002-7000-8000-000000000002"
  @ca_root_id "019577a0-0010-7000-8000-000000000010"
  @ca_sub_id "019577a0-0011-7000-8000-000000000011"
  @keystore1_id "019577a0-0003-7000-8000-000000000003"
  @keystore2_id "019577a0-0004-7000-8000-000000000004"
  @ceremony1_id "019577a0-0005-7000-8000-000000000005"
  @issuer_key1_id "019577a0-0006-7000-8000-000000000006"

  # --- Agent helpers ---

  defp initial_state do
    %{
      users: [
        %{
          id: @user1_id,
          username: "admin1",
          display_name: "Admin One",
          role: "ca_admin",
          status: "active",
          credentials: [
            %{credential_type: "signing", algorithm: "ECC-P256", status: "active"},
            %{credential_type: "kem", algorithm: "ECDH-P256", status: "active"}
          ]
        },
        %{
          id: @user2_id,
          username: "keymgr1",
          display_name: "Key Manager One",
          role: "key_manager",
          status: "active",
          credentials: [
            %{credential_type: "signing", algorithm: "ECC-P256", status: "active"}
          ]
        }
      ],
      keystores: [
        %{
          id: @keystore1_id,
          type: "software",
          status: "active",
          provider_name: "StrapSoftPrivKeyStoreProvider"
        },
        %{
          id: @keystore2_id,
          type: "hsm",
          status: "inactive",
          provider_name: "StrapSofthsmPrivKeyStoreProvider"
        }
      ],
      ceremonies: [
        %{id: @ceremony1_id, ceremony_type: "sync", status: "completed", algorithm: "ML-DSA-65"}
      ],
      last_ceremony: nil,
      ca_instances: [
        %{
          id: @ca_root_id,
          name: "Root CA",
          parent_id: nil,
          role: "root",
          status: "active",
          issuer_key_count: 1
        },
        %{
          id: @ca_sub_id,
          name: "Intermediate CA 1",
          parent_id: @ca_root_id,
          role: "intermediate",
          status: "active",
          issuer_key_count: 0
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

  defp put_state(key, value) do
    ensure_started()
    Agent.update(__MODULE__, &Map.put(&1, key, value))
  end

  @doc "Reset mock state to initial values. Use in test setup to avoid cross-test contamination."
  def reset! do
    ensure_started()
    Agent.update(__MODULE__, fn _ -> initial_state() end)
  end

  # --- Behaviour implementation ---

  @impl true
  def list_users(_ca_instance_id, _opts \\ []) do
    {:ok, get_state(:users)}
  end

  @impl true
  def create_user(_ca_instance_id, attrs, _opts \\ []) do
    user = Map.merge(%{id: Uniq.UUID.uuid7(), status: "active"}, attrs)
    update_state(:users, fn users -> users ++ [user] end)
    {:ok, user}
  end

  @impl true
  def create_user_with_admin(_ca_instance_id, attrs, _admin_context, _opts \\ []) do
    user = Map.merge(%{id: Uniq.UUID.uuid7(), status: "active"}, attrs)
    update_state(:users, fn users -> users ++ [user] end)
    {:ok, user}
  end

  @impl true
  def get_user(id, _opts \\ []) do
    users = get_state(:users)

    case Enum.find(users, &(&1.id == id)) do
      nil ->
        {:ok,
         %{
           id: id,
           username: "user-#{id}",
           display_name: "User #{id}",
           role: "ca_admin",
           status: "active"
         }}

      user ->
        {:ok, user}
    end
  end

  @impl true
  def delete_user(id, _opts \\ []) do
    update_state(:users, fn users -> Enum.reject(users, &(&1.id == id)) end)
    {:ok, %{id: id, status: "suspended"}}
  end

  @impl true
  def list_keystores(_ca_instance_id, _opts \\ []) do
    {:ok, get_state(:keystores)}
  end

  @impl true
  def configure_keystore(_ca_instance_id, attrs, _opts \\ []) do
    provider = case attrs[:type] || attrs["type"] do
      "hsm" -> "StrapSofthsmPrivKeyStoreProvider"
      _ -> "StrapSoftPrivKeyStoreProvider"
    end
    keystore = Map.merge(%{id: Uniq.UUID.uuid7(), status: "active", provider_name: provider}, attrs)
    update_state(:keystores, fn keystores -> keystores ++ [keystore] end)
    {:ok, keystore}
  end

  @impl true
  def list_issuer_keys(_ca_instance_id, _opts \\ []) do
    {:ok,
     [
       %{id: @issuer_key1_id, key_alias: "root-1", algorithm: "ML-DSA-65", status: "active", is_root: true}
     ]}
  end

  @impl true
  def get_engine_status(_ca_instance_id, _opts \\ []) do
    {:ok, %{status: "running", active_keys: 1, uptime_seconds: 3600}}
  end

  @impl true
  def initiate_ceremony(_ca_instance_id, params, _opts \\ []) do
    ceremony = %{
      id: Uniq.UUID.uuid7(),
      status: "initiated",
      ceremony_type: params[:ceremony_type] || "sync",
      algorithm: params[:algorithm]
    }

    update_state(:ceremonies, fn ceremonies -> ceremonies ++ [ceremony] end)
    put_state(:last_ceremony, ceremony)
    {:ok, ceremony}
  end

  @impl true
  def list_ceremonies(_ca_instance_id, _opts \\ []) do
    {:ok, get_state(:ceremonies)}
  end

  @impl true
  def authenticate(username, _password, _opts \\ []) do
    {:ok, %{id: @user1_id, username: username, role: "ca_admin", display_name: "Mock Admin"}}
  end

  @impl true
  def authenticate_with_session(username, _password, _opts \\ []) do
    user = %{id: @user1_id, username: username, role: "ca_admin", display_name: "Mock Admin"}
    session_info = %{session_key: :crypto.strong_rand_bytes(32), session_salt: :crypto.strong_rand_bytes(32)}
    {:ok, user, session_info}
  end

  @impl true
  def register_user(_ca_instance_id, attrs, _opts \\ []) do
    user = Map.merge(%{id: Uniq.UUID.uuid7(), status: "active", role: "ca_admin",
      credentials: [
        %{credential_type: "signing", algorithm: "ECC-P256", status: "active"},
        %{credential_type: "kem", algorithm: "ECDH-P256", status: "active"}
      ]}, attrs)
    update_state(:users, fn users -> users ++ [user] end)
    {:ok, user}
  end

  @impl true
  def needs_setup?(_ca_instance_id, _opts \\ []) do
    users = get_state(:users)
    Enum.empty?(users)
  end

  @impl true
  def get_user_by_username(_username, _ca_instance_id, _opts \\ []) do
    {:ok, %{id: "mock-user-id", email: "test@example.com"}}
  end

  @impl true
  def update_ca_instance(id, attrs, _opts \\ []) do
    update_state(:ca_instances, fn instances ->
      Enum.map(instances, fn i ->
        if (i[:id] || i["id"]) == id do
          Map.merge(i, atomize_map(attrs))
        else
          i
        end
      end)
    end)

    {:ok, %{id: id}}
  end

  defp atomize_map(map) do
    Map.new(map, fn
      {k, v} when is_binary(k) -> {String.to_atom(k), v}
      {k, v} -> {k, v}
    end)
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

  @impl true
  def list_ca_instances(_opts \\ []) do
    {:ok, get_state(:ca_instances)}
  end

  @impl true
  def create_ca_instance(attrs, _opts \\ []) do
    role =
      if attrs[:parent_id] || attrs["parent_id"],
        do: "intermediate",
        else: "root"

    instance =
      Map.merge(
        %{id: Uniq.UUID.uuid7(), status: "active", role: role, issuer_key_count: 0},
        attrs
      )

    update_state(:ca_instances, fn instances -> instances ++ [instance] end)
    {:ok, instance}
  end

  @impl true
  def query_audit_log(_filters, _opts \\ []) do
    {:ok,
     [
       %{
         event_id: "evt-1",
         action: "login",
         actor: "admin1",
         timestamp: DateTime.utc_now()
       },
       %{
         event_id: "evt-2",
         action: "key_generated",
         actor: "keymgr1",
         timestamp: DateTime.utc_now()
       }
     ]}
  end
end
