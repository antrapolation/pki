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
          status: "active"
        },
        %{
          id: @user2_id,
          username: "keymgr1",
          display_name: "Key Manager One",
          role: "key_manager",
          status: "active"
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
      last_ceremony: nil
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
  def list_users(_ca_instance_id) do
    {:ok, get_state(:users)}
  end

  @impl true
  def create_user(_ca_instance_id, attrs) do
    user = Map.merge(%{id: Uniq.UUID.uuid7(), status: "active"}, attrs)
    update_state(:users, fn users -> users ++ [user] end)
    {:ok, user}
  end

  @impl true
  def get_user(id) do
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
  def delete_user(id) do
    update_state(:users, fn users -> Enum.reject(users, &(&1.id == id)) end)
    {:ok, %{id: id, status: "suspended"}}
  end

  @impl true
  def list_keystores(_ca_instance_id) do
    {:ok, get_state(:keystores)}
  end

  @impl true
  def configure_keystore(_ca_instance_id, attrs) do
    provider = case attrs[:type] || attrs["type"] do
      "hsm" -> "StrapSofthsmPrivKeyStoreProvider"
      _ -> "StrapSoftPrivKeyStoreProvider"
    end
    keystore = Map.merge(%{id: Uniq.UUID.uuid7(), status: "active", provider_name: provider}, attrs)
    update_state(:keystores, fn keystores -> keystores ++ [keystore] end)
    {:ok, keystore}
  end

  @impl true
  def list_issuer_keys(_ca_instance_id) do
    {:ok,
     [
       %{id: @issuer_key1_id, key_alias: "root-1", algorithm: "ML-DSA-65", status: "active", is_root: true}
     ]}
  end

  @impl true
  def get_engine_status(_ca_instance_id) do
    {:ok, %{status: "running", active_keys: 1, uptime_seconds: 3600}}
  end

  @impl true
  def initiate_ceremony(_ca_instance_id, params) do
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
  def list_ceremonies(_ca_instance_id) do
    {:ok, get_state(:ceremonies)}
  end

  @impl true
  def authenticate(username, _password) do
    {:ok, %{id: @user1_id, username: username, role: "ca_admin", display_name: "Mock Admin"}}
  end

  @impl true
  def register_user(_ca_instance_id, attrs) do
    user = Map.merge(%{id: Uniq.UUID.uuid7(), status: "active", role: "ca_admin"}, attrs)
    update_state(:users, fn users -> users ++ [user] end)
    {:ok, user}
  end

  @impl true
  def needs_setup?(_ca_instance_id) do
    users = get_state(:users)
    Enum.empty?(users)
  end

  @impl true
  def query_audit_log(_filters) do
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
