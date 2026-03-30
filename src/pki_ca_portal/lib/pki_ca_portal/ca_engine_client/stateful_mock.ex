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
  def list_users(_ca_instance_id) do
    {:ok, Agent.get(__MODULE__, & &1.users)}
  end

  @impl true
  def create_user(_ca_instance_id, attrs) do
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
  def create_user(ca_instance_id, attrs, _admin_context) do
    create_user(ca_instance_id, attrs)
  end

  @impl true
  def get_user(id) do
    case Agent.get(__MODULE__, fn state -> Enum.find(state.users, &(&1.id == id)) end) do
      nil -> {:error, :not_found}
      user -> {:ok, user}
    end
  end

  @impl true
  def delete_user(id) do
    Agent.update(__MODULE__, fn state ->
      %{state | users: Enum.reject(state.users, &(&1.id == id))}
    end)

    {:ok, %{id: id, status: "suspended"}}
  end

  @impl true
  def list_keystores(_ca_instance_id) do
    {:ok, Agent.get(__MODULE__, & &1.keystores)}
  end

  @impl true
  def configure_keystore(_ca_instance_id, attrs) do
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
  def list_issuer_keys(_ca_instance_id) do
    {:ok, Agent.get(__MODULE__, & &1.issuer_keys)}
  end

  @impl true
  def get_engine_status(_ca_instance_id) do
    keys_count = Agent.get(__MODULE__, fn state -> length(state.issuer_keys) end)
    {:ok, %{status: "running", active_keys: keys_count, uptime_seconds: 3600}}
  end

  @impl true
  def initiate_ceremony(_ca_instance_id, params) do
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
  def list_ceremonies(_ca_instance_id) do
    {:ok, Agent.get(__MODULE__, & &1.ceremonies)}
  end

  @impl true
  def authenticate(username, _password) do
    {:ok, %{id: Uniq.UUID.uuid7(), username: username, role: "ca_admin", display_name: "Mock Admin"}}
  end

  @impl true
  def authenticate_with_session(username, _password) do
    user = %{id: Uniq.UUID.uuid7(), username: username, role: "ca_admin", display_name: "Mock Admin"}
    session_info = %{session_key: :crypto.strong_rand_bytes(32), session_salt: :crypto.strong_rand_bytes(32)}
    {:ok, user, session_info}
  end

  @impl true
  def register_user(_ca_instance_id, attrs) do
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
  def needs_setup?(_ca_instance_id) do
    users = Agent.get(__MODULE__, & &1.users)
    Enum.empty?(users)
  end

  @impl true
  def list_ca_instances do
    {:ok, Agent.get(__MODULE__, fn state -> Map.get(state, :ca_instances, []) end)}
  end

  @impl true
  def create_ca_instance(attrs) do
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
  def query_audit_log(_filters) do
    {:ok, Agent.get(__MODULE__, & &1.audit_events)}
  end

  @impl true
  def get_user_by_username(_username, _ca_instance_id) do
    {:ok, %{id: "mock-user-id", email: "test@example.com"}}
  end

  # -- Private --

  defp provider_for_type("software"), do: "StrapSoftPrivKeyStoreProvider"
  defp provider_for_type("hsm"), do: "StrapSofthsmPrivKeyStoreProvider"
  defp provider_for_type(_), do: "UnknownProvider"
end
