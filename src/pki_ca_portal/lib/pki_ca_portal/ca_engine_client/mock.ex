defmodule PkiCaPortal.CaEngineClient.Mock do
  @moduledoc """
  Mock implementation of the CA engine client.

  Returns realistic static data for development and testing,
  allowing the portal to be built independently of the actual CA engine.
  """

  @behaviour PkiCaPortal.CaEngineClient

  @impl true
  def list_users(_ca_instance_id) do
    {:ok,
     [
       %{
         id: 1,
         did: "did:ssdid:admin1",
         display_name: "Admin One",
         role: "ca_admin",
         status: "active"
       },
       %{
         id: 2,
         did: "did:ssdid:keymgr1",
         display_name: "Key Manager One",
         role: "key_manager",
         status: "active"
       }
     ]}
  end

  @impl true
  def create_user(_ca_instance_id, attrs) do
    {:ok, Map.merge(%{id: System.unique_integer([:positive]), status: "active"}, attrs)}
  end

  @impl true
  def get_user(id) do
    {:ok,
     %{
       id: id,
       did: "did:ssdid:user#{id}",
       display_name: "User #{id}",
       role: "ca_admin",
       status: "active"
     }}
  end

  @impl true
  def delete_user(id), do: {:ok, %{id: id, status: "suspended"}}

  @impl true
  def list_keystores(_ca_instance_id) do
    {:ok,
     [
       %{
         id: 1,
         type: "software",
         status: "active",
         provider_name: "StrapSoftPrivKeyStoreProvider"
       },
       %{
         id: 2,
         type: "hsm",
         status: "inactive",
         provider_name: "StrapSofthsmPrivKeyStoreProvider"
       }
     ]}
  end

  @impl true
  def configure_keystore(_ca_instance_id, attrs) do
    {:ok, Map.merge(%{id: System.unique_integer([:positive]), status: "active"}, attrs)}
  end

  @impl true
  def list_issuer_keys(_ca_instance_id) do
    {:ok,
     [
       %{id: 1, key_alias: "root-1", algorithm: "ML-DSA-65", status: "active", is_root: true}
     ]}
  end

  @impl true
  def get_engine_status(_ca_instance_id) do
    {:ok, %{status: "running", active_keys: 1, uptime_seconds: 3600}}
  end

  @impl true
  def initiate_ceremony(_ca_instance_id, params) do
    {:ok,
     %{
       id: System.unique_integer([:positive]),
       status: "initiated",
       algorithm: params[:algorithm]
     }}
  end

  @impl true
  def list_ceremonies(_ca_instance_id) do
    {:ok,
     [
       %{id: 1, ceremony_type: "sync", status: "completed", algorithm: "ML-DSA-65"}
     ]}
  end

  @impl true
  def query_audit_log(_filters) do
    {:ok,
     [
       %{
         event_id: "evt-1",
         action: "login",
         actor_did: "did:ssdid:admin1",
         timestamp: DateTime.utc_now()
       },
       %{
         event_id: "evt-2",
         action: "key_generated",
         actor_did: "did:ssdid:keymgr1",
         timestamp: DateTime.utc_now()
       }
     ]}
  end
end
