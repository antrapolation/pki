defmodule PkiCaEngine.Engine do
  @moduledoc """
  Core CA Engine GenServer.

  Main entry point that orchestrates all sub-modules. Uses DynamicSupervisor
  so engines can be started per CA instance.
  """
  use GenServer

  alias PkiCaEngine.CertificateSigning

  # ── Client API ────────────────────────────────────────────────

  @doc """
  Starts an engine for the given CA instance via DynamicSupervisor.
  """
  def start_engine(ca_instance_id) do
    DynamicSupervisor.start_child(
      PkiCaEngine.EngineSupervisor,
      {__MODULE__, ca_instance_id: ca_instance_id}
    )
  end

  @doc """
  Stops the engine for the given CA instance.
  """
  def stop_engine(ca_instance_id) do
    case whereis(ca_instance_id) do
      nil -> {:error, :not_running}
      pid -> DynamicSupervisor.terminate_child(PkiCaEngine.EngineSupervisor, pid)
    end
  end

  def start_link(opts) do
    ca_instance_id = Keyword.fetch!(opts, :ca_instance_id)
    GenServer.start_link(__MODULE__, opts, name: via_tuple(ca_instance_id))
  end

  @doc """
  Signs a certificate through the engine (tenant-aware).

  Options:
    - `:activation_server` - the KeyActivation server to use
  """
  def sign_certificate(tenant_id, ca_instance_id, issuer_key_id, csr_data, cert_profile, opts \\ []) do
    GenServer.call(via_tuple(ca_instance_id), {:sign_certificate_tenant, tenant_id, issuer_key_id, csr_data, cert_profile, opts})
  end

  @doc """
  Returns the status of the engine for the given CA instance.
  """
  def get_status(ca_instance_id) do
    GenServer.call(via_tuple(ca_instance_id), :get_status)
  end

  # ── Registration Helpers ──────────────────────────────────────

  defp via_tuple(ca_instance_id), do: {:global, {__MODULE__, ca_instance_id}}

  defp whereis(ca_instance_id), do: GenServer.whereis(via_tuple(ca_instance_id))

  # ── Server Callbacks ──────────────────────────────────────────

  @impl true
  def init(opts) do
    ca_instance_id = Keyword.fetch!(opts, :ca_instance_id)

    {:ok,
     %{
       ca_instance_id: ca_instance_id,
       started_at: DateTime.utc_now() |> DateTime.truncate(:second)
     }}
  end

  @impl true
  def handle_call({:sign_certificate_tenant, tenant_id, issuer_key_id, csr_data, cert_profile, opts}, _from, state) do
    result = CertificateSigning.sign_certificate(tenant_id, issuer_key_id, csr_data, cert_profile, opts)
    {:reply, result, state}
  end

  @impl true
  def handle_call(:get_status, _from, state) do
    {:reply, {:ok, %{ca_instance_id: state.ca_instance_id, started_at: state.started_at}}, state}
  end
end
