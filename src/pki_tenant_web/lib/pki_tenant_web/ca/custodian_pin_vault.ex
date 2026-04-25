defmodule PkiTenantWeb.Ca.CustodianPinVault do
  @moduledoc """
  Short-lived GenServer holding custodian PINs during a key ceremony.

  LiveView holds only opaque tokens; this vault holds the actual PIN bytes
  in process state. PINs are zeroized immediately after consume/2 returns.
  On real HSM PED hardware (Phase E5+), the host never sees the PIN at all.
  """
  use GenServer

  # ---------------------------------------------------------------------------
  # API
  # ---------------------------------------------------------------------------

  def start_link(opts \\ []), do: GenServer.start_link(__MODULE__, %{}, opts)
  def stop(pid), do: GenServer.stop(pid)

  @doc """
  Store a PIN in the vault. Returns an opaque token the caller can hold
  in place of the raw PIN bytes.
  """
  def store(pid, pin) when is_binary(pin) do
    token = :crypto.strong_rand_bytes(16) |> Base.encode16()
    GenServer.call(pid, {:store, token, pin})
    token
  end

  @doc """
  Consume a PIN by token. Returns `{:ok, pin}` the first time, then
  `{:error, :already_consumed}` on any subsequent call for the same token.
  The PIN is removed from vault state before this call returns.
  """
  def consume(pid, token), do: GenServer.call(pid, {:consume, token})

  # ---------------------------------------------------------------------------
  # GenServer callbacks
  # ---------------------------------------------------------------------------

  @impl true
  def init(state), do: {:ok, state}

  @impl true
  def handle_call({:store, token, pin}, _from, state) do
    {:reply, :ok, Map.put(state, token, pin)}
  end

  def handle_call({:consume, token}, _from, state) do
    case Map.pop(state, token) do
      {nil, state} -> {:reply, {:error, :already_consumed}, state}
      {pin, new_state} -> {:reply, {:ok, pin}, new_state}
    end
  end
end
