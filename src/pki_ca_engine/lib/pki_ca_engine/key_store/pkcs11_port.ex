defmodule PkiCaEngine.KeyStore.Pkcs11Port do
  @moduledoc """
  GenServer managing an Erlang Port to the PKCS#11 C binary.

  One GenServer per HSM slot. Serializes commands, handles port crashes
  with exponential backoff restart.

  Protocol: 4-byte big-endian length prefix + JSON payload on stdin/stdout.
  When opened with {:packet, 4}, the BEAM handles the length framing automatically.

  Commands:
    {:sign, key_label, data_binary}
    {:get_public_key, key_label}
    :ping

  Usage:
    {:ok, pid} = Pkcs11Port.start_link(
      library_path: "/opt/homebrew/lib/softhsm/libsofthsm2.so",
      slot_id: 0,
      pin: "1234"
    )
    {:ok, signature} = Pkcs11Port.call(pid, {:sign, "my-key", tbs_data})
    {:ok, :pong} = Pkcs11Port.ping(pid)
  """
  use GenServer
  require Logger

  @port_binary_name "pkcs11_port"
  @call_timeout 5_000
  @max_backoff 30_000

  # -- Client API --

  @doc "Start a Pkcs11Port GenServer linked to the calling process."
  def start_link(opts) do
    name = Keyword.get(opts, :name)
    gen_opts = if name, do: [name: name], else: []
    GenServer.start_link(__MODULE__, opts, gen_opts)
  end

  @doc """
  Send a command to the port.

  Commands:
    {:sign, label, data_binary}
    {:get_public_key, label}
    {:generate_key, label, algorithm}  — algorithm: "ECC-P256"|"ECC-P384"|"ECC-P521"|"RSA-2048"|"RSA-4096"

  generate_key returns {:ok, map} where map contains:
    ECC: %{key_type: "ec", public_key: binary, key_id: hex_string}
    RSA: %{key_type: "rsa", modulus: binary, public_exponent: binary, key_id: hex_string}
  """
  def call(server, command) do
    GenServer.call(server, {:command, command}, @call_timeout)
  end

  @doc "Health check — returns {:ok, :pong} or {:error, reason}."
  def ping(server) do
    GenServer.call(server, :ping, @call_timeout)
  end

  @doc "Gracefully stop the GenServer."
  def stop(server) do
    GenServer.stop(server)
  end

  # -- Server Callbacks --

  @impl true
  def init(opts) do
    port_binary = Keyword.get(opts, :port_binary, default_port_binary())
    library_path = Keyword.fetch!(opts, :library_path)
    slot_id = Keyword.fetch!(opts, :slot_id)
    pin = Keyword.fetch!(opts, :pin)

    state = %{
      port_binary: port_binary,
      library_path: library_path,
      slot_id: slot_id,
      pin: pin,
      port: nil,
      backoff: 1_000
    }

    case start_port(state) do
      {:ok, new_state} ->
        case init_hsm(new_state) do
          {:ok, final_state} -> {:ok, final_state}
          {:error, reason} -> {:stop, {:init_hsm_failed, reason}}
        end

      {:error, reason} ->
        {:stop, {:port_start_failed, reason}}
    end
  end

  @impl true
  def handle_call(:ping, _from, state) do
    case send_command(state.port, %{cmd: "ping"}) do
      {:ok, %{"ok" => true}} -> {:reply, {:ok, :pong}, state}
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:command, {:sign, label, data}}, _from, state) do
    data_b64 = Base.encode64(data)

    result =
      case send_command(state.port, %{cmd: "sign", label: label, data: data_b64}) do
        {:ok, %{"ok" => true, "signature" => sig_b64}} ->
          case Base.decode64(sig_b64) do
            {:ok, sig} -> {:ok, sig}
            :error -> {:error, :invalid_signature_encoding}
          end

        {:ok, %{"error" => err}} ->
          {:error, err}

        {:error, reason} ->
          {:error, reason}
      end

    {:reply, result, state}
  end

  @impl true
  def handle_call({:command, {:get_public_key, label}}, _from, state) do
    result =
      case send_command(state.port, %{cmd: "get_public_key", label: label}) do
        {:ok, %{"ok" => true, "public_key" => pk_b64}} ->
          case Base.decode64(pk_b64) do
            {:ok, pk} -> {:ok, pk}
            :error -> {:error, :invalid_key_encoding}
          end

        {:ok, %{"error" => err}} ->
          {:error, err}

        {:error, reason} ->
          {:error, reason}
      end

    {:reply, result, state}
  end

  @impl true
  def handle_call({:command, {:generate_key, label, algorithm}}, _from, state) do
    result =
      case send_command(state.port, %{cmd: "generate_key", label: label, algorithm: algorithm}) do
        {:ok, %{"ok" => true, "key_type" => "ec", "public_key" => pk_b64, "key_id" => key_id}} ->
          case Base.decode64(pk_b64) do
            {:ok, pk} -> {:ok, %{key_type: "ec", public_key: pk, key_id: key_id}}
            :error -> {:error, :invalid_key_encoding}
          end

        {:ok, %{"ok" => true, "key_type" => "rsa", "modulus" => mod_b64,
                "public_exponent" => exp_b64, "key_id" => key_id}} ->
          with {:ok, modulus} <- Base.decode64(mod_b64),
               {:ok, exponent} <- Base.decode64(exp_b64) do
            {:ok, %{key_type: "rsa", modulus: modulus, public_exponent: exponent, key_id: key_id}}
          else
            :error -> {:error, :invalid_key_encoding}
          end

        {:ok, %{"error" => err}} ->
          {:error, err}

        {:error, reason} ->
          {:error, reason}
      end

    {:reply, result, state}
  end

  @impl true
  def handle_info({port, {:exit_status, status}}, %{port: port} = state) do
    Logger.warning("PKCS#11 port exited with status #{status}, restarting in #{state.backoff}ms")
    Process.send_after(self(), :restart_port, state.backoff)
    new_backoff = min(state.backoff * 2, @max_backoff)
    {:noreply, %{state | port: nil, backoff: new_backoff}}
  end

  @impl true
  def handle_info(:restart_port, state) do
    case start_port(state) do
      {:ok, new_state} ->
        case init_hsm(new_state) do
          {:ok, final_state} ->
            Logger.info("PKCS#11 port restarted successfully")
            {:noreply, %{final_state | backoff: 1_000}}

          {:error, reason} ->
            Logger.error("HSM re-init failed: #{inspect(reason)}, retrying in #{state.backoff}ms")
            Process.send_after(self(), :restart_port, state.backoff)
            {:noreply, state}
        end

      {:error, _reason} ->
        Process.send_after(self(), :restart_port, state.backoff)
        {:noreply, state}
    end
  end

  @impl true
  def handle_info({_port, {:data, _data}}, state) do
    # Unexpected async data from port — ignore (responses are received synchronously in send_command)
    {:noreply, state}
  end

  @impl true
  def terminate(_reason, %{port: port} = _state) when not is_nil(port) do
    try do
      send_command(port, %{cmd: "shutdown"})
    catch
      _, _ -> :ok
    end

    :ok
  end

  def terminate(_reason, _state), do: :ok

  # -- Private --

  defp default_port_binary do
    Path.join(:code.priv_dir(:pki_ca_engine), @port_binary_name)
  end

  defp start_port(state) do
    if File.exists?(state.port_binary) do
      port =
        Port.open({:spawn_executable, state.port_binary}, [
          :binary,
          :exit_status,
          {:packet, 4}
        ])

      {:ok, %{state | port: port}}
    else
      {:error, :port_binary_not_found}
    end
  end

  defp init_hsm(state) do
    cmd = %{
      cmd: "init",
      library: state.library_path,
      slot: state.slot_id,
      pin: state.pin
    }

    case send_command(state.port, cmd) do
      {:ok, %{"ok" => true}} -> {:ok, state}
      {:ok, %{"error" => err}} -> {:error, err}
      {:error, reason} -> {:error, reason}
    end
  end

  @impl true
  def format_status(status) do
    Map.update(status, :state, status[:state], fn state ->
      %{state | pin: :redacted}
    end)
  end

  defp send_command(nil, _cmd), do: {:error, :port_not_running}

  defp send_command(port, cmd) do
    req_id = System.unique_integer([:positive])
    json = Jason.encode!(Map.put(cmd, :id, req_id))
    Port.command(port, json)
    await_response(port, req_id, @call_timeout)
  end

  defp await_response(port, req_id, timeout) do
    receive do
      {^port, {:data, data}} ->
        case Jason.decode(data) do
          {:ok, %{"id" => ^req_id} = parsed} ->
            {:ok, parsed}

          {:ok, _stale} ->
            await_response(port, req_id, timeout)

          {:error, _} ->
            {:error, :invalid_json_response}
        end
    after
      timeout -> {:error, :timeout}
    end
  end
end
