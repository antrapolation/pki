defmodule PkiValidation.CrlPublisher do
  @moduledoc """
  CRL Publisher against Mnesia (RFC 5280 simplified).

  Periodically queries Mnesia for all revoked CertificateStatus records and
  builds a CRL data structure. For signed CRLs, calls
  `PkiCaEngine.KeyActivation.get_active_key/2` directly — no separate
  SigningKeyStore needed since both engines run in the same tenant BEAM.

  PQC signing (KAZ-SIGN, ML-DSA) works transparently through PkiCrypto.
  """

  use GenServer
  require Logger

  alias PkiMnesia.{Repo, Structs.CertificateStatus, Structs.IssuerKey}
  alias PkiCaEngine.{KeyActivation, KeyStore.Dispatcher}

  @default_interval_ms :timer.hours(1)
  @crl_validity_seconds 3600

  # -- Client API --

  def start_link(opts \\ []) do
    name = Keyword.get(opts, :name, __MODULE__)
    GenServer.start_link(__MODULE__, opts, name: name)
  end

  @doc """
  Returns the most recently generated CRL.

  If the last generation failed, returns the last valid CRL with a
  `generation_error: true` warning flag.
  """
  def get_current_crl(server \\ __MODULE__) do
    GenServer.call(server, :get_crl)
  end

  @doc """
  Force regeneration of the CRL (useful for testing or on revocation events).
  Returns `{:ok, crl}` with the freshly generated CRL data.
  """
  def regenerate(server \\ __MODULE__) do
    GenServer.call(server, :regenerate)
  end

  @doc """
  Build and return a signed CRL for the given issuer_key_id.

  Options:
    - `:activation_server` — GenServer name/pid for KeyActivation (default: `KeyActivation`)
  """
  def signed_crl(issuer_key_id, opts \\ []) do
    _activation_server = Keyword.get(opts, :activation_server, KeyActivation)

    with {:ok, crl} <- do_generate_crl(),
         crl_data <- :erlang.term_to_binary(crl),
         {:ok, signature} <- Dispatcher.sign(issuer_key_id, crl_data),
         {:ok, issuer_key} <- Repo.get(IssuerKey, issuer_key_id) do
      {:ok, Map.merge(crl, %{signature: signature, algorithm: issuer_key.algorithm})}
    else
      {:error, :not_active} ->
        # Key not yet activated — return unsigned CRL
        case do_generate_crl() do
          {:ok, crl} -> {:ok, Map.put(crl, :unsigned, true)}
          err -> err
        end

      {:error, :agent_not_connected} ->
        # Remote HSM agent not connected — return unsigned CRL
        case do_generate_crl() do
          {:ok, crl} -> {:ok, Map.put(crl, :unsigned, true)}
          err -> err
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  # -- Server callbacks --

  @impl true
  def init(opts) do
    interval = Keyword.get(opts, :interval, @default_interval_ms)

    state = %{
      crl: empty_crl(),
      interval: interval,
      generation_error: false
    }

    # Generate initial CRL after a short delay to allow Mnesia to be ready
    Process.send_after(self(), :generate, 100)
    schedule_regeneration(interval)

    {:ok, state}
  end

  @impl true
  def handle_call(:get_crl, _from, state) do
    crl =
      if state.generation_error do
        Map.put(state.crl, :generation_error, true)
      else
        state.crl
      end

    {:reply, {:ok, crl}, state}
  end

  @impl true
  def handle_call(:regenerate, _from, state) do
    case do_generate_crl() do
      {:ok, crl} ->
        {:reply, {:ok, crl}, %{state | crl: crl, generation_error: false}}

      {:error, _reason} ->
        crl =
          if state.generation_error do
            Map.put(state.crl, :generation_error, true)
          else
            state.crl
          end

        {:reply, {:ok, crl}, %{state | generation_error: true}}
    end
  end

  @impl true
  def handle_info(:generate, state) do
    case do_generate_crl() do
      {:ok, crl} ->
        {:noreply, %{state | crl: crl, generation_error: false}}

      {:error, _reason} ->
        {:noreply, %{state | generation_error: true}}
    end
  end

  @impl true
  def handle_info(:regenerate, state) do
    new_state =
      case do_generate_crl() do
        {:ok, crl} ->
          %{state | crl: crl, generation_error: false}

        {:error, _reason} ->
          %{state | generation_error: true}
      end

    schedule_regeneration(state.interval)
    {:noreply, new_state}
  end

  # -- Private helpers --

  defp do_generate_crl do
    case Repo.where(CertificateStatus, fn cs -> cs.status == "revoked" end) do
      {:ok, revoked} ->
        revoked_certs =
          revoked
          |> Enum.map(fn cs ->
            %{
              serial_number: cs.serial_number,
              revoked_at: cs.revoked_at,
              reason: cs.revocation_reason
            }
          end)
          |> Enum.sort_by(& &1.revoked_at)

        {:ok, build_crl(revoked_certs)}

      {:error, reason} ->
        Logger.error("CRL generation failed: #{inspect(reason)}")
        {:error, reason}
    end
  end

  defp build_crl(revoked_certs) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    %{
      type: "X509CRL",
      version: 2,
      this_update: DateTime.to_iso8601(now),
      next_update: now |> DateTime.add(@crl_validity_seconds, :second) |> DateTime.to_iso8601(),
      revoked_certificates: revoked_certs,
      total_revoked: length(revoked_certs)
    }
  end

  defp empty_crl, do: build_crl([])

  defp schedule_regeneration(interval) do
    Process.send_after(self(), :regenerate, interval)
  end

end
