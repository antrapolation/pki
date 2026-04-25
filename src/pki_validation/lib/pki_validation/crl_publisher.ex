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

  alias PkiMnesia.{Repo, Structs.CertificateStatus, Structs.IssuerKey, Structs.PreSignedCrl}
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

  Branches on the `crl_strategy` field of the associated `IssuerKey`:

    - `"per_interval"` (default) — requires an active key lease. Returns
      `{:error, :no_active_lease}` if no lease is present.
    - `"pre_signed"` — looks up the nearest `PreSignedCrl` record whose
      window covers the current time. Returns `{:error, :no_valid_pre_signed_crl}`
      if none is found.

  Options:
    - `:activation_server` — GenServer name/pid for KeyActivation (default: `KeyActivation`)
  """
  def signed_crl(issuer_key_id, opts \\ []) do
    activation_server = Keyword.get(opts, :activation_server, KeyActivation)

    case Repo.get(IssuerKey, issuer_key_id) do
      {:ok, nil} ->
        {:error, :issuer_key_not_found}

      {:ok, issuer_key} ->
        strategy = Map.get(issuer_key, :crl_strategy, "per_interval") || "per_interval"
        do_signed_crl(strategy, issuer_key_id, issuer_key, activation_server)

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp do_signed_crl("per_interval", issuer_key_id, issuer_key, activation_server) do
    status = KeyActivation.lease_status(activation_server, issuer_key_id)

    if Map.get(status, :active, false) do
      with {:ok, crl} <- do_generate_crl(),
           crl_data <- :erlang.term_to_binary(crl),
           {:ok, signature} <- Dispatcher.sign(issuer_key_id, crl_data) do
        {:ok, Map.merge(crl, %{signature: signature, algorithm: issuer_key.algorithm})}
      else
        {:error, reason} ->
          {:error, {:signing_failed, reason}}
      end
    else
      {:error, :no_active_lease}
    end
  end

  defp do_signed_crl("pre_signed", issuer_key_id, _issuer_key, _activation_server) do
    now = DateTime.utc_now()

    case Repo.where(PreSignedCrl, fn crl ->
           crl.issuer_key_id == issuer_key_id and
             DateTime.compare(crl.valid_from, now) != :gt and
             DateTime.compare(crl.valid_until, now) == :gt
         end) do
      {:ok, [record | _]} ->
        {:ok, record.crl_der}

      {:ok, []} ->
        {:error, :no_valid_pre_signed_crl}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp do_signed_crl(unknown_strategy, _issuer_key_id, _issuer_key, _activation_server) do
    {:error, {:unknown_crl_strategy, unknown_strategy}}
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
