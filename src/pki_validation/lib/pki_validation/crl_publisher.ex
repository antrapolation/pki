defmodule PkiValidation.CrlPublisher do
  @moduledoc """
  CRL Publisher (RFC 5280 simplified).

  Periodically generates a Certificate Revocation List containing
  all revoked certificates. The CRL is served via HTTP as JSON
  (real DER encoding deferred to integration phase).
  """

  use GenServer

  require Logger

  alias PkiValidation.Repo
  alias PkiValidation.Schema.CertificateStatus

  import Ecto.Query

  @default_interval_ms :timer.hours(1)
  @crl_validity_seconds 3600

  # Client API

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
  Force regeneration of the CRL (useful for testing).
  """
  def regenerate(server \\ __MODULE__) do
    GenServer.call(server, :regenerate)
  end

  # Server callbacks

  @impl true
  def init(opts) do
    interval = Keyword.get(opts, :interval, @default_interval_ms)

    state = %{
      crl: empty_crl(),
      interval: interval,
      generation_error: false
    }

    # Generate initial CRL after a short delay to allow Repo to start
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

  @doc """
  Generates a CRL data structure from all revoked certificates.
  """
  def generate_crl do
    case do_generate_crl() do
      {:ok, crl} -> crl
      {:error, _reason} -> empty_crl()
    end
  end

  defp do_generate_crl do
    try do
      revoked_certs =
        from(cs in CertificateStatus,
          where: cs.status == "revoked",
          order_by: [asc: cs.revoked_at],
          select: %{
            serial_number: cs.serial_number,
            revoked_at: cs.revoked_at,
            reason: cs.revocation_reason
          }
        )
        |> Repo.all()

      {:ok, build_crl(revoked_certs)}
    rescue
      e ->
        Logger.error("CRL generation failed: #{Exception.message(e)}")
        {:error, Exception.message(e)}
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
