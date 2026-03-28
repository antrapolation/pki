defmodule PkiCaEngine.KeyCeremony.AsyncCeremony do
  @moduledoc """
  Asynchronous key ceremony with time-windowed share collection.

  Custodians join independently within the window. The GenServer:
  - Holds encrypted key material in memory during collection
  - Accepts share submissions from custodians one at a time
  - Auto-completes when all N shares are collected
  - Fails when the window timer expires
  - Zeroes key material on termination
  """
  use GenServer

  alias PkiCaEngine.{Repo, Schema.KeyCeremony, Schema.ThresholdShare}
  alias PkiCaEngine.KeyCeremony.ShareEncryption

  defstruct [
    :ceremony_id,
    :issuer_key_id,
    :private_key_material,
    :threshold_k,
    :threshold_n,
    :shares_collected,
    :timer_ref,
    :custodians_submitted,
    :all_shares
  ]

  # ── Client API ────────────────────────────────────────────────

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts)
  end

  @doc "Submit a custodian's share. Returns {:ok, :share_accepted} or {:ok, :ceremony_complete}."
  def submit_share(pid, custodian_user_id, password) do
    GenServer.call(pid, {:submit_share, custodian_user_id, password})
  end

  @doc "Returns current ceremony status map."
  def get_status(pid) do
    GenServer.call(pid, :get_status)
  end

  # ── Server Callbacks ──────────────────────────────────────────

  @impl true
  def init(opts) do
    ceremony = opts[:ceremony]
    window_ms = opts[:window_ms] || 86_400_000

    # Generate keypair via PkiCrypto - private key held in memory only
    algo_struct = PkiCrypto.Registry.get(ceremony.algorithm)
    {:ok, keypair} = PkiCrypto.Algorithm.generate_keypair(algo_struct)

    # Split the secret ONCE upfront so all shares come from the same polynomial
    {:ok, all_shares} =
      PkiCrypto.Shamir.split(
        keypair.private_key,
        ceremony.threshold_k,
        ceremony.threshold_n
      )

    timer_ref = Process.send_after(self(), :window_expired, window_ms)

    state = %__MODULE__{
      ceremony_id: ceremony.id,
      issuer_key_id: ceremony.issuer_key_id,
      private_key_material: keypair.private_key,
      threshold_k: ceremony.threshold_k,
      threshold_n: ceremony.threshold_n,
      shares_collected: 0,
      timer_ref: timer_ref,
      custodians_submitted: MapSet.new(),
      all_shares: all_shares
    }

    # Update ceremony status to in_progress
    ceremony |> Ecto.Changeset.change(status: "in_progress") |> Repo.update()

    {:ok, state}
  end

  @impl true
  def handle_call({:submit_share, custodian_user_id, password}, _from, state) do
    if MapSet.member?(state.custodians_submitted, custodian_user_id) do
      {:reply, {:error, :already_submitted}, state}
    else
      # Use pre-split share from init (same polynomial for all custodians)
      share = Enum.at(state.all_shares, state.shares_collected)

      # Encrypt and store in DB
      {:ok, encrypted} = ShareEncryption.encrypt_share(share, password)

      changeset =
        %ThresholdShare{}
        |> ThresholdShare.changeset(%{
          issuer_key_id: state.issuer_key_id,
          custodian_user_id: custodian_user_id,
          share_index: state.shares_collected + 1,
          encrypted_share: encrypted,
          min_shares: state.threshold_k,
          total_shares: state.threshold_n
        })

      case Repo.insert(changeset) do
        {:ok, _record} ->
          new_state = %{
            state
            | shares_collected: state.shares_collected + 1,
              custodians_submitted: MapSet.put(state.custodians_submitted, custodian_user_id)
          }

          if new_state.shares_collected == state.threshold_n do
            # All shares collected - cancel timer and wipe key material
            Process.cancel_timer(state.timer_ref)

            {:reply, {:ok, :ceremony_complete},
             %{new_state | private_key_material: nil, timer_ref: nil, all_shares: nil}}
          else
            {:reply, {:ok, :share_accepted}, new_state}
          end

        {:error, _changeset} ->
          {:reply, {:error, :db_error}, state}
      end
    end
  end

  @impl true
  def handle_call(:get_status, _from, state) do
    status = %{
      ceremony_id: state.ceremony_id,
      shares_collected: state.shares_collected,
      threshold_n: state.threshold_n,
      complete: state.shares_collected == state.threshold_n
    }

    {:reply, status, state}
  end

  @impl true
  def handle_info(:window_expired, state) do
    # Mark ceremony as failed in DB
    if ceremony = Repo.get(KeyCeremony, state.ceremony_id) do
      ceremony |> Ecto.Changeset.change(status: "failed") |> Repo.update()
    end

    {:stop, :normal, %{state | private_key_material: nil, timer_ref: nil}}
  end

  @impl true
  def terminate(_reason, state) do
    _wiped = %{state | private_key_material: nil, all_shares: nil}
    :ok
  end
end
