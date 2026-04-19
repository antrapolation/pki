defmodule PkiRaEngine.DcvChallenge do
  @moduledoc """
  Domain control validation challenge lifecycle against Mnesia.

  Creates, verifies, and tracks DCV challenges for CSR approval.
  Supports dns and http challenge types.
  """

  alias PkiMnesia.{Repo, Structs.DcvChallenge}

  @doc "Create a new DCV challenge for a CSR domain."
  @spec create_challenge(binary(), String.t(), keyword()) :: {:ok, DcvChallenge.t()} | {:error, term()}
  def create_challenge(csr_request_id, domain, opts \\ []) do
    challenge =
      DcvChallenge.new(%{
        csr_request_id: csr_request_id,
        domain: domain,
        challenge_type: Keyword.get(opts, :challenge_type, "dns")
      })

    Repo.insert(challenge)
  end

  @doc "Verify a challenge by matching the provided token."
  @spec verify_challenge(binary(), String.t()) :: {:ok, DcvChallenge.t()} | {:error, term()}
  def verify_challenge(challenge_id, token) do
    case Repo.get(DcvChallenge, challenge_id) do
      {:ok, nil} ->
        {:error, :not_found}

      {:ok, %{status: "verified"}} ->
        {:error, :already_verified}

      {:ok, challenge} ->
        if challenge.challenge_token == token do
          now = DateTime.utc_now() |> DateTime.truncate(:second)
          Repo.update(challenge, %{status: "verified", verified_at: now})
        else
          {:error, :invalid_token}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Check if DCV has passed for a CSR.
  Returns :ok if all challenges are verified, error otherwise.
  """
  @spec check_dcv_passed(binary()) :: :ok | {:error, :no_dcv_challenge | :dcv_not_complete}
  def check_dcv_passed(csr_request_id) do
    case Repo.where(DcvChallenge, fn c -> c.csr_request_id == csr_request_id end) do
      {:ok, []} ->
        {:error, :no_dcv_challenge}

      {:ok, challenges} ->
        all_verified = Enum.all?(challenges, fn c -> c.status == "verified" end)
        if all_verified, do: :ok, else: {:error, :dcv_not_complete}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc "Get a challenge by ID."
  @spec get_challenge(binary()) :: {:ok, DcvChallenge.t()} | {:error, :not_found | term()}
  def get_challenge(id) do
    case Repo.get(DcvChallenge, id) do
      {:ok, nil} -> {:error, :not_found}
      {:ok, challenge} -> {:ok, challenge}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc "List all DCV challenges for a CSR."
  @spec get_for_csr(binary()) :: {:ok, [DcvChallenge.t()]} | {:error, term()}
  def get_for_csr(csr_request_id) do
    Repo.where(DcvChallenge, fn c -> c.csr_request_id == csr_request_id end)
  end
end
