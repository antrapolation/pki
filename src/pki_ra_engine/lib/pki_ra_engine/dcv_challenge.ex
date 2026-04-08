defmodule PkiRaEngine.DcvChallenge do
  @moduledoc """
  Domain Control Validation challenge management.

  Creates, verifies, and tracks DCV challenges for CSR approval.
  Supports HTTP-01 and DNS-01 validation methods.
  """

  require Logger
  import Ecto.Query

  alias PkiRaEngine.TenantRepo
  alias PkiRaEngine.Schema.DcvChallenge
  alias PkiRaEngine.DcvVerifier

  @doc "Create a new DCV challenge for a CSR domain."
  @spec create(String.t(), String.t(), String.t(), String.t(), String.t(), pos_integer()) ::
          {:ok, DcvChallenge.t()} | {:error, term()}
  def create(tenant_id, csr_id, domain, method, initiated_by, timeout_hours \\ 24) do
    repo = TenantRepo.ra_repo(tenant_id)

    token = :crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false)
    token_value = :crypto.hash(:sha256, token <> domain) |> Base.encode16(case: :lower)

    now = DateTime.utc_now() |> DateTime.truncate(:second)
    expires_at = DateTime.add(now, timeout_hours * 3600, :second)

    attrs = %{
      csr_id: csr_id,
      domain: domain,
      method: method,
      token: token,
      token_value: token_value,
      status: "pending",
      initiated_by: initiated_by,
      expires_at: expires_at
    }

    %DcvChallenge{}
    |> DcvChallenge.changeset(attrs)
    |> repo.insert()
  end

  @doc "Run verification check on a challenge and update its status."
  @spec verify(String.t(), String.t()) :: {:ok, DcvChallenge.t()} | {:error, term()}
  def verify(tenant_id, challenge_id) do
    repo = TenantRepo.ra_repo(tenant_id)

    with {:ok, challenge} <- get_challenge(repo, challenge_id),
         :ok <- check_verifiable(challenge) do
      now = DateTime.utc_now() |> DateTime.truncate(:second)

      result =
        case challenge.method do
          "http-01" ->
            DcvVerifier.check_http_01(challenge.domain, challenge.token, challenge.token_value)

          "dns-01" ->
            DcvVerifier.check_dns_01(challenge.domain, challenge.token_value)
        end

      update_attrs =
        case result do
          :ok ->
            Logger.info("dcv_challenge_passed challenge_id=#{challenge_id} domain=#{challenge.domain}")

            %{
              status: "passed",
              verified_at: now,
              last_checked_at: now,
              attempts: challenge.attempts + 1,
              error_details: nil
            }

          {:error, reason} ->
            Logger.info("dcv_challenge_check_failed challenge_id=#{challenge_id} domain=#{challenge.domain} reason=#{reason}")

            %{
              last_checked_at: now,
              attempts: challenge.attempts + 1,
              error_details: reason
            }
        end

      challenge
      |> DcvChallenge.changeset(update_attrs)
      |> repo.update()
    end
  end

  @doc "List all DCV challenges for a CSR."
  @spec get_for_csr(String.t(), String.t()) :: [DcvChallenge.t()]
  def get_for_csr(tenant_id, csr_id) do
    repo = TenantRepo.ra_repo(tenant_id)

    DcvChallenge
    |> where([c], c.csr_id == ^csr_id)
    |> order_by([c], desc: c.inserted_at)
    |> repo.all()
  end

  @doc "Check if DCV has passed for a CSR. Returns :ok or {:error, :dcv_not_passed}."
  @spec check_dcv_passed(String.t(), String.t()) :: :ok | {:error, :dcv_not_passed}
  def check_dcv_passed(tenant_id, csr_id) do
    repo = TenantRepo.ra_repo(tenant_id)
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    passed_count =
      DcvChallenge
      |> where([c], c.csr_id == ^csr_id and c.status == "passed" and c.expires_at > ^now)
      |> repo.aggregate(:count)

    if passed_count > 0 do
      :ok
    else
      {:error, :dcv_not_passed}
    end
  end

  @doc "Sweep expired challenges — set status to 'expired' for overdue pending challenges."
  @spec expire_overdue(String.t()) :: {non_neg_integer(), nil}
  def expire_overdue(tenant_id) do
    repo = TenantRepo.ra_repo(tenant_id)
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    DcvChallenge
    |> where([c], c.status == "pending" and c.expires_at <= ^now)
    |> repo.update_all(set: [status: "expired", updated_at: now])
  end

  @doc "List pending challenges that haven't expired (for polling)."
  @spec list_pending(String.t()) :: [DcvChallenge.t()]
  def list_pending(tenant_id) do
    repo = TenantRepo.ra_repo(tenant_id)
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    DcvChallenge
    |> where([c], c.status == "pending" and c.expires_at > ^now)
    |> repo.all()
  end

  # -- Private --

  defp get_challenge(repo, challenge_id) do
    case repo.get(DcvChallenge, challenge_id) do
      nil -> {:error, :not_found}
      challenge -> {:ok, challenge}
    end
  end

  defp check_verifiable(%DcvChallenge{status: "pending"}), do: :ok

  defp check_verifiable(%DcvChallenge{status: status}),
    do: {:error, {:not_verifiable, status}}
end
