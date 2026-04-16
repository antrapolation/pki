defmodule PkiRaEngine.CsrValidation do
  @moduledoc """
  CSR Validation against Mnesia.

  Status state machine:
    pending -> verified  (auto-validation pass)
    pending -> rejected  (auto-validation fail)
    verified -> approved (officer)
    verified -> rejected (officer)
    approved -> issued   (after CA signs)
  """

  require Logger

  alias PkiMnesia.{Repo, Structs.CsrRequest}
  alias PkiRaEngine.CertProfileConfig

  # Transitions allowed via explicit API calls (approve, reject, mark_issued)
  @api_transitions %{
    {"verified", "approved"} => true,
    {"verified", "rejected"} => true,
    {"approved", "issued"} => true
  }

  # Additional transitions only allowed internally (auto-validation)
  @auto_transitions %{
    {"pending", "verified"} => true,
    {"pending", "rejected"} => true
  }

  # ── Public API ──────────────────────────────────────────────────────

  @doc "Submit a CSR. Accepts CSR PEM string, cert_profile_id, and optional keyword opts."
  @spec submit_csr(String.t(), String.t(), keyword()) :: {:ok, CsrRequest.t()} | {:error, term()}
  def submit_csr(csr_pem, cert_profile_id, opts \\ []) do
    submitted_by_key_id = Keyword.get(opts, :submitted_by_key_id)
    subject_dn = extract_subject_dn(csr_pem)

    csr = CsrRequest.new(%{
      csr_pem: csr_pem,
      cert_profile_id: cert_profile_id,
      subject_dn: subject_dn,
      status: "pending",
      submitted_by_key_id: submitted_by_key_id
    })

    Repo.insert(csr)
  end

  @doc "Auto-validate a pending CSR. Basic structural checks."
  @spec validate_csr(String.t()) :: {:ok, CsrRequest.t()} | {:error, term()}
  def validate_csr(csr_id) do
    with {:ok, csr} <- get_csr(csr_id),
         :ok <- check_auto_transition(csr.status, "verified") do
      case run_validations(csr) do
        :ok ->
          transition(csr, "verified", %{})

        {:error, _reason} ->
          transition(csr, "rejected", %{})
      end
    end
  end

  @doc "RA officer approves a verified CSR."
  @spec approve_csr(String.t(), String.t()) :: {:ok, CsrRequest.t()} | {:error, term()}
  def approve_csr(csr_id, reviewer_user_id) do
    with {:ok, csr} <- get_csr(csr_id),
         :ok <- check_transition(csr.status, "approved") do
      now = DateTime.utc_now() |> DateTime.truncate(:second)

      case transition(csr, "approved", %{reviewed_by: reviewer_user_id, reviewed_at: now}) do
        {:ok, approved_csr} ->
          # Auto-forward to CA for signing (async)
          Task.start(fn -> forward_to_ca(csr_id) end)
          {:ok, approved_csr}

        error ->
          error
      end
    end
  end

  @doc "RA officer rejects a verified CSR with reason."
  @spec reject_csr(String.t(), String.t(), String.t()) :: {:ok, CsrRequest.t()} | {:error, term()}
  def reject_csr(csr_id, reviewer_user_id, reason) do
    reason = if is_binary(reason), do: String.slice(reason, 0, 1000), else: "No reason provided"

    with {:ok, csr} <- get_csr(csr_id),
         :ok <- check_transition(csr.status, "rejected") do
      now = DateTime.utc_now() |> DateTime.truncate(:second)
      transition(csr, "rejected", %{reviewed_by: reviewer_user_id, reviewed_at: now, rejection_reason: reason})
    end
  end

  @doc "Forward an approved CSR to the CA engine for signing."
  @spec forward_to_ca(String.t()) :: {:ok, CsrRequest.t()} | {:error, term()}
  def forward_to_ca(csr_id) do
    with {:ok, csr} <- get_csr(csr_id),
         :ok <- check_transition(csr.status, "issued"),
         {:ok, profile} <- CertProfileConfig.get_profile(csr.cert_profile_id) do

      validity_days = profile.validity_days || 365

      cert_profile_map = %{
        id: csr.cert_profile_id,
        issuer_key_id: profile.issuer_key_id,
        subject_dn: csr.subject_dn,
        validity_days: validity_days
      }

      case PkiCaEngine.CertificateSigning.sign_certificate(
             profile.issuer_key_id, csr.csr_pem, cert_profile_map
           ) do
        {:ok, cert} -> mark_issued(csr_id, cert.serial_number)
        {:error, reason} -> {:error, reason}
      end
    end
  end

  @doc "Mark an approved CSR as issued with the certificate serial."
  @spec mark_issued(String.t(), String.t()) :: {:ok, CsrRequest.t()} | {:error, term()}
  def mark_issued(csr_id, cert_serial) do
    with {:ok, csr} <- get_csr(csr_id),
         :ok <- check_transition(csr.status, "issued") do
      transition(csr, "issued", %{issued_cert_serial: cert_serial})
    end
  end

  @doc "Get a CSR by ID."
  @spec get_csr(String.t()) :: {:ok, CsrRequest.t()} | {:error, :not_found}
  def get_csr(id) do
    case Repo.get(CsrRequest, id) do
      {:ok, nil} -> {:error, :not_found}
      {:ok, csr} -> {:ok, csr}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc "List CSRs with optional filters (:status, :cert_profile_id)."
  @spec list_csrs(keyword()) :: {:ok, [CsrRequest.t()]} | {:error, term()}
  def list_csrs(filters \\ []) do
    status_filter = Keyword.get(filters, :status)
    profile_filter = Keyword.get(filters, :cert_profile_id)

    Repo.where(CsrRequest, fn csr ->
      (status_filter == nil or csr.status == status_filter) and
        (profile_filter == nil or csr.cert_profile_id == profile_filter)
    end)
  end

  # ── Private ─────────────────────────────────────────────────────────

  defp transition(csr, new_status, extra_attrs) do
    changes =
      Map.merge(extra_attrs, %{
        status: new_status,
        updated_at: DateTime.utc_now() |> DateTime.truncate(:second)
      })

    Repo.update(csr, changes)
  end

  defp check_transition(from, to) do
    if Map.get(@api_transitions, {from, to}), do: :ok, else: {:error, {:invalid_transition, from, to}}
  end

  defp check_auto_transition(from, to) do
    if Map.get(@auto_transitions, {from, to}) || Map.get(@api_transitions, {from, to}),
      do: :ok,
      else: {:error, {:invalid_transition, from, to}}
  end

  defp run_validations(csr) do
    with :ok <- validate_csr_not_empty(csr),
         :ok <- validate_profile_exists(csr) do
      :ok
    end
  end

  defp validate_csr_not_empty(csr) do
    csr_data = csr.csr_pem || csr.csr_der

    if csr_data && csr_data != "" && byte_size(csr_data) > 0 do
      :ok
    else
      {:error, :empty_csr}
    end
  end

  defp validate_profile_exists(csr) do
    case CertProfileConfig.get_profile(csr.cert_profile_id) do
      {:ok, _} -> :ok
      {:error, :not_found} -> {:error, :profile_not_found}
    end
  end

  defp extract_subject_dn(csr_pem) when is_binary(csr_pem) and byte_size(csr_pem) > 0 do
    case X509.CSR.from_pem(csr_pem) do
      {:ok, csr} ->
        dn = X509.RDNSequence.to_string(X509.CSR.subject(csr))
        if dn == "", do: "CN=unknown", else: dn

      _ ->
        "CN=unknown"
    end
  rescue
    _ -> "CN=unknown"
  end

  defp extract_subject_dn(_), do: "CN=unknown"
end
