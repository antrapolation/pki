defmodule PkiRaEngine.CsrValidation do
  @moduledoc """
  CSR Validation — submit, validate, approve/reject, and track CSR lifecycle.

  Status state machine:
    pending -> verified  (auto-validation pass)
    pending -> rejected  (auto-validation fail)
    verified -> approved (officer)
    verified -> rejected (officer)
    approved -> issued   (after CA signs)
  """

  import PkiRaEngine.QueryHelpers

  alias PkiRaEngine.Repo
  alias PkiRaEngine.Schema.CsrRequest
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

  @doc "Submit a CSR. Accepts CSR PEM string and cert_profile_id."
  @spec submit_csr(String.t(), integer()) :: {:ok, CsrRequest.t()} | {:error, term()}
  def submit_csr(csr_pem, cert_profile_id) do
    # Extract a basic subject_dn placeholder (real crypto extraction comes later)
    subject_dn = extract_subject_dn(csr_pem)

    attrs = %{
      csr_pem: csr_pem,
      cert_profile_id: cert_profile_id,
      subject_dn: subject_dn,
      status: "pending",
      submitted_at: DateTime.utc_now()
    }

    %CsrRequest{}
    |> CsrRequest.changeset(attrs)
    |> Repo.insert()
  end

  @doc "Auto-validate a pending CSR. Basic structural checks."
  @spec validate_csr(integer()) :: {:ok, CsrRequest.t()} | {:error, term()}
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
  @spec approve_csr(integer(), integer()) :: {:ok, CsrRequest.t()} | {:error, term()}
  def approve_csr(csr_id, reviewer_user_id) do
    with {:ok, csr} <- get_csr(csr_id),
         :ok <- check_transition(csr.status, "approved") do
      transition(csr, "approved", %{
        reviewed_by: reviewer_user_id,
        reviewed_at: DateTime.utc_now()
      })
    end
  end

  @doc "RA officer rejects a verified CSR with reason."
  @spec reject_csr(integer(), integer(), String.t()) :: {:ok, CsrRequest.t()} | {:error, term()}
  def reject_csr(csr_id, reviewer_user_id, reason) do
    with {:ok, csr} <- get_csr(csr_id),
         :ok <- check_transition(csr.status, "rejected") do
      transition(csr, "rejected", %{
        reviewed_by: reviewer_user_id,
        reviewed_at: DateTime.utc_now(),
        rejection_reason: reason
      })
    end
  end

  @doc "Get a CSR by ID."
  @spec get_csr(integer()) :: {:ok, CsrRequest.t()} | {:error, :not_found}
  def get_csr(id) do
    case Repo.get(CsrRequest, id) do
      nil -> {:error, :not_found}
      csr -> {:ok, csr}
    end
  end

  @doc "List CSRs with optional filters (:status, :cert_profile_id)."
  @spec list_csrs(keyword()) :: [CsrRequest.t()]
  def list_csrs(filters) do
    CsrRequest
    |> apply_eq_filters(filters)
    |> Repo.all()
  end

  @doc "Forward an approved CSR to the CA engine for signing."
  @spec forward_to_ca(integer()) :: {:ok, CsrRequest.t()} | {:error, term()}
  def forward_to_ca(csr_id) do
    ca_module =
      Application.get_env(:pki_ra_engine, :ca_engine_module, __MODULE__.DefaultCaClient)

    with {:ok, csr} <- get_csr(csr_id),
         :ok <- check_transition(csr.status, "issued") do
      case ca_module.sign_certificate(csr.csr_pem, %{id: csr.cert_profile_id}) do
        {:ok, cert_data} ->
          mark_issued(csr_id, cert_data.serial_number)

        {:error, reason} ->
          {:error, reason}
      end
    end
  end

  @doc "Mark an approved CSR as issued with the certificate serial."
  @spec mark_issued(integer(), String.t()) :: {:ok, CsrRequest.t()} | {:error, term()}
  def mark_issued(csr_id, cert_serial) do
    with {:ok, csr} <- get_csr(csr_id),
         :ok <- check_transition(csr.status, "issued") do
      transition(csr, "issued", %{issued_cert_serial: cert_serial})
    end
  end

  # ── Private ─────────────────────────────────────────────────────────

  defp check_transition(from, to) do
    if Map.get(@api_transitions, {from, to}) do
      :ok
    else
      {:error, {:invalid_transition, from, to}}
    end
  end

  defp check_auto_transition(from, to) do
    if Map.get(@auto_transitions, {from, to}) || Map.get(@api_transitions, {from, to}) do
      :ok
    else
      {:error, {:invalid_transition, from, to}}
    end
  end

  defp transition(csr, new_status, extra_attrs) do
    attrs = Map.merge(extra_attrs, %{status: new_status})

    csr
    |> CsrRequest.changeset(attrs)
    |> Repo.update()
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
      {:ok, _profile} -> :ok
      {:error, :not_found} -> {:error, :profile_not_found}
    end
  end

  defp extract_subject_dn(csr_pem) do
    # Placeholder — real extraction requires ASN.1 parsing of the CSR
    # For now, return a generic DN
    if csr_pem && csr_pem != "" do
      "CN=pending_extraction"
    else
      "CN=unknown"
    end
  end

end
