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

  require Logger
  import PkiRaEngine.QueryHelpers

  alias PkiRaEngine.TenantRepo
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
  @spec submit_csr(String.t(), String.t(), String.t()) :: {:ok, CsrRequest.t()} | {:error, term()}
  def submit_csr(tenant_id, csr_pem, cert_profile_id) do
    repo = TenantRepo.ra_repo(tenant_id)

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
    |> repo.insert()
  end

  @doc "Auto-validate a pending CSR. Basic structural checks."
  @spec validate_csr(String.t(), String.t()) :: {:ok, CsrRequest.t()} | {:error, term()}
  def validate_csr(tenant_id, csr_id) do
    repo = TenantRepo.ra_repo(tenant_id)

    with {:ok, csr} <- get_csr(tenant_id, csr_id),
         :ok <- check_auto_transition(csr.status, "verified") do
      case run_validations(tenant_id, csr) do
        :ok ->
          transition(repo, csr, "verified", %{})

        {:error, _reason} ->
          transition(repo, csr, "rejected", %{})
      end
    end
  end

  @doc "RA officer approves a verified CSR."
  @spec approve_csr(String.t(), String.t(), String.t()) :: {:ok, CsrRequest.t()} | {:error, term()}
  def approve_csr(tenant_id, csr_id, reviewer_user_id) do
    repo = TenantRepo.ra_repo(tenant_id)

    with {:ok, csr} <- get_csr(tenant_id, csr_id),
         :ok <- check_transition(csr.status, "approved") do
      transition(repo, csr, "approved", %{
        reviewed_by: reviewer_user_id,
        reviewed_at: DateTime.utc_now()
      })
    end
  end

  @doc "RA officer rejects a verified CSR with reason."
  @spec reject_csr(String.t(), String.t(), String.t(), String.t()) :: {:ok, CsrRequest.t()} | {:error, term()}
  def reject_csr(tenant_id, csr_id, reviewer_user_id, reason) do
    repo = TenantRepo.ra_repo(tenant_id)

    with {:ok, csr} <- get_csr(tenant_id, csr_id),
         :ok <- check_transition(csr.status, "rejected") do
      transition(repo, csr, "rejected", %{
        reviewed_by: reviewer_user_id,
        reviewed_at: DateTime.utc_now(),
        rejection_reason: reason
      })
    end
  end

  @doc "Get a CSR by ID."
  @spec get_csr(String.t(), String.t()) :: {:ok, CsrRequest.t()} | {:error, :not_found}
  def get_csr(tenant_id, id) do
    repo = TenantRepo.ra_repo(tenant_id)

    case repo.get(CsrRequest, id) do
      nil -> {:error, :not_found}
      csr -> {:ok, csr}
    end
  end

  @doc "List CSRs with optional filters (:status, :cert_profile_id)."
  @spec list_csrs(String.t(), keyword()) :: [CsrRequest.t()]
  def list_csrs(tenant_id, filters) do
    repo = TenantRepo.ra_repo(tenant_id)

    CsrRequest
    |> apply_eq_filters(filters)
    |> repo.all()
  end

  @doc "Forward an approved CSR to the CA engine for signing."
  @spec forward_to_ca(String.t(), String.t()) :: {:ok, CsrRequest.t()} | {:error, term()}
  def forward_to_ca(tenant_id, csr_id) do
    ca_module =
      Application.get_env(:pki_ra_engine, :ca_engine_module) ||
        raise "ca_engine_module not configured. Set CA_ENGINE_URL in environment."

    with {:ok, csr} <- get_csr(tenant_id, csr_id),
         :ok <- check_transition(csr.status, "issued"),
         {:ok, profile} <- CertProfileConfig.get_profile(tenant_id, csr.cert_profile_id) do
      cert_profile_map = %{id: csr.cert_profile_id, issuer_key_id: profile.issuer_key_id}

      case ca_module.sign_certificate(csr.csr_pem, cert_profile_map) do
        {:ok, cert_data} ->
          mark_issued(tenant_id, csr_id, cert_data.serial_number)

        {:error, reason} ->
          {:error, reason}
      end
    end
  end

  @doc "Mark an approved CSR as issued with the certificate serial."
  @spec mark_issued(String.t(), String.t(), String.t()) :: {:ok, CsrRequest.t()} | {:error, term()}
  def mark_issued(tenant_id, csr_id, cert_serial) do
    repo = TenantRepo.ra_repo(tenant_id)

    with {:ok, csr} <- get_csr(tenant_id, csr_id),
         :ok <- check_transition(csr.status, "issued") do
      transition(repo, csr, "issued", %{issued_cert_serial: cert_serial})
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

  defp transition(repo, csr, new_status, extra_attrs) do
    attrs = Map.merge(extra_attrs, %{status: new_status})

    csr
    |> CsrRequest.changeset(attrs)
    |> repo.update()
  end

  defp run_validations(tenant_id, csr) do
    with :ok <- validate_csr_not_empty(csr),
         :ok <- validate_profile_exists(tenant_id, csr) do
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

  defp validate_profile_exists(tenant_id, csr) do
    case CertProfileConfig.get_profile(tenant_id, csr.cert_profile_id) do
      {:ok, _profile} -> :ok
      {:error, :not_found} -> {:error, :profile_not_found}
    end
  end

  defp extract_subject_dn(csr_pem) when is_binary(csr_pem) and byte_size(csr_pem) > 0 do
    # Try X509 library PEM parsing first
    case X509.CSR.from_pem(csr_pem) do
      {:ok, csr} ->
        subject = X509.CSR.subject(csr)
        dn = X509.RDNSequence.to_string(subject)

        if dn == "" do
          Logger.warning("CSR parsed successfully but subject DN is empty")
          "CN=unknown"
        else
          dn
        end

      {:error, :not_found} ->
        # PEM block not found — try DER decoding in case raw binary was passed
        try_der_decode(csr_pem)

      {:error, :malformed} ->
        Logger.warning("CSR PEM is malformed, could not parse subject DN")
        "CN=unknown"
    end
  rescue
    e ->
      Logger.warning("CSR subject DN extraction failed: #{Exception.message(e)}")
      "CN=unknown"
  end

  defp extract_subject_dn(nil) do
    Logger.warning("CSR PEM is nil, cannot extract subject DN")
    "CN=unknown"
  end

  defp extract_subject_dn(_) do
    Logger.warning("CSR PEM is not a valid binary, cannot extract subject DN")
    "CN=unknown"
  end

  defp try_der_decode(der_data) do
    case X509.CSR.from_der(der_data) do
      {:ok, csr} ->
        subject = X509.CSR.subject(csr)
        dn = X509.RDNSequence.to_string(subject)
        if dn == "", do: "CN=unknown", else: dn

      {:error, _} ->
        Logger.warning(
          "CSR could not be parsed as PEM or DER, falling back to CN=unknown"
        )

        "CN=unknown"
    end
  rescue
    _ ->
      Logger.warning("CSR DER decode failed, falling back to CN=unknown")
      "CN=unknown"
  end

end
