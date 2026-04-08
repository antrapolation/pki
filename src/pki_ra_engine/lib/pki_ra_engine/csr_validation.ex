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
  alias PkiRaEngine.UserManagement
  alias PkiRaEngine.WebhookDelivery

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
  @spec submit_csr(String.t(), String.t(), String.t(), keyword()) :: {:ok, CsrRequest.t()} | {:error, term()}
  def submit_csr(tenant_id, csr_pem, cert_profile_id, opts \\ []) do
    repo = TenantRepo.ra_repo(tenant_id)
    submitted_by_key_id = Keyword.get(opts, :submitted_by_key_id)

    # Extract a basic subject_dn placeholder (real crypto extraction comes later)
    subject_dn = extract_subject_dn(csr_pem)

    attrs = %{
      csr_pem: csr_pem,
      cert_profile_id: cert_profile_id,
      subject_dn: subject_dn,
      status: "pending",
      submitted_at: DateTime.utc_now(),
      submitted_by_key_id: submitted_by_key_id
    }

    case %CsrRequest{} |> CsrRequest.changeset(attrs) |> repo.insert() do
      {:ok, csr} ->
        PkiRaEngine.Telemetry.csr_submitted(%{csr_id: csr.id, tenant_id: tenant_id})
        WebhookDelivery.deliver_for_csr(tenant_id, csr, "csr_submitted")
        {:ok, csr}

      error ->
        error
    end
  end

  @doc "Auto-validate a pending CSR. Basic structural checks. Triggers auto-approve if profile allows."
  @spec validate_csr(String.t(), String.t()) :: {:ok, CsrRequest.t()} | {:error, term()}
  def validate_csr(tenant_id, csr_id) do
    repo = TenantRepo.ra_repo(tenant_id)

    with {:ok, csr} <- get_csr(tenant_id, csr_id),
         :ok <- check_auto_transition(csr.status, "verified") do
      case run_validations(tenant_id, csr) do
        :ok ->
          case transition(repo, csr, "verified", %{}) do
            {:ok, verified} ->
              WebhookDelivery.deliver_for_csr(tenant_id, verified, "csr_validated", %{result: "verified"})
              maybe_auto_approve(tenant_id, verified)
              {:ok, verified}

            {:error, _} = err ->
              err
          end

        {:error, _reason} ->
          case transition(repo, csr, "rejected", %{}) do
            {:ok, rejected} ->
              WebhookDelivery.deliver_for_csr(tenant_id, rejected, "csr_validated", %{result: "rejected"})
              {:ok, rejected}

            error ->
              error
          end
      end
    end
  end

  @doc "RA officer approves a verified CSR."
  @spec approve_csr(String.t(), String.t(), String.t()) :: {:ok, CsrRequest.t()} | {:error, term()}
  def approve_csr(tenant_id, csr_id, reviewer_user_id) do
    repo = TenantRepo.ra_repo(tenant_id)

    with {:ok, csr} <- get_csr(tenant_id, csr_id),
         :ok <- check_transition(csr.status, "approved"),
         :ok <- check_dcv_requirement(tenant_id, csr),
         {:ok, approved_csr} <- transition(repo, csr, "approved", %{
           reviewed_by: reviewer_user_id,
           reviewed_at: DateTime.utc_now()
         }) do
      audit("csr_approved", tenant_id, reviewer_user_id, "csr", csr_id, %{
        subject_dn: approved_csr.subject_dn,
        cert_profile_id: approved_csr.cert_profile_id
      })
      PkiRaEngine.Telemetry.csr_approved(%{csr_id: csr_id, auto: false})
      WebhookDelivery.deliver_for_csr(tenant_id, approved_csr, "csr_approved")

      # Auto-forward to CA for signing (async, supervised)
      Task.Supervisor.start_child(PkiRaEngine.TaskSupervisor, fn ->
        case forward_to_ca(tenant_id, csr_id) do
          {:ok, _} ->
            Logger.info("csr_auto_forwarded csr_id=#{csr_id}")
          {:error, reason} ->
            Logger.error("csr_auto_forward_failed csr_id=#{csr_id} reason=#{inspect(reason)}")
        end
      end)

      {:ok, approved_csr}
    end
  end

  @doc "RA officer rejects a verified CSR with reason."
  @spec reject_csr(String.t(), String.t(), String.t(), String.t()) :: {:ok, CsrRequest.t()} | {:error, term()}
  def reject_csr(tenant_id, csr_id, reviewer_user_id, reason) do
    repo = TenantRepo.ra_repo(tenant_id)
    reason = if is_binary(reason), do: String.slice(reason, 0, 1000), else: "No reason provided"

    with {:ok, csr} <- get_csr(tenant_id, csr_id),
         :ok <- check_transition(csr.status, "rejected"),
         {:ok, rejected_csr} <- transition(repo, csr, "rejected", %{
           reviewed_by: reviewer_user_id,
           reviewed_at: DateTime.utc_now(),
           rejection_reason: reason
         }) do
      audit("csr_rejected", tenant_id, reviewer_user_id, "csr", csr_id, %{
        subject_dn: rejected_csr.subject_dn,
        reason: reason
      })
      PkiRaEngine.Telemetry.csr_rejected(%{csr_id: csr_id, reason: reason})
      WebhookDelivery.deliver_for_csr(tenant_id, rejected_csr, "csr_rejected", %{reason: reason})

      {:ok, rejected_csr}
    end
  end

  @doc "Revoke a certificate by forwarding to CA Engine."
  @spec revoke_certificate(String.t(), String.t(), String.t()) :: {:ok, map()} | {:error, term()}
  def revoke_certificate(tenant_id, serial_number, reason) do
    ca_module =
      Application.get_env(:pki_ra_engine, :ca_engine_module) ||
        raise "ca_engine_module not configured"

    case ca_module.revoke_certificate(tenant_id, serial_number, reason) do
      {:ok, result} ->
        audit("cert_revoked", tenant_id, nil, "certificate", serial_number, %{reason: reason})
        WebhookDelivery.deliver_for_cert(tenant_id, serial_number, "cert_revoked", %{reason: reason})
        {:ok, result}

      error ->
        error
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
      validity_days =
        Map.get(profile, :validity_days) ||
        get_in(profile.validity_policy || %{}, ["days"]) ||
        365

      cert_profile_map = %{
        id: csr.cert_profile_id,
        issuer_key_id: profile.issuer_key_id,
        subject_dn: csr.subject_dn,
        validity_days: validity_days
      }

      case ca_module.sign_certificate(tenant_id, profile.issuer_key_id, csr.csr_pem, cert_profile_map) do
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
         :ok <- check_transition(csr.status, "issued"),
         {:ok, issued_csr} <- transition(repo, csr, "issued", %{issued_cert_serial: cert_serial}) do
      audit("cert_issued", tenant_id, nil, "csr", csr_id, %{
        serial_number: cert_serial,
        subject_dn: issued_csr.subject_dn
      })
      PkiRaEngine.Telemetry.csr_issued(%{csr_id: csr_id, serial: cert_serial})
      WebhookDelivery.deliver_for_csr(tenant_id, issued_csr, "cert_issued", %{serial_number: cert_serial})

      {:ok, issued_csr}
    end
  end

  # ── Private ─────────────────────────────────────────────────────────

  defp maybe_auto_approve(tenant_id, csr) do
    case CertProfileConfig.get_profile(tenant_id, csr.cert_profile_id) do
      {:ok, %{approval_mode: "auto"}} ->
        dcv_ok = case check_dcv_requirement(tenant_id, csr) do
          :ok -> true
          _ -> false
        end

        if dcv_ok do
          csr_id = csr.id

          Task.Supervisor.start_child(PkiRaEngine.TaskSupervisor, fn ->
            repo = TenantRepo.ra_repo(tenant_id)

            # Re-fetch CSR to guard against concurrent state changes (e.g. manual rejection)
            with {:ok, fresh_csr} <- get_csr(tenant_id, csr_id),
                 :ok <- check_transition(fresh_csr.status, "approved"),
                 {:ok, approved_csr} <- transition(repo, fresh_csr, "approved", %{
                   reviewed_by: nil,
                   reviewed_at: DateTime.utc_now()
                 }) do
              audit("csr_approved", tenant_id, nil, "csr", csr_id, %{
                subject_dn: fresh_csr.subject_dn,
                auto_approved: true
              })
              WebhookDelivery.deliver_for_csr(tenant_id, approved_csr, "csr_approved", %{auto_approved: true})

              case forward_to_ca(tenant_id, csr_id) do
                {:ok, _} ->
                  Logger.info("csr_auto_approved_and_issued csr_id=#{csr_id}")

                {:error, reason} ->
                  Logger.error("csr_auto_approve_ca_failed csr_id=#{csr_id} reason=#{inspect(reason)}")
              end
            else
              {:error, {:invalid_transition, from, _to}} ->
                Logger.info("csr_auto_approve_skipped csr_id=#{csr_id} current_status=#{from}")

              {:error, reason} ->
                Logger.error("csr_auto_approve_failed csr_id=#{csr_id} reason=#{inspect(reason)}")
            end
          end)
        end

      _ ->
        # Manual approval or profile not found — do nothing
        :ok
    end
  rescue
    e ->
      Logger.error("maybe_auto_approve_crashed csr_id=#{csr.id} error=#{Exception.message(e)}")
      :ok
  end

  defp check_dcv_requirement(tenant_id, csr) do
    case CertProfileConfig.get_profile(tenant_id, csr.cert_profile_id) do
      {:ok, profile} ->
        policy = profile.subject_dn_policy || %{}

        if policy["require_dcv"] == true do
          PkiRaEngine.DcvChallenge.check_dcv_passed(tenant_id, csr.id)
        else
          :ok
        end

      {:error, :not_found} ->
        # Profile not found — skip DCV (profile was likely deleted after CSR submission)
        :ok

      {:error, reason} ->
        # Transient error (DB, etc.) — do NOT silently skip DCV
        {:error, {:dcv_check_failed, reason}}
    end
  end

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
    import Ecto.Query

    attrs = Map.merge(extra_attrs, %{status: new_status})

    # Atomic: claim the row only if status hasn't changed (prevents double-approve etc.)
    # Uses update_all with a no-op SET to lock the row with a WHERE status guard,
    # then applies the real change via changeset for proper Ecto type casting.
    claim_query =
      from(c in CsrRequest,
        where: c.id == ^csr.id and c.status == ^csr.status
      )

    repo.transaction(fn ->
      case repo.update_all(claim_query, set: [status: new_status]) do
        {1, _} ->
          # Re-fetch the row (now with new status) and apply full changeset
          case repo.get(CsrRequest, csr.id) do
            nil ->
              repo.rollback(:not_found)

            fresh ->
              changeset = CsrRequest.changeset(fresh, attrs)

              case repo.update(changeset) do
                {:ok, updated} -> updated
                {:error, changeset} -> repo.rollback({:changeset_error, changeset})
              end
          end

        {0, _} ->
          repo.rollback({:invalid_transition, csr.status, new_status})
      end
    end)
    |> case do
      {:ok, updated} -> {:ok, updated}
      {:error, :not_found} -> {:error, :not_found}
      {:error, {:invalid_transition, from, to}} -> {:error, {:invalid_transition, from, to}}
      {:error, {:changeset_error, cs}} -> {:error, cs}
    end
  end

  defp run_validations(tenant_id, csr) do
    with :ok <- validate_csr_not_empty(csr),
         :ok <- validate_profile_exists(tenant_id, csr),
         :ok <- validate_csr_key_strength(csr),
         :ok <- validate_subject_dn_policy(tenant_id, csr) do
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

  defp validate_csr_key_strength(csr) do
    csr_pem = csr.csr_pem

    try do
      case X509.CSR.from_pem(csr_pem) do
        {:ok, parsed_csr} ->
          pub_key = X509.CSR.public_key(parsed_csr)
          validate_public_key(pub_key)

        _ ->
          # Can't parse CSR (PQC or malformed) — skip key validation, let CA handle it
          :ok
      end
    rescue
      _ -> :ok
    end
  end

  defp validate_public_key({:RSAPublicKey, modulus, _exp}) do
    bit_size = :erlang.bit_size(:binary.encode_unsigned(modulus))
    if bit_size >= 2048 do
      :ok
    else
      Logger.warning("[csr_validation] RSA key too small: #{bit_size} bits (minimum 2048)")
      {:error, :weak_key}
    end
  end

  defp validate_public_key({{:ECPoint, _point}, {:namedCurve, curve_oid}}) do
    # Accept P-256, P-384, P-521
    accepted_curves = [
      {1, 2, 840, 10045, 3, 1, 7},   # P-256
      {1, 3, 132, 0, 34},             # P-384
      {1, 3, 132, 0, 35}              # P-521
    ]

    if curve_oid in accepted_curves do
      :ok
    else
      Logger.warning("[csr_validation] Unsupported ECC curve OID: #{inspect(curve_oid)}")
      {:error, :unsupported_curve}
    end
  end

  # PQC or unknown key type — allow (CA will validate further)
  defp validate_public_key(_), do: :ok

  defp validate_profile_exists(tenant_id, csr) do
    case CertProfileConfig.get_profile(tenant_id, csr.cert_profile_id) do
      {:ok, _profile} -> :ok
      {:error, :not_found} -> {:error, :profile_not_found}
    end
  end

  defp validate_subject_dn_policy(tenant_id, csr) do
    case CertProfileConfig.get_profile(tenant_id, csr.cert_profile_id) do
      {:ok, profile} ->
        policy = profile.subject_dn_policy || %{}

        if map_size(policy) == 0 do
          # No policy configured — allow any subject DN
          :ok
        else
          subject_dn = csr.subject_dn || ""
          check_dn_against_policy(subject_dn, policy)
        end

      _ ->
        # Profile not found — already caught by validate_profile_exists
        :ok
    end
  end

  defp check_dn_against_policy(subject_dn, policy) do
    dn_lower = String.downcase(subject_dn)

    errors =
      Enum.reduce(policy, [], fn {key, rule}, acc ->
        case {key, rule} do
          {"required_fields", fields} when is_list(fields) ->
            # Check that required DN fields are present (e.g., ["CN", "O", "C"])
            missing = Enum.filter(fields, fn field ->
              field_lower = String.downcase(field)
              not String.contains?(dn_lower, "#{field_lower}=")
            end)

            if missing == [] do
              acc
            else
              ["Missing required DN fields: #{Enum.join(missing, ", ")}" | acc]
            end

          {"allowed_domains", domains} when is_list(domains) ->
            # Check CN matches an allowed domain pattern
            cn = extract_cn(subject_dn)
            if cn == nil or Enum.any?(domains, &domain_matches?(cn, &1)) do
              acc
            else
              ["CN '#{cn}' does not match any allowed domain" | acc]
            end

          {"forbidden_patterns", patterns} when is_list(patterns) ->
            # Reject DNs containing forbidden strings
            found = Enum.filter(patterns, &String.contains?(dn_lower, String.downcase(&1)))
            if found == [] do
              acc
            else
              ["Subject DN contains forbidden pattern: #{Enum.join(found, ", ")}" | acc]
            end

          _ ->
            acc
        end
      end)

    if errors == [] do
      :ok
    else
      Logger.warning("[csr_validation] Subject DN policy violation: #{Enum.join(errors, "; ")}")
      {:error, {:dn_policy_violation, errors}}
    end
  end

  defp extract_cn(dn) do
    case Regex.run(~r/CN=([^,\/]+)/i, dn) do
      [_, cn] -> String.trim(cn)
      _ -> nil
    end
  end

  defp domain_matches?(cn, pattern) do
    cn_lower = String.downcase(cn)
    pattern_lower = String.downcase(pattern)

    cond do
      # Exact match
      cn_lower == pattern_lower -> true
      # Wildcard: *.example.com matches sub.example.com
      String.starts_with?(pattern_lower, "*.") ->
        suffix = String.slice(pattern_lower, 1..-1//1)
        String.ends_with?(cn_lower, suffix) and not String.contains?(String.replace_suffix(cn_lower, suffix, ""), ".")
      # Suffix match: .example.com matches anything.example.com
      String.starts_with?(pattern_lower, ".") ->
        String.ends_with?(cn_lower, pattern_lower)
      true ->
        false
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

  # Audit helper — fire-and-forget, never fails the caller
  defp audit(action, tenant_id, actor_id, target_type, target_id, details) do
    # Look up actor username if we have an actor_id
    actor_username =
      if actor_id do
        case UserManagement.get_user(tenant_id, actor_id) do
          {:ok, user} -> user.username || user.display_name
          _ -> nil
        end
      else
        nil
      end

    PkiPlatformEngine.PlatformAudit.log(action, %{
      actor_id: actor_id,
      actor_username: actor_username,
      target_type: target_type,
      target_id: target_id,
      tenant_id: tenant_id,
      portal: "ra",
      details: details
    })
  rescue
    e ->
      Logger.error("audit_log_failed action=#{action} error=#{Exception.message(e)}")
      PkiRaEngine.Telemetry.emit([:pki, :ra, :audit, :failed], %{count: 1}, %{action: action})
  end

end
