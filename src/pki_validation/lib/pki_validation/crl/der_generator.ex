defmodule PkiValidation.Crl.DerGenerator do
  @moduledoc """
  Generates RFC 5280 DER-encoded CertificateList (CRL) values for a given
  issuer, signed with the issuer's active key from KeyActivation.

  CRL number is tracked in a simple in-process counter (ETS) per issuer_key_id.
  In a multi-node deployment, each node maintains its own monotonic counter;
  a distributed CRL number coordinator is a Phase 2 concern.
  """

  require Logger

  alias PkiMnesia.{Repo, Structs.CertificateStatus, Structs.IssuerKey}
  alias PkiCaEngine.KeyActivation

  @crl_number_oid {2, 5, 29, 20}
  @crl_reason_oid {2, 5, 29, 21}
  @default_validity_seconds 24 * 3600

  @type signing_key :: %{
          required(:algorithm) => String.t(),
          required(:private_key) => binary(),
          required(:certificate_der) => binary()
        }

  @doc """
  Generate, sign, and return the DER-encoded CRL for the given issuer.

  Returns `{:ok, der_binary, crl_number}` on success.

  Options:
    - `:validity_seconds` — CRL validity window (default: 86400)
    - `:activation_server` — GenServer name/pid for KeyActivation (default: `KeyActivation`)
  """
  @spec generate(binary(), keyword()) ::
          {:ok, binary(), pos_integer()} | {:error, term()}
  def generate(issuer_key_id, opts \\ []) do
    validity_seconds = Keyword.get(opts, :validity_seconds, @default_validity_seconds)
    activation_server = Keyword.get(opts, :activation_server, KeyActivation)

    with {:ok, private_key} <- KeyActivation.get_active_key(activation_server, issuer_key_id),
         {:ok, %IssuerKey{} = issuer_key} <- Repo.get(IssuerKey, issuer_key_id),
         true <- not is_nil(issuer_key.certificate_der) do
      signing_key = %{
        algorithm: issuer_key.algorithm,
        private_key: private_key,
        certificate_der: issuer_key.certificate_der
      }

      do_generate(issuer_key_id, signing_key, validity_seconds)
    else
      {:error, :not_active} -> {:error, :key_not_active}
      {:ok, nil} -> {:error, :issuer_key_not_found}
      false -> {:error, :no_certificate_der}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Generate a signed DER CRL from a provided signing key map.
  Used when the caller has already resolved the key (e.g. in tests).
  """
  @spec generate_with_key(binary(), signing_key(), keyword()) ::
          {:ok, binary(), pos_integer()} | {:error, term()}
  def generate_with_key(issuer_key_id, signing_key, opts \\ []) do
    validity_seconds = Keyword.get(opts, :validity_seconds, @default_validity_seconds)
    do_generate(issuer_key_id, signing_key, validity_seconds)
  end

  # -- Private helpers --

  defp do_generate(issuer_key_id, signing_key, validity_seconds) do
    now = DateTime.utc_now()
    next_update = DateTime.add(now, validity_seconds, :second)
    crl_number = next_crl_number(issuer_key_id)

    case load_revoked(issuer_key_id) do
      {:ok, revoked} ->
        try do
          tbs = build_tbs(signing_key, revoked, crl_number, now, next_update)
          tbs_der = :public_key.der_encode(:TBSCertList, tbs)
          {sig_alg_id, signature} = sign_tbs(tbs_der, signing_key)
          cert_list = {:CertificateList, tbs, sig_alg_id, signature}
          der = :public_key.der_encode(:CertificateList, cert_list)
          {:ok, der, crl_number}
        rescue
          e ->
            Logger.error("CRL DER generation failed: #{Exception.message(e)}")
            {:error, {:der_generation_failed, Exception.message(e)}}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp load_revoked(issuer_key_id) do
    case Repo.where(CertificateStatus, fn cs ->
           cs.issuer_key_id == issuer_key_id && cs.status == "revoked"
         end) do
      {:ok, revoked} ->
        entries =
          revoked
          |> Enum.map(fn cs ->
            %{serial_number: cs.serial_number, revoked_at: cs.revoked_at, reason: cs.revocation_reason}
          end)
          |> Enum.sort_by(& &1.revoked_at)

        {:ok, entries}

      {:error, _} = err ->
        err
    end
  end

  # Simple per-node monotonic counter using persistent_term per issuer.
  # Not distributed-safe, but correct for single-node deployments.
  defp next_crl_number(issuer_key_id) do
    key = {__MODULE__, :crl_number, issuer_key_id}

    current =
      try do
        :persistent_term.get(key)
      rescue
        ArgumentError -> 0
      end

    next = current + 1
    :persistent_term.put(key, next)
    next
  end

  defp build_tbs(signing_key, revoked, crl_number, this_update, next_update) do
    issuer = extract_issuer(signing_key.certificate_der)
    sig_alg_id = algorithm_identifier(signing_key.algorithm)

    revoked_entries =
      case Enum.map(revoked, &build_revoked_entry/1) do
        [] -> :asn1_NOVALUE
        list -> list
      end

    crl_extensions = [
      {:Extension, @crl_number_oid, false, :public_key.der_encode(:CRLNumber, crl_number)}
    ]

    {:TBSCertList, :v2, sig_alg_id, issuer, utc_time(this_update), utc_time(next_update),
     revoked_entries, crl_extensions}
  end

  defp build_revoked_entry(%{serial_number: serial_str, revoked_at: revoked_at, reason: reason}) do
    serial_int = parse_serial(serial_str)
    reason_atom = reason_to_atom(reason)

    extensions =
      case reason_atom do
        nil -> []
        atom ->
          [{:Extension, @crl_reason_oid, false, :public_key.der_encode(:CRLReason, atom)}]
      end

    {:TBSCertList_revokedCertificates_SEQOF, serial_int, utc_time(revoked_at), extensions}
  end

  defp extract_issuer(cert_der) do
    plain = :public_key.pkix_decode_cert(cert_der, :plain)
    tbs = :erlang.element(2, plain)
    :erlang.element(7, tbs)
  end

  defp utc_time(%DateTime{} = dt) do
    charlist =
      dt
      |> Calendar.strftime("%y%m%d%H%M%SZ")
      |> String.to_charlist()

    {:utcTime, charlist}
  end

  defp parse_serial(bin) when is_binary(bin) do
    case Integer.parse(bin) do
      {int, ""} ->
        int
      _ ->
        case Integer.parse(bin, 16) do
          {int, ""} -> int
          _ -> raise ArgumentError, "invalid serial number: #{inspect(bin)}"
        end
    end
  end

  defp reason_to_atom(nil), do: nil
  defp reason_to_atom("unspecified"), do: :unspecified
  defp reason_to_atom("key_compromise"), do: :keyCompromise
  defp reason_to_atom("ca_compromise"), do: :cACompromise
  defp reason_to_atom("affiliation_changed"), do: :affiliationChanged
  defp reason_to_atom("superseded"), do: :superseded
  defp reason_to_atom("cessation_of_operation"), do: :cessationOfOperation
  defp reason_to_atom("certificate_hold"), do: :certificateHold
  defp reason_to_atom("remove_from_crl"), do: :removeFromCRL
  defp reason_to_atom("privilege_withdrawn"), do: :privilegeWithdrawn
  defp reason_to_atom("aa_compromise"), do: :aACompromise

  defp reason_to_atom(other) do
    Logger.warning("Unknown revocation reason in CRL: #{inspect(other)}, using :unspecified")
    :unspecified
  end

  defp sign_tbs(tbs_der, %{algorithm: algorithm, private_key: priv}) do
    case PkiCrypto.AlgorithmRegistry.by_id(algorithm) do
      {:ok, %{family: family}} when family in [:ml_dsa, :kaz_sign, :slh_dsa] ->
        {:ok, algo} = PkiCrypto.Registry.get(algorithm)
        {:ok, sig} = PkiCrypto.Algorithm.sign(algo, priv, tbs_der)
        {pqc_algorithm_identifier(algorithm), sig}

      {:ok, %{family: :ecdsa}} ->
        hash = if algorithm == "ECC-P384", do: :sha384, else: :sha256
        native_key = :public_key.der_decode(:ECPrivateKey, priv)
        sig = :public_key.sign(tbs_der, hash, native_key)
        curve = if algorithm == "ECC-P384", do: :secp384r1, else: :prime256v1
        alg_id = {:AlgorithmIdentifier, {1, 2, 840, 10045, 4, 3, 2}, {:namedCurve, curve}}
        {alg_id, sig}

      {:ok, %{family: :rsa}} ->
        native_key = :public_key.der_decode(:RSAPrivateKey, priv)
        sig = :public_key.sign(tbs_der, :sha256, native_key)
        alg_id = {:AlgorithmIdentifier, :sha256WithRSAEncryption, :asn1_NOVALUE}
        {alg_id, sig}

      _ ->
        raise "unknown algorithm for CRL signing: #{inspect(algorithm)}"
    end
  end

  # Returns the AlgorithmIdentifier ASN.1 record for the given algorithm string.
  defp algorithm_identifier(algorithm) do
    case PkiCrypto.AlgorithmRegistry.by_id(algorithm) do
      {:ok, %{family: :ecdsa}} ->
        curve = if algorithm == "ECC-P384", do: :secp384r1, else: :prime256v1
        {:AlgorithmIdentifier, {1, 2, 840, 10045, 4, 3, 2}, {:namedCurve, curve}}

      {:ok, %{family: :rsa}} ->
        {:AlgorithmIdentifier, :sha256WithRSAEncryption, :asn1_NOVALUE}

      {:ok, %{family: _pqc}} ->
        pqc_algorithm_identifier(algorithm)

      _ ->
        raise "unknown algorithm identifier for: #{inspect(algorithm)}"
    end
  end

  defp pqc_algorithm_identifier(algorithm) do
    # PQC algorithm identifiers — OIDs from NIST/IETF drafts.
    # These will need to be updated as standards stabilize.
    oid =
      case algorithm do
        "ML-DSA-44" -> {2, 16, 840, 1, 101, 3, 4, 3, 17}
        "ML-DSA-65" -> {2, 16, 840, 1, 101, 3, 4, 3, 18}
        "ML-DSA-87" -> {2, 16, 840, 1, 101, 3, 4, 3, 19}
        # KAZ-SIGN — placeholder OID until official assignment
        _ -> {2, 16, 458, 1, 1, 1, 1}
      end

    {:AlgorithmIdentifier, oid, :asn1_NOVALUE}
  end
end
