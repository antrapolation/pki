defmodule PkiValidation.Crl.DerGenerator do
  @moduledoc """
  Generates RFC 5280 DER-encoded `CertificateList` (CRL) values for
  a given issuer, signed with a delegated CRL signer key held by the
  validation service.

  ## Design

    * The CRL `issuer` field is taken from the SUBJECT DN of the
      signing certificate, implementing the delegated CRL signer
      model from RFC 5280 §5. In production the delegated signer's
      subject is typically arranged to match the CA's own subject so
      clients can associate the CRL with revocations from that CA.

    * Each generated CRL includes the `cRLNumber` extension
      (OID 2.5.29.20) with a monotonically increasing integer per
      issuer. The counter lives in the `crl_metadata` row for the
      issuer and is incremented inside a transaction with a
      `FOR UPDATE` row lock to prevent races between concurrent
      generators.

    * Each revoked entry includes the `reasonCode` extension
      (OID 2.5.29.21) encoding the RFC 5280 `CRLReason` value
      derived from the `certificate_status.revocation_reason`
      column.

    * Signing uses the same ECC/RSA patterns as
      `PkiValidation.Ocsp.ResponseBuilder`. For ECC we construct an
      `ECPrivateKey` record at sign time from the raw scalar; for
      RSA we decode the stored DER-encoded `:RSAPrivateKey` before
      calling `:public_key.sign/3`.

    * The signed DER bytes are cached in the `crl_metadata` row
      (`last_der_bytes`, `last_der_size`, `last_generated_at`) so
      readers can serve the most recent CRL without re-signing.
  """

  import Ecto.Query

  alias PkiValidation.Repo
  alias PkiValidation.Schema.{CertificateStatus, CrlMetadata}

  @secp256r1_oid {1, 2, 840, 10045, 3, 1, 7}
  @secp384r1_oid {1, 3, 132, 0, 34}

  @ecdsa_sha256_oid {1, 2, 840, 10045, 4, 3, 2}
  @ecdsa_sha384_oid {1, 2, 840, 10045, 4, 3, 3}
  @rsa_sha256_oid {1, 2, 840, 113_549, 1, 1, 11}

  @crl_number_oid {2, 5, 29, 20}
  @crl_reason_oid {2, 5, 29, 21}

  # CRL validity window for next_update.
  @default_validity_seconds 24 * 3600

  @type signing_key :: %{
          required(:algorithm) => String.t(),
          required(:private_key) => binary(),
          required(:certificate_der) => binary(),
          optional(any()) => any()
        }

  @doc """
  Generate, sign, persist, and return the DER-encoded CRL for the
  given issuer.

  Returns `{:ok, der_binary, crl_number}` on success, where
  `crl_number` is the value embedded in the generated CRL's
  `cRLNumber` extension.
  """
  @spec generate(binary(), signing_key(), keyword()) ::
          {:ok, binary(), pos_integer()} | {:error, term()}
  def generate(issuer_key_id, signing_key, opts \\ []) do
    validity_seconds = Keyword.get(opts, :validity_seconds, @default_validity_seconds)
    now = DateTime.utc_now()
    next_update = DateTime.add(now, validity_seconds, :second)

    revoked = load_revoked(issuer_key_id)

    Repo.transaction(fn ->
      meta = get_or_create_metadata_locked(issuer_key_id)
      current_number = meta.crl_number

      try do
        tbs = build_tbs(signing_key, revoked, current_number, now, next_update)
        tbs_der = :public_key.der_encode(:TBSCertList, tbs)
        {sig_alg_id, signature} = sign_tbs(tbs_der, signing_key)
        cert_list = {:CertificateList, tbs, sig_alg_id, signature}
        der = :public_key.der_encode(:CertificateList, cert_list)

        update_metadata!(meta, current_number + 1, der, now)

        {der, current_number}
      rescue
        e -> Repo.rollback(e)
      end
    end)
    |> case do
      {:ok, {der, number}} -> {:ok, der, number}
      {:error, reason} -> {:error, reason}
    end
  end

  # ---- Metadata row management ----

  defp get_or_create_metadata_locked(issuer_key_id) do
    query =
      from c in CrlMetadata,
        where: c.issuer_key_id == ^issuer_key_id,
        lock: "FOR UPDATE"

    case Repo.one(query) do
      nil ->
        {:ok, meta} =
          %CrlMetadata{}
          |> CrlMetadata.changeset(%{
            issuer_key_id: issuer_key_id,
            crl_number: 1,
            generation_count: 0
          })
          |> Repo.insert()

        meta

      %CrlMetadata{} = meta ->
        meta
    end
  end

  defp update_metadata!(%CrlMetadata{} = meta, next_number, der, %DateTime{} = now) do
    meta
    |> CrlMetadata.changeset(%{
      crl_number: next_number,
      last_der_bytes: der,
      last_der_size: byte_size(der),
      last_generated_at: now,
      generation_count: meta.generation_count + 1
    })
    |> Repo.update!()
  end

  # ---- Data loading ----

  defp load_revoked(issuer_key_id) do
    from(cs in CertificateStatus,
      where: cs.issuer_key_id == ^issuer_key_id and cs.status == "revoked",
      order_by: [asc: cs.revoked_at],
      select: %{
        serial_number: cs.serial_number,
        revoked_at: cs.revoked_at,
        reason: cs.revocation_reason
      }
    )
    |> Repo.all()
  end

  # ---- TBSCertList construction ----

  defp build_tbs(signing_key, revoked, crl_number, this_update, next_update) do
    issuer = extract_issuer(signing_key.certificate_der)
    sig_alg_id = sig_alg_identifier(signing_key)

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
        nil ->
          []

        atom ->
          [
            {:Extension, @crl_reason_oid, false, :public_key.der_encode(:CRLReason, atom)}
          ]
      end

    {:TBSCertList_revokedCertificates_SEQOF, serial_int, utc_time(revoked_at), extensions}
  end

  # ---- Issuer extraction ----

  defp extract_issuer(cert_der) do
    plain = :public_key.pkix_decode_cert(cert_der, :plain)
    # :plain Certificate record:
    #   {:Certificate, tbsCertificate, signatureAlgorithm, signature}
    tbs = :erlang.element(2, plain)
    # :plain TBSCertificate fields (1-indexed inside the tuple where
    # position 1 is the record tag):
    #   2 version, 3 serialNumber, 4 signature, 5 issuer, 6 validity,
    #   7 subject, 8 subjectPublicKeyInfo, ...
    :erlang.element(7, tbs)
  end

  # ---- Time helpers ----

  defp utc_time(%DateTime{} = dt) do
    # DateTime.utc_now/0 and stored revoked_at columns are already UTC;
    # do NOT call DateTime.shift_zone!/2 (pulls in tzdata unnecessarily).
    charlist =
      dt
      |> Calendar.strftime("%y%m%d%H%M%SZ")
      |> String.to_charlist()

    {:utcTime, charlist}
  end

  # ---- Serial parsing ----

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

  # ---- Reason mapping ----

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

  # ---- Signature algorithm identifiers ----

  defp sig_alg_identifier(%{algorithm: "ecc_p256"}),
    do: {:AlgorithmIdentifier, @ecdsa_sha256_oid, :asn1_NOVALUE}

  defp sig_alg_identifier(%{algorithm: "ecc_p384"}),
    do: {:AlgorithmIdentifier, @ecdsa_sha384_oid, :asn1_NOVALUE}

  defp sig_alg_identifier(%{algorithm: alg}) when alg in ["rsa2048", "rsa4096"],
    do: {:AlgorithmIdentifier, @rsa_sha256_oid, <<5, 0>>}

  defp sig_alg_identifier(%{algorithm: alg}),
    do: raise(ArgumentError, "unsupported signing algorithm: #{inspect(alg)}")

  # ---- Signing ----

  defp sign_tbs(tbs_der, %{algorithm: "ecc_p256", private_key: priv}) do
    ec_priv =
      {:ECPrivateKey, 1, priv, {:namedCurve, @secp256r1_oid}, :asn1_NOVALUE, :asn1_NOVALUE}

    signature = :public_key.sign(tbs_der, :sha256, ec_priv)
    {sig_alg_identifier(%{algorithm: "ecc_p256"}), signature}
  end

  defp sign_tbs(tbs_der, %{algorithm: "ecc_p384", private_key: priv}) do
    ec_priv =
      {:ECPrivateKey, 1, priv, {:namedCurve, @secp384r1_oid}, :asn1_NOVALUE, :asn1_NOVALUE}

    signature = :public_key.sign(tbs_der, :sha384, ec_priv)
    {sig_alg_identifier(%{algorithm: "ecc_p384"}), signature}
  end

  defp sign_tbs(tbs_der, %{algorithm: alg, private_key: priv})
       when alg in ["rsa2048", "rsa4096"] do
    # SigningKeyStore stores RSA private keys as DER-encoded :RSAPrivateKey
    # bytes. :public_key.sign/3 requires the decoded record form, so we
    # decode at sign time. Same pattern as Ocsp.ResponseBuilder (fix D1).
    rsa_priv = :public_key.der_decode(:RSAPrivateKey, priv)
    signature = :public_key.sign(tbs_der, :sha256, rsa_priv)
    {sig_alg_identifier(%{algorithm: alg}), signature}
  end

  defp sign_tbs(_tbs, %{algorithm: alg}) do
    raise ArgumentError, "unsupported signing algorithm: #{inspect(alg)}"
  end
end
