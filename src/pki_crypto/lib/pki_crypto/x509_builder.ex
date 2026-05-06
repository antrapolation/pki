defmodule PkiCrypto.X509Builder do
  @moduledoc """
  X.509 v3 TBSCertificate construction and signing with cross-algorithm support.

  Phase 2: classical issuer (RSA/ECDSA) signs a subject with any algorithm
  (classical or PQC). PQC issuer paths are stubbed until Phase 3.

  Extensions emitted (for sub-CA issuance):
  - basicConstraints (critical) CA:TRUE
  - keyUsage (critical) keyCertSign | cRLSign
  - subjectKeyIdentifier — SHA-1 of subject SPKI bit-string content
  - authorityKeyIdentifier — keyIdentifier = SHA-1 of issuer SPKI bit-string content
  """

  alias PkiCrypto.{Asn1, AlgorithmRegistry}

  @type issuer_ref :: %{cert_der: binary(), algorithm_id: String.t()}

  @doc """
  Build a TBSCertificate DER from a parsed CSR, issuer reference, target
  subject DN, validity in days, and serial number.

  Returns `{:ok, tbs_der, signature_algorithm_oid}`.
  """
  @spec build_tbs_cert(
          PkiCrypto.Csr.parsed(),
          issuer_ref(),
          String.t(),
          pos_integer(),
          pos_integer()
        ) :: {:ok, binary(), tuple()} | {:error, term()}
  def build_tbs_cert(csr, issuer_ref, subject_dn, validity_days, serial) do
    with {:ok, subject_meta} <- AlgorithmRegistry.by_id(csr.algorithm_id),
         {:ok, issuer_meta} <- AlgorithmRegistry.by_id(issuer_ref.algorithm_id) do
      version = Asn1.tagged(0, :explicit, Asn1.integer(2))
      serial_der = Asn1.integer(serial)
      sig_alg = Asn1.sequence([Asn1.oid(issuer_meta.sig_alg_oid)])
      issuer_name = extract_subject_name_der(issuer_ref.cert_der)

      now = DateTime.utc_now() |> DateTime.truncate(:second)
      not_after = DateTime.add(now, validity_days * 86_400, :second)
      validity = Asn1.sequence([encode_time(now), encode_time(not_after)])

      subject_name = encode_name_from_dn_string(subject_dn)

      spki =
        Asn1.sequence([
          Asn1.sequence([Asn1.oid(subject_meta.public_key_oid)]),
          Asn1.bit_string(csr.subject_public_key)
        ])

      extensions = build_sub_ca_extensions(csr.subject_public_key, issuer_ref.cert_der)

      tbs =
        Asn1.sequence([
          version,
          serial_der,
          sig_alg,
          issuer_name,
          validity,
          subject_name,
          spki,
          extensions
        ])

      {:ok, tbs, issuer_meta.sig_alg_oid}
    else
      :error -> {:error, :unknown_algorithm}
    end
  end

  @doc """
  Sign a TBS DER with the issuer's private key in the given algorithm.
  Wraps `(tbs, sigAlg, signature)` into a final X.509 Certificate DER.

  Classical issuers use `:public_key.sign/3` with the algorithm-appropriate
  hash (sha256 for RSA, sha256/sha384 for ECDSA). PQC issuers will be
  implemented in Phase 3.
  """
  @spec sign_tbs(binary(), String.t(), term()) :: {:ok, binary()} | {:error, term()}
  def sign_tbs(tbs_der, issuer_algorithm_id, issuer_private_key) do
    case AlgorithmRegistry.by_id(issuer_algorithm_id) do
      {:ok, %{family: :ecdsa} = meta} ->
        hash = ecdsa_hash_for(issuer_algorithm_id)
        signature = :public_key.sign(tbs_der, hash, issuer_private_key)
        {:ok, wrap_cert(tbs_der, meta.sig_alg_oid, signature)}

      {:ok, %{family: :rsa} = meta} ->
        signature = :public_key.sign(tbs_der, :sha256, issuer_private_key)
        {:ok, wrap_cert(tbs_der, meta.sig_alg_oid, signature)}

      {:ok, %{family: family} = meta} when family in [:ml_dsa, :kaz_sign, :slh_dsa] ->
        algo = PkiCrypto.Registry.get(issuer_algorithm_id)

        case PkiCrypto.Algorithm.sign(algo, issuer_private_key, tbs_der) do
          {:ok, signature} -> {:ok, wrap_cert(tbs_der, meta.sig_alg_oid, signature)}
          other -> {:error, {:pqc_sign_failed, other}}
        end

      :error ->
        {:error, :unknown_issuer_algorithm}
    end
  end

  @doc """
  Build the TBSCertificate DER for a self-signed root certificate without signing it.

  Returns `{:ok, tbs_der, sig_alg_oid}`. The caller can sign `tbs_der` externally
  (e.g. via an HSM) and assemble the final certificate with `assemble_cert/3`.
  """
  @spec build_self_signed_tbs(String.t(), term(), String.t(), pos_integer()) ::
          {:ok, binary(), tuple()} | {:error, term()}
  def build_self_signed_tbs(algorithm_id, public_key, subject_dn, validity_days) do
    with {:ok, %{public_key_oid: pk_oid, sig_alg_oid: sig_oid}} <-
           AlgorithmRegistry.by_id(algorithm_id) do
      version = Asn1.tagged(0, :explicit, Asn1.integer(2))
      serial = Asn1.integer(:crypto.strong_rand_bytes(8) |> :binary.decode_unsigned())
      sig_alg = Asn1.sequence([Asn1.oid(sig_oid)])
      name = encode_name_from_dn_string(subject_dn)

      now = DateTime.utc_now() |> DateTime.truncate(:second)
      not_after = DateTime.add(now, validity_days * 86_400, :second)
      validity = Asn1.sequence([encode_time(now), encode_time(not_after)])

      spki_alg_id = build_spki_alg_id(algorithm_id, pk_oid)
      spki_pub_bytes = extract_spki_public_bytes(algorithm_id, public_key)
      spki = Asn1.sequence([spki_alg_id, Asn1.bit_string(spki_pub_bytes)])

      bc = make_extension({2, 5, 29, 19}, true, Asn1.sequence([Asn1.boolean(true)]))
      ku = make_extension({2, 5, 29, 15}, true, key_usage_keycertsign_crlsign())
      ski = make_extension({2, 5, 29, 14}, false, Asn1.octet_string(sha1(spki_pub_bytes)))
      extensions = Asn1.tagged(3, :explicit, Asn1.sequence([bc, ku, ski]))

      tbs =
        Asn1.sequence([version, serial, sig_alg, name, validity, name, spki, extensions])

      {:ok, tbs, sig_oid}
    else
      :error -> {:error, :unknown_algorithm}
    end
  end

  @doc """
  Build and sign a self-signed X.509 root certificate.

  For classical algorithms the `private_key` in the map is a `:public_key`
  record and `public_key` is the matching record form (ECDSA: `{{:ECPoint, point}, params}`,
  RSA: `:RSAPublicKey` record). For PQC algorithms both are raw NIF byte strings.

  `subject_dn` is slash-separated (`"/CN=Root/O=Example"`). `validity_days`
  applies from now.

  Returns `{:ok, cert_der}`.
  """
  @spec self_sign(String.t(), map(), String.t(), pos_integer()) ::
          {:ok, binary()} | {:error, term()}
  def self_sign(algorithm_id, %{public_key: pub, private_key: priv}, subject_dn, validity_days) do
    with {:ok, tbs, _sig_oid} <- build_self_signed_tbs(algorithm_id, pub, subject_dn, validity_days) do
      sign_tbs(tbs, algorithm_id, priv)
    end
  end

  # SPKI AlgorithmIdentifier: ECDSA requires named-curve OID in parameters,
  # RSA requires NULL parameters, PQC has no parameters.
  defp build_spki_alg_id("ECC-P256", pk_oid) do
    Asn1.sequence([Asn1.oid(pk_oid), Asn1.oid({1, 2, 840, 10045, 3, 1, 7})])
  end

  defp build_spki_alg_id("ECC-P384", pk_oid) do
    Asn1.sequence([Asn1.oid(pk_oid), Asn1.oid({1, 3, 132, 0, 34})])
  end

  defp build_spki_alg_id(algorithm_id, pk_oid) do
    case AlgorithmRegistry.by_id(algorithm_id) do
      {:ok, %{family: :rsa}} -> Asn1.sequence([Asn1.oid(pk_oid), Asn1.null()])
      _ -> Asn1.sequence([Asn1.oid(pk_oid)])
    end
  end

  # SPKI subjectPublicKey bytes — raw public-key bytes for the bit_string.
  defp extract_spki_public_bytes(algorithm_id, pub) do
    case AlgorithmRegistry.by_id(algorithm_id) do
      {:ok, %{family: family}} when family in [:ml_dsa, :kaz_sign, :slh_dsa] ->
        pub

      {:ok, %{family: :ecdsa}} ->
        case pub do
          {{:ECPoint, point}, _params} -> point
          <<_::binary>> -> pub
          other -> raise "unexpected ECDSA public key shape: #{inspect(other)}"
        end

      {:ok, %{family: :rsa}} ->
        :public_key.der_encode(:RSAPublicKey, pub)
    end
  end

  defp ecdsa_hash_for("ECC-P256"), do: :sha256
  defp ecdsa_hash_for("ECC-P384"), do: :sha384

  @doc """
  Assemble a full X.509 Certificate DER from a TBS DER, signature algorithm OID,
  and raw signature bytes.

  Used by callers (e.g. CertificateSigning) that build TBS first, sign via an
  external adapter (HSM), then assemble the final certificate.
  """
  @spec assemble_cert(binary(), tuple(), binary()) :: binary()
  def assemble_cert(tbs_der, sig_alg_oid, signature) do
    wrap_cert(tbs_der, sig_alg_oid, signature)
  end

  defp wrap_cert(tbs_der, sig_alg_oid, signature) do
    sig_alg = Asn1.sequence([Asn1.oid(sig_alg_oid)])
    Asn1.sequence([tbs_der, sig_alg, Asn1.bit_string(signature)])
  end

  # --- Extensions ---

  defp build_sub_ca_extensions(subject_pub, issuer_cert_der) do
    bc = make_extension({2, 5, 29, 19}, true, Asn1.sequence([Asn1.boolean(true)]))
    ku = make_extension({2, 5, 29, 15}, true, key_usage_keycertsign_crlsign())
    ski = make_extension({2, 5, 29, 14}, false, Asn1.octet_string(sha1(subject_pub)))
    aki = make_extension({2, 5, 29, 35}, false, aki_body(issuer_cert_der))

    ext_seq = Asn1.sequence([bc, ku, ski, aki])
    Asn1.tagged(3, :explicit, ext_seq)
  end

  defp make_extension(oid, critical, value_der) do
    items =
      if critical do
        [Asn1.oid(oid), Asn1.boolean(true), Asn1.octet_string(value_der)]
      else
        [Asn1.oid(oid), Asn1.octet_string(value_der)]
      end

    Asn1.sequence(items)
  end

  # KeyUsage BIT STRING: bits 5 (keyCertSign) and 6 (cRLSign) set → 0x06, with 1 unused bit.
  defp key_usage_keycertsign_crlsign do
    content = <<0x01, 0x06>>
    <<0x03, byte_size(content)>> <> content
  end

  defp aki_body(issuer_cert_der) do
    issuer_spki_content = extract_spki_bit_string_content(issuer_cert_der)
    ki = sha1(issuer_spki_content)
    # [0] IMPLICIT OCTET STRING — tag 0x80, length, bytes
    ki_tagged = <<0x80, byte_size(ki)>> <> ki
    Asn1.sequence([ki_tagged])
  end

  # --- Issuer cert extraction ---

  defp extract_subject_name_der(cert_der) do
    {tbs_items, _spki} = tbs_items_and_spki(cert_der)
    [_serial, _sig_alg, _issuer, _validity, subject | _] = tbs_items
    subject
  end

  defp extract_spki_bit_string_content(cert_der) do
    {_tbs_items, spki_der} = tbs_items_and_spki(cert_der)
    {spki_body, <<>>} = Asn1.read_sequence(spki_der)
    [_alg_id, bit_string_der] = Asn1.read_sequence_items(spki_body)
    {content, <<>>} = Asn1.read_bit_string(bit_string_der)
    content
  end

  defp tbs_items_and_spki(cert_der) do
    {body, <<>>} = Asn1.read_sequence(cert_der)
    [tbs_der | _] = Asn1.read_sequence_items(body)
    {tbs_body, <<>>} = Asn1.read_sequence(tbs_der)

    items = Asn1.read_sequence_items(tbs_body) |> drop_optional_version()
    [_serial, _sig_alg, _issuer, _validity, _subject, spki_der | _] = items
    {items, spki_der}
  end

  defp drop_optional_version([<<0xA0, _::binary>> | rest]), do: rest
  defp drop_optional_version(items), do: items

  # --- Time / Name helpers ---

  defp encode_time(%DateTime{year: y} = dt) when y >= 1950 and y < 2050, do: Asn1.utc_time(dt)
  defp encode_time(dt), do: Asn1.generalized_time(dt)

  defp encode_name_from_dn_string(dn_string) do
    parts =
      dn_string
      |> String.split("/", trim: true)
      |> Enum.map(fn part ->
        [k, v] = String.split(part, "=", parts: 2)
        {dn_key_to_oid(k), v}
      end)

    rdns =
      Enum.map(parts, fn {oid, value} ->
        atv =
          Asn1.sequence([
            Asn1.oid(oid),
            # UTF8String tag 0x0C
            <<0x0C, byte_size(value)>> <> value
          ])

        Asn1.set([atv])
      end)

    Asn1.sequence(rdns)
  end

  defp dn_key_to_oid("CN"), do: {2, 5, 4, 3}
  defp dn_key_to_oid("C"), do: {2, 5, 4, 6}
  defp dn_key_to_oid("L"), do: {2, 5, 4, 7}
  defp dn_key_to_oid("ST"), do: {2, 5, 4, 8}
  defp dn_key_to_oid("O"), do: {2, 5, 4, 10}
  defp dn_key_to_oid("OU"), do: {2, 5, 4, 11}

  defp sha1(bytes), do: :crypto.hash(:sha, bytes)
end
