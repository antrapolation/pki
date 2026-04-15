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
