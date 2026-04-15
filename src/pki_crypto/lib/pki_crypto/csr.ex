defmodule PkiCrypto.Csr do
  @moduledoc """
  PKCS#10 CertificationRequest (RFC 2986) parse + verify + generate.

  This module understands both classical (RSA/ECDSA) and PQC (ML-DSA,
  KAZ-SIGN) CSRs. The algorithm is detected from `subjectPublicKeyInfo.algorithm`
  via `PkiCrypto.AlgorithmRegistry.by_oid/1`.

  `parse/1` is the sole entry point for reading a CSR. `verify_pop/1` (Task 5
  of Phase 2) verifies the self-signature. `generate/3` (Task 4) emits a new
  CSR in either family.
  """

  alias PkiCrypto.{Asn1, AlgorithmRegistry}

  # ecPublicKey OID — when present in SPKI, the parameters carry the named curve OID
  @ec_public_key_oid {1, 2, 840, 10045, 2, 1}

  # Named curve OIDs to algorithm id strings
  @named_curve_oids %{
    {1, 2, 840, 10045, 3, 1, 7} => "ECC-P256",
    {1, 3, 132, 0, 34} => "ECC-P384"
  }

  @type parsed :: %{
          algorithm_id: String.t(),
          subject_dn: String.t(),
          subject_public_key: binary(),
          raw_tbs: binary(),
          signature: binary()
        }

  @doc """
  Parse a PEM-encoded PKCS#10 CSR.

  Returns `{:ok, parsed()}` on success or `{:error, reason}`. Possible reasons:
  `:not_a_csr`, `:unknown_algorithm_oid`, `:malformed_csr`.
  """
  @spec parse(binary()) :: {:ok, parsed()} | {:error, atom()}
  def parse(pem) when is_binary(pem) do
    with {:ok, der} <- decode_pem(pem) do
      do_parse(der)
    end
  rescue
    _ -> {:error, :malformed_csr}
  catch
    :throw, reason when is_atom(reason) -> {:error, reason}
  end

  @doc """
  Verify the Proof-of-Possession signature on a parsed CSR. Returns `:ok`
  on valid, `{:error, :invalid_signature}` otherwise.

  Every signing-path entry must call this before trusting a CSR.
  """
  @spec verify_pop(parsed()) :: :ok | {:error, :invalid_signature}
  def verify_pop(%{algorithm_id: algorithm_id, subject_public_key: pub, raw_tbs: tbs, signature: sig}) do
    algo = PkiCrypto.Registry.get(algorithm_id)

    case PkiCrypto.Algorithm.verify(algo, pub, sig, tbs) do
      :ok -> :ok
      _ -> {:error, :invalid_signature}
    end
  end

  @doc """
  Generate a PKCS#10 CSR for the given algorithm, key, and subject DN.

  Classical algorithms delegate to `X509.CSR.new` with a `:public_key`
  private-key record. PQC algorithms hand-roll the PKCS#10 structure and
  self-sign via the PQC signer. For PQC, the `key` argument must be a
  `%{public_key: binary, private_key: binary}` map.

  The `subject_dn` string is slash-separated: `"/CN=Foo/O=Bar"`.
  """
  @spec generate(String.t(), term(), String.t()) :: {:ok, binary()} | {:error, term()}
  def generate(algorithm_id, key, subject_dn)

  def generate(algorithm_id, private_key, subject_dn)
      when algorithm_id in ["ECC-P256", "ECC-P384", "RSA-2048", "RSA-4096"] do
    csr = X509.CSR.new(private_key, subject_dn)
    {:ok, X509.CSR.to_pem(csr)}
  end

  def generate(algorithm_id, %{public_key: pub, private_key: priv}, subject_dn) do
    with {:ok, %{family: family, public_key_oid: pk_oid, sig_alg_oid: sig_oid}} <-
           AlgorithmRegistry.by_id(algorithm_id),
         true <- family in [:ml_dsa, :kaz_sign, :slh_dsa] do
      cri_der = build_cri(pk_oid, pub, subject_dn)

      algo = PkiCrypto.Registry.get(algorithm_id)
      {:ok, signature} = PkiCrypto.Algorithm.sign(algo, priv, cri_der)

      sig_alg_der = Asn1.sequence([Asn1.oid(sig_oid)])
      csr_der = Asn1.sequence([cri_der, sig_alg_der, Asn1.bit_string(signature)])

      pem = :public_key.pem_encode([{:CertificationRequest, csr_der, :not_encrypted}])
      {:ok, pem}
    else
      :error -> {:error, :unknown_algorithm}
      false -> {:error, :algorithm_not_pqc}
    end
  end

  # Build CertificationRequestInfo body.
  defp build_cri(pk_oid, public_key, subject_dn) do
    version = Asn1.integer(0)
    subject = encode_name(subject_dn)

    spki =
      Asn1.sequence([
        Asn1.sequence([Asn1.oid(pk_oid)]),
        Asn1.bit_string(public_key)
      ])

    # attributes [0] IMPLICIT SET OF Attribute — empty
    attrs = Asn1.tagged(0, :explicit, <<>>)

    Asn1.sequence([version, subject, spki, attrs])
  end

  defp encode_name(dn_string) do
    parts =
      dn_string
      |> String.split("/", trim: true)
      |> Enum.map(fn part ->
        [key, value] = String.split(part, "=", parts: 2)
        {dn_key_to_oid(key), value}
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

  # --- Private ---

  defp decode_pem(pem) do
    try do
      case :public_key.pem_decode(pem) do
        [{:CertificationRequest, der, _}] -> {:ok, der}
        _ -> {:error, :not_a_csr}
      end
    rescue
      _ -> {:error, :not_a_csr}
    end
  end

  defp do_parse(der) do
    {outer_body, <<>>} = Asn1.read_sequence(der)

    [cri_der, _sig_alg_der, sig_bit_string_der] =
      case Asn1.read_sequence_items(outer_body) do
        [_, _, _] = items -> items
        _ -> throw(:malformed_csr)
      end

    {signature, <<>>} = Asn1.read_bit_string(sig_bit_string_der)

    cri = parse_cri(cri_der)

    algorithm_id = resolve_algorithm_id(cri.spki_oid, cri.spki_curve_oid)

    {:ok,
     %{
       algorithm_id: algorithm_id,
       subject_dn: cri.subject_dn,
       subject_public_key: cri.spki_key,
       raw_tbs: cri_der,
       signature: signature
     }}
  end

  # Resolve algorithm id from the SPKI OID.
  # For ECDSA, try to use the named curve OID from AlgorithmIdentifier parameters.
  # Falls back to public_key_oid search across known algorithm ids.
  defp resolve_algorithm_id(spki_oid, curve_oid) do
    # 1. Direct sig_alg_oid match
    case AlgorithmRegistry.by_oid(spki_oid) do
      {:ok, %{id: id}} ->
        id

      :error ->
        # 2. For ECDSA: use named curve OID to find exact algorithm
        case {spki_oid, curve_oid} do
          {@ec_public_key_oid, curve} when not is_nil(curve) ->
            case Map.get(@named_curve_oids, curve) do
              nil -> fallback_by_public_key_oid(spki_oid)
              id -> id
            end

          _ ->
            fallback_by_public_key_oid(spki_oid)
        end
    end
  end

  # Search all known algorithm ids for a matching public_key_oid.
  # Returns first match; throws :unknown_algorithm_oid if none found.
  defp fallback_by_public_key_oid(oid) do
    ids = ~w[RSA-2048 RSA-4096 ECC-P256 ECC-P384 ML-DSA-44 ML-DSA-65 ML-DSA-87 KAZ-SIGN-128 KAZ-SIGN-192 KAZ-SIGN-256]

    result =
      Enum.find_value(ids, nil, fn id ->
        case AlgorithmRegistry.by_id(id) do
          {:ok, %{public_key_oid: ^oid}} -> id
          _ -> nil
        end
      end)

    case result do
      nil -> throw(:unknown_algorithm_oid)
      id -> id
    end
  end

  defp parse_cri(<<0x30, _::binary>> = cri_der) do
    {body, <<>>} = Asn1.read_sequence(cri_der)
    items = Asn1.read_sequence_items(body)

    [version_der, subject_der, spki_der | _rest_attrs] = items
    {0, <<>>} = Asn1.read_integer(version_der)

    subject_dn = decode_subject_dn(subject_der)
    {spki_oid, spki_curve_oid, spki_key} = decode_spki(spki_der)

    %{subject_dn: subject_dn, spki_oid: spki_oid, spki_curve_oid: spki_curve_oid, spki_key: spki_key}
  end

  defp decode_subject_dn(<<0x30, _::binary>> = name_der) do
    {name_body, <<>>} = Asn1.read_sequence(name_der)
    rdns = Asn1.read_sequence_items(name_body)
    parts = Enum.flat_map(rdns, &decode_rdn/1)
    "/" <> Enum.join(parts, "/")
  end

  defp decode_rdn(<<0x31, rest::binary>>) do
    {_len, body, _after} = Asn1.decode_length(rest)
    atvs = Asn1.read_sequence_items(body)

    Enum.map(atvs, fn atv ->
      {atv_body, <<>>} = Asn1.read_sequence(atv)
      [oid_der, value_der] = Asn1.read_sequence_items(atv_body)
      {oid_tuple, <<>>} = Asn1.read_oid(oid_der)
      key = oid_to_dn_key(oid_tuple)
      value = decode_directory_string(value_der)
      "#{key}=#{value}"
    end)
  end

  defp oid_to_dn_key({2, 5, 4, 3}), do: "CN"
  defp oid_to_dn_key({2, 5, 4, 6}), do: "C"
  defp oid_to_dn_key({2, 5, 4, 7}), do: "L"
  defp oid_to_dn_key({2, 5, 4, 8}), do: "ST"
  defp oid_to_dn_key({2, 5, 4, 10}), do: "O"
  defp oid_to_dn_key({2, 5, 4, 11}), do: "OU"
  defp oid_to_dn_key(other), do: Enum.join(Tuple.to_list(other), ".")

  defp decode_directory_string(<<_tag, rest::binary>>) do
    {_len, body, _after} = Asn1.decode_length(rest)
    body
  end

  # Decode SubjectPublicKeyInfo, returning {algorithm_oid, curve_oid_or_nil, public_key_bytes}.
  # For ECDSA keys the AlgorithmIdentifier parameters carry the named curve OID.
  defp decode_spki(<<0x30, _::binary>> = spki_der) do
    {body, <<>>} = Asn1.read_sequence(spki_der)
    [alg_id_der, bit_string_der] = Asn1.read_sequence_items(body)
    {alg_body, <<>>} = Asn1.read_sequence(alg_id_der)
    alg_items = Asn1.read_sequence_items(alg_body)

    {oid, <<>>} = Asn1.read_oid(hd(alg_items))

    # Extract named curve OID if present (ECDSA uses this)
    curve_oid =
      case {oid, tl(alg_items)} do
        {@ec_public_key_oid, [params_der | _]} ->
          try do
            {curve_oid, _} = Asn1.read_oid(params_der)
            curve_oid
          rescue
            _ -> nil
          end

        _ ->
          nil
      end

    {key, <<>>} = Asn1.read_bit_string(bit_string_der)
    {oid, curve_oid, key}
  end
end
