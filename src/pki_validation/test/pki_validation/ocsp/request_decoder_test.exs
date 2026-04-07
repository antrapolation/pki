defmodule PkiValidation.Ocsp.RequestDecoderTest do
  use ExUnit.Case, async: true

  alias PkiValidation.Ocsp.RequestDecoder

  # Pre-encoded DER for AlgorithmIdentifier { id-sha1, NULL }
  # SEQUENCE { OID 1.3.14.3.2.26, NULL }
  @sha1_alg_der <<0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A, 0x05, 0x00>>

  # OID 1.3.6.1.5.5.7.48.1.2 (id-pkix-ocsp-nonce)
  @nonce_oid {1, 3, 6, 1, 5, 5, 7, 48, 1, 2}

  test "decodes a DER OCSP request with a single CertID and no nonce" do
    der = build_request(serial: 12345, nonce: nil)

    assert {:ok, decoded} = RequestDecoder.decode(der)
    assert is_list(decoded.cert_ids)
    assert [cert_id] = decoded.cert_ids
    assert is_binary(cert_id.issuer_name_hash)
    assert is_binary(cert_id.issuer_key_hash)
    assert byte_size(cert_id.issuer_name_hash) == 20
    assert byte_size(cert_id.issuer_key_hash) == 20
    assert cert_id.serial_number == 12345
    assert is_nil(decoded.nonce)
  end

  test "extracts nonce extension when present" do
    nonce = :crypto.strong_rand_bytes(16)
    der = build_request(serial: 99999, nonce: nonce)

    assert {:ok, decoded} = RequestDecoder.decode(der)
    assert decoded.nonce == nonce
    assert [cert_id] = decoded.cert_ids
    assert cert_id.serial_number == 99999
  end

  test "returns {:error, :malformed} for garbage input" do
    assert {:error, :malformed} = RequestDecoder.decode(<<0, 1, 2, 3>>)
  end

  test "returns {:error, :malformed} for an empty binary" do
    assert {:error, :malformed} = RequestDecoder.decode(<<>>)
  end

  test "decodes a TBSRequest with an empty requestList" do
    tbs = {:TBSRequest, :v1, :asn1_NOVALUE, [], :asn1_NOVALUE}
    ocsp_req = {:OCSPRequest, tbs, :asn1_NOVALUE}
    {:ok, der} = :OCSP.encode(:OCSPRequest, ocsp_req)
    der = IO.iodata_to_binary(der)

    assert {:ok, decoded} = RequestDecoder.decode(der)
    assert decoded.cert_ids == []
    assert is_nil(decoded.nonce)
  end

  test "returns {:error, :malformed} for a truncated DER request without crashing" do
    full = build_request(serial: 77, nonce: :crypto.strong_rand_bytes(16))
    half = binary_part(full, 0, div(byte_size(full), 2))

    assert {:error, :malformed} = RequestDecoder.decode(half)
  end

  test "decodes a request with multiple CertIDs" do
    cert_id_a = build_cert_id(serial: 1)
    cert_id_b = build_cert_id(serial: 2)
    request_a = {:Request, cert_id_a, :asn1_NOVALUE}
    request_b = {:Request, cert_id_b, :asn1_NOVALUE}
    tbs = {:TBSRequest, :v1, :asn1_NOVALUE, [request_a, request_b], :asn1_NOVALUE}
    ocsp_req = {:OCSPRequest, tbs, :asn1_NOVALUE}
    {:ok, der} = :OCSP.encode(:OCSPRequest, ocsp_req)
    der = IO.iodata_to_binary(der)

    assert {:ok, decoded} = RequestDecoder.decode(der)
    assert length(decoded.cert_ids) == 2
    assert Enum.map(decoded.cert_ids, & &1.serial_number) == [1, 2]
  end

  # ---- Helpers ----

  defp build_request(opts) do
    cert_id = build_cert_id(serial: opts[:serial])
    request = {:Request, cert_id, :asn1_NOVALUE}

    extensions =
      case opts[:nonce] do
        nil ->
          :asn1_NOVALUE

        nonce ->
          # extnValue is the DER encoding of the value (OCTET STRING wrapping the nonce).
          inner_octet_string = <<0x04, byte_size(nonce)>> <> nonce

          :public_key.der_encode(:Extensions, [
            {:Extension, @nonce_oid, false, inner_octet_string}
          ])
      end

    tbs = {:TBSRequest, :v1, :asn1_NOVALUE, [request], extensions}
    ocsp_req = {:OCSPRequest, tbs, :asn1_NOVALUE}
    {:ok, der} = :OCSP.encode(:OCSPRequest, ocsp_req)
    IO.iodata_to_binary(der)
  end

  defp build_cert_id(opts) do
    {
      :CertID,
      @sha1_alg_der,
      :crypto.strong_rand_bytes(20),
      :crypto.strong_rand_bytes(20),
      opts[:serial]
    }
  end
end
