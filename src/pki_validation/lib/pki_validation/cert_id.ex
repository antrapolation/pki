defmodule PkiValidation.CertId do
  @moduledoc """
  RFC 6960 CertID helpers.

      CertID ::= SEQUENCE {
          hashAlgorithm   AlgorithmIdentifier,
          issuerNameHash  OCTET STRING,
          issuerKeyHash   OCTET STRING,
          serialNumber    CertificateSerialNumber }

  We use SHA-1 throughout (the OCSP default per RFC 6960). `issuerNameHash`
  is the hash of the DER-encoded issuer DN; `issuerKeyHash` is the hash of
  the raw public key BIT STRING value (excluding tag and length) per
  RFC 6960 section 4.1.1.
  """

  @doc """
  Compute the SHA-1 hash of an issuer's DER-encoded subject DN.

  Input is a DER-encoded X.509 certificate (the issuer's certificate). The
  function extracts the certificate's subject field, re-encodes it as a
  DER `Name`, and SHA-1 hashes the result.
  """
  @spec issuer_name_hash(binary()) :: binary()
  def issuer_name_hash(der_cert) when is_binary(der_cert) do
    otp_cert = :public_key.pkix_decode_cert(der_cert, :otp)
    tbs = :erlang.element(2, otp_cert)
    # OTPTBSCertificate fields (positions inside the record tuple, where
    # position 1 is the record tag :OTPTBSCertificate):
    #   2 version, 3 serialNumber, 4 signature, 5 issuer, 6 validity,
    #   7 subject, 8 subjectPublicKeyInfo, 9 issuerUID, 10 subjectUID,
    #   11 extensions
    subject = :erlang.element(7, tbs)
    subject_der = :public_key.der_encode(:Name, subject)
    :crypto.hash(:sha, subject_der)
  end

  @doc """
  Compute the SHA-1 hash of an issuer's public key BIT STRING.

  Per RFC 6960 section 4.1.1: "issuerKeyHash is the hash of the issuer's
  public key. The hash shall be calculated over the value (excluding tag
  and length) of the subject public key field in the issuer's certificate."
  """
  @spec issuer_key_hash(binary()) :: binary()
  def issuer_key_hash(der_cert) when is_binary(der_cert) do
    otp_cert = :public_key.pkix_decode_cert(der_cert, :otp)
    tbs = :erlang.element(2, otp_cert)
    spki = :erlang.element(8, tbs)
    # OTPSubjectPublicKeyInfo: {:OTPSubjectPublicKeyInfo, algorithm, public_key}
    raw_key_bytes = extract_key_bytes(:erlang.element(3, spki))
    :crypto.hash(:sha, raw_key_bytes)
  end

  @doc """
  Returns true if a request CertID matches a known issuer's hashes and serial.

    * `request_cert_id` shape: `%{issuer_name_hash, issuer_key_hash, serial_number}`
    * `known` shape: `%{name_hash, key_hash, serial_number}`
  """
  @spec matches?(map(), map()) :: boolean()
  def matches?(request_cert_id, known) do
    request_cert_id.issuer_name_hash == known.name_hash and
      request_cert_id.issuer_key_hash == known.key_hash and
      request_cert_id.serial_number == known.serial_number
  end

  # Convert various OTP public key representations into the raw BIT STRING bytes
  # (the "value excluding tag and length" of the subjectPublicKey field).
  defp extract_key_bytes(bytes) when is_binary(bytes), do: bytes
  defp extract_key_bytes({:ECPoint, point}) when is_binary(point), do: point

  defp extract_key_bytes({:RSAPublicKey, _modulus, _exponent} = rsa) do
    :public_key.der_encode(:RSAPublicKey, rsa)
  end

  defp extract_key_bytes(other) do
    raise "Unsupported public key shape for CertID: #{inspect(other)}"
  end
end
