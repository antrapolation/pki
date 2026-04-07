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
    # Use the :plain decoder so the raw subjectPublicKey BIT STRING bytes are
    # preserved exactly as they appear on the wire. The :otp decoder eagerly
    # parses the key into algorithm-specific records (e.g. RSAPublicKey), and
    # re-encoding via :public_key.der_encode/2 may produce bytes that differ
    # from the original DER (e.g. leading-zero handling on the modulus),
    # which makes the issuerKeyHash diverge from openssl's output.
    #
    # The :plain Certificate record is:
    #   {:Certificate, tbsCertificate, signatureAlgorithm, signature}
    # The :plain TBSCertificate record exposes subjectPublicKeyInfo at
    # element 8 (1-indexed). The :plain SubjectPublicKeyInfo record is:
    #   {:SubjectPublicKeyInfo, algorithm, raw_key_bytes :: binary}
    # OTP already strips the leading "unused bits" byte from the BIT STRING,
    # so element 3 is the raw value (excluding tag and length) per
    # RFC 6960 section 4.1.1.
    plain_cert = :public_key.pkix_decode_cert(der_cert, :plain)
    tbs = :erlang.element(2, plain_cert)
    spki = :erlang.element(8, tbs)
    raw_key_bytes = :erlang.element(3, spki)
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

end
