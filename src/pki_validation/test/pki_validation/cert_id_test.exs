defmodule PkiValidation.CertIdTest do
  use ExUnit.Case, async: true

  alias PkiValidation.CertId

  setup do
    {:ok, der_cert: generate_test_cert()}
  end

  test "issuer_name_hash returns 20-byte SHA-1 hash", %{der_cert: der} do
    hash = CertId.issuer_name_hash(der)
    assert is_binary(hash)
    assert byte_size(hash) == 20
  end

  test "issuer_name_hash is deterministic", %{der_cert: der} do
    assert CertId.issuer_name_hash(der) == CertId.issuer_name_hash(der)
  end

  test "issuer_key_hash returns 20-byte SHA-1 hash", %{der_cert: der} do
    hash = CertId.issuer_key_hash(der)
    assert is_binary(hash)
    assert byte_size(hash) == 20
  end

  test "issuer_key_hash is deterministic", %{der_cert: der} do
    assert CertId.issuer_key_hash(der) == CertId.issuer_key_hash(der)
  end

  test "issuer_key_hash matches openssl-computed hash for an RSA cert" do
    # Fixture-based test: the .der is a 2048-bit RSA self-signed cert and
    # the .bin is the 20-byte SHA-1 hash of the raw subjectPublicKey BIT STRING
    # value as computed by `openssl ocsp -reqout` (cross-checked at fixture
    # creation time). This guards the C1 regression where re-encoding RSA via
    # the :otp decoder produced bytes that didn't match openssl.
    fixture_dir = Path.expand("../fixtures", __DIR__)
    rsa_der = File.read!(Path.join(fixture_dir, "test_issuer_rsa.der"))
    expected_hash = File.read!(Path.join(fixture_dir, "test_issuer_rsa_keyhash.bin"))

    assert byte_size(expected_hash) == 20
    assert CertId.issuer_key_hash(rsa_der) == expected_hash
  end

  test "matches? returns true when name_hash, key_hash, and serial all match" do
    name_hash = :crypto.strong_rand_bytes(20)
    key_hash = :crypto.strong_rand_bytes(20)
    serial = 12345

    assert CertId.matches?(
             %{issuer_name_hash: name_hash, issuer_key_hash: key_hash, serial_number: serial},
             %{name_hash: name_hash, key_hash: key_hash, serial_number: serial}
           )
  end

  test "matches? returns false when serial differs" do
    name_hash = :crypto.strong_rand_bytes(20)
    key_hash = :crypto.strong_rand_bytes(20)

    refute CertId.matches?(
             %{issuer_name_hash: name_hash, issuer_key_hash: key_hash, serial_number: 1},
             %{name_hash: name_hash, key_hash: key_hash, serial_number: 2}
           )
  end

  test "matches? returns false when name_hash differs" do
    a = :crypto.strong_rand_bytes(20)
    b = :crypto.strong_rand_bytes(20)
    key_hash = :crypto.strong_rand_bytes(20)

    refute CertId.matches?(
             %{issuer_name_hash: a, issuer_key_hash: key_hash, serial_number: 1},
             %{name_hash: b, key_hash: key_hash, serial_number: 1}
           )
  end

  defp generate_test_cert do
    try do
      %{cert: der} = :public_key.pkix_test_root_cert(~c"Test Issuer", [])
      der
    rescue
      _ -> load_fixture()
    end
  end

  defp load_fixture do
    fixture_path = Path.expand("../fixtures/test_issuer.der", __DIR__)
    File.read!(fixture_path)
  end
end
