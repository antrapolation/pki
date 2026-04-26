defmodule PkiValidation.Crl.DerGeneratorTest do
  use ExUnit.Case, async: false

  alias PkiMnesia.{TestHelper, Repo}
  alias PkiMnesia.Structs.CertificateStatus
  alias PkiValidation.Crl.DerGenerator

  @secp256r1_oid {1, 2, 840, 10045, 3, 1, 7}
  @secp384r1_oid {1, 3, 132, 0, 34}

  setup do
    dir = TestHelper.setup_mnesia()
    on_exit(fn -> TestHelper.teardown_mnesia(dir) end)
    :ok
  end

  defp ecc_signing_key(algorithm \\ "ECC-P256") do
    {curve, oid} =
      if algorithm == "ECC-P384",
        do: {:secp384r1, @secp384r1_oid},
        else: {:secp256r1, @secp256r1_oid}

    {pub, priv} = :crypto.generate_key(:ecdh, curve)
    ec_priv = {:ECPrivateKey, 1, priv, {:namedCurve, oid}, pub, :asn1_NOVALUE}
    %{cert: cert_der} = :public_key.pkix_test_root_cert(~c"CRL Test Issuer", [{:key, ec_priv}])

    %{
      algorithm: algorithm,
      private_key: :public_key.der_encode(:ECPrivateKey, ec_priv),
      certificate_der: cert_der
    }
  end

  defp pqc_signing_key(algorithm) do
    algo = PkiCrypto.Registry.get(algorithm)
    {:ok, %{private_key: sk}} = PkiCrypto.Algorithm.generate_keypair(algo)
    # Use a classical cert for extract_issuer — OTP cannot build PQC self-signed certs.
    {pub_ecc, priv_ecc} = :crypto.generate_key(:ecdh, :secp256r1)
    ecc_key = {:ECPrivateKey, 1, priv_ecc, {:namedCurve, @secp256r1_oid}, pub_ecc, :asn1_NOVALUE}
    %{cert: cert_der} = :public_key.pkix_test_root_cert(~c"CRL PQC Test Issuer", [{:key, ecc_key}])
    %{algorithm: algorithm, private_key: sk, certificate_der: cert_der}
  end

  defp decode_crl(der) do
    {:CertificateList, tbs, {:CertificateList_algorithmIdentifier, oid, _}, _sig} =
      :public_key.der_decode(:CertificateList, der)

    {:TBSCertList, _version, {:TBSCertList_signature, _tbs_oid, _}, _issuer, _this, _next,
     revoked, _exts} = tbs

    %{oid: oid, revoked: revoked}
  end

  describe "generate_with_key/3 — classical algorithms" do
    test "generates empty CRL with ECC-P256" do
      key = ecc_signing_key("ECC-P256")
      assert {:ok, der, crl_number} = DerGenerator.generate_with_key("test-ecc-1", key)
      assert is_binary(der)
      assert crl_number >= 1
      %{revoked: revoked} = decode_crl(der)
      assert revoked == :asn1_NOVALUE
    end

    test "generates CRL with revoked entry" do
      key = ecc_signing_key("ECC-P256")
      now = DateTime.utc_now() |> DateTime.truncate(:second)

      cs =
        CertificateStatus.new(%{
          serial_number: "98765",
          issuer_key_id: "test-ecc-2",
          status: "revoked",
          revoked_at: now,
          revocation_reason: "key_compromise"
        })

      {:ok, _} = Repo.insert(cs)

      assert {:ok, der, _n} = DerGenerator.generate_with_key("test-ecc-2", key)
      %{revoked: revoked} = decode_crl(der)
      assert is_list(revoked)
      assert length(revoked) == 1
    end

    test "generates CRL with ECC-P384" do
      key = ecc_signing_key("ECC-P384")
      assert {:ok, der, _n} = DerGenerator.generate_with_key("test-ecc-3", key)
      assert is_binary(der)
    end
  end

  describe "generate_with_key/3 — PQC algorithms" do
    test "generates CRL signed with ML-DSA-65, OID verifies" do
      key = pqc_signing_key("ML-DSA-65")
      assert {:ok, der, _n} = DerGenerator.generate_with_key("test-mldsa-1", key)
      assert is_binary(der)
      %{oid: oid} = decode_crl(der)
      assert oid == {2, 16, 840, 1, 101, 3, 4, 3, 18}
    end

    test "generates CRL signed with ML-DSA-87, OID verifies" do
      key = pqc_signing_key("ML-DSA-87")
      assert {:ok, der, _n} = DerGenerator.generate_with_key("test-mldsa-2", key)
      %{oid: oid} = decode_crl(der)
      assert oid == {2, 16, 840, 1, 101, 3, 4, 3, 19}
    end

    test "generates CRL signed with KAZ-SIGN-128" do
      key = pqc_signing_key("KAZ-SIGN-128")
      assert {:ok, der, _n} = DerGenerator.generate_with_key("test-kaz-1", key)
      assert is_binary(der)
    end

    test "generates CRL signed with KAZ-SIGN-192" do
      key = pqc_signing_key("KAZ-SIGN-192")
      assert {:ok, der, _n} = DerGenerator.generate_with_key("test-kaz-2", key)
      assert is_binary(der)
    end

    test "ML-DSA-65 CRL includes revoked entries" do
      key = pqc_signing_key("ML-DSA-65")
      now = DateTime.utc_now() |> DateTime.truncate(:second)

      for {serial, i} <- Enum.with_index(["11111", "22222"]) do
        cs =
          CertificateStatus.new(%{
            serial_number: serial,
            issuer_key_id: "test-mldsa-pqc-3",
            status: "revoked",
            revoked_at: DateTime.add(now, i, :second),
            revocation_reason: "superseded"
          })

        {:ok, _} = Repo.insert(cs)
      end

      assert {:ok, der, _n} = DerGenerator.generate_with_key("test-mldsa-pqc-3", key)
      %{revoked: revoked} = decode_crl(der)
      assert is_list(revoked)
      assert length(revoked) == 2
    end
  end
end
