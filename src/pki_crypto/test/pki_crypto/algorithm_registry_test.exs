defmodule PkiCrypto.AlgorithmRegistryTest do
  use ExUnit.Case, async: false

  alias PkiCrypto.AlgorithmRegistry

  describe "by_id/1 for classical algorithms" do
    test "returns metadata for RSA-2048" do
      assert {:ok, %{id: "RSA-2048", family: :rsa, sig_alg_oid: {1, 2, 840, 113549, 1, 1, 11}}} =
               AlgorithmRegistry.by_id("RSA-2048")
    end

    test "returns metadata for ECC-P256" do
      assert {:ok, %{id: "ECC-P256", family: :ecdsa, sig_alg_oid: {1, 2, 840, 10045, 4, 3, 2}}} =
               AlgorithmRegistry.by_id("ECC-P256")
    end

    test "returns metadata for ECC-P384" do
      assert {:ok, %{id: "ECC-P384", family: :ecdsa, sig_alg_oid: {1, 2, 840, 10045, 4, 3, 3}}} =
               AlgorithmRegistry.by_id("ECC-P384")
    end

    test "returns :error for unknown id" do
      assert :error = AlgorithmRegistry.by_id("NOT-AN-ALGO")
    end
  end

  describe "by_oid/1 for classical algorithms" do
    test "finds RSA-2048 by its sig_alg OID" do
      assert {:ok, %{id: "RSA-2048"}} = AlgorithmRegistry.by_oid({1, 2, 840, 113549, 1, 1, 11})
    end

    test "returns :error for unknown OID" do
      assert :error = AlgorithmRegistry.by_oid({1, 2, 3, 4, 5})
    end
  end

  describe "by_id/1 for PQC algorithms" do
    test "returns metadata for ML-DSA-44" do
      assert {:ok, %{id: "ML-DSA-44", family: :ml_dsa,
                     sig_alg_oid: {2, 16, 840, 1, 101, 3, 4, 3, 17}}} =
               AlgorithmRegistry.by_id("ML-DSA-44")
    end

    test "returns metadata for ML-DSA-65" do
      assert {:ok, %{id: "ML-DSA-65", sig_alg_oid: {2, 16, 840, 1, 101, 3, 4, 3, 18}}} =
               AlgorithmRegistry.by_id("ML-DSA-65")
    end

    test "returns metadata for ML-DSA-87" do
      assert {:ok, %{id: "ML-DSA-87", sig_alg_oid: {2, 16, 840, 1, 101, 3, 4, 3, 19}}} =
               AlgorithmRegistry.by_id("ML-DSA-87")
    end

    test "returns metadata for KAZ-SIGN-128 with placeholder OID" do
      assert {:ok, %{id: "KAZ-SIGN-128", family: :kaz_sign,
                     sig_alg_oid: {1, 3, 6, 1, 4, 1, 99999, 1, 1, 1}}} =
               AlgorithmRegistry.by_id("KAZ-SIGN-128")
    end

    test "returns metadata for KAZ-SIGN-192 with placeholder OID" do
      assert {:ok, %{id: "KAZ-SIGN-192", sig_alg_oid: {1, 3, 6, 1, 4, 1, 99999, 1, 1, 2}}} =
               AlgorithmRegistry.by_id("KAZ-SIGN-192")
    end

    test "returns metadata for KAZ-SIGN-256 with placeholder OID" do
      assert {:ok, %{id: "KAZ-SIGN-256", sig_alg_oid: {1, 3, 6, 1, 4, 1, 99999, 1, 1, 3}}} =
               AlgorithmRegistry.by_id("KAZ-SIGN-256")
    end
  end

  describe "OID override" do
    # NOT async: Application.put_env affects global state.
    # Override applies to any alg id; this describe block must NOT run async.

    setup do
      original = Application.get_env(:pki_crypto, :oid_overrides, %{})

      on_exit(fn ->
        Application.put_env(:pki_crypto, :oid_overrides, original)
      end)

      :ok
    end

    test "override replaces sig_alg_oid for KAZ-SIGN-192" do
      real_oid = {1, 3, 6, 1, 4, 1, 55555, 1, 1, 2}

      Application.put_env(:pki_crypto, :oid_overrides, %{
        "KAZ-SIGN-192" => %{sig_alg_oid: real_oid, public_key_oid: real_oid}
      })

      assert {:ok, %{id: "KAZ-SIGN-192", sig_alg_oid: ^real_oid, public_key_oid: ^real_oid}} =
               AlgorithmRegistry.by_id("KAZ-SIGN-192")
    end

    test "by_oid/1 finds an entry by its overridden OID" do
      real_oid = {1, 3, 6, 1, 4, 1, 55555, 1, 1, 2}

      Application.put_env(:pki_crypto, :oid_overrides, %{
        "KAZ-SIGN-192" => %{sig_alg_oid: real_oid, public_key_oid: real_oid}
      })

      assert {:ok, %{id: "KAZ-SIGN-192"}} = AlgorithmRegistry.by_oid(real_oid)
    end
  end
end
