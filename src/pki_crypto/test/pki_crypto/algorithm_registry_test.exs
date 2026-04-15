defmodule PkiCrypto.AlgorithmRegistryTest do
  use ExUnit.Case, async: true

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
end
