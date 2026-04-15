defmodule PkiValidation.Crypto.Signer.RegistryPqcTest do
  use ExUnit.Case, async: true

  alias PkiValidation.Crypto.Signer.Registry

  describe "PQC algorithm resolution" do
    test "ML-DSA-44 maps to MlDsa44 module" do
      assert {:ok, PkiValidation.Crypto.Signer.MlDsa44} = Registry.fetch("ml_dsa_44")
    end

    test "ML-DSA-65 maps to MlDsa65 module" do
      assert {:ok, PkiValidation.Crypto.Signer.MlDsa65} = Registry.fetch("ml_dsa_65")
    end

    test "ML-DSA-87 maps to MlDsa87 module" do
      assert {:ok, PkiValidation.Crypto.Signer.MlDsa87} = Registry.fetch("ml_dsa_87")
    end

    test "KAZ-SIGN-128 maps to KazSign128 module" do
      assert {:ok, PkiValidation.Crypto.Signer.KazSign128} = Registry.fetch("kaz_sign_128")
    end

    test "KAZ-SIGN-192 maps to KazSign192 module" do
      assert {:ok, PkiValidation.Crypto.Signer.KazSign192} = Registry.fetch("kaz_sign_192")
    end

    test "KAZ-SIGN-256 maps to KazSign256 module" do
      assert {:ok, PkiValidation.Crypto.Signer.KazSign256} = Registry.fetch("kaz_sign_256")
    end

    test "algorithms/0 includes all six PQC strings" do
      algos = Registry.algorithms()

      for id <- ~w[ml_dsa_44 ml_dsa_65 ml_dsa_87 kaz_sign_128 kaz_sign_192 kaz_sign_256] do
        assert id in algos, "expected #{id} in #{inspect(algos)}"
      end
    end
  end
end
