defmodule PkiValidation.Crypto.Signer.RegistryTest do
  use ExUnit.Case, async: true

  alias PkiValidation.Crypto.Signer.Registry
  alias PkiValidation.Crypto.Signer.{EcdsaP256, EcdsaP384, Rsa2048, Rsa4096}

  test "fetch/1 returns the signer module for each known algorithm string" do
    assert Registry.fetch("ecc_p256") == {:ok, EcdsaP256}
    assert Registry.fetch("ecc_p384") == {:ok, EcdsaP384}
    assert Registry.fetch("rsa2048") == {:ok, Rsa2048}
    assert Registry.fetch("rsa4096") == {:ok, Rsa4096}
  end

  test "fetch/1 returns :error for an unknown algorithm string" do
    assert Registry.fetch("bogus") == :error
    assert Registry.fetch("") == :error
  end

  test "fetch/1 returns :error for non-binary input" do
    assert Registry.fetch(nil) == :error
    assert Registry.fetch(:atom) == :error
    assert Registry.fetch(123) == :error
  end

  test "algorithms/0 returns every algorithm string registered in the mapping" do
    algorithms = Registry.algorithms()
    assert is_list(algorithms)
    assert "ecc_p256" in algorithms
    assert "ecc_p384" in algorithms
    assert "rsa2048" in algorithms
    assert "rsa4096" in algorithms
    assert "ml_dsa_44" in algorithms
    assert "ml_dsa_65" in algorithms
    assert "ml_dsa_87" in algorithms
    assert "kaz_sign_128" in algorithms
    assert "kaz_sign_192" in algorithms
    assert "kaz_sign_256" in algorithms
    assert length(algorithms) == 10
  end
end
