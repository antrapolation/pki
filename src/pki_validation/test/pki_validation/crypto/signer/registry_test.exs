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
    assert Registry.fetch("ml_dsa_65") == :error
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
    assert length(algorithms) == 4
  end

  test "SigningKeyConfig @valid_algorithms stays in sync with Registry" do
    # Regression guard: the schema's @valid_algorithms is derived from
    # Registry.algorithms/0 at compile time. If someone ever hard-codes
    # the list in the schema again, this test fails immediately and
    # points back to the C1 pre-merge fix that established the invariant.
    #
    # We read the schema's private @valid_algorithms via the changeset
    # path: a changeset that tries every registered algorithm must
    # validate the :algorithm field cleanly, and an algorithm not in
    # the registry must produce a validation error.
    alias PkiValidation.Schema.SigningKeyConfig

    base = %{
      issuer_key_id: Uniq.UUID.uuid7(),
      certificate_pem: "-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----",
      encrypted_private_key: <<1, 2, 3>>,
      not_before: DateTime.utc_now(),
      not_after: DateTime.add(DateTime.utc_now(), 30, :day),
      status: "active"
    }

    for alg <- Registry.algorithms() do
      changeset =
        SigningKeyConfig.changeset(%SigningKeyConfig{}, Map.put(base, :algorithm, alg))

      refute Keyword.has_key?(changeset.errors, :algorithm),
             "Registered algorithm #{alg} should pass SigningKeyConfig validation"
    end

    unregistered_changeset =
      SigningKeyConfig.changeset(
        %SigningKeyConfig{},
        Map.put(base, :algorithm, "definitely_not_a_real_algorithm")
      )

    assert Keyword.has_key?(unregistered_changeset.errors, :algorithm)
  end
end
