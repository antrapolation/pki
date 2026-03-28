defmodule PkiCrypto.AttestationTest do
  use ExUnit.Case, async: true

  alias PkiCrypto.{Attestation, Algorithm, Registry}

  describe "attest/3 and verify_attestation/4" do
    test "attestation round-trip with ECC-P256" do
      algo = Registry.get("ECC-P256")
      {:ok, admin_keys} = Algorithm.generate_keypair(algo)
      {:ok, target_keys} = Algorithm.generate_keypair(algo)

      {:ok, signature} = Attestation.attest(admin_keys.private_key, "ECC-P256", target_keys.public_key)
      assert is_binary(signature)

      assert :ok = Attestation.verify_attestation(
        admin_keys.public_key, "ECC-P256", signature, target_keys.public_key
      )
    end

    test "verification fails with wrong target key" do
      algo = Registry.get("ECC-P256")
      {:ok, admin_keys} = Algorithm.generate_keypair(algo)
      {:ok, target_keys} = Algorithm.generate_keypair(algo)
      {:ok, other_keys} = Algorithm.generate_keypair(algo)

      {:ok, signature} = Attestation.attest(admin_keys.private_key, "ECC-P256", target_keys.public_key)

      assert {:error, _} = Attestation.verify_attestation(
        admin_keys.public_key, "ECC-P256", signature, other_keys.public_key
      )
    end

    test "verification fails with wrong admin key" do
      algo = Registry.get("ECC-P256")
      {:ok, admin_keys} = Algorithm.generate_keypair(algo)
      {:ok, other_admin} = Algorithm.generate_keypair(algo)
      {:ok, target_keys} = Algorithm.generate_keypair(algo)

      {:ok, signature} = Attestation.attest(admin_keys.private_key, "ECC-P256", target_keys.public_key)

      assert {:error, _} = Attestation.verify_attestation(
        other_admin.public_key, "ECC-P256", signature, target_keys.public_key
      )
    end
  end
end
