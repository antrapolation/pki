defmodule PkiValidation.Schema.SigningKeyConfigPqcTest do
  use ExUnit.Case, async: true

  alias PkiValidation.Schema.SigningKeyConfig

  describe "changeset/2 algorithm validation" do
    test "accepts ML-DSA-44" do
      attrs = valid_attrs(%{algorithm: "ml_dsa_44"})
      cs = SigningKeyConfig.changeset(%SigningKeyConfig{}, attrs)
      assert cs.valid?, "expected valid, got #{inspect(cs.errors)}"
    end

    test "accepts KAZ-SIGN-192" do
      attrs = valid_attrs(%{algorithm: "kaz_sign_192"})
      cs = SigningKeyConfig.changeset(%SigningKeyConfig{}, attrs)
      assert cs.valid?, "expected valid, got #{inspect(cs.errors)}"
    end

    test "still accepts classical ECC-P256" do
      attrs = valid_attrs(%{algorithm: "ecc_p256"})
      cs = SigningKeyConfig.changeset(%SigningKeyConfig{}, attrs)
      assert cs.valid?, "expected valid, got #{inspect(cs.errors)}"
    end

    test "rejects unknown algorithm" do
      attrs = valid_attrs(%{algorithm: "not_real"})
      cs = SigningKeyConfig.changeset(%SigningKeyConfig{}, attrs)
      refute cs.valid?
      assert cs.errors[:algorithm]
    end
  end

  defp valid_attrs(overrides) do
    Map.merge(
      %{
        issuer_key_id: Ecto.UUID.generate(),
        algorithm: "ecc_p256",
        certificate_pem: "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----",
        encrypted_private_key: <<0, 1, 2>>,
        not_before: DateTime.utc_now(),
        not_after: DateTime.utc_now() |> DateTime.add(365 * 86400, :second),
        status: "active"
      },
      overrides
    )
  end
end
