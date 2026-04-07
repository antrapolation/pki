defmodule PkiValidation.SigningKeyStoreTest do
  use PkiValidation.DataCase, async: false

  alias PkiValidation.SigningKeyStore
  alias PkiValidation.Schema.SigningKeyConfig
  alias PkiValidation.Repo

  setup do
    issuer_key_id = Uniq.UUID.uuid7()
    {cert_pem, encrypted_priv} = generate_test_signing_keypair()

    {:ok, _} =
      %SigningKeyConfig{}
      |> SigningKeyConfig.changeset(%{
        issuer_key_id: issuer_key_id,
        algorithm: "ecc_p256",
        certificate_pem: cert_pem,
        encrypted_private_key: encrypted_priv,
        not_before: DateTime.utc_now(),
        not_after: DateTime.add(DateTime.utc_now(), 30, :day),
        status: "active"
      })
      |> Repo.insert()

    name = :"signing_key_store_#{System.unique_integer([:positive])}"
    {:ok, pid} = SigningKeyStore.start_link(name: name, password: "test-password")
    {:ok, store: pid, name: name, issuer_key_id: issuer_key_id}
  end

  test "loads signing keys at startup", %{name: name, issuer_key_id: id} do
    assert {:ok, %{algorithm: "ecc_p256"}} = SigningKeyStore.get(name, id)
  end

  test "returns :not_found for unknown issuer", %{name: name} do
    assert :not_found = SigningKeyStore.get(name, "unknown-id")
  end

  test "lookup includes private key and certificate_der", %{name: name, issuer_key_id: id} do
    {:ok, key} = SigningKeyStore.get(name, id)
    assert is_binary(key.private_key)
    assert is_binary(key.certificate_der)
  end

  test "reload picks up newly inserted active key", %{name: name} do
    new_id = Uniq.UUID.uuid7()
    {cert_pem, encrypted_priv} = generate_test_signing_keypair()

    {:ok, _} =
      %SigningKeyConfig{}
      |> SigningKeyConfig.changeset(%{
        issuer_key_id: new_id,
        algorithm: "ecc_p256",
        certificate_pem: cert_pem,
        encrypted_private_key: encrypted_priv,
        not_before: DateTime.utc_now(),
        not_after: DateTime.add(DateTime.utc_now(), 30, :day),
        status: "active"
      })
      |> Repo.insert()

    assert :not_found = SigningKeyStore.get(name, new_id)
    :ok = SigningKeyStore.reload(name)
    assert {:ok, _} = SigningKeyStore.get(name, new_id)
  end

  defp generate_test_signing_keypair do
    {_pub, priv} = :crypto.generate_key(:ecdh, :secp256r1)
    encrypted = SigningKeyStore.encrypt_for_test(priv, "test-password")

    cert_pem =
      case :public_key.pkix_test_root_cert(~c"Test Signing", []) do
        %{cert: der} ->
          :public_key.pem_encode([{:Certificate, der, :not_encrypted}])

        {tbs, _} ->
          der = :public_key.pkix_encode(:OTPCertificate, tbs, :otp)
          :public_key.pem_encode([{:Certificate, der, :not_encrypted}])
      end

    {cert_pem, encrypted}
  end
end
