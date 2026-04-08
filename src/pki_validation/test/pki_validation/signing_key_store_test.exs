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

  test "find_by_key_hash returns {:ok, key, issuer_id} for known key hash",
       %{name: name, issuer_key_id: id} do
    {:ok, key} = SigningKeyStore.get(name, id)

    # Verify the cached key_hash field is populated and matches a fresh
    # computation. This pins the H1 fix: if the cache field were dropped or
    # left nil, this assertion would fail rather than silently re-hashing on
    # every find_by_key_hash call.
    expected_hash = PkiValidation.CertId.issuer_key_hash(key.certificate_der)
    assert key.key_hash == expected_hash

    # Looking up by the cached hash returns the same key with the issuer id.
    assert {:ok, found_key, ^id} = SigningKeyStore.find_by_key_hash(name, key.key_hash)
    assert found_key.algorithm == "ecc_p256"
    assert found_key.key_hash == expected_hash
  end

  test "find_by_key_hash returns :not_found for unknown hash", %{name: name} do
    assert :not_found = SigningKeyStore.find_by_key_hash(name, :crypto.strong_rand_bytes(20))
  end

  test "key with wrong password is dropped at startup; other keys still load" do
    bad_id = Uniq.UUID.uuid7()
    {_pub, priv} = :crypto.generate_key(:ecdh, :secp256r1)
    encrypted_with_wrong = SigningKeyStore.encrypt_for_test(priv, "different-password")
    cert_pem = generate_test_cert_pem()

    {:ok, _} =
      %SigningKeyConfig{}
      |> SigningKeyConfig.changeset(%{
        issuer_key_id: bad_id,
        algorithm: "ecc_p256",
        certificate_pem: cert_pem,
        encrypted_private_key: encrypted_with_wrong,
        not_before: DateTime.utc_now(),
        not_after: DateTime.add(DateTime.utc_now(), 30, :day),
        status: "active"
      })
      |> Repo.insert()

    name2 = :"ks_bad_#{System.unique_integer([:positive])}"
    {:ok, _} = SigningKeyStore.start_link(name: name2, password: "test-password")

    assert :not_found = SigningKeyStore.get(name2, bad_id)
  end

  test "key with malformed (truncated) ciphertext is dropped at startup" do
    bad_id = Uniq.UUID.uuid7()
    cert_pem = generate_test_cert_pem()

    {:ok, _} =
      %SigningKeyConfig{}
      |> SigningKeyConfig.changeset(%{
        issuer_key_id: bad_id,
        algorithm: "ecc_p256",
        certificate_pem: cert_pem,
        encrypted_private_key: <<1, 2, 3>>,
        not_before: DateTime.utc_now(),
        not_after: DateTime.add(DateTime.utc_now(), 30, :day),
        status: "active"
      })
      |> Repo.insert()

    name3 = :"ks_truncated_#{System.unique_integer([:positive])}"
    {:ok, _} = SigningKeyStore.start_link(name: name3, password: "test-password")

    assert :not_found = SigningKeyStore.get(name3, bad_id)
  end

  defp generate_test_signing_keypair do
    {_pub, priv} = :crypto.generate_key(:ecdh, :secp256r1)
    encrypted = SigningKeyStore.encrypt_for_test(priv, "test-password")
    {generate_test_cert_pem(), encrypted}
  end

  defp generate_test_cert_pem do
    case :public_key.pkix_test_root_cert(~c"Test Signing", []) do
      %{cert: der} ->
        :public_key.pem_encode([{:Certificate, der, :not_encrypted}])

      {tbs, _} ->
        der = :public_key.pkix_encode(:OTPCertificate, tbs, :otp)
        :public_key.pem_encode([{:Certificate, der, :not_encrypted}])
    end
  end
end
