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

  describe "status/1" do
    test "reports healthy state when all keys load", %{name: name, issuer_key_id: _id} do
      status = SigningKeyStore.status(name)
      assert status.healthy == true
      assert status.loaded == 1
      assert status.failed == 0
      assert status.last_error == nil
    end

    test "reports failed count when a key has wrong password" do
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

      name2 = :"ks_status_bad_#{System.unique_integer([:positive])}"
      {:ok, _} = SigningKeyStore.start_link(name: name2, password: "test-password")

      status = SigningKeyStore.status(name2)
      assert status.healthy == false
      assert status.failed >= 1
      assert status.last_error == :decryption_failed
    end

    test "reports zero loaded when the only key is malformed" do
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

      name3 = :"ks_status_trunc_#{System.unique_integer([:positive])}"
      {:ok, _} = SigningKeyStore.start_link(name: name3, password: "test-password")

      status = SigningKeyStore.status(name3)
      assert status.healthy == false
      assert status.failed >= 1
      assert status.last_error in [:malformed_ciphertext, :decryption_failed]
    end
  end

  describe "signer resolution at load time" do
    test "entries include the resolved signer module", %{name: name, issuer_key_id: id} do
      {:ok, key} = SigningKeyStore.get(name, id)
      assert key.signer == PkiValidation.Crypto.Signer.EcdsaP256
    end

    test "private_key is decoded via the signer at load time",
         %{name: name, issuer_key_id: id} do
      {:ok, key} = SigningKeyStore.get(name, id)
      # ECC P-256 decode_private_key/1 is passthrough — raw scalar bytes
      assert is_binary(key.private_key)
      assert byte_size(key.private_key) == 32
    end

    test "row with unknown algorithm is dropped and reported in status/0" do
      bad_id = Uniq.UUID.uuid7()
      {_pub, priv} = :crypto.generate_key(:ecdh, :secp256r1)
      encrypted = SigningKeyStore.encrypt_for_test(priv, "test-password")
      cert_pem = generate_test_cert_pem()

      now = DateTime.utc_now()
      not_after = DateTime.add(now, 30, :day)

      # Bypass the changeset enum validation by inserting raw SQL.
      {:ok, _} =
        Ecto.Adapters.SQL.query(
          Repo,
          """
          INSERT INTO signing_key_config
            (id, issuer_key_id, algorithm, certificate_pem, encrypted_private_key,
             not_before, not_after, status, inserted_at, updated_at)
          VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
          """,
          [
            Uniq.UUID.string_to_binary!(Uniq.UUID.uuid7()),
            Uniq.UUID.string_to_binary!(bad_id),
            "made_up_algo",
            cert_pem,
            encrypted,
            now,
            not_after,
            "active",
            now,
            now
          ]
        )

      name_u = :"ks_unknown_algo_#{System.unique_integer([:positive])}"
      {:ok, _} = SigningKeyStore.start_link(name: name_u, password: "test-password")

      assert :not_found = SigningKeyStore.get(name_u, bad_id)

      status = SigningKeyStore.status(name_u)
      assert status.healthy == false
      assert status.failed >= 1
      assert status.last_error == :unknown_algorithm
    end
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
