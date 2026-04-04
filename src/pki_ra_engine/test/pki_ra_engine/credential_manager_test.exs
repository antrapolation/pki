defmodule PkiRaEngine.CredentialManagerTest do
  use PkiRaEngine.DataCase, async: true

  alias PkiRaEngine.CredentialManager
  alias PkiRaEngine.CredentialManager.Credential
  alias PkiRaEngine.Schema.RaUser

  @password "secure-password-123"

  defp create_user_with_creds(opts \\ []) do
    uniq = System.unique_integer([:positive])

    attrs = %{
      username: "testuser-#{uniq}",
      display_name: "Test User",
      role: "ra_admin"
    }

    CredentialManager.create_user_with_credentials(nil, attrs, @password, opts)
  end

  # -- create_user_with_credentials --

  describe "create_user_with_credentials/3" do
    test "creates user with 2 credentials (signing + kem)" do
      assert {:ok, %RaUser{} = user} = create_user_with_creds()
      assert length(user.credentials) == 2

      types = Enum.map(user.credentials, & &1.credential_type) |> Enum.sort()
      assert types == ["kem", "signing"]
    end

    test "created user has password_hash set" do
      assert {:ok, user} = create_user_with_creds()
      assert is_binary(user.password_hash)
      assert user.password_hash != @password
    end

    test "signing credential has correct type and algorithm" do
      assert {:ok, user} = create_user_with_creds()
      signing = Enum.find(user.credentials, &(&1.credential_type == "signing"))

      assert %Credential{} = signing
      assert signing.credential_type == "signing"
      assert signing.algorithm == "ECC-P256"
      assert signing.status == "active"
      assert is_binary(signing.public_key)
      assert is_binary(signing.encrypted_private_key)
      assert is_binary(signing.salt)
    end

    test "KEM credential has correct type and algorithm" do
      assert {:ok, user} = create_user_with_creds()
      kem = Enum.find(user.credentials, &(&1.credential_type == "kem"))

      assert %Credential{} = kem
      assert kem.credential_type == "kem"
      assert kem.algorithm == "ECDH-P256"
      assert kem.status == "active"
      assert is_binary(kem.public_key)
      assert is_binary(kem.encrypted_private_key)
      assert is_binary(kem.salt)
    end

    test "supports custom algorithms via opts" do
      assert {:ok, user} = create_user_with_creds(signing_algorithm: "RSA-4096")
      signing = Enum.find(user.credentials, &(&1.credential_type == "signing"))

      assert signing.algorithm == "RSA-4096"
    end

    test "rolls back all records on invalid user attrs" do
      # Missing required username
      attrs = %{display_name: "Bad User", role: "ra_admin"}
      assert {:error, _changeset} = CredentialManager.create_user_with_credentials(nil, attrs, @password)

      # Verify no credentials were left behind
      assert Repo.all(from c in Credential) == []
    end
  end

  # -- authenticate --

  describe "authenticate/2" do
    test "succeeds with correct password" do
      {:ok, user} = create_user_with_creds()

      assert {:ok, authed_user, session_info} = CredentialManager.authenticate(nil,user.username, @password)
      assert authed_user.id == user.id
      assert is_binary(session_info.session_key)
      assert byte_size(session_info.session_key) == 32
      assert is_binary(session_info.session_salt)
    end

    test "fails with wrong password" do
      {:ok, _user} = create_user_with_creds()

      assert {:error, :invalid_credentials} = CredentialManager.authenticate(nil,"testuser-wrong", "wrong-password")
    end

    test "fails with nonexistent user" do
      assert {:error, :invalid_credentials} = CredentialManager.authenticate(nil,"nonexistent-user", "any-password")
    end

    test "fails with correct password but wrong username" do
      {:ok, _user} = create_user_with_creds()

      assert {:error, :invalid_credentials} = CredentialManager.authenticate(nil,"wrong-username", @password)
    end
  end

  # -- get_signing_credential --

  describe "get_signing_credential/1" do
    test "returns signing credential for user" do
      {:ok, user} = create_user_with_creds()

      cred = CredentialManager.get_signing_credential(user.id)
      assert %Credential{} = cred
      assert cred.credential_type == "signing"
      assert cred.user_id == user.id
    end

    test "returns nil for nonexistent user" do
      assert is_nil(CredentialManager.get_signing_credential(Uniq.UUID.uuid7()))
    end
  end

  # -- get_kem_credential --

  describe "get_kem_credential/1" do
    test "returns KEM credential for user" do
      {:ok, user} = create_user_with_creds()

      cred = CredentialManager.get_kem_credential(user.id)
      assert %Credential{} = cred
      assert cred.credential_type == "kem"
      assert cred.user_id == user.id
    end

    test "returns nil for nonexistent user" do
      assert is_nil(CredentialManager.get_kem_credential(Uniq.UUID.uuid7()))
    end
  end

  # -- sign_with_credential --

  describe "sign_with_credential/3" do
    test "signs data verifiable with public key" do
      {:ok, user} = create_user_with_creds()
      data = "important message to sign"

      assert {:ok, signature} = CredentialManager.sign_with_credential(user.id, @password, data)
      assert is_binary(signature)

      # Verify with public key
      signing_cred = CredentialManager.get_signing_credential(user.id)
      algo = PkiCrypto.Registry.get(signing_cred.algorithm)
      assert :ok = PkiCrypto.Algorithm.verify(algo, signing_cred.public_key, signature, data)
    end

    test "returns error for nonexistent user" do
      assert {:error, :credential_not_found} =
               CredentialManager.sign_with_credential(Uniq.UUID.uuid7(), @password, "data")
    end
  end
end
