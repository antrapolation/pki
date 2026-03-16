defmodule PkiCaEngine.KeyCeremony.SyncCeremonyTest do
  use PkiCaEngine.DataCase, async: true

  alias PkiCaEngine.KeyCeremony.{SyncCeremony, TestCryptoAdapter}
  alias PkiCaEngine.Schema.{CaInstance, CaUser, Keystore, ThresholdShare}

  setup do
    {:ok, ca} =
      Repo.insert(CaInstance.changeset(%CaInstance{}, %{name: "ceremony-ca-#{System.unique_integer([:positive])}", created_by: "admin"}))

    {:ok, keystore} =
      Repo.insert(Keystore.changeset(%Keystore{}, %{ca_instance_id: ca.id, type: "software"}))

    {:ok, initiator} =
      Repo.insert(CaUser.changeset(%CaUser{}, %{
        ca_instance_id: ca.id,
        did: "did:example:initiator-#{System.unique_integer([:positive])}",
        role: "key_manager"
      }))

    # Create custodian users
    custodians =
      for i <- 1..3 do
        {:ok, user} =
          Repo.insert(CaUser.changeset(%CaUser{}, %{
            ca_instance_id: ca.id,
            did: "did:example:custodian-#{i}-#{System.unique_integer([:positive])}",
            role: "key_manager"
          }))
        user
      end

    adapter = %TestCryptoAdapter{}

    %{
      ca: ca,
      keystore: keystore,
      initiator: initiator,
      custodians: custodians,
      adapter: adapter
    }
  end

  # ── initiate/2 ──────────────────────────────────────────────────

  describe "initiate/2" do
    test "creates ceremony and issuer_key records with correct status", ctx do
      params = %{
        algorithm: "RSA-4096",
        keystore_id: ctx.keystore.id,
        threshold_k: 2,
        threshold_n: 3,
        domain_info: %{"org" => "Test Corp"},
        initiated_by: ctx.initiator.id
      }

      assert {:ok, {ceremony, issuer_key}} = SyncCeremony.initiate(ctx.ca.id, params)

      assert ceremony.ca_instance_id == ctx.ca.id
      assert ceremony.ceremony_type == "sync"
      assert ceremony.status == "initiated"
      assert ceremony.algorithm == "RSA-4096"
      assert ceremony.threshold_k == 2
      assert ceremony.threshold_n == 3
      assert ceremony.keystore_id == ctx.keystore.id

      assert issuer_key.ca_instance_id == ctx.ca.id
      assert issuer_key.algorithm == "RSA-4096"
      assert issuer_key.status == "pending"
    end

    test "returns error when keystore does not exist", ctx do
      params = %{
        algorithm: "RSA-4096",
        keystore_id: -1,
        threshold_k: 2,
        threshold_n: 3,
        initiated_by: ctx.initiator.id
      }

      assert {:error, :not_found} = SyncCeremony.initiate(ctx.ca.id, params)
    end

    test "returns error when k < 2", ctx do
      params = %{
        algorithm: "RSA-4096",
        keystore_id: ctx.keystore.id,
        threshold_k: 1,
        threshold_n: 3,
        initiated_by: ctx.initiator.id
      }

      assert {:error, :invalid_threshold} = SyncCeremony.initiate(ctx.ca.id, params)
    end

    test "returns error when k > n", ctx do
      params = %{
        algorithm: "RSA-4096",
        keystore_id: ctx.keystore.id,
        threshold_k: 4,
        threshold_n: 3,
        initiated_by: ctx.initiator.id
      }

      assert {:error, :invalid_threshold} = SyncCeremony.initiate(ctx.ca.id, params)
    end
  end

  describe "initiate/2 transaction error handling (D7 regression)" do
    test "returns {:error, ...} instead of crashing on invalid data inside transaction", ctx do
      # Use a nil ca_instance_id to trigger a DB foreign key or changeset error
      # inside the transaction. The fix ensures this returns {:error, _} not a crash.
      params = %{
        algorithm: "RSA-4096",
        keystore_id: ctx.keystore.id,
        threshold_k: 2,
        threshold_n: 3,
        initiated_by: ctx.initiator.id
      }

      # Pass a non-existent ca_instance_id to trigger FK error in the transaction
      assert {:error, _reason} = SyncCeremony.initiate(-999_999, params)
    end
  end

  # ── generate_keypair/2 ──────────────────────────────────────────

  describe "generate_keypair/2" do
    test "generates keypair via CryptoAdapter", ctx do
      assert {:ok, %{public_key: pub, private_key: priv}} =
               SyncCeremony.generate_keypair(ctx.adapter, "RSA-4096")

      assert is_binary(pub)
      assert is_binary(priv)
      assert byte_size(pub) == 32
      assert byte_size(priv) == 32
    end
  end

  # ── distribute_shares/4 ────────────────────────────────────────

  describe "distribute_shares/4" do
    setup ctx do
      params = %{
        algorithm: "RSA-4096",
        keystore_id: ctx.keystore.id,
        threshold_k: 2,
        threshold_n: 3,
        initiated_by: ctx.initiator.id
      }

      {:ok, {ceremony, _issuer_key}} = SyncCeremony.initiate(ctx.ca.id, params)
      {:ok, %{public_key: _pub, private_key: priv}} = SyncCeremony.generate_keypair(ctx.adapter, "RSA-4096")

      Map.merge(ctx, %{ceremony: ceremony, private_key: priv})
    end

    test "splits and encrypts shares, stores in DB", ctx do
      custodian_passwords =
        Enum.map(ctx.custodians, fn user -> {user.id, "password-#{user.id}"} end)

      assert {:ok, 3} =
               SyncCeremony.distribute_shares(
                 ctx.ceremony,
                 ctx.private_key,
                 custodian_passwords,
                 ctx.adapter
               )

      # Verify shares stored in DB
      shares = Repo.all(from(s in ThresholdShare, where: s.issuer_key_id == ^ctx.ceremony.issuer_key_id))
      assert length(shares) == 3

      # Verify each share has correct metadata
      for share <- shares do
        assert share.min_shares == 2
        assert share.total_shares == 3
        assert is_binary(share.encrypted_share)
      end
    end

    test "returns error when custodian count does not match threshold_n", ctx do
      # Only 2 custodians for threshold_n=3
      custodian_passwords =
        ctx.custodians
        |> Enum.take(2)
        |> Enum.map(fn user -> {user.id, "password-#{user.id}"} end)

      assert {:error, :wrong_custodian_count} =
               SyncCeremony.distribute_shares(
                 ctx.ceremony,
                 ctx.private_key,
                 custodian_passwords,
                 ctx.adapter
               )
    end

    test "encrypted shares can be decrypted with correct passwords", ctx do
      custodian_passwords =
        Enum.map(ctx.custodians, fn user -> {user.id, "password-#{user.id}"} end)

      {:ok, 3} =
        SyncCeremony.distribute_shares(
          ctx.ceremony,
          ctx.private_key,
          custodian_passwords,
          ctx.adapter
        )

      shares = Repo.all(from(s in ThresholdShare, where: s.issuer_key_id == ^ctx.ceremony.issuer_key_id, order_by: s.share_index))

      # Each encrypted share should decrypt with corresponding password
      for {share, {_user_id, password}} <- Enum.zip(shares, custodian_passwords) do
        assert {:ok, _plaintext} =
                 PkiCaEngine.KeyCeremony.ShareEncryption.decrypt_share(
                   share.encrypted_share,
                   password
                 )
      end
    end
  end

  # ── complete_as_root/3 ─────────────────────────────────────────

  describe "complete_as_root/3" do
    setup ctx do
      params = %{
        algorithm: "RSA-4096",
        keystore_id: ctx.keystore.id,
        threshold_k: 2,
        threshold_n: 3,
        initiated_by: ctx.initiator.id,
        is_root: true
      }

      {:ok, {ceremony, _issuer_key}} = SyncCeremony.initiate(ctx.ca.id, params)

      Map.put(ctx, :ceremony, ceremony)
    end

    test "marks ceremony completed and issuer_key active", ctx do
      cert_der = <<0x30, 0x82, 0x01, 0x22>>
      cert_pem = "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----"

      assert {:ok, updated_ceremony} =
               SyncCeremony.complete_as_root(ctx.ceremony, cert_der, cert_pem)

      assert updated_ceremony.status == "completed"

      # Issuer key should be active with certificate
      {:ok, key} = PkiCaEngine.IssuerKeyManagement.get_issuer_key(ctx.ceremony.issuer_key_id)
      assert key.status == "active"
      assert key.certificate_der == cert_der
      assert key.certificate_pem == cert_pem
    end
  end

  # ── complete_as_sub_ca/1 ───────────────────────────────────────

  describe "complete_as_sub_ca/1" do
    setup ctx do
      params = %{
        algorithm: "RSA-4096",
        keystore_id: ctx.keystore.id,
        threshold_k: 2,
        threshold_n: 3,
        initiated_by: ctx.initiator.id,
        is_root: false
      }

      {:ok, {ceremony, _issuer_key}} = SyncCeremony.initiate(ctx.ca.id, params)

      Map.put(ctx, :ceremony, ceremony)
    end

    test "marks ceremony completed but key stays pending", ctx do
      assert {:ok, {updated_ceremony, csr}} = SyncCeremony.complete_as_sub_ca(ctx.ceremony)

      assert updated_ceremony.status == "completed"
      assert is_binary(csr)

      # Issuer key should still be pending (awaiting external CA signing)
      {:ok, key} = PkiCaEngine.IssuerKeyManagement.get_issuer_key(ctx.ceremony.issuer_key_id)
      assert key.status == "pending"
    end
  end
end
