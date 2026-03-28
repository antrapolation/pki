defmodule PkiCaEngine.KeyActivationTest do
  use PkiCaEngine.DataCase, async: false

  alias PkiCaEngine.KeyActivation
  alias PkiCaEngine.KeyCeremony.SyncCeremony
  alias PkiCaEngine.Schema.{CaInstance, CaUser, Keystore}

  setup do
    {:ok, ca} =
      Repo.insert(
        CaInstance.changeset(%CaInstance{}, %{
          name: "activation-ca-#{System.unique_integer([:positive])}",
          created_by: "admin"
        })
      )

    {:ok, keystore} =
      Repo.insert(
        Keystore.changeset(%Keystore{}, %{ca_instance_id: ca.id, type: "software"})
      )

    {:ok, initiator} =
      Repo.insert(
        CaUser.changeset(%CaUser{}, %{
          ca_instance_id: ca.id,
          role: "key_manager"
        })
      )

    custodians =
      for i <- 1..3 do
        {:ok, user} =
          Repo.insert(
            CaUser.changeset(%CaUser{}, %{
              ca_instance_id: ca.id,
              role: "key_manager"
            })
          )

        user
      end

    # Create ceremony + issuer key
    {:ok, {ceremony, issuer_key}} =
      SyncCeremony.initiate(ca.id, %{
        algorithm: "ECC-P256",
        keystore_id: keystore.id,
        threshold_k: 2,
        threshold_n: 3,
        initiated_by: initiator.id
      })

    # Generate keypair and distribute shares
    {:ok, keypair} = SyncCeremony.generate_keypair("ECC-P256")

    custodian_passwords =
      Enum.map(custodians, fn user -> {user.id, "password-#{user.id}"} end)

    {:ok, 3} =
      SyncCeremony.distribute_shares(ceremony, keypair.private_key, custodian_passwords)

    %{
      ca: ca,
      issuer_key: issuer_key,
      custodians: custodians,
      ceremony: ceremony,
      custodian_passwords: custodian_passwords
    }
  end

  describe "start_link/1" do
    test "starts the KeyActivation GenServer" do
      name = :"test_activation_#{System.unique_integer([:positive])}"

      {:ok, pid} =
        KeyActivation.start_link(
          name: name,

          timeout_ms: 5_000
        )

      assert Process.alive?(pid)
      GenServer.stop(pid)
    end
  end

  describe "submit_share/4" do
    test "custodian submits share, decrypted and accumulated", ctx do
      name = :"test_activation_#{System.unique_integer([:positive])}"

      start_supervised!(
        {KeyActivation,
         name: name, timeout_ms: 5_000},
        restart: :temporary
      )

      [c1 | _] = ctx.custodians
      password = "password-#{c1.id}"

      assert {:ok, :share_accepted} =
               KeyActivation.submit_share(name, ctx.issuer_key.id, c1.id, password)
    end

    test "returns :key_activated when K threshold met", ctx do
      name = :"test_activation_#{System.unique_integer([:positive])}"

      start_supervised!(
        {KeyActivation,
         name: name, timeout_ms: 5_000},
        restart: :temporary
      )

      [c1, c2 | _] = ctx.custodians
      pw1 = "password-#{c1.id}"
      pw2 = "password-#{c2.id}"

      assert {:ok, :share_accepted} =
               KeyActivation.submit_share(name, ctx.issuer_key.id, c1.id, pw1)

      assert {:ok, :key_activated} =
               KeyActivation.submit_share(name, ctx.issuer_key.id, c2.id, pw2)
    end
  end

  describe "is_active?/2" do
    test "returns true if key is activated", ctx do
      name = :"test_activation_#{System.unique_integer([:positive])}"

      start_supervised!(
        {KeyActivation,
         name: name, timeout_ms: 5_000},
        restart: :temporary
      )

      [c1, c2 | _] = ctx.custodians

      assert KeyActivation.is_active?(name, ctx.issuer_key.id) == false

      KeyActivation.submit_share(name, ctx.issuer_key.id, c1.id, "password-#{c1.id}")
      assert KeyActivation.is_active?(name, ctx.issuer_key.id) == false

      KeyActivation.submit_share(name, ctx.issuer_key.id, c2.id, "password-#{c2.id}")
      assert KeyActivation.is_active?(name, ctx.issuer_key.id) == true
    end
  end

  describe "deactivate/2" do
    test "explicitly wipes key and removes from active", ctx do
      name = :"test_activation_#{System.unique_integer([:positive])}"

      start_supervised!(
        {KeyActivation,
         name: name, timeout_ms: 5_000},
        restart: :temporary
      )

      [c1, c2 | _] = ctx.custodians
      KeyActivation.submit_share(name, ctx.issuer_key.id, c1.id, "password-#{c1.id}")
      KeyActivation.submit_share(name, ctx.issuer_key.id, c2.id, "password-#{c2.id}")

      assert KeyActivation.is_active?(name, ctx.issuer_key.id) == true

      assert :ok = KeyActivation.deactivate(name, ctx.issuer_key.id)
      assert KeyActivation.is_active?(name, ctx.issuer_key.id) == false
    end

    test "returns error when key not active", ctx do
      name = :"test_activation_#{System.unique_integer([:positive])}"

      start_supervised!(
        {KeyActivation,
         name: name, timeout_ms: 5_000},
        restart: :temporary
      )

      assert {:error, :not_active} = KeyActivation.deactivate(name, ctx.issuer_key.id)
    end
  end

  describe "timeout" do
    test "key auto-deactivates after configured timeout", ctx do
      name = :"test_activation_#{System.unique_integer([:positive])}"

      start_supervised!(
        {KeyActivation,
         name: name, timeout_ms: 100},
        restart: :temporary
      )

      [c1, c2 | _] = ctx.custodians
      KeyActivation.submit_share(name, ctx.issuer_key.id, c1.id, "password-#{c1.id}")
      KeyActivation.submit_share(name, ctx.issuer_key.id, c2.id, "password-#{c2.id}")

      assert KeyActivation.is_active?(name, ctx.issuer_key.id) == true

      # Wait for timeout
      Process.sleep(200)

      assert KeyActivation.is_active?(name, ctx.issuer_key.id) == false
    end
  end

  describe "duplicate share submission (D3 regression)" do
    test "same custodian submitting twice returns {:error, :already_submitted}", ctx do
      name = :"test_activation_#{System.unique_integer([:positive])}"

      start_supervised!(
        {KeyActivation,
         name: name, timeout_ms: 5_000},
        restart: :temporary
      )

      [c1 | _] = ctx.custodians
      password = "password-#{c1.id}"

      assert {:ok, :share_accepted} =
               KeyActivation.submit_share(name, ctx.issuer_key.id, c1.id, password)

      assert {:error, :already_submitted} =
               KeyActivation.submit_share(name, ctx.issuer_key.id, c1.id, password)
    end
  end

  describe "error: wrong password" do
    test "returns :decryption_failed for wrong password", ctx do
      name = :"test_activation_#{System.unique_integer([:positive])}"

      start_supervised!(
        {KeyActivation,
         name: name, timeout_ms: 5_000},
        restart: :temporary
      )

      [c1 | _] = ctx.custodians

      assert {:error, :decryption_failed} =
               KeyActivation.submit_share(name, ctx.issuer_key.id, c1.id, "wrong-password")
    end
  end

  # ── UC-CA-30 edge cases ────────────────────────────────────────

  describe "submit_share/4 with non-existent issuer key" do
    test "returns {:error, :share_not_found} when no share exists for given key and custodian",
         ctx do
      name = :"test_activation_#{System.unique_integer([:positive])}"

      start_supervised!(
        {KeyActivation,
         name: name, timeout_ms: 5_000},
        restart: :temporary
      )

      [c1 | _] = ctx.custodians
      non_existent_key_id = Uniq.UUID.uuid7()

      assert {:error, :share_not_found} =
               KeyActivation.submit_share(name, non_existent_key_id, c1.id, "password-#{c1.id}")
    end
  end

  describe "get_active_key/2" do
    test "returns {:ok, secret} for activated key", ctx do
      name = :"test_activation_#{System.unique_integer([:positive])}"

      start_supervised!(
        {KeyActivation,
         name: name, timeout_ms: 5_000},
        restart: :temporary
      )

      [c1, c2 | _] = ctx.custodians
      KeyActivation.submit_share(name, ctx.issuer_key.id, c1.id, "password-#{c1.id}")
      KeyActivation.submit_share(name, ctx.issuer_key.id, c2.id, "password-#{c2.id}")

      assert {:ok, secret} = KeyActivation.get_active_key(name, ctx.issuer_key.id)
      assert is_binary(secret)
    end

    test "returns {:error, :not_active} for non-activated key", ctx do
      name = :"test_activation_#{System.unique_integer([:positive])}"

      start_supervised!(
        {KeyActivation,
         name: name, timeout_ms: 5_000},
        restart: :temporary
      )

      assert {:error, :not_active} =
               KeyActivation.get_active_key(name, ctx.issuer_key.id)
    end

    test "returns {:error, :not_active} after deactivation", ctx do
      name = :"test_activation_#{System.unique_integer([:positive])}"

      start_supervised!(
        {KeyActivation,
         name: name, timeout_ms: 5_000},
        restart: :temporary
      )

      [c1, c2 | _] = ctx.custodians
      KeyActivation.submit_share(name, ctx.issuer_key.id, c1.id, "password-#{c1.id}")
      KeyActivation.submit_share(name, ctx.issuer_key.id, c2.id, "password-#{c2.id}")

      assert {:ok, _} = KeyActivation.get_active_key(name, ctx.issuer_key.id)

      :ok = KeyActivation.deactivate(name, ctx.issuer_key.id)

      assert {:error, :not_active} =
               KeyActivation.get_active_key(name, ctx.issuer_key.id)
    end
  end

  describe "deactivate/2 double deactivation" do
    test "deactivating an already-deactivated key returns {:error, :not_active}", ctx do
      name = :"test_activation_#{System.unique_integer([:positive])}"

      start_supervised!(
        {KeyActivation,
         name: name, timeout_ms: 5_000},
        restart: :temporary
      )

      [c1, c2 | _] = ctx.custodians
      KeyActivation.submit_share(name, ctx.issuer_key.id, c1.id, "password-#{c1.id}")
      KeyActivation.submit_share(name, ctx.issuer_key.id, c2.id, "password-#{c2.id}")

      assert :ok = KeyActivation.deactivate(name, ctx.issuer_key.id)
      assert {:error, :not_active} = KeyActivation.deactivate(name, ctx.issuer_key.id)
    end
  end
end
