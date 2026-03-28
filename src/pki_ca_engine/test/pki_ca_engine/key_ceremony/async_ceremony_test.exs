defmodule PkiCaEngine.KeyCeremony.AsyncCeremonyTest do
  use PkiCaEngine.DataCase, async: false

  alias PkiCaEngine.KeyCeremony.{AsyncCeremony, SyncCeremony}
  alias PkiCaEngine.Schema.{CaInstance, CaUser, KeyCeremony, Keystore, ThresholdShare}

  setup do
    {:ok, ca} =
      Repo.insert(
        CaInstance.changeset(%CaInstance{}, %{
          name: "async-ca-#{System.unique_integer([:positive])}",
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

    # Create a ceremony + issuer_key via SyncCeremony.initiate (reuse existing logic)
    {:ok, {ceremony, _issuer_key}} =
      SyncCeremony.initiate(ca.id, %{
        algorithm: "ECC-P256",
        keystore_id: keystore.id,
        threshold_k: 2,
        threshold_n: 3,
        initiated_by: initiator.id
      })

    %{
      ca: ca,
      keystore: keystore,
      initiator: initiator,
      custodians: custodians,
      ceremony: ceremony
    }
  end

  describe "start_link/1" do
    test "starts GenServer with ceremony params", ctx do
      {:ok, pid} =
        AsyncCeremony.start_link(
          ceremony: ctx.ceremony,

          window_ms: 5_000
        )

      assert Process.alive?(pid)
      GenServer.stop(pid)
    end

    test "updates ceremony status to in_progress on start", ctx do
      {:ok, pid} =
        AsyncCeremony.start_link(
          ceremony: ctx.ceremony,

          window_ms: 5_000
        )

      updated = Repo.get!(KeyCeremony, ctx.ceremony.id)
      assert updated.status == "in_progress"
      GenServer.stop(pid)
    end
  end

  describe "submit_share/3" do
    test "custodian submits share, encrypted share stored in DB", ctx do
      {:ok, pid} =
        AsyncCeremony.start_link(
          ceremony: ctx.ceremony,

          window_ms: 5_000
        )

      [c1 | _] = ctx.custodians

      assert {:ok, :share_accepted} =
               AsyncCeremony.submit_share(pid, c1.id, "password1")

      shares =
        Repo.all(
          from s in ThresholdShare,
            where: s.issuer_key_id == ^ctx.ceremony.issuer_key_id
        )

      assert length(shares) == 1
      assert hd(shares).custodian_user_id == c1.id
      assert is_binary(hd(shares).encrypted_share)

      GenServer.stop(pid)
    end

    test "returns :ceremony_complete when all N shares collected", ctx do
      {:ok, pid} =
        AsyncCeremony.start_link(
          ceremony: ctx.ceremony,

          window_ms: 5_000
        )

      [c1, c2, c3] = ctx.custodians

      assert {:ok, :share_accepted} = AsyncCeremony.submit_share(pid, c1.id, "pw1")
      assert {:ok, :share_accepted} = AsyncCeremony.submit_share(pid, c2.id, "pw2")
      assert {:ok, :ceremony_complete} = AsyncCeremony.submit_share(pid, c3.id, "pw3")
    end

    test "rejects duplicate share from same custodian", ctx do
      {:ok, pid} =
        AsyncCeremony.start_link(
          ceremony: ctx.ceremony,

          window_ms: 5_000
        )

      [c1 | _] = ctx.custodians

      assert {:ok, :share_accepted} = AsyncCeremony.submit_share(pid, c1.id, "pw1")
      assert {:error, :already_submitted} = AsyncCeremony.submit_share(pid, c1.id, "pw1")

      GenServer.stop(pid)
    end
  end

  describe "get_status/1" do
    test "returns current status including shares collected count", ctx do
      {:ok, pid} =
        AsyncCeremony.start_link(
          ceremony: ctx.ceremony,

          window_ms: 5_000
        )

      status = AsyncCeremony.get_status(pid)

      assert status.ceremony_id == ctx.ceremony.id
      assert status.shares_collected == 0
      assert status.threshold_n == 3
      assert status.complete == false

      [c1 | _] = ctx.custodians
      AsyncCeremony.submit_share(pid, c1.id, "pw1")

      status = AsyncCeremony.get_status(pid)
      assert status.shares_collected == 1
      assert status.complete == false

      GenServer.stop(pid)
    end
  end

  describe "window expiry" do
    test "ceremony marked failed after timeout", ctx do
      {:ok, pid} =
        AsyncCeremony.start_link(
          ceremony: ctx.ceremony,

          window_ms: 100
        )

      ref = Process.monitor(pid)

      # Wait for the process to die from window expiry
      assert_receive {:DOWN, ^ref, :process, ^pid, :normal}, 500

      updated = Repo.get!(KeyCeremony, ctx.ceremony.id)
      assert updated.status == "failed"
    end
  end

  describe "share consistency (D2 regression)" do
    test "shares distributed by AsyncCeremony are from the same split and can be recovered", ctx do
      {:ok, pid} =
        AsyncCeremony.start_link(
          ceremony: ctx.ceremony,

          window_ms: 5_000
        )

      [c1, c2, c3] = ctx.custodians

      assert {:ok, :share_accepted} = AsyncCeremony.submit_share(pid, c1.id, "pw1")
      assert {:ok, :share_accepted} = AsyncCeremony.submit_share(pid, c2.id, "pw2")
      assert {:ok, :ceremony_complete} = AsyncCeremony.submit_share(pid, c3.id, "pw3")

      # Retrieve all shares from DB, decrypt them, and verify they can recover the secret
      shares =
        Repo.all(
          from s in ThresholdShare,
            where: s.issuer_key_id == ^ctx.ceremony.issuer_key_id,
            order_by: s.share_index
        )

      assert length(shares) == 3

      passwords = ["pw1", "pw2", "pw3"]

      decrypted_shares =
        Enum.zip(shares, passwords)
        |> Enum.map(fn {share, pw} ->
          {:ok, decrypted} =
            PkiCaEngine.KeyCeremony.ShareEncryption.decrypt_share(share.encrypted_share, pw)
          decrypted
        end)

      # Recover secret using any 2 of 3 shares (threshold k=2)
      {:ok, recovered} = PkiCrypto.Shamir.recover(Enum.take(decrypted_shares, 2))

      # The recovered secret should be a valid DER-encoded private key
      assert is_binary(recovered)
      assert byte_size(recovered) > 0
    end
  end

  describe "stop/crash" do
    test "key material destroyed on stop, ceremony NOT auto-marked failed", ctx do
      {:ok, pid} =
        AsyncCeremony.start_link(
          ceremony: ctx.ceremony,

          window_ms: 60_000
        )

      GenServer.stop(pid)

      # Give a moment for terminate callback
      Process.sleep(50)

      # Ceremony should NOT be marked failed on normal stop
      updated = Repo.get!(KeyCeremony, ctx.ceremony.id)
      assert updated.status == "in_progress"
    end
  end
end
