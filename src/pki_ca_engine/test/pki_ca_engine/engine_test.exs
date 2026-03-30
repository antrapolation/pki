defmodule PkiCaEngine.EngineTest do
  use PkiCaEngine.DataCase, async: false

  alias PkiCaEngine.Engine
  alias PkiCaEngine.KeyActivation
  alias PkiCaEngine.KeyCeremony.SyncCeremony
  alias PkiCaEngine.Schema.{CaInstance, CaUser, Keystore}

  setup do
    {:ok, ca} =
      Repo.insert(
        CaInstance.changeset(%CaInstance{}, %{
          name: "engine-ca-#{System.unique_integer([:positive])}",
          created_by: "admin"
        })
      )

    %{ca: ca}
  end

  describe "start_engine/1" do
    test "starts an engine for a ca_instance_id", ctx do
      assert {:ok, pid} = Engine.start_engine(ctx.ca.id)
      assert Process.alive?(pid)
      Engine.stop_engine(ctx.ca.id)
    end

    test "returns error when starting duplicate engine for same ca_instance", ctx do
      assert {:ok, _pid} = Engine.start_engine(ctx.ca.id)
      assert {:error, {:already_started, _pid}} = Engine.start_engine(ctx.ca.id)
      Engine.stop_engine(ctx.ca.id)
    end
  end

  describe "stop_engine/1" do
    test "stops a running engine", ctx do
      {:ok, pid} = Engine.start_engine(ctx.ca.id)
      assert Process.alive?(pid)
      assert :ok = Engine.stop_engine(ctx.ca.id)
      refute Process.alive?(pid)
    end

    test "returns error when engine is not running", ctx do
      assert {:error, :not_running} = Engine.stop_engine(ctx.ca.id)
    end
  end

  describe "multiple engines" do
    test "two engines with different ca_instance_ids run simultaneously" do
      {:ok, ca1} =
        Repo.insert(
          CaInstance.changeset(%CaInstance{}, %{
            name: "multi-1-#{System.unique_integer([:positive])}",
            created_by: "admin"
          })
        )

      {:ok, ca2} =
        Repo.insert(
          CaInstance.changeset(%CaInstance{}, %{
            name: "multi-2-#{System.unique_integer([:positive])}",
            created_by: "admin"
          })
        )

      ca1_id = ca1.id
      ca2_id = ca2.id

      {:ok, pid1} = Engine.start_engine(ca1.id)
      {:ok, pid2} = Engine.start_engine(ca2.id)

      assert pid1 != pid2
      assert {:ok, %{ca_instance_id: ^ca1_id}} = Engine.get_status(ca1.id)
      assert {:ok, %{ca_instance_id: ^ca2_id}} = Engine.get_status(ca2.id)

      :ok = Engine.stop_engine(ca1.id)
      :ok = Engine.stop_engine(ca2.id)
    end
  end

  describe "get_status/1" do
    test "returns engine status", ctx do
      {:ok, _pid} = Engine.start_engine(ctx.ca.id)

      assert {:ok, status} = Engine.get_status(ctx.ca.id)
      assert status.ca_instance_id == ctx.ca.id
      assert %DateTime{} = status.started_at

      Engine.stop_engine(ctx.ca.id)
    end
  end

  describe "sign_certificate/4" do
    setup ctx do
      {:ok, keystore} =
        Repo.insert(
          Keystore.changeset(%Keystore{}, %{ca_instance_id: ctx.ca.id, type: "software"})
        )

      {:ok, initiator} =
        Repo.insert(
          CaUser.changeset(%CaUser{}, %{
            ca_instance_id: ctx.ca.id,
            role: "key_manager"
          })
        )

      custodians =
        for i <- 1..3 do
          {:ok, user} =
            Repo.insert(
              CaUser.changeset(%CaUser{}, %{
                ca_instance_id: ctx.ca.id,
                role: "key_manager"
              })
            )

          user
        end

      {:ok, {ceremony, issuer_key}} =
        SyncCeremony.initiate(ctx.ca.id, %{
          algorithm: "RSA-4096",
          keystore_id: keystore.id,
          threshold_k: 2,
          threshold_n: 3,
          initiated_by: initiator.id
        })

      {:ok, keypair} = SyncCeremony.generate_keypair("RSA-4096")

      custodian_passwords =
        Enum.map(custodians, fn user -> {user.id, "password-#{user.id}"} end)

      {:ok, 3} =
        SyncCeremony.distribute_shares(ceremony, keypair.private_key, custodian_passwords)

      # Complete ceremony as root with real self-signed certificate
      {cert_der, cert_pem} =
        PkiCaEngine.IntegrationHelpers.generate_self_signed_root_cert(keypair.private_key)
      {:ok, _completed} = SyncCeremony.complete_as_root(ceremony, cert_der, cert_pem)

      # Start KeyActivation and activate key
      activation_name = :"test_engine_activation_#{System.unique_integer([:positive])}"

      start_supervised!(
        {KeyActivation,
         name: activation_name, timeout_ms: 60_000},
        restart: :temporary
      )

      [c1, c2 | _] = custodians
      {:ok, :share_accepted} = KeyActivation.submit_share(activation_name, issuer_key.id, c1.id, "password-#{c1.id}")
      {:ok, :key_activated} = KeyActivation.submit_share(activation_name, issuer_key.id, c2.id, "password-#{c2.id}")

      {:ok, _pid} = Engine.start_engine(ctx.ca.id)

      on_exit(fn ->
        Engine.stop_engine(ctx.ca.id)
      end)

      issuer_key = Repo.get!(PkiCaEngine.Schema.IssuerKey, issuer_key.id)
      %{issuer_key: issuer_key, activation_server: activation_name}
    end

    test "delegates certificate signing through the engine", ctx do
      {csr_data, _} = PkiCaEngine.IntegrationHelpers.generate_test_csr()
      cert_profile = %{validity_days: 365, subject_dn: "CN=engine.example.com,O=Test"}

      assert {:ok, cert} =
               Engine.sign_certificate(
                 "default",
                 ctx.ca.id,
                 ctx.issuer_key.id,
                 csr_data,
                 cert_profile,
                 activation_server: ctx.activation_server
               )

      assert cert.serial_number != nil
      assert cert.issuer_key_id == ctx.issuer_key.id
      assert cert.subject_dn == "CN=engine.example.com,O=Test"
    end
  end
end
