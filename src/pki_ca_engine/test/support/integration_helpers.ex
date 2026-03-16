defmodule PkiCaEngine.IntegrationHelpers do
  @moduledoc """
  Helper functions for Layer 1 integration tests.

  Provides convenience wrappers that chain together multiple engine modules
  to set up full CA environments for testing.
  """

  alias PkiCaEngine.Repo
  alias PkiCaEngine.Schema.{CaInstance, CaUser, Keystore}
  alias PkiCaEngine.KeyCeremony.{SyncCeremony, TestCryptoAdapter}
  alias PkiCaEngine.KeyActivation

  @doc """
  Creates a full CA setup: CA instance, users (admin, 3 key managers, auditor),
  and a software keystore. Returns a map with all created entities.
  """
  def create_full_ca_setup! do
    uniq = System.unique_integer([:positive])

    {:ok, ca} =
      Repo.insert(
        CaInstance.changeset(%CaInstance{}, %{
          name: "integ-ca-#{uniq}",
          created_by: "admin"
        })
      )

    {:ok, ca_admin} =
      Repo.insert(
        CaUser.changeset(%CaUser{}, %{
          ca_instance_id: ca.id,
          did: "did:example:admin-#{uniq}",
          role: "ca_admin",
          display_name: "CA Admin"
        })
      )

    key_managers =
      for i <- 1..3 do
        {:ok, user} =
          Repo.insert(
            CaUser.changeset(%CaUser{}, %{
              ca_instance_id: ca.id,
              did: "did:example:km-#{i}-#{uniq}",
              role: "key_manager",
              display_name: "Key Manager #{i}"
            })
          )

        user
      end

    {:ok, auditor} =
      Repo.insert(
        CaUser.changeset(%CaUser{}, %{
          ca_instance_id: ca.id,
          did: "did:example:auditor-#{uniq}",
          role: "auditor",
          display_name: "Auditor"
        })
      )

    {:ok, keystore} =
      Repo.insert(
        Keystore.changeset(%Keystore{}, %{
          ca_instance_id: ca.id,
          type: "software"
        })
      )

    %{
      ca: ca,
      ca_admin: ca_admin,
      key_managers: key_managers,
      auditor: auditor,
      keystore: keystore,
      adapter: %TestCryptoAdapter{}
    }
  end

  @doc """
  Runs a full synchronous key ceremony: initiate, generate keypair,
  distribute shares, complete as root. Returns ceremony, issuer_key, and
  custodian passwords list.

  `setup` is the map returned by `create_full_ca_setup!/0`.
  `opts` allows overriding `:threshold_k` (default 2), `:threshold_n` (default 3).
  """
  def run_ceremony!(setup, opts \\ []) do
    threshold_k = Keyword.get(opts, :threshold_k, 2)
    threshold_n = Keyword.get(opts, :threshold_n, 3)
    [km1 | _] = setup.key_managers

    {:ok, {ceremony, issuer_key}} =
      SyncCeremony.initiate(setup.ca.id, %{
        algorithm: "RSA-4096",
        keystore_id: setup.keystore.id,
        threshold_k: threshold_k,
        threshold_n: threshold_n,
        initiated_by: km1.id
      })

    {:ok, keypair} = SyncCeremony.generate_keypair(setup.adapter, "RSA-4096")

    custodian_passwords =
      setup.key_managers
      |> Enum.take(threshold_n)
      |> Enum.map(fn user -> {user.id, "secret-#{user.id}"} end)

    {:ok, ^threshold_n} =
      SyncCeremony.distribute_shares(
        ceremony,
        keypair.private_key,
        custodian_passwords,
        setup.adapter
      )

    # Complete as root CA with placeholder certificate
    cert_der = "ROOT_CERT_DER_PLACEHOLDER"
    cert_pem = "ROOT_CERT_PEM_PLACEHOLDER"
    {:ok, completed_ceremony} = SyncCeremony.complete_as_root(ceremony, cert_der, cert_pem)

    %{
      ceremony: completed_ceremony,
      issuer_key: Repo.get!(PkiCaEngine.Schema.IssuerKey, issuer_key.id),
      custodian_passwords: custodian_passwords,
      keypair: keypair
    }
  end

  @doc """
  Activates a key by submitting K shares from the custodian_passwords list.

  `activation_server` is the named KeyActivation GenServer.
  `ceremony_result` is the map returned by `run_ceremony!/1`.
  `k` is the number of shares to submit (must be >= threshold).
  """
  def activate_key!(activation_server, ceremony_result, k) do
    ceremony_result.custodian_passwords
    |> Enum.take(k)
    |> Enum.with_index(1)
    |> Enum.each(fn {{user_id, password}, index} ->
      expected = if index < k, do: :share_accepted, else: :key_activated

      {:ok, ^expected} =
        KeyActivation.submit_share(
          activation_server,
          ceremony_result.issuer_key.id,
          user_id,
          password
        )
    end)

    :ok
  end
end
