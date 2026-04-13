defmodule PkiCaEngine.IntegrationHelpers do
  @moduledoc """
  Helper functions for Layer 1 integration tests.

  Provides convenience wrappers that chain together multiple engine modules
  to set up full CA environments for testing.
  """

  alias PkiCaEngine.Repo
  alias PkiCaEngine.Schema.{CaInstance, CaUser, Keystore}
  alias PkiCaEngine.KeyCeremony.SyncCeremony
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
      keystore: keystore
    }
  end

  @doc """
  Runs a full synchronous key ceremony: initiate, generate keypair,
  distribute shares, complete as root with a real self-signed certificate.

  `setup` is the map returned by `create_full_ca_setup!/0`.
  `opts` allows overriding `:threshold_k` (default 2), `:threshold_n` (default 3).
  """
  def run_ceremony!(setup, opts \\ []) do
    threshold_k = Keyword.get(opts, :threshold_k, 2)
    threshold_n = Keyword.get(opts, :threshold_n, 3)
    [km1 | _] = setup.key_managers

    {:ok, {ceremony, issuer_key}} =
      SyncCeremony.initiate(nil, setup.ca.id, %{
        algorithm: "RSA-4096",
        keystore_id: setup.keystore.id,
        threshold_k: threshold_k,
        threshold_n: threshold_n,
        initiated_by: km1.id
      })

    {:ok, keypair} = SyncCeremony.generate_keypair("RSA-4096")

    custodian_passwords =
      setup.key_managers
      |> Enum.take(threshold_n)
      |> Enum.map(fn user -> {user.id, "secret-#{user.id}"} end)

    {:ok, ^threshold_n} =
      SyncCeremony.distribute_shares(
        nil,
        ceremony,
        keypair.private_key,
        custodian_passwords
      )

    # Generate a real self-signed root CA certificate
    {cert_der, cert_pem} = generate_self_signed_root_cert(keypair.private_key)
    {:ok, completed_ceremony} = SyncCeremony.complete_as_root(nil, ceremony, cert_der, cert_pem)

    # Bring CA back online (auto-offlined after root ceremony completion)
    ca = Repo.get!(PkiCaEngine.Schema.CaInstance, setup.ca.id)
    ca |> PkiCaEngine.Schema.CaInstance.changeset(%{is_offline: false}) |> Repo.update!()

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
          nil,
          ceremony_result.issuer_key.id,
          user_id,
          password
        )
    end)

    :ok
  end

  @doc """
  Generates a real self-signed root CA certificate from a DER-encoded private key.
  Returns `{cert_der_binary, cert_pem_string}`.
  """
  def generate_self_signed_root_cert(private_key_der) do
    # Decode the DER-encoded private key (try RSA first, then EC)
    native_key = decode_private_key(private_key_der)

    # Create self-signed root CA certificate
    root_cert =
      X509.Certificate.self_signed(native_key, "/CN=Test Root CA/O=IntegTest",
        template: :root_ca,
        hash: :sha256,
        serial: {:random, 8},
        validity: 365 * 25
      )

    cert_der = X509.Certificate.to_der(root_cert)
    cert_pem = X509.Certificate.to_pem(root_cert)

    {cert_der, cert_pem}
  end

  @doc """
  Generates a real CSR PEM for testing, signed by a fresh RSA-2048 keypair.
  Returns `{csr_pem, subject_dn}`.
  """
  def generate_test_csr(subject \\ "/CN=test.example.com/O=TestOrg") do
    key = X509.PrivateKey.new_rsa(2048)
    csr = X509.CSR.new(key, subject)
    csr_pem = X509.CSR.to_pem(csr)
    {csr_pem, subject}
  end

  defp decode_private_key(der) do
    try do
      :public_key.der_decode(:RSAPrivateKey, der)
    rescue
      _ -> :public_key.der_decode(:ECPrivateKey, der)
    end
  end
end
