defmodule PkiCaEngine.CertificateSigningTest do
  use ExUnit.Case, async: false

  alias PkiMnesia.{TestHelper, Repo}
  alias PkiMnesia.Structs.{CaInstance, IssuerKey, IssuedCertificate}
  alias PkiCaEngine.{CertificateSigning, KeyActivation}

  setup do
    dir = TestHelper.setup_mnesia()

    Application.put_env(:pki_ca_engine, :allow_dev_activate, true)
    {:ok, ka_pid} = KeyActivation.start_link(name: :test_signing_ka, timeout_ms: 60_000)

    # Create a CA instance so check_ca_online/check_leaf_ca pass
    ca = CaInstance.new(%{name: "Test CA", is_root: true, status: "active"})
    {:ok, _} = Repo.insert(ca)

    on_exit(fn ->
      if Process.alive?(ka_pid), do: GenServer.stop(ka_pid)
      Application.put_env(:pki_ca_engine, :allow_dev_activate, false)
      TestHelper.teardown_mnesia(dir)
    end)

    %{ka: :test_signing_ka, ca_id: ca.id}
  end

  test "sign_certificate returns error when key not active", %{ka: ka, ca_id: ca_id} do
    key = IssuerKey.new(%{
      ca_instance_id: ca_id,
      algorithm: "ECC-P256",
      status: "active",
      certificate_der: <<1, 2, 3>>,
      certificate_pem: "fake"
    })
    {:ok, _} = Repo.insert(key)

    result = CertificateSigning.sign_certificate(
      key.id, "fake-csr", %{}, activation_server: ka
    )

    assert {:error, :key_not_active} = result
  end

  test "sign_certificate returns error for non-existent key", %{ka: ka} do
    result = CertificateSigning.sign_certificate(
      "nonexistent", "fake-csr", %{}, activation_server: ka
    )

    assert {:error, :issuer_key_not_found} = result
  end

  test "sign_certificate returns error for pending key status", %{ka: ka, ca_id: ca_id} do
    key = IssuerKey.new(%{
      ca_instance_id: ca_id,
      algorithm: "ECC-P256",
      status: "pending"
    })
    {:ok, _} = Repo.insert(key)

    result = CertificateSigning.sign_certificate(
      key.id, "fake-csr", %{}, activation_server: ka
    )

    assert {:error, :key_not_active} = result
  end
end
