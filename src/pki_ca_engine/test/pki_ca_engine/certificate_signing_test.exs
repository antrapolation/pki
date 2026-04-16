defmodule PkiCaEngine.CertificateSigningTest do
  use ExUnit.Case, async: false

  alias PkiMnesia.{TestHelper, Repo}
  alias PkiMnesia.Structs.{CaInstance, IssuerKey, IssuedCertificate}
  alias PkiCaEngine.{CertificateSigning, KeyActivation}

  setup do
    dir = TestHelper.setup_mnesia()

    Application.put_env(:pki_ca_engine, :allow_dev_activate, true)
    {:ok, ka_pid} = KeyActivation.start_link(name: :test_signing_ka, timeout_ms: 60_000)

    on_exit(fn ->
      if Process.alive?(ka_pid), do: GenServer.stop(ka_pid)
      Application.put_env(:pki_ca_engine, :allow_dev_activate, false)
      TestHelper.teardown_mnesia(dir)
    end)

    %{ka: :test_signing_ka}
  end

  test "sign_certificate returns error when key not active", %{ka: ka} do
    key = IssuerKey.new(%{
      ca_instance_id: nil,
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

  test "sign_certificate returns error for pending key status", %{ka: ka} do
    key = IssuerKey.new(%{
      ca_instance_id: nil,
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
