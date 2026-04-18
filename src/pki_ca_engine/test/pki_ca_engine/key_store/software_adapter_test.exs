defmodule PkiCaEngine.KeyStore.SoftwareAdapterTest do
  use ExUnit.Case, async: false

  alias PkiMnesia.{TestHelper, Repo}
  alias PkiMnesia.Structs.IssuerKey
  alias PkiCaEngine.KeyStore.SoftwareAdapter
  alias PkiCaEngine.KeyActivation

  setup do
    dir = TestHelper.setup_mnesia()
    {:ok, ka_pid} = KeyActivation.start_link(name: :test_ka_sw, timeout_ms: 60_000)
    Application.put_env(:pki_ca_engine, :allow_dev_activate, true)

    on_exit(fn ->
      Application.put_env(:pki_ca_engine, :allow_dev_activate, false)
      if Process.alive?(ka_pid), do: GenServer.stop(ka_pid)
      TestHelper.teardown_mnesia(dir)
    end)

    %{ka: :test_ka_sw}
  end

  test "sign/2 returns :not_active when key not activated" do
    key = IssuerKey.new(%{
      ca_instance_id: "ca-1",
      algorithm: "ECC-P256",
      status: "active",
      keystore_type: :software
    })
    {:ok, _} = Repo.insert(key)

    assert {:error, :not_active} = SoftwareAdapter.sign(key.id, "tbs-data")
  end

  test "sign/3 signs data when key is activated via dev_activate", %{ka: ka} do
    {pub_point, priv_der} = generate_ecc_keypair()

    key = IssuerKey.new(%{
      ca_instance_id: "ca-1",
      algorithm: "ECC-P256",
      status: "active",
      keystore_type: :software
    })
    {:ok, _} = Repo.insert(key)

    {:ok, :dev_activated} = KeyActivation.dev_activate(ka, key.id, priv_der)

    tbs_data = :crypto.strong_rand_bytes(64)
    result = SoftwareAdapter.sign(key.id, tbs_data, activation_server: ka)

    assert {:ok, signature} = result
    assert is_binary(signature)
    assert byte_size(signature) > 0

    # Verify the signature using the raw public point
    assert :crypto.verify(:ecdsa, :sha256, tbs_data, signature, [pub_point, :secp256r1])
  end

  test "sign/3 returns :issuer_key_not_found for missing key", %{ka: ka} do
    assert {:error, :issuer_key_not_found} =
      SoftwareAdapter.sign("nonexistent-id", "data", activation_server: ka)
  end

  test "key_available?/1 returns false when key not activated" do
    key = IssuerKey.new(%{
      ca_instance_id: "ca-1",
      algorithm: "ECC-P256",
      status: "active",
      keystore_type: :software
    })
    {:ok, _} = Repo.insert(key)

    refute SoftwareAdapter.key_available?(key.id)
  end

  test "key_available?/2 returns true when key is activated", %{ka: ka} do
    key = IssuerKey.new(%{
      ca_instance_id: "ca-1",
      algorithm: "ECC-P256",
      status: "active",
      keystore_type: :software
    })
    {:ok, _} = Repo.insert(key)

    refute SoftwareAdapter.key_available?(key.id, activation_server: ka)

    {_pub, priv_der} = generate_ecc_keypair()
    {:ok, :dev_activated} = KeyActivation.dev_activate(ka, key.id, priv_der)

    assert SoftwareAdapter.key_available?(key.id, activation_server: ka)
  end

  # -- Helpers --

  defp generate_ecc_keypair do
    ec_key = :public_key.generate_key({:namedCurve, :secp256r1})
    priv_der = :public_key.der_encode(:ECPrivateKey, ec_key)
    # elem(ec_key, 4) is the raw public point binary in ECPrivateKey tuple
    pub_point = elem(ec_key, 4)
    {pub_point, priv_der}
  end
end
