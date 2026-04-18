defmodule PkiCaEngine.KeyStore.MockHsmAdapterTest do
  @moduledoc """
  Unit tests for MockHsmAdapter — the in-memory mock HSM backend.

  No PKCS#11 library or hardware required.  All operations use PkiCrypto
  primitives directly.
  """
  use ExUnit.Case, async: false

  alias PkiMnesia.{TestHelper, Repo}
  alias PkiMnesia.Structs.IssuerKey
  alias PkiCaEngine.KeyStore.MockHsmAdapter

  setup do
    dir = TestHelper.setup_mnesia()

    # Start the MockHsmAdapter GenServer (safe if already running)
    pid =
      case MockHsmAdapter.start_link(name: :mock_hsm_test) do
        {:ok, p} -> p
        {:error, {:already_started, p}} -> p
      end

    # Fresh slate for every test
    MockHsmAdapter.reset()

    on_exit(fn ->
      if Process.alive?(pid), do: GenServer.stop(pid)
      TestHelper.teardown_mnesia(dir)
    end)

    :ok
  end

  # ---------------------------------------------------------------------------
  # generate_keypair/1
  # ---------------------------------------------------------------------------

  describe "generate_keypair/1" do
    test "generates ECC-P256 keypair and returns a non-empty public key" do
      assert {:ok, pub, _key_id} = MockHsmAdapter.generate_keypair("ECC-P256")
      assert is_binary(pub)
      assert byte_size(pub) > 0
    end

    test "generates RSA-2048 keypair and returns a non-empty public key" do
      assert {:ok, pub, _key_id} = MockHsmAdapter.generate_keypair("RSA-2048")
      assert is_binary(pub)
      assert byte_size(pub) > 0
    end

    test "returns error for unknown algorithm" do
      assert {:error, {:unknown_algorithm, "FAKE-ALGO"}} =
               MockHsmAdapter.generate_keypair("FAKE-ALGO")
    end

    test "stores the generated key so key_available? returns true" do
      {:ok, _pub, key_id} = MockHsmAdapter.generate_keypair("ECC-P256")
      assert MockHsmAdapter.key_available?(key_id)
    end
  end

  # ---------------------------------------------------------------------------
  # import_key/3 and key_available?/1
  # ---------------------------------------------------------------------------

  describe "import_key/3 and key_available?/1" do
    test "imported key is available" do
      {_pub, priv_der, key_id} = generate_ecc_keypair()
      :ok = MockHsmAdapter.import_key(key_id, "ECC-P256", priv_der)
      assert MockHsmAdapter.key_available?(key_id)
    end

    test "unknown key is not available" do
      refute MockHsmAdapter.key_available?("nonexistent-key-id")
    end

    test "deleted key is no longer available" do
      {_pub, priv_der, key_id} = generate_ecc_keypair()
      :ok = MockHsmAdapter.import_key(key_id, "ECC-P256", priv_der)
      assert MockHsmAdapter.key_available?(key_id)

      :ok = MockHsmAdapter.delete_key(key_id)
      refute MockHsmAdapter.key_available?(key_id)
    end

    test "reset clears all keys" do
      {_pub1, priv1, id1} = generate_ecc_keypair()
      {_pub2, priv2, id2} = generate_ecc_keypair()
      MockHsmAdapter.import_key(id1, "ECC-P256", priv1)
      MockHsmAdapter.import_key(id2, "ECC-P256", priv2)

      MockHsmAdapter.reset()

      refute MockHsmAdapter.key_available?(id1)
      refute MockHsmAdapter.key_available?(id2)
    end
  end

  # ---------------------------------------------------------------------------
  # sign/2 — ECC-P256 round-trip (uses the KeyStore.Dispatcher interface)
  # ---------------------------------------------------------------------------

  describe "sign/2 with ECC-P256" do
    test "sign + verify round-trip via import_key then sign" do
      {pub_point, priv_der, key_id} = generate_ecc_keypair()
      :ok = MockHsmAdapter.import_key(key_id, "ECC-P256", priv_der)

      tbs_data = :crypto.strong_rand_bytes(64)
      assert {:ok, signature} = MockHsmAdapter.sign(key_id, tbs_data)
      assert is_binary(signature)
      assert byte_size(signature) > 0

      # Verify with the native Erlang :public_key
      assert :crypto.verify(:ecdsa, :sha256, tbs_data, signature, [pub_point, :secp256r1])
    end

    test "sign returns error for key not in store" do
      assert {:error, {:key_not_in_mock_hsm, "missing-id"}} =
               MockHsmAdapter.sign("missing-id", "some-data")
    end

    test "sign via generate_keypair is consistent" do
      # generate_keypair stores the private key; we can sign with the returned key_id
      assert {:ok, _pub, key_id} = MockHsmAdapter.generate_keypair("ECC-P256")

      tbs = :crypto.strong_rand_bytes(32)
      assert {:ok, sig} = MockHsmAdapter.sign(key_id, tbs)
      assert byte_size(sig) > 0
    end
  end

  # ---------------------------------------------------------------------------
  # sign/2 — RSA round-trip
  # ---------------------------------------------------------------------------

  describe "sign/2 with RSA-2048" do
    test "sign + verify round-trip" do
      {pub_der, priv_der, key_id} = generate_rsa_keypair()
      :ok = MockHsmAdapter.import_key(key_id, "RSA-2048", priv_der)

      tbs_data = :crypto.strong_rand_bytes(64)
      assert {:ok, signature} = MockHsmAdapter.sign(key_id, tbs_data)
      assert is_binary(signature)
      assert byte_size(signature) > 0

      # Decode RSA public key for verification
      pub_key = :public_key.der_decode(:RSAPublicKey, pub_der)
      assert :public_key.verify(tbs_data, :sha256, signature, pub_key)
    end
  end

  # ---------------------------------------------------------------------------
  # PQC: KAZ-SIGN-192 (skipped unless NIF is available)
  # ---------------------------------------------------------------------------

  describe "sign/2 with KAZ-SIGN-192" do
    @tag :pqc
    test "generate KAZ-SIGN-192 keypair and sign + verify" do
      algo = PkiCrypto.Registry.get("KAZ-SIGN-192")

      if algo do
        result = PkiCrypto.Algorithm.generate_keypair(algo)

        case result do
          {:ok, %{public_key: pub, private_key: priv}} ->
            key_id = "kaz-sign-test-#{System.unique_integer([:positive])}"
            :ok = MockHsmAdapter.import_key(key_id, "KAZ-SIGN-192", priv)

            tbs = :crypto.strong_rand_bytes(64)
            assert {:ok, signature} = MockHsmAdapter.sign(key_id, tbs)
            assert byte_size(signature) > 0

            # Verify using PkiCrypto directly
            assert :ok = PkiCrypto.Algorithm.verify(algo, pub, signature, tbs)

          {:error, _} ->
            # KAZ-SIGN NIF not loaded — log and skip gracefully
            IO.puts("  [SKIP] KAZ-SIGN-192 NIF not available; skipping PQC round-trip")
        end
      else
        IO.puts("  [SKIP] KAZ-SIGN-192 not in PkiCrypto.Registry; skipping")
      end
    end
  end

  # ---------------------------------------------------------------------------
  # get_public_key/1
  # ---------------------------------------------------------------------------

  describe "get_public_key/1" do
    test "returns error for unknown key" do
      assert {:error, {:key_not_in_mock_hsm, "no-such-key"}} =
               MockHsmAdapter.get_public_key("no-such-key")
    end

    test "returns a non-empty binary for an imported RSA key" do
      {_pub, priv_der, key_id} = generate_rsa_keypair()
      :ok = MockHsmAdapter.import_key(key_id, "RSA-2048", priv_der)

      assert {:ok, pub_bytes} = MockHsmAdapter.get_public_key(key_id)
      assert is_binary(pub_bytes)
      assert byte_size(pub_bytes) > 0
    end
  end

  # ---------------------------------------------------------------------------
  # Dispatcher routing to MockHsmAdapter
  # ---------------------------------------------------------------------------

  describe "Dispatcher routes :mock_hsm to MockHsmAdapter" do
    test "sign via Dispatcher succeeds for :mock_hsm keystore_type" do
      alias PkiCaEngine.KeyStore.Dispatcher

      {_pub_point, priv_der, _gen_key_id} = generate_ecc_keypair()

      key =
        IssuerKey.new(%{
          ca_instance_id: "ca-mock-dispatch-1",
          algorithm: "ECC-P256",
          status: "active",
          keystore_type: :mock_hsm
        })

      {:ok, _} = Repo.insert(key)

      # Import the key using the issuer_key id so the adapter can find it
      :ok = MockHsmAdapter.import_key(key.id, "ECC-P256", priv_der)

      tbs = :crypto.strong_rand_bytes(32)
      assert {:ok, sig} = Dispatcher.sign(key.id, tbs)
      assert byte_size(sig) > 0
    end

    test "key_available? via Dispatcher returns true for :mock_hsm key in store" do
      alias PkiCaEngine.KeyStore.Dispatcher

      {_pub, priv_der, _} = generate_ecc_keypair()

      key =
        IssuerKey.new(%{
          ca_instance_id: "ca-mock-dispatch-2",
          algorithm: "ECC-P256",
          status: "active",
          keystore_type: :mock_hsm
        })

      {:ok, _} = Repo.insert(key)
      :ok = MockHsmAdapter.import_key(key.id, "ECC-P256", priv_der)

      assert Dispatcher.key_available?(key.id)
    end

    test "key_available? via Dispatcher returns false for :mock_hsm key not in store" do
      alias PkiCaEngine.KeyStore.Dispatcher

      key =
        IssuerKey.new(%{
          ca_instance_id: "ca-mock-dispatch-3",
          algorithm: "ECC-P256",
          status: "active",
          keystore_type: :mock_hsm
        })

      {:ok, _} = Repo.insert(key)

      # No key imported — should be false
      refute Dispatcher.key_available?(key.id)
    end
  end

  # ---------------------------------------------------------------------------
  # Private helpers
  # ---------------------------------------------------------------------------

  defp generate_ecc_keypair do
    ec_key  = :public_key.generate_key({:namedCurve, :secp256r1})
    priv_der = :public_key.der_encode(:ECPrivateKey, ec_key)
    pub_point = elem(ec_key, 4)
    key_id    = "ecc-#{System.unique_integer([:positive])}"
    {pub_point, priv_der, key_id}
  end

  defp generate_rsa_keypair do
    rsa_key  = :public_key.generate_key({:rsa, 2048, 65537})
    priv_der = :public_key.der_encode(:RSAPrivateKey, rsa_key)
    pub_key  = {:RSAPublicKey, elem(rsa_key, 2), elem(rsa_key, 3)}
    pub_der  = :public_key.der_encode(:RSAPublicKey, pub_key)
    key_id   = "rsa-#{System.unique_integer([:positive])}"
    {pub_der, priv_der, key_id}
  end
end
