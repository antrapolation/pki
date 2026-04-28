defmodule PkiValidation.CrlStrategyTest do
  use ExUnit.Case, async: false

  alias PkiMnesia.{TestHelper, Repo}
  alias PkiMnesia.Structs.{IssuerKey, PreSignedCrl}
  alias PkiCaEngine.{KeyActivation}
  alias PkiCaEngine.KeyStore.MockHsmAdapter
  alias PkiValidation.CrlPublisher

  # Secp256r1 OID — same as OcspResponderLeaseTest
  @secp256r1_oid {1, 2, 840, 10045, 3, 1, 7}

  setup do
    dir = TestHelper.setup_mnesia()

    on_exit(fn ->
      if :ets.whereis(:mock_hsm_keys) != :undefined do
        MockHsmAdapter.reset()
      end

      TestHelper.teardown_mnesia(dir)
    end)

    :ok
  end

  describe "per_interval strategy" do
    test "returns {:error, :no_active_lease} when no active lease exists" do
      issuer_key = IssuerKey.new(%{
        ca_instance_id: "ca-1",
        algorithm: "RSA",
        key_alias: "test-key-per-interval",
        status: "active",
        crl_strategy: "per_interval"
      })
      {:ok, _} = Repo.insert(issuer_key)

      # Start a KeyActivation server with no leases
      {:ok, ka_pid} = PkiCaEngine.KeyActivation.start_link(name: :test_ka_per_interval)

      on_exit(fn ->
        if Process.alive?(ka_pid), do: GenServer.stop(ka_pid)
      end)

      result = CrlPublisher.signed_crl(issuer_key.id,
        activation_server: :test_ka_per_interval
      )

      assert result == {:error, :no_active_lease}
    end

    test "returns a signed CRL map when an active lease exists" do
      # Start MockHsmAdapter so Dispatcher can route :mock_hsm keys
      mock_pid =
        case MockHsmAdapter.start_link(name: :test_mock_hsm_crl) do
          {:ok, pid} -> pid
          {:error, {:already_started, pid}} -> pid
        end

      {:ok, ka_pid} = KeyActivation.start_link(name: :test_ka_per_interval_happy)

      on_exit(fn ->
        if Process.alive?(ka_pid), do: GenServer.stop(ka_pid)
        if Process.alive?(mock_pid), do: GenServer.stop(mock_pid)
      end)

      key_id = "crl-happy-#{System.unique_integer()}"

      # Generate a real ECC-P256 private key and DER-encode it
      {pub_point, priv_bin} = :crypto.generate_key(:ecdh, :secp256r1)

      priv_der =
        :public_key.der_encode(
          :ECPrivateKey,
          {:ECPrivateKey, 1, priv_bin, {:namedCurve, @secp256r1_oid}, pub_point, :asn1_NOVALUE}
        )

      # Import the key into MockHsmAdapter
      :ok = MockHsmAdapter.import_key(key_id, "ECC-P256", priv_der)

      # Insert IssuerKey with keystore_type :mock_hsm so Dispatcher routes correctly
      issuer_key =
        IssuerKey.new(%{
          id: key_id,
          ca_instance_id: "ca-happy",
          algorithm: "ECC-P256",
          key_alias: "test-key-per-interval-happy",
          status: "active",
          crl_strategy: "per_interval",
          keystore_type: :mock_hsm
        })

      {:ok, _} = Repo.insert(issuer_key)

      # Activate a lease — handle is opaque; signing is done via MockHsmAdapter ETS lookup
      handle = :crypto.strong_rand_bytes(32)
      {:ok, ^key_id} = KeyActivation.activate(ka_pid, key_id, handle, ["alice"], max_ops: 10)

      # Pre-condition: lease is active
      assert %{active: true} = KeyActivation.lease_status(:test_ka_per_interval_happy, key_id)

      result = CrlPublisher.signed_crl(key_id, activation_server: :test_ka_per_interval_happy)

      # Must succeed — no error, no :unsigned flag
      assert {:ok, crl} = result
      assert is_binary(crl.signature), "expected a binary signature in the signed CRL"
      assert crl.algorithm == "ECC-P256"
      refute Map.has_key?(crl, :unsigned), "per_interval must never return an unsigned CRL"
    end
  end

  describe "pre_signed strategy" do
    test "returns crl_der when a valid PreSignedCrl exists for current time" do
      issuer_key = IssuerKey.new(%{
        ca_instance_id: "ca-2",
        algorithm: "RSA",
        key_alias: "test-key-pre-signed",
        status: "active",
        crl_strategy: "pre_signed"
      })
      {:ok, _} = Repo.insert(issuer_key)

      now = DateTime.utc_now() |> DateTime.truncate(:second)
      valid_from = DateTime.add(now, -300, :second)
      valid_until = DateTime.add(now, 3600, :second)
      crl_der = :erlang.term_to_binary(%{type: "X509CRL", stub: true})

      pre_signed = PreSignedCrl.new(%{
        issuer_key_id: issuer_key.id,
        valid_from: valid_from,
        valid_until: valid_until,
        crl_der: crl_der
      })
      {:ok, _} = Repo.insert(pre_signed)

      result = CrlPublisher.signed_crl(issuer_key.id)

      assert result == {:ok, crl_der}
    end

    test "returns {:error, :no_valid_pre_signed_crl} when no valid record exists" do
      issuer_key = IssuerKey.new(%{
        ca_instance_id: "ca-3",
        algorithm: "RSA",
        key_alias: "test-key-pre-signed-empty",
        status: "active",
        crl_strategy: "pre_signed"
      })
      {:ok, _} = Repo.insert(issuer_key)

      # Insert an expired pre-signed CRL (valid_until in the past)
      now = DateTime.utc_now() |> DateTime.truncate(:second)
      expired_from = DateTime.add(now, -7200, :second)
      expired_until = DateTime.add(now, -3600, :second)

      expired = PreSignedCrl.new(%{
        issuer_key_id: issuer_key.id,
        valid_from: expired_from,
        valid_until: expired_until,
        crl_der: <<1, 2, 3>>
      })
      {:ok, _} = Repo.insert(expired)

      result = CrlPublisher.signed_crl(issuer_key.id)

      assert result == {:error, :no_valid_pre_signed_crl}
    end
  end
end
