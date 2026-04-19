defmodule PkiCaEngine.KeyStore.LocalHsmAdapterTest do
  use ExUnit.Case, async: false

  alias PkiMnesia.{TestHelper, Repo}
  alias PkiMnesia.Structs.IssuerKey
  alias PkiCaEngine.KeyStore.{LocalHsmAdapter, Pkcs11Port}

  # SoftHSM2 library path — override via SOFTHSM2_LIB env var.
  @softhsm_lib System.get_env("SOFTHSM2_LIB") || "/opt/homebrew/lib/softhsm/libsofthsm2.so"

  setup do
    dir = TestHelper.setup_mnesia()

    on_exit(fn ->
      TestHelper.teardown_mnesia(dir)
    end)

    :ok
  end

  # ---------------------------------------------------------------------------
  # Port binary existence
  # ---------------------------------------------------------------------------

  test "pkcs11_port binary exists at expected priv path" do
    port_binary = Path.join(:code.priv_dir(:pki_ca_engine), "pkcs11_port")
    assert File.exists?(port_binary), "pkcs11_port binary not found at #{port_binary} — run 'make' in src/pki_ca_engine/priv/"
  end

  # ---------------------------------------------------------------------------
  # key_available?/1
  # ---------------------------------------------------------------------------

  test "key_available? returns true for :local_hsm keys" do
    key = IssuerKey.new(%{
      ca_instance_id: "ca-1",
      algorithm: "ECC-P256",
      status: "active",
      keystore_type: :local_hsm,
      hsm_config: %{
        "library_path" => "/some/lib.so",
        "slot_id" => 0,
        "pin" => "1234",
        "key_label" => "k"
      }
    })
    {:ok, _} = Repo.insert(key)

    # key_available? checks keystore_type only — actual HSM connectivity is
    # deferred to sign time.
    assert LocalHsmAdapter.key_available?(key.id)
  end

  test "key_available? returns false for unknown issuer_key_id" do
    refute LocalHsmAdapter.key_available?("nonexistent-id")
  end

  # ---------------------------------------------------------------------------
  # sign/2 — error paths (no real HSM required)
  # ---------------------------------------------------------------------------

  test "sign returns error when port binary not available (nonexistent library)" do
    key = IssuerKey.new(%{
      ca_instance_id: "ca-1",
      algorithm: "ECC-P256",
      status: "active",
      keystore_type: :local_hsm,
      hsm_config: %{
        "library_path" => "/nonexistent/libhsm.so",
        "slot_id" => 0,
        "pin" => "1234",
        "key_label" => "test-key"
      }
    })
    {:ok, _} = Repo.insert(key)

    # Pkcs11Port fails to init_hsm because the library doesn't exist —
    # start_link returns an error and sign propagates it.
    assert {:error, _reason} = LocalHsmAdapter.sign(key.id, "tbs-data")
  end

  test "sign returns error for unknown issuer_key_id" do
    assert {:error, :issuer_key_not_found} = LocalHsmAdapter.sign("nonexistent-id", "tbs-data")
  end

  # ---------------------------------------------------------------------------
  # SoftHSM2 integration tests (tagged :softhsm — skipped by default)
  # ---------------------------------------------------------------------------

  @tag :softhsm
  test "Pkcs11Port starts and responds to ping" do
    port_binary = Path.join(:code.priv_dir(:pki_ca_engine), "pkcs11_port")

    if File.exists?(port_binary) and File.exists?(@softhsm_lib) do
      {:ok, pid} =
        Pkcs11Port.start_link(
          port_binary: port_binary,
          library_path: @softhsm_lib,
          slot_id: 0,
          pin: "1234",
          name: :test_pkcs11_port_ping
        )

      assert {:ok, :pong} = Pkcs11Port.ping(pid)
      GenServer.stop(pid)
    else
      IO.puts("Skipping: SoftHSM2 (#{@softhsm_lib}) or pkcs11_port binary not found")
    end
  end

  @tag :softhsm
  test "sign via LocalHsmAdapter with SoftHSM2" do
    port_binary = Path.join(:code.priv_dir(:pki_ca_engine), "pkcs11_port")

    if File.exists?(port_binary) and File.exists?(@softhsm_lib) do
      key = IssuerKey.new(%{
        ca_instance_id: "ca-1",
        algorithm: "ECC-P256",
        status: "active",
        keystore_type: :local_hsm,
        hsm_config: %{
          "library_path" => @softhsm_lib,
          "slot_id" => 0,
          "pin" => "1234",
          "key_label" => "test-key"
        }
      })
      {:ok, _} = Repo.insert(key)

      tbs_data = :crypto.hash(:sha256, "test data to sign")
      result = LocalHsmAdapter.sign(key.id, tbs_data)

      assert {:ok, signature} = result
      assert is_binary(signature)
      assert byte_size(signature) > 0
    else
      IO.puts("Skipping: SoftHSM2 (#{@softhsm_lib}) or pkcs11_port binary not found")
    end
  end
end
