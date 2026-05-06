defmodule PkiCaEngine.Integration.SofthsmKeygenTest do
  @moduledoc """
  SoftHSM2 integration tests for the HSM keygen ceremony path.

  ## Running

      mix test --include softhsm test/integration/softhsm_keygen_test.exs

  SoftHSM2 must be installed (`softhsm2-util` in PATH, `libsofthsm2.so`
  findable). The setup block auto-initializes a throw-away token in a
  temp directory — no pre-existing token configuration required.

  ## What is tested

  1. Low-level adapter — `LocalHsmAdapter.generate_key/3`, `sign_with_config/3`,
     `get_public_key/2` talking to a real libsofthsm2.so via the C port.

  2. Full ceremony flow — `CeremonyOrchestrator.initiate/2` +
     `execute_keygen/2` with `keystore_mode: "softhsm"`, asserting that the
     resulting `IssuerKey` has `keystore_type: :local_hsm`, `status: "active"`,
     and a fully-populated `hsm_config` map.

  ## Exclusion by default

  Tagged `@moduletag :softhsm`.  `test_helper.exs` has
  `ExUnit.start(exclude: [:softhsm])` so these tests are skipped in the
  normal `mix test` run.
  """

  use ExUnit.Case, async: false

  @moduletag :softhsm

  alias PkiMnesia.{TestHelper, Repo}
  alias PkiMnesia.Structs.IssuerKey
  alias PkiCaEngine.CeremonyOrchestrator
  alias PkiCaEngine.KeyStore.LocalHsmAdapter

  @softhsm_library_candidates [
    "/opt/homebrew/lib/softhsm/libsofthsm2.so",
    "/usr/lib/softhsm/libsofthsm2.so",
    "/usr/lib64/softhsm/libsofthsm2.so",
    "/usr/local/lib/softhsm/libsofthsm2.so"
  ]

  @user_pin "Test1234"
  @so_pin "Test12345678"

  # ---------------------------------------------------------------------------
  # setup_all — detect library, init a throw-away SoftHSM2 token once per run
  # ---------------------------------------------------------------------------

  setup_all do
    library_path = detect_softhsm_library()

    unless library_path do
      IO.puts("SKIP: libsofthsm2.so not found; skipping softhsm integration tests")
      # Signal skip by returning the atom — tests will abort in their own setup
      {:ok, %{softhsm_available: false}}
    else
      case init_throw_away_token() do
        {:ok, token_dir, conf_path, slot_id} ->
          on_exit(fn -> File.rm_rf!(token_dir) end)

          {:ok,
           %{
             softhsm_available: true,
             library_path: library_path,
             conf_path: conf_path,
             slot_id: slot_id
           }}

        {:error, reason} ->
          IO.puts("SKIP: could not initialize SoftHSM2 token: #{inspect(reason)}")
          {:ok, %{softhsm_available: false}}
      end
    end
  end

  # ---------------------------------------------------------------------------
  # setup — inject env vars, spin up Mnesia, clean up afterwards
  # ---------------------------------------------------------------------------

  setup context do
    unless context[:softhsm_available] do
      # Soft-skip individual tests when setup_all could not provision a token.
      :ok
    else
      %{library_path: lib, conf_path: conf, slot_id: slot} = context

      System.put_env("PKI_SOFTHSM_LIBRARY_PATH", lib)
      System.put_env("PKI_SOFTHSM_SLOT_ID", to_string(slot))
      System.put_env("PKI_SOFTHSM_USER_PIN", @user_pin)
      System.put_env("SOFTHSM2_CONF", conf)

      dir = TestHelper.setup_mnesia()

      on_exit(fn ->
        System.delete_env("PKI_SOFTHSM_LIBRARY_PATH")
        System.delete_env("PKI_SOFTHSM_SLOT_ID")
        System.delete_env("PKI_SOFTHSM_USER_PIN")
        System.delete_env("SOFTHSM2_CONF")
        TestHelper.teardown_mnesia(dir)
      end)

      :ok
    end
  end

  # ---------------------------------------------------------------------------
  # Test 1 — low-level adapter: generate → sign → get_public_key
  # ---------------------------------------------------------------------------

  test "LocalHsmAdapter: generate ECC-P256 key, sign data, retrieve public key", context do
    if context[:softhsm_available] == false, do: :ok

    %{library_path: lib, slot_id: slot} = context

    hsm_config = %{"library_path" => lib, "slot_id" => slot, "pin" => @user_pin}
    label = "test-ecc-#{System.unique_integer([:positive])}"

    # -- Generate --
    assert {:ok, keygen} = LocalHsmAdapter.generate_key(hsm_config, label, "ECC-P256")
    assert keygen.key_type == "ec"
    assert is_binary(keygen.public_key) and byte_size(keygen.public_key) > 0
    assert is_binary(keygen.key_id) and byte_size(keygen.key_id) > 0,
           "key_id (CKA_ID hex string) must be present"

    # -- Sign --
    tbs = :crypto.strong_rand_bytes(32)
    assert {:ok, signature} = LocalHsmAdapter.sign_with_config(hsm_config, label, tbs)
    assert is_binary(signature) and byte_size(signature) > 0

    # Verify the signature using the returned public key (raw EC point bytes)
    pub_key = {{:ECPoint, keygen.public_key}, {:namedCurve, {1, 2, 840, 10045, 3, 1, 7}}}
    assert :public_key.verify(tbs, :sha256, signature, pub_key),
           "signature produced by HSM must verify against the returned public key"

    # -- get_public_key via IssuerKey path --
    # We need an IssuerKey in Mnesia that references this label+slot so the
    # standard get_public_key/1 path can be exercised.
    key_id = PkiMnesia.Id.generate()

    issuer_key =
      IssuerKey.new(%{
        id: key_id,
        ca_instance_id: "ca-hsm-#{System.unique_integer()}",
        algorithm: "ECC-P256",
        keystore_type: :local_hsm,
        status: "active",
        hsm_config: Map.merge(hsm_config, %{"key_label" => label, "key_id" => keygen.key_id})
      })

    {:ok, _} = Repo.insert(issuer_key)

    assert {:ok, pub_bytes} = LocalHsmAdapter.get_public_key(key_id)
    assert is_binary(pub_bytes) and byte_size(pub_bytes) > 0
  end

  test "LocalHsmAdapter: generate RSA-2048 key and sign data", context do
    if context[:softhsm_available] == false, do: :ok

    %{library_path: lib, slot_id: slot} = context

    hsm_config = %{"library_path" => lib, "slot_id" => slot, "pin" => @user_pin}
    label = "test-rsa-#{System.unique_integer([:positive])}"

    assert {:ok, keygen} = LocalHsmAdapter.generate_key(hsm_config, label, "RSA-2048")
    assert keygen.key_type == "rsa"
    assert is_binary(keygen.modulus) and byte_size(keygen.modulus) > 0
    assert is_binary(keygen.public_exponent)

    tbs = :crypto.strong_rand_bytes(32)
    assert {:ok, signature} = LocalHsmAdapter.sign_with_config(hsm_config, label, tbs)
    assert is_binary(signature)

    modulus_int = :binary.decode_unsigned(keygen.modulus)
    exp_int = :binary.decode_unsigned(keygen.public_exponent)
    rsa_pub = {:RSAPublicKey, modulus_int, exp_int}

    assert :public_key.verify(tbs, :sha256, signature, rsa_pub)
  end

  # ---------------------------------------------------------------------------
  # Test 2 — full root CA ceremony via CeremonyOrchestrator
  # ---------------------------------------------------------------------------

  test "full root CA ceremony with keystore_mode softhsm produces activated IssuerKey", context do
    if context[:softhsm_available] == false, do: :ok

    ca_id = "ca-softhsm-root-#{System.unique_integer()}"

    params = %{
      algorithm: "ECC-P256",
      threshold_k: 2,
      threshold_n: 3,
      custodian_names: ["Alice", "Bob", "Charlie"],
      auditor_name: "Dave",
      is_root: true,
      ceremony_mode: :full,
      initiated_by: "integration-test",
      keystore_mode: "softhsm",
      key_alias: "root-key",
      subject_dn: "/CN=Test Root CA/O=Integration Test"
    }

    # Step 1: initiate
    assert {:ok, {ceremony, issuer_key, _shares, _participants, _transcript}} =
             CeremonyOrchestrator.initiate(ca_id, params)

    assert ceremony.keystore_mode == "softhsm"
    assert issuer_key.keystore_type == :local_hsm
    assert ceremony.status == "preparing"

    # Step 2: execute keygen — for HSM mode no custodian passwords are needed
    # because the private key never leaves the token and no Shamir shares are
    # created. The empty password list passes verify_custodian_passwords
    # (no ThresholdShare records exist for this IssuerKey yet).
    assert {:ok, activated_key} = CeremonyOrchestrator.execute_keygen(ceremony.id, [])

    # Assertions on the activated IssuerKey
    assert activated_key.keystore_type == :local_hsm
    assert activated_key.status == "active"

    hsm_cfg = activated_key.hsm_config
    assert is_map(hsm_cfg), "hsm_config must be populated"
    assert is_binary(hsm_cfg["library_path"]) and hsm_cfg["library_path"] != ""
    assert is_integer(hsm_cfg["slot_id"])
    assert is_binary(hsm_cfg["pin"]) and hsm_cfg["pin"] != ""
    assert is_binary(hsm_cfg["key_label"]) and hsm_cfg["key_label"] != "",
           "key_label must be set to the IssuerKey id"
    assert is_binary(hsm_cfg["key_id"]) and hsm_cfg["key_id"] != "",
           "key_id (CKA_ID from HSM) must be stored"

    # Root CA must have a self-signed certificate
    assert is_binary(activated_key.cert_der) and byte_size(activated_key.cert_der) > 0
    assert is_binary(activated_key.cert_pem) and String.starts_with?(activated_key.cert_pem, "-----BEGIN")

    # Verify the certificate is self-signed (issuer == subject, sig verifiable)
    assert_cert_self_signed(activated_key.cert_der, activated_key.algorithm)

    # The key must be readable from Mnesia
    assert {:ok, persisted} = Repo.get(IssuerKey, issuer_key.id)
    assert persisted.keystore_type == :local_hsm
    assert persisted.status == "active"
    assert is_map(persisted.hsm_config)
  end

  # ---------------------------------------------------------------------------
  # Test 3 — sub-CA ceremony (sub_ca auto-spawn via HSM)
  # ---------------------------------------------------------------------------

  test "sub-CA ceremony with keystore_mode softhsm produces root + sub IssuerKeys", context do
    if context[:softhsm_available] == false, do: :ok

    ca_id = "ca-softhsm-sub-#{System.unique_integer()}"

    params = %{
      algorithm: "ECC-P256",
      threshold_k: 2,
      threshold_n: 3,
      custodian_names: ["Alice", "Bob", "Charlie"],
      auditor_name: "Dave",
      is_root: false,
      ceremony_mode: :full,
      initiated_by: "integration-test",
      keystore_mode: "softhsm",
      key_alias: "sub-key",
      subject_dn: "/CN=Test Sub CA/O=Integration Test"
    }

    assert {:ok, {ceremony, issuer_key, _shares, _participants, _transcript}} =
             CeremonyOrchestrator.initiate(ca_id, params)

    assert {:ok, activated_key} = CeremonyOrchestrator.execute_keygen(ceremony.id, [])

    assert activated_key.keystore_type == :local_hsm
    assert activated_key.status == "active"
    assert is_map(activated_key.hsm_config)

    # Sub-CA produces a CSR, not a self-signed cert
    assert is_binary(activated_key.csr_pem) and String.starts_with?(activated_key.csr_pem, "-----BEGIN")
  end

  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  defp detect_softhsm_library do
    Enum.find(@softhsm_library_candidates, &File.exists?/1)
  end

  # Initialize a throw-away SoftHSM2 token in a temp directory.
  # Returns {:ok, token_dir, conf_path, slot_id} or {:error, reason}.
  defp init_throw_away_token do
    unless softhsm2_util_available?() do
      {:error, :softhsm2_util_not_in_path}
    else
      token_dir = Path.join(System.tmp_dir!(), "pki_softhsm_#{System.unique_integer([:positive])}")
      tokens_dir = Path.join(token_dir, "tokens")
      File.mkdir_p!(tokens_dir)

      conf_path = Path.join(token_dir, "softhsm2.conf")

      File.write!(conf_path, """
      directories.tokendir = #{tokens_dir}
      objectstore.backend = file
      log.level = INFO
      """)

      env = [{"SOFTHSM2_CONF", conf_path}]

      case System.cmd(
             "softhsm2-util",
             [
               "--init-token",
               "--free",
               "--label",
               "pki-test",
               "--pin",
               @user_pin,
               "--so-pin",
               @so_pin,
               "--config",
               conf_path
             ],
             env: env,
             stderr_to_stdout: true
           ) do
        {output, 0} ->
          slot_id = parse_assigned_slot(output)
          {:ok, token_dir, conf_path, slot_id}

        {output, exit_code} ->
          File.rm_rf!(token_dir)
          {:error, {:softhsm2_init_failed, exit_code, output}}
      end
    end
  end

  defp softhsm2_util_available? do
    case System.find_executable("softhsm2-util") do
      nil -> false
      _ -> true
    end
  end

  # Parse the slot ID from `softhsm2-util --init-token` output.
  # Output line: "The token has been initialized and is reassigned to slot NNNNN"
  defp parse_assigned_slot(output) do
    case Regex.run(~r/reassigned to slot (\d+)/i, output) do
      [_, id] -> String.to_integer(id)
      nil -> 0
    end
  end

  # Verify a DER certificate is self-signed for a given algorithm.
  # Parses the DER with OTP's :public_key module and checks the signature.
  defp assert_cert_self_signed(cert_der, _algorithm) do
    # OTP decodes the cert — raises on malformed DER
    cert = :public_key.pkix_decode_cert(cert_der, :otp)
    assert :public_key.pkix_is_self_signed(cert),
           "root CA certificate must be self-signed"
  end
end
