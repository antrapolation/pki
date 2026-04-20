defmodule PkiPlatformEngine.SofthsmTokenManagerTest do
  @moduledoc """
  Task #22: per-tenant SoftHSM2 token initialization.

  Tests shell out to real `softhsm2-util` — tagged `:softhsm` so CI
  without the binary skips them (matches the existing convention in
  `test/test_helper.exs`). The skipping path (`available?/0`) is
  also covered so we know the wizard keeps going when softhsm is
  absent.
  """
  use ExUnit.Case, async: false

  alias PkiPlatformEngine.SofthsmTokenManager

  setup do
    base = Path.join(System.tmp_dir!(), "softhsm_token_mgr_test_#{System.unique_integer([:positive])}")
    File.mkdir_p!(base)
    on_exit(fn -> File.rm_rf!(base) end)
    {:ok, base: base}
  end

  describe "available?/0" do
    test "does not raise regardless of softhsm2-util presence" do
      assert is_boolean(SofthsmTokenManager.available?())
    end
  end

  describe "cleanup_tenant_token/2" do
    test "is idempotent — removing a non-existent dir is :ok", %{base: base} do
      assert :ok = SofthsmTokenManager.cleanup_tenant_token("never-created", base_dir: base)
    end

    test "removes the tenant dir when present", %{base: base} do
      tenant_dir = Path.join(base, "to-delete")
      File.mkdir_p!(tenant_dir)
      File.write!(Path.join(tenant_dir, "marker"), "x")
      refute File.dir?(tenant_dir) == false

      assert :ok = SofthsmTokenManager.cleanup_tenant_token("to-delete", base_dir: base)
      refute File.dir?(tenant_dir)
    end
  end

  @tag :softhsm
  describe "init_tenant_token/2" do
    test "creates conf, inits token, returns a slot + PINs", %{base: base} do
      slug = "test-tenant-#{System.unique_integer([:positive])}"

      assert {:ok, info} =
               SofthsmTokenManager.init_tenant_token(slug,
                 base_dir: base,
                 user_pin: "1234",
                 so_pin: "12345678"
               )

      assert info.conf_path == Path.join([base, slug, "softhsm2.conf"])
      assert info.tenant_dir == Path.join(base, slug)
      assert info.label == "tenant-#{slug}"
      assert info.user_pin == "1234"
      assert info.so_pin == "12345678"
      assert is_integer(info.slot_id)

      # Conf file written with the expected tokendir line.
      conf = File.read!(info.conf_path)
      assert conf =~ "directories.tokendir = #{info.tenant_dir}"

      # PIN file exists, contains both PINs, and is mode 0600.
      pin_path = Path.join(info.tenant_dir, ".pins")
      assert File.exists?(pin_path)
      assert File.read!(pin_path) == "user=1234\nso=12345678\n"
      # stat mode includes the file type bits — mask to the perm bits.
      %File.Stat{mode: mode} = File.stat!(pin_path)
      assert Bitwise.band(mode, 0o777) == 0o600
    end

    test "two tenants get distinct directories and slots", %{base: base} do
      slug_a = "iso-a-#{System.unique_integer([:positive])}"
      slug_b = "iso-b-#{System.unique_integer([:positive])}"

      assert {:ok, a} = SofthsmTokenManager.init_tenant_token(slug_a, base_dir: base)
      assert {:ok, b} = SofthsmTokenManager.init_tenant_token(slug_b, base_dir: base)

      refute a.tenant_dir == b.tenant_dir
      refute a.slot_id == b.slot_id
      refute a.conf_path == b.conf_path
    end

    test "with tenant_id + master key: wraps PINs into envelope, skips .pins file", %{base: base} do
      defmodule StubBackend do
        @behaviour PkiPlatformEngine.SecretManager
        @impl true
        def master_key, do: {:ok, <<9::256>>}
      end

      prev = Application.get_env(:pki_platform_engine, :secret_manager)
      Application.put_env(:pki_platform_engine, :secret_manager, StubBackend)

      on_exit(fn ->
        if prev,
          do: Application.put_env(:pki_platform_engine, :secret_manager, prev),
          else: Application.delete_env(:pki_platform_engine, :secret_manager)
      end)

      slug = "wrapped-#{System.unique_integer([:positive])}"
      tenant_id = "01ffffff-0000-7000-8000-#{String.slice(slug <> "000000000000", 0, 12)}"

      assert {:ok, info} =
               SofthsmTokenManager.init_tenant_token(slug,
                 base_dir: base,
                 tenant_id: tenant_id,
                 user_pin: "4321",
                 so_pin: "87654321"
               )

      # Envelope came back, carries the expected v1 shape.
      assert is_map(info.pin_envelope)
      assert info.pin_envelope["version"] == "v1"

      # PIN file must NOT be on disk when envelope path is taken.
      refute File.exists?(Path.join(info.tenant_dir, ".pins"))

      # Round-trip the envelope to confirm it's decryptable with the
      # same tenant_id + master key.
      assert {:ok, %{user_pin: "4321", so_pin: "87654321"}} =
               PkiPlatformEngine.SofthsmPinCustody.unwrap(tenant_id, info.pin_envelope)
    end

    test "cleanup_tenant_token removes an initialized token", %{base: base} do
      slug = "cleanup-#{System.unique_integer([:positive])}"

      {:ok, info} = SofthsmTokenManager.init_tenant_token(slug, base_dir: base)
      assert File.dir?(info.tenant_dir)

      assert :ok = SofthsmTokenManager.cleanup_tenant_token(slug, base_dir: base)
      refute File.dir?(info.tenant_dir)
    end
  end
end
