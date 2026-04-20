defmodule PkiIntegration.TenantPeerPqcNifTest do
  @moduledoc """
  Coverage for task #20: PQC NIFs must load on spawned tenant peers.

  Per project policy, KAZ-SIGN (Malaysia's PQC algorithm) and liboqs
  (NIST PQC standards — ML-DSA, SLH-DSA, etc.) are production
  dependencies, not optional fallbacks. A tenant peer that comes up
  without these NIFs silently falls back to classical algorithms,
  which is a deployment-level failure we want to catch in CI rather
  than at cert-issuance time.

  The parent's `:code.get_path()` (forwarded via `-pa` when the peer
  is spawned) includes the kaz_sign and pki_oqs_nif ebin + priv
  directories. `:application.ensure_all_started(:pki_tenant_web)`
  transitively loads `:pki_crypto`, whose application deps include
  both NIF apps — which is what registers their priv paths so
  `:erlang.load_nif` can locate the `.so` binaries.

  If this test ever starts failing, the fix is to rebuild the NIFs
  for the target platform (or fix the cross-compile) — not to
  disable the test.
  """
  use ExUnit.Case, async: false

  @tag :pqc_nif
  @peer_boot_timeout 90_000

  setup_all do
    System.cmd("epmd", ["-daemon"], stderr_to_stdout: true)

    unless Node.alive?() do
      {:ok, _} = Node.start(:"tenant_peer_pqc_nif_test", :shortnames)
      Node.set_cookie(:tenant_peer_pqc_nif_test_cookie)
    end

    :ok
  end

  setup do
    base = Path.join(System.tmp_dir!(), "pki_tenant_pqc_nif_test_#{System.unique_integer([:positive])}")
    File.mkdir_p!(base)

    prev_base = Application.get_env(:pki_platform_engine, :tenant_mnesia_base)
    Application.put_env(:pki_platform_engine, :tenant_mnesia_base, base)

    engine_apps = [:pki_ca_engine, :pki_ra_engine, :pki_validation]
    prev_engine_flags =
      for app <- engine_apps, do: {app, Application.get_env(app, :start_application)}

    for app <- engine_apps, do: Application.put_env(app, :start_application, true)

    on_exit(fn ->
      if prev_base,
        do: Application.put_env(:pki_platform_engine, :tenant_mnesia_base, prev_base),
        else: Application.delete_env(:pki_platform_engine, :tenant_mnesia_base)

      for {app, prev} <- prev_engine_flags do
        if is_nil(prev),
          do: Application.delete_env(app, :start_application),
          else: Application.put_env(app, :start_application, prev)
      end

      File.rm_rf!(base)
    end)

    %{base: base}
  end

  test "KAZ-SIGN and liboqs NIFs load and are callable on the tenant peer" do
    tenant = spawn_and_boot("pqc_nif")

    try do
      # --- liboqs (ML-DSA-65) -----------------------------------------
      assert {:ok, %{public_key: pub, private_key: priv}} =
               :rpc.call(tenant.node, PkiOqsNif, :keygen, ["ML-DSA-65"], @peer_boot_timeout),
             "PkiOqsNif.keygen/1 must succeed on the peer — NIF missing or not loaded"

      assert byte_size(pub) > 0 and byte_size(priv) > 0

      assert {:ok, sig} =
               :rpc.call(tenant.node, PkiOqsNif, :sign, ["ML-DSA-65", priv, "hello"], @peer_boot_timeout)

      assert byte_size(sig) > 0

      assert :ok =
               :rpc.call(tenant.node, PkiOqsNif, :verify, ["ML-DSA-65", pub, sig, "hello"], @peer_boot_timeout)

      # --- KAZ-SIGN 128 -----------------------------------------------
      assert :ok = :rpc.call(tenant.node, KazSign, :init, [128], @peer_boot_timeout),
             "KazSign.init/1 must succeed on the peer — NIF missing or init fails"

      assert {:ok, %{public_key: k_pub, private_key: k_priv}} =
               :rpc.call(tenant.node, KazSign, :keypair, [128], @peer_boot_timeout)

      assert byte_size(k_pub) > 0 and byte_size(k_priv) > 0

      assert {:ok, k_sig} =
               :rpc.call(tenant.node, KazSign, :sign_detached, [128, "hello", k_priv], @peer_boot_timeout)

      assert byte_size(k_sig) > 0

      assert {:ok, true} =
               :rpc.call(tenant.node, KazSign, :verify_detached, [128, "hello", k_sig, k_pub], @peer_boot_timeout)
    after
      stop_peer(tenant.pid)
    end
  end

  # --- helpers ----------------------------------------------------------

  defp spawn_and_boot(prefix) do
    slug = "#{prefix}#{System.unique_integer([:positive])}"
    tenant_id = "01ffffff-0000-7000-8000-" <> String.slice(slug <> "000000000000", 0, 12)
    web_port = 5_000 + rem(System.unique_integer([:positive]), 10_000)

    {:ok, pid, node} =
      PkiPlatformEngine.TenantLifecycle.spawn_tenant_for_test(tenant_id, slug, 0)

    on_exit(fn -> stop_peer(pid) end)

    assert :ok =
             PkiPlatformEngine.TenantLifecycle.boot_tenant_apps(node, web_port, @peer_boot_timeout)

    %{pid: pid, node: node, slug: slug, web_port: web_port}
  end

  defp stop_peer(pid) do
    try do
      :peer.stop(pid)
    catch
      :exit, _ -> :ok
    end

    :ok
  end
end
