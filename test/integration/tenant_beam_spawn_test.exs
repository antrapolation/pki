defmodule PkiIntegration.TenantBeamSpawnTest do
  @moduledoc """
  End-to-end test for the per-tenant BEAM spawn path.

  Reproduces exactly what `PkiPlatformEngine.TenantLifecycle` does when
  the platform portal creates a tenant:

    1. `:peer.start/1` a fresh BEAM with matching -sname/-name and the
       parent's full code path forwarded via -pa.
    2. RPC `:application.ensure_all_started/1` for `:elixir`, then for
       `:pki_tenant_web` on the peer node.
    3. RPC `PkiTenant.PortalUserAdmin.create_user/1` on the peer to mint
       the first ca_admin.

  Regression coverage for every breakage discovered during the M6a
  manual QA session:

    * short vs long name mismatch ({:exit_status, 1} in net_kernel)
    * missing Elixir on the peer's code path (elixir.app not found)
    * missing PkiTenant.PortalUserAdmin on the peer (no Mnesia init)

  No Postgres involved — this test only covers the BEAM-spawn path,
  not the wrapping Tenant row writes. A separate test can combine
  both once a dedicated platform-test Postgres DB is available.
  """
  use ExUnit.Case, async: false

  @peer_boot_timeout 90_000

  setup_all do
    System.cmd("epmd", ["-daemon"], stderr_to_stdout: true)

    unless Node.alive?() do
      {:ok, _} = Node.start(:"tenant_beam_spawn_test", :shortnames)
      Node.set_cookie(:tenant_beam_spawn_test_cookie)
    end

    :ok
  end

  setup do
    slug = "itest#{System.unique_integer([:positive])}"
    tenant_id = Uniq.UUID.uuid7()
    mnesia_dir = Path.join(System.tmp_dir!(), "pki_tenant_spawn_test/#{slug}")

    on_exit(fn -> File.rm_rf!(mnesia_dir) end)

    %{slug: slug, tenant_id: tenant_id, mnesia_dir: mnesia_dir}
  end

  test "peer BEAM boots, runs pki_tenant_web, can create ca_admin", ctx do
    %{slug: slug, tenant_id: tenant_id, mnesia_dir: mnesia_dir} = ctx

    {name_flag, node_name} = peer_name_for(slug)
    code_path_args = Enum.flat_map(:code.get_path(), fn p -> [~c"-pa", p] end)
    cookie = Node.get_cookie() |> Atom.to_charlist()

    args =
      [~c"-setcookie", cookie, name_flag, Atom.to_charlist(node_name)] ++ code_path_args

    env = [
      {~c"TENANT_ID", String.to_charlist(tenant_id)},
      {~c"TENANT_SLUG", String.to_charlist(slug)},
      {~c"MNESIA_DIR", String.to_charlist(mnesia_dir)}
    ]

    # 1. :peer.start should return successfully (not exit the test process).
    peer_result =
      :peer.start(%{
        name: node_name,
        args: args,
        env: env,
        connection: :standard_io
      })

    {peer_pid, actual_node} =
      case peer_result do
        {:ok, pid, node} -> {pid, node}
        {:ok, pid} -> {pid, node_name}
        other -> flunk("peer start failed: #{inspect(other)}")
      end

    on_exit(fn ->
      try do
        :peer.stop(peer_pid)
      catch
        :exit, _ -> :ok
      end
    end)

    # 2. Boot the app stack exactly the way the real flow does —
    #    forwards compile-time config to the peer, starts :elixir,
    #    then :pki_tenant_web (which pulls in pki_tenant,
    #    pki_ca_engine, pki_ra_engine, pki_validation, pki_mnesia and
    #    runs PkiTenant.MnesiaBootstrap.init/1 to create the Mnesia
    #    schema at MNESIA_DIR).
    assert :ok = PkiPlatformEngine.TenantLifecycle.boot_tenant_apps(actual_node, @peer_boot_timeout)

    running_apps =
      :rpc.call(actual_node, :application, :which_applications, [])
      |> Enum.map(&elem(&1, 0))

    assert :pki_tenant_web in running_apps
    assert :pki_tenant in running_apps
    assert :pki_mnesia in running_apps

    # 3. Create the first ca_admin via the same helper the wizard calls.
    attrs = %{
      username: "#{slug}-admin",
      display_name: "Test Admin #{slug}",
      email: "admin@#{slug}.example",
      role: "ca_admin"
    }

    assert {:ok, user, plaintext} =
             PkiPlatformEngine.TenantLifecycle.create_initial_admin(actual_node, attrs)

    assert user.username == "#{slug}-admin"
    assert user.role == "ca_admin"
    assert user.status == "active"
    assert is_binary(plaintext)
    assert String.length(plaintext) == 16
    assert String.starts_with?(user.password_hash, "$argon2")

    # 4. Sanity: a second user with the same username should be rejected
    #    by the tenant's Mnesia uniqueness guard.
    assert {:error, :username_taken} =
             PkiPlatformEngine.TenantLifecycle.create_initial_admin(actual_node, attrs)
  end

  # Matches the naming convention in PkiPlatformEngine.TenantLifecycle.peer_name/1.
  # Erlang won't let short-name (-sname) and long-name (-name) nodes cluster,
  # so the peer has to follow whichever style the parent node uses.
  defp peer_name_for(slug) do
    parent = Node.self() |> Atom.to_string()
    short_name = "pki_tenant_spawn_test_#{slug}"

    [_, host] = String.split(parent, "@", parts: 2)

    if String.contains?(host, ".") do
      {~c"-name", :"#{short_name}@#{host}"}
    else
      {~c"-sname", :"#{short_name}@#{host}"}
    end
  end
end
