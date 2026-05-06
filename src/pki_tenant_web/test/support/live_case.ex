defmodule PkiTenantWeb.LiveCase do
  @moduledoc """
  Test case for Phoenix LiveView tests.

  Starts Mnesia per test and injects a ca_admin session into the conn.
  PkiTenantWeb.{PubSub,SessionStore,Endpoint} are already running via
  the pki_tenant_web application supervisor.
  """

  use ExUnit.CaseTemplate

  alias PkiMnesia.Repo
  alias PkiMnesia.Structs.{IssuerKey, IssuedCertificate}

  # ---------------------------------------------------------------------------
  # Public helpers — called from setup and from test modules via using
  # ---------------------------------------------------------------------------

  def build_conn_for_role(role, opts \\ []) do
    {:ok, sid} =
      PkiTenantWeb.SessionStore.create(%{
        user_id: "test-#{role}-#{System.unique_integer()}",
        username: "test_#{role}",
        role: role,
        ip: "127.0.0.1",
        user_agent: "ExUnit",
        display_name: "Test #{role}",
        email: "#{role}@test.local"
      })

    host = Keyword.get(opts, :host, "localhost")

    Phoenix.ConnTest.build_conn()
    |> Map.put(:host, host)
    |> Phoenix.ConnTest.init_test_session(%{"session_id" => sid})
  end

  def build_ra_conn_for_role(role) do
    build_conn_for_role(role, host: "tenant.ra.localhost")
  end

  def seed_issuer_key(attrs \\ %{}) do
    key =
      IssuerKey.new(
        Map.merge(
          %{
            ca_instance_id: "ca-test-#{System.unique_integer()}",
            key_alias: "test-key-#{System.unique_integer()}",
            algorithm: "ECC-P256",
            status: "active",
            crl_strategy: "per_interval",
            key_mode: "threshold",
            key_role: "issuing_sub",
            keystore_type: :software
          },
          attrs
        )
      )

    {:ok, inserted} = Repo.insert(key)
    inserted
  end

  def seed_certificate(attrs \\ %{}) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    cert =
      IssuedCertificate.new(
        Map.merge(
          %{
            serial_number: "serial-#{System.unique_integer([:positive])}",
            issuer_key_id: "key-test-#{System.unique_integer()}",
            subject_dn: "CN=Test Subject",
            cert_pem: "-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----",
            not_before: now,
            not_after: DateTime.add(now, 365 * 86400, :second),
            status: "active"
          },
          attrs
        )
      )

    {:ok, inserted} = Repo.insert(cert)
    inserted
  end

  # ---------------------------------------------------------------------------
  # using — imports into test modules
  # ---------------------------------------------------------------------------

  using do
    quote do
      import Phoenix.ConnTest
      import Phoenix.LiveViewTest

      @endpoint PkiTenantWeb.Endpoint

      alias PkiMnesia.Repo
      alias PkiMnesia.Structs.{IssuerKey, IssuedCertificate}

      defdelegate build_conn_for_role(role, opts \\ []), to: PkiTenantWeb.LiveCase
      defdelegate build_ra_conn_for_role(role), to: PkiTenantWeb.LiveCase
      defdelegate seed_issuer_key(attrs \\ %{}), to: PkiTenantWeb.LiveCase
      defdelegate seed_certificate(attrs \\ %{}), to: PkiTenantWeb.LiveCase
    end
  end

  # ---------------------------------------------------------------------------
  # Per-test setup
  # ---------------------------------------------------------------------------

  setup do
    dir = PkiMnesia.TestHelper.setup_mnesia()
    on_exit(fn -> PkiMnesia.TestHelper.teardown_mnesia(dir) end)
    {:ok, conn: build_conn_for_role(:ca_admin)}
  end
end
