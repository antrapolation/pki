defmodule PkiMnesia.SchemaTest do
  use ExUnit.Case, async: false

  alias PkiMnesia.{Schema, TestHelper}
  alias PkiMnesia.Structs.{CaInstance, IssuerKey, IssuedCertificate, CsrRequest, CertificateStatus, KeyCeremony}

  setup do
    dir = TestHelper.setup_mnesia()
    on_exit(fn -> TestHelper.teardown_mnesia(dir) end)
    :ok
  end

  test "create_tables creates all 17 tables (including schema_versions)" do
    # Tables already created by setup_mnesia, verify they exist
    tables = :mnesia.system_info(:local_tables) -- [:schema]
    assert length(tables) == 17
  end

  test "ca_instances table has correct attributes" do
    table = Schema.table_name(CaInstance)
    attrs = :mnesia.table_info(table, :attributes)
    expected = Schema.struct_attributes(CaInstance)
    assert attrs == expected
  end

  test "issuer_keys table has correct attributes" do
    table = Schema.table_name(IssuerKey)
    attrs = :mnesia.table_info(table, :attributes)
    expected = Schema.struct_attributes(IssuerKey)
    assert attrs == expected
  end

  test "struct_attributes returns :id first for IssuerKey" do
    attrs = Schema.struct_attributes(IssuerKey)
    assert hd(attrs) == :id
  end

  test "issued_certificates uses disc_only_copies" do
    table = Schema.table_name(IssuedCertificate)
    disc_only = :mnesia.table_info(table, :disc_only_copies)
    assert node() in disc_only
  end

  test "csr_requests uses disc_only_copies" do
    table = Schema.table_name(CsrRequest)
    disc_only = :mnesia.table_info(table, :disc_only_copies)
    assert node() in disc_only
  end

  test "certificate_status uses disc_only_copies" do
    table = Schema.table_name(CertificateStatus)
    disc_only = :mnesia.table_info(table, :disc_only_copies)
    assert node() in disc_only
  end

  test "ca_instances uses disc_copies" do
    table = Schema.table_name(CaInstance)
    disc = :mnesia.table_info(table, :disc_copies)
    assert node() in disc
  end

  test "table_name converts struct module to plural snake_case atom" do
    assert Schema.table_name(CaInstance) == :ca_instances
    assert Schema.table_name(IssuerKey) == :issuer_keys
    assert Schema.table_name(CertificateStatus) == :certificate_status
  end

  test "table_name applies plural overrides for key_ceremony" do
    assert Schema.table_name(KeyCeremony) == :key_ceremonies
  end

  test "create_tables is idempotent (calling twice does not error)" do
    assert :ok == Schema.create_tables()
  end
end
