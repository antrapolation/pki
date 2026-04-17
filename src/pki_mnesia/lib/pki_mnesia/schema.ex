defmodule PkiMnesia.Schema do
  @moduledoc """
  Creates all Mnesia tables for a tenant node.
  Each table stores Elixir structs. Table attributes match struct fields.
  """

  require Logger

  alias PkiMnesia.Structs.{
    CaInstance, IssuerKey, KeyCeremony, CeremonyParticipant,
    CeremonyTranscript, ThresholdShare, IssuedCertificate,
    RaInstance, RaCaConnection, CertProfile, CsrRequest,
    ApiKey, DcvChallenge, CertificateStatus, PortalUser
  }

  @schema_version 1

  @plural_overrides %{
    "key_ceremony" => "key_ceremonies"
  }

  @doc """
  Creates all Mnesia tables. Call once on first boot or in tests.
  Returns :ok or {:error, reason}.
  """
  def create_tables do
    tables = [
      # CA Engine tables (disc_copies)
      {CaInstance, :disc_copies, [:name, :parent_id, :status]},
      {IssuerKey, :disc_copies, [:ca_instance_id, :key_alias, :status]},
      {KeyCeremony, :disc_copies, [:ca_instance_id, :issuer_key_id, :status]},
      {CeremonyParticipant, :disc_copies, [:ceremony_id, :name, :role]},
      {CeremonyTranscript, :disc_copies, [:ceremony_id]},
      {ThresholdShare, :disc_copies, [:issuer_key_id, :custodian_name]},

      # CA Engine tables (disc_only_copies - large data)
      {IssuedCertificate, :disc_only_copies, [:serial_number, :issuer_key_id, :status]},

      # RA Engine tables (disc_copies)
      {RaInstance, :disc_copies, [:name, :status]},
      {RaCaConnection, :disc_copies, [:ra_instance_id, :issuer_key_id]},
      {CertProfile, :disc_copies, [:ra_instance_id, :name, :issuer_key_id]},
      {ApiKey, :disc_copies, [:ra_instance_id, :key_hash, :status]},
      {DcvChallenge, :disc_copies, [:csr_request_id, :domain, :status]},

      # RA Engine tables (disc_only_copies - large data)
      {CsrRequest, :disc_only_copies, [:cert_profile_id, :status, :submitted_by_key_id]},

      # Validation tables (disc_only_copies)
      {CertificateStatus, :disc_only_copies, [:serial_number, :issuer_key_id, :status]},

      # Portal users (disc_copies)
      {PortalUser, :disc_copies, [:username, :email, :role]}
    ]

    results = Enum.map(tables, fn {struct_mod, storage_type, indices} ->
      create_table(struct_mod, storage_type, indices)
    end)

    case Enum.find(results, fn r -> r != :ok end) do
      nil ->
        create_schema_versions_table()
        check_and_migrate()
      error -> error
    end
  end

  @doc "Current schema version."
  def schema_version, do: @schema_version

  @doc """
  Creates a single Mnesia table for the given struct module.
  """
  def create_table(struct_mod, storage_type, indices) do
    table_name = table_name(struct_mod)
    attributes = struct_attributes(struct_mod)

    result = :mnesia.create_table(table_name, [
      {:attributes, attributes},
      {:type, :set},
      {storage_type, [node()]}
    ])

    case result do
      {:atomic, :ok} ->
        add_indices(table_name, indices)

      {:aborted, {:already_exists, _}} ->
        :ok

      {:aborted, reason} ->
        {:error, {:table_creation_failed, table_name, reason}}
    end
  end

  defp add_indices(_table_name, []), do: :ok

  defp add_indices(table_name, [index_field | rest]) do
    case :mnesia.add_table_index(table_name, index_field) do
      {:atomic, :ok} ->
        add_indices(table_name, rest)

      {:aborted, {:already_exists, _, _}} ->
        add_indices(table_name, rest)

      {:aborted, reason} ->
        {:error, {:index_creation_failed, table_name, index_field, reason}}
    end
  end

  @doc "Convert a struct module to a Mnesia table name atom."
  def table_name(struct_mod) do
    base =
      struct_mod
      |> Module.split()
      |> List.last()
      |> Macro.underscore()

    pluralized =
      case Map.fetch(@plural_overrides, base) do
        {:ok, override} -> override
        :error ->
          if String.ends_with?(base, "s"), do: base, else: base <> "s"
      end

    String.to_atom(pluralized)
  end

  @doc """
  Get the ordered list of attributes (field names) for a struct.
  Delegates to `struct_mod.fields/0` which guarantees :id is first.
  """
  def struct_attributes(struct_mod) do
    struct_mod.fields()
  end

  # -- Schema versioning --

  defp create_schema_versions_table do
    case :mnesia.create_table(:schema_versions, [
      {:attributes, [:key, :value]},
      {:type, :set},
      {:disc_copies, [node()]}
    ]) do
      {:atomic, :ok} -> :ok
      {:aborted, {:already_exists, _}} -> :ok
      {:aborted, reason} -> {:error, {:table_creation_failed, :schema_versions, reason}}
    end
  end

  @doc """
  Check the stored schema version against @schema_version and run any
  pending migrations. Currently the migration list is empty — this
  mechanism exists so future field additions are safe.
  """
  def check_and_migrate do
    stored = read_schema_version()
    current = @schema_version

    if stored < current do
      run_migrations(stored, current)
      write_schema_version(current)
      Logger.info("Mnesia schema migrated from v#{stored} to v#{current}")
    else
      Logger.info("Mnesia schema at v#{current} — no migration needed")
    end

    :ok
  end

  defp read_schema_version do
    case :mnesia.transaction(fn -> :mnesia.read(:schema_versions, :schema_version) end) do
      {:atomic, [{:schema_versions, :schema_version, version}]} -> version
      {:atomic, []} -> 0
      _ -> 0
    end
  end

  defp write_schema_version(version) do
    :mnesia.transaction(fn ->
      :mnesia.write({:schema_versions, :schema_version, version})
    end)
  end

  defp run_migrations(from, to) do
    # Migration registry: add entries as {version, description, fun} tuples.
    # Each fun runs inside a Mnesia transaction context.
    _migrations = []

    # Filter and run migrations between `from` and `to`
    # (empty for now — mechanism is in place for future use)
    Logger.info("Running schema migrations from v#{from} to v#{to} (0 pending)")
    :ok
  end
end
