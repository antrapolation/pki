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
    ApiKey, DcvChallenge, CertificateStatus, PortalUser,
    BackupRecord, ServiceConfig, AuditLogEntry, Keystore
  }

  @schema_version 1

  @sync_tables [
    :ca_instances, :issuer_keys, :keystores, :threshold_shares,
    :key_ceremonies, :ceremony_participants, :ceremony_transcripts,
    :portal_users, :cert_profiles, :ra_instances, :ra_ca_connections,
    :api_keys, :dcv_challenges, :service_configs, :backup_records,
    :schema_versions
  ]

  @async_tables [:issued_certificates, :csr_requests, :certificate_status, :audit_log_entries]

  @doc "List of table names replicated synchronously (disc_copies primary, ram_copies replica)."
  def sync_tables, do: @sync_tables

  @doc "List of table names replicated asynchronously (disc_only_copies on both nodes)."
  def async_tables, do: @async_tables

  @doc """
  Join an existing primary node's Mnesia cluster and add table copies.
  Called on a replica node after :mnesia.start() (without creating schema).

  Sync tables get :ram_copies (synchronous replication, zero data loss).
  Async tables get :disc_only_copies (asynchronous, eventual consistency).

  Returns :ok or {:error, reason}.
  """
  @spec add_replica_copies(node()) :: :ok | {:error, term()}
  def add_replica_copies(primary_node) do
    case :mnesia.change_config(:extra_db_nodes, [primary_node]) do
      {:ok, [^primary_node]} -> :ok
      {:ok, []} -> {:error, {:cannot_connect, primary_node}}
      {:error, reason} -> {:error, {:change_config_failed, reason}}
    end
    |> case do
      :ok ->
        with :ok <- add_copies(@sync_tables, :ram_copies),
             :ok <- add_copies(@async_tables, :disc_only_copies) do
          all_tables = @sync_tables ++ @async_tables
          case :mnesia.wait_for_tables(all_tables, 30_000) do
            :ok -> :ok
            {:timeout, tables} -> {:error, {:table_timeout, tables}}
            {:error, reason} -> {:error, {:wait_failed, reason}}
          end
        end

      error ->
        error
    end
  end

  @doc """
  Promote a replica node to primary by converting ram_copies to disc_copies.
  Called during manual failover. Async tables are already disc_only_copies,
  so only sync tables need conversion.

  Returns :ok or {:error, reason}.
  """
  @spec promote_to_primary() :: :ok | {:error, term()}
  def promote_to_primary do
    Enum.reduce_while(@sync_tables, :ok, fn table, :ok ->
      case :mnesia.change_table_copy_type(table, node(), :disc_copies) do
        {:atomic, :ok} ->
          {:cont, :ok}

        {:aborted, {:already_exists, _, _, _}} ->
          {:cont, :ok}

        {:aborted, reason} ->
          {:halt, {:error, {:promote_failed, table, reason}}}
      end
    end)
  end

  @doc """
  Demote a promoted node back to replica mode by converting disc_copies
  to ram_copies and re-joining the primary's Mnesia cluster.

  Returns :ok or {:error, reason}.
  """
  @spec demote_to_replica(node()) :: :ok | {:error, term()}
  def demote_to_replica(primary_node) do
    case :mnesia.change_config(:extra_db_nodes, [primary_node]) do
      {:ok, _} -> :ok
      {:error, reason} -> {:error, {:change_config_failed, reason}}
    end
    |> case do
      :ok ->
        Enum.reduce_while(@sync_tables, :ok, fn table, :ok ->
          case :mnesia.change_table_copy_type(table, node(), :ram_copies) do
            {:atomic, :ok} ->
              {:cont, :ok}

            {:aborted, {:already_exists, _, _, _}} ->
              {:cont, :ok}

            {:aborted, reason} ->
              {:halt, {:error, {:demote_failed, table, reason}}}
          end
        end)

      error ->
        error
    end
  end

  defp add_copies(tables, copy_type) do
    Enum.reduce_while(tables, :ok, fn table, :ok ->
      case :mnesia.add_table_copy(table, node(), copy_type) do
        {:atomic, :ok} ->
          {:cont, :ok}

        {:aborted, {:already_exists, _, _}} ->
          {:cont, :ok}

        {:aborted, reason} ->
          {:halt, {:error, {:add_table_copy_failed, table, reason}}}
      end
    end)
  end

  @plural_overrides %{
    "key_ceremony" => "key_ceremonies",
    "audit_log_entry" => "audit_log_entries"
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
      {Keystore, :disc_copies, [:ca_instance_id, :type, :status]},
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
      {ServiceConfig, :disc_copies, [:service_type, :status]},

      # RA Engine tables (disc_only_copies - large data)
      {CsrRequest, :disc_only_copies, [:cert_profile_id, :status, :submitted_by_key_id]},

      # Validation tables (disc_only_copies)
      {CertificateStatus, :disc_only_copies, [:serial_number, :issuer_key_id, :status]},

      # Audit trail (disc_only_copies - grows unbounded)
      {AuditLogEntry, :disc_only_copies, [:timestamp, :action, :category, :actor]},

      # Portal users (disc_copies)
      {PortalUser, :disc_copies, [:username, :email, :role]},

      # Operations tables (disc_copies)
      {BackupRecord, :disc_copies, [:timestamp, :type, :status]}
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
