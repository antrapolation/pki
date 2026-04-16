defmodule PkiMnesia.Schema do
  @moduledoc """
  Creates all Mnesia tables for a tenant node.
  Each table stores Elixir structs. Table attributes match struct fields.
  """

  alias PkiMnesia.Structs.{
    CaInstance, IssuerKey, KeyCeremony, CeremonyParticipant,
    CeremonyTranscript, ThresholdShare, IssuedCertificate,
    RaInstance, RaCaConnection, CertProfile, CsrRequest,
    ApiKey, DcvChallenge, CertificateStatus, PortalUser
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
      nil -> :ok
      error -> error
    end
  end

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
        Enum.each(indices, fn index_field ->
          :mnesia.add_table_index(table_name, index_field)
        end)
        :ok

      {:aborted, {:already_exists, _}} ->
        :ok

      {:aborted, reason} ->
        {:error, {:table_creation_failed, table_name, reason}}
    end
  end

  @doc "Convert a struct module to a Mnesia table name atom."
  def table_name(struct_mod) do
    struct_mod
    |> Module.split()
    |> List.last()
    |> Macro.underscore()
    |> Kernel.<>("s")
    |> String.to_atom()
  end

  @doc "Get the list of attributes (field names) for a struct, excluding :__struct__."
  def struct_attributes(struct_mod) do
    struct_mod.__struct__()
    |> Map.keys()
    |> Enum.reject(&(&1 == :__struct__))
    |> Enum.sort()
  end
end
