defmodule PkiMnesia.Structs.ActivationSession do
  @moduledoc """
  Tracks the state machine for an activation ceremony:
  k custodians authenticate → threshold met → lease granted.

  ## Status values

    * `"awaiting_custodians"` — session open, waiting for custodians to submit auth
    * `"threshold_met"`       — k-of-n custodians authenticated; lease grant in progress
    * `"lease_active"`        — `KeyActivation.activate/4` succeeded; key lease is live
    * `"cancelled"`           — cancelled by an operator before threshold was met
    * `"failed"`              — threshold was met but lease grant failed

  ## authenticated_custodians

  List of maps, one entry per successful custodian auth:

      [%{name: "Alice", authenticated_at: ~U[2026-04-24 10:00:00Z]}, ...]

  Appended by `ActivationCeremony.submit_auth/4` and never removed within a
  session — duplicate-custodian protection is enforced before appending.
  """

  @fields [
    :id,
    :issuer_key_id,
    :ceremony_id,
    :status,
    :threshold_k,
    :threshold_n,
    :authenticated_custodians,
    :auth_tokens,
    :started_at,
    :completed_at,
    :inserted_at,
    :updated_at
  ]
  def fields, do: @fields

  defstruct @fields

  @type custodian_entry :: %{name: String.t(), authenticated_at: DateTime.t()}

  @type t :: %__MODULE__{
    id: binary(),
    issuer_key_id: binary(),
    ceremony_id: binary() | nil,
    status: String.t(),
    threshold_k: integer(),
    threshold_n: integer(),
    authenticated_custodians: [custodian_entry()],
    auth_tokens: [term()],
    started_at: DateTime.t(),
    completed_at: DateTime.t() | nil,
    inserted_at: DateTime.t(),
    updated_at: DateTime.t()
  }

  @valid_statuses ~w(awaiting_custodians threshold_met lease_active cancelled failed)

  @doc "Valid status values for an ActivationSession."
  def valid_statuses, do: @valid_statuses

  @doc "Validates required fields before Mnesia write."
  def validate(%__MODULE__{} = s) do
    missing =
      [{:issuer_key_id, s.issuer_key_id}, {:threshold_k, s.threshold_k}, {:threshold_n, s.threshold_n}]
      |> Enum.filter(fn {_k, v} -> is_nil(v) end)
      |> Enum.map(fn {k, _v} -> k end)

    cond do
      missing != [] ->
        {:error, {:missing_fields, missing}}

      s.threshold_k > s.threshold_n ->
        {:error, :invalid_threshold}

      s.status not in @valid_statuses ->
        {:error, {:invalid_status, s.status}}

      true ->
        :ok
    end
  end

  def new(attrs \\ %{}) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)
    %__MODULE__{
      id: attrs[:id] || PkiMnesia.Id.generate(),
      issuer_key_id: attrs[:issuer_key_id],
      ceremony_id: attrs[:ceremony_id],
      status: Map.get(attrs, :status, "awaiting_custodians"),
      threshold_k: attrs[:threshold_k],
      threshold_n: attrs[:threshold_n],
      authenticated_custodians: Map.get(attrs, :authenticated_custodians, []),
      auth_tokens: Map.get(attrs, :auth_tokens, []),
      started_at: attrs[:started_at] || now,
      completed_at: attrs[:completed_at],
      inserted_at: attrs[:inserted_at] || now,
      updated_at: attrs[:updated_at] || now
    }
  end
end
