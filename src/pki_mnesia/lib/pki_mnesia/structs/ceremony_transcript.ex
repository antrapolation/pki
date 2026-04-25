defmodule PkiMnesia.Structs.CeremonyTranscript do
  @moduledoc """
  Serialized event log for ceremony PDF generation.
  Entries are a list of maps: %{timestamp, actor, action, details, prev_hash, event_hash}.

  Each entry is hash-chained: event_hash = sha256(prev_hash <> json(content_fields)).
  This makes the transcript tamper-evident — any alteration breaks the chain.
  The genesis entry uses <<0::256>> as prev_hash.

  ## Auditor digital signature (E4.2)

  After the ceremony the auditor may register their public key via
  `CeremonyOrchestrator.register_auditor_key/2`, then sign the transcript
  digest (SHA-256 of the JSON-encoded entries list) offline with their private
  key. The portal verifies the signature with `verify_auditor_signature/1` and
  persists the result via `CeremonyOrchestrator.record_auditor_signature/3`.

  Supported key types: Ed25519 and ECDSA P-256.
  """

  @fields [
    :id, :ceremony_id, :entries, :finalized_at, :inserted_at,
    :auditor_public_key, :auditor_signature, :signed_at
  ]
  def fields, do: @fields

  defstruct @fields

  @type t :: %__MODULE__{
    id: binary(),
    ceremony_id: binary(),
    entries: [map()],
    finalized_at: DateTime.t() | nil,
    inserted_at: DateTime.t(),
    auditor_public_key: binary() | nil,
    auditor_signature: binary() | nil,
    signed_at: DateTime.t() | nil
  }

  @genesis_hash <<0::256>>

  def new(attrs \\ %{}) do
    %__MODULE__{
      id: attrs[:id] || PkiMnesia.Id.generate(),
      ceremony_id: attrs[:ceremony_id],
      entries: Map.get(attrs, :entries, []),
      finalized_at: attrs[:finalized_at],
      inserted_at: attrs[:inserted_at] || DateTime.utc_now() |> DateTime.truncate(:second),
      auditor_public_key: attrs[:auditor_public_key],
      auditor_signature: attrs[:auditor_signature],
      signed_at: attrs[:signed_at]
    }
  end

  @doc """
  Appends a new entry to the transcript, computing a hash chain over
  prev_hash and the entry content fields (timestamp, actor, action, details).

  The entry map should be:
    %{"timestamp" => ..., "actor" => ..., "action" => ..., "details" => ...}
  """
  @spec append(t(), map()) :: t()
  def append(%__MODULE__{} = transcript, event_map) when is_map(event_map) do
    prev =
      case List.last(transcript.entries || []) do
        nil -> @genesis_hash
        # Tolerate pre-E4.1 entries written with atom keys and no event_hash.
        last -> Map.get(last, "event_hash") || Map.get(last, :event_hash) || @genesis_hash
      end

    event_hash = :crypto.hash(:sha256, prev <> Jason.encode!(event_map))
    entry = Map.merge(event_map, %{"prev_hash" => prev, "event_hash" => event_hash})
    %{transcript | entries: (transcript.entries || []) ++ [entry]}
  end

  @doc """
  Walks all entries and recomputes each event_hash from the stored prev_hash
  and the content fields (everything except prev_hash and event_hash).

  Returns :ok if the chain is intact, or {:error, {:broken_at, index}} where
  index is 1-based, on the first mismatch.
  """
  @spec verify_chain(t()) :: :ok | {:error, {:broken_at, pos_integer()}}
  def verify_chain(%__MODULE__{entries: entries}) do
    entries
    |> Enum.with_index(1)
    |> Enum.reduce_while(:ok, fn {entry, idx}, :ok ->
      case {Map.fetch(entry, "prev_hash"), Map.fetch(entry, "event_hash")} do
        {{:ok, prev_hash}, {:ok, stored_hash}} ->
          content = Map.drop(entry, ["prev_hash", "event_hash"])
          expected = :crypto.hash(:sha256, prev_hash <> Jason.encode!(content))

          if expected == stored_hash do
            {:cont, :ok}
          else
            {:halt, {:error, {:broken_at, idx}}}
          end

        _ ->
          # Pre-E4.1 entry without hash fields — skip verification for this entry.
          {:cont, :ok}
      end
    end)
  end

  @doc """
  Verifies the auditor's digital signature against the transcript digest.

  The digest is `SHA-256(:erlang.term_to_binary(entries))`. Using the Erlang
  external term format avoids JSON-encoding issues with the raw binary
  `prev_hash` / `event_hash` fields stored in each entry by `append/2`.

  Supports:
  - Ed25519: `auditor_public_key` stored as a PEM-encoded `SubjectPublicKeyInfo`
    (the format produced by `:public_key.pem_encode/1`). Raw 32-byte key bytes
    are also accepted as a convenience for test callers.
  - ECDSA P-256: PEM-encoded `SubjectPublicKeyInfo`.

  Returns `:ok` or `{:error, :invalid_signature}`.
  """
  @spec verify_auditor_signature(t()) :: :ok | {:error, :invalid_signature}
  def verify_auditor_signature(%__MODULE__{
        auditor_public_key: pem_or_raw,
        auditor_signature: sig,
        entries: entries
      })
      when is_binary(pem_or_raw) and is_binary(sig) and is_list(entries) do
    # The auditor signs the transcript before the "auditor_signed" confirmation
    # event is appended. Strip that (and any subsequent) trailing entry so the
    # digest computed here matches the one the auditor actually signed offline.
    signable_entries = entries_before_auditor_signed(entries)
    digest = transcript_digest(signable_entries)

    try do
      public_key = decode_public_key(pem_or_raw)
      do_verify(digest, sig, public_key)
    rescue
      _ -> {:error, :invalid_signature}
    catch
      _, _ -> {:error, :invalid_signature}
    end
  end

  def verify_auditor_signature(_), do: {:error, :invalid_signature}

  @doc """
  Compute the auditor-signable digest for a transcript's entries list.

  Returns a 32-byte binary: `SHA-256(:erlang.term_to_binary(signable_entries))`.

  `signable_entries` is the entries list with any trailing `auditor_signed`
  event stripped — the auditor signs the transcript before that confirmation
  entry is appended, so verification must use the same pre-signing snapshot.

  The Erlang external term format is used rather than JSON to avoid encoding
  errors when entries contain raw binary `prev_hash` / `event_hash` fields.
  """
  @spec transcript_digest([map()]) :: binary()
  def transcript_digest(entries) when is_list(entries) do
    :crypto.hash(:sha256, :erlang.term_to_binary(entries_before_auditor_signed(entries)))
  end

  # Strip the trailing "auditor_signed" entry (if present) so the digest
  # matches what the auditor signed offline before the event was recorded.
  defp entries_before_auditor_signed([]), do: []

  defp entries_before_auditor_signed(entries) do
    case List.last(entries) do
      %{"action" => "auditor_signed"} -> List.delete_at(entries, -1)
      _ -> entries
    end
  end

  # Decode a PEM-encoded public key (SubjectPublicKeyInfo) or, as a
  # convenience for test callers, accept raw Ed25519 key bytes (32 bytes).
  defp decode_public_key(pem_or_raw) do
    cond do
      String.contains?(pem_or_raw, "-----BEGIN") ->
        [{type, der, _} | _] = :public_key.pem_decode(pem_or_raw)
        :public_key.pem_entry_decode({type, der, :not_encrypted})

      byte_size(pem_or_raw) == 32 ->
        # Raw Ed25519 public key bytes — wrap into the OTP tuple form
        {:ed_pub, :ed25519, pem_or_raw}

      true ->
        # Assume DER-encoded SubjectPublicKeyInfo
        :public_key.der_decode(:SubjectPublicKeyInfo, pem_or_raw)
    end
  end

  # Dispatch verification based on public key type.
  defp do_verify(digest, sig, {:ed_pub, :ed25519, _key_bytes} = pub_key) do
    case :public_key.verify(digest, :none, sig, pub_key) do
      true -> :ok
      false -> {:error, :invalid_signature}
    end
  end

  defp do_verify(digest, sig, {{:ECPoint, _}, {_, {:namedCurve, _}}} = ec_pub_key) do
    # ECDSA P-256: the input is the raw SHA-256 digest; pass :sha256 so
    # :public_key.verify treats the data as a pre-hashed message.
    case :public_key.verify(digest, :sha256, sig, ec_pub_key) do
      true -> :ok
      false -> {:error, :invalid_signature}
    end
  end

  defp do_verify(digest, sig, {ec_point, params} = ec_pub_key)
       when is_tuple(ec_point) and is_tuple(params) do
    case :public_key.verify(digest, :sha256, sig, ec_pub_key) do
      true -> :ok
      false -> {:error, :invalid_signature}
    end
  end

  defp do_verify(_digest, _sig, _unknown_key), do: {:error, :invalid_signature}
end
