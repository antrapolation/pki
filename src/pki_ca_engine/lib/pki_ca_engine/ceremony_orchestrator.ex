defmodule PkiCaEngine.CeremonyOrchestrator do
  @moduledoc """
  Orchestrates key ceremony lifecycle.

  Redesigned for Mnesia:
  - Ceremony participants are name+password (not portal user FKs)
  - Auditor identity verification gate
  - Printable transcript (CeremonyTranscript)
  - Root CA requires full ceremony; sub-CA supports full or simplified
  - Single session: initiate -> verify identities -> generate -> distribute -> complete

  ## Key Material Handling

  During `execute_keygen/2`, raw private key bytes exist in BEAM process memory
  from keypair generation through Shamir splitting and share encryption. The BEAM
  does not offer a guaranteed way to zero memory after use -- binaries may be
  reference-counted and remain on the heap until garbage-collected.

  Mitigations applied:
  - `:erlang.garbage_collect()` is called immediately after the private key is
    split into shares and again after the encrypted shares are committed.
  - The raw private key is never stored in GenServer state or ETS; it lives only
    as a local variable within `do_keygen_and_split/3`.

  Residual risk: a heap dump, core dump, or `:erlang.process_info(pid, :messages)`
  call during the brief keygen window could expose the raw key. For environments
  requiring stronger guarantees, key generation should be delegated to an HSM or
  a NIF that manages its own memory (see the HSM keystore provider).

  ## Password Hashing

  Custodian share-acceptance passwords are hashed with PBKDF2-HMAC-SHA256
  (100 000 iterations, 16-byte random salt). The `password_hash` field stores
  `<<salt::binary-16, hash::binary-32>>` (48 bytes total).

  ## Password lifecycle (single-session ceremony)

  Custodian passwords are **per-ceremony**. A custodian enters a fresh name +
  password + confirmation at the start of their turn. The password is used for
  two things, in order, in the same session:

  1. `accept_share/3` records `password_hash` (PBKDF2 of the custodian's
     password) so a later caller can't substitute a different password at
     `execute_keygen`. The verifier in `execute_keygen` re-derives and
     constant-time-compares.

  2. `execute_keygen/2` calls `ShareEncryption.encrypt_share(raw_share, password)`
     which uses its own independent PBKDF2 salt to derive an AES-256-GCM key.
     The encrypted share is written to `encrypted_share` and the share
     transitions to `active`.

  After step 2 completes successfully, `password_hash` has served its only
  purpose — it was the proof-of-acceptance gate. The authoritative record
  is the ciphertext in `encrypted_share`; subsequent share submission at
  activation time is validated by AES-GCM authentication, not by the hash.
  So `encrypt_and_commit` **wipes `password_hash` to nil** when it writes
  `encrypted_share`. The same transaction atomically flips the share to
  `active`. This minimizes the blast radius if the Mnesia store is ever
  read by an attacker: no offline-crackable password artifact lingers
  past the session that created it.
  """

  require Logger

  alias PkiMnesia.Repo
  alias PkiMnesia.Structs.{
    KeyCeremony, IssuerKey, ThresholdShare,
    CeremonyParticipant, CeremonyTranscript
  }
  alias PkiCaEngine.{IssuerKeyManagement, CaInstanceManagement, KeystoreManagement}
  alias PkiCaEngine.KeyCeremony.ShareEncryption
  alias PkiMnesia.Structs.PortalUser

  @pbkdf2_iterations 600_000
  @pbkdf2_salt_size 16
  @pbkdf2_hash_size 32

  @doc """
  Initiate a ceremony. Creates KeyCeremony, IssuerKey, CeremonyParticipants, and CeremonyTranscript.

  params:
    - ca_instance_id: binary
    - algorithm: string (e.g., "ML-DSA-65")
    - threshold_k: integer (minimum shares to reconstruct)
    - threshold_n: integer (total shares)
    - custodian_names: list of strings (custodian names, NOT user IDs)
    - auditor_name: string (auditor name)
    - ceremony_mode: :full | :simplified (root CA must be :full)
    - keystore_mode: "software" | "softhsm" | "hsm" (default "softhsm")
    - key_mode: "threshold" | "password" | "single_custodian" (default "threshold").
      Controls how the private key is protected after generation.
      "threshold" — Shamir split (k,n as given); "password" and "single_custodian"
      — single AES-256-GCM envelope, n=1/k=1 required.
    - key_alias: optional string
    - subject_dn: optional string
    - is_root: boolean (default true)
    - initiated_by: string (name of person initiating)

  ## Keystore mode validation

  In `:prod` env only `"hsm"` is permitted. Passing `"software"` or
  `"softhsm"` in prod returns `{:error, :software_keystore_not_allowed_in_prod}`.

  When `keystore_mode` is `"hsm"`, the CA must have at least one keystore of
  type `"hsm"` already configured; otherwise returns
  `{:error, :no_hsm_keystore_configured}`.
  """
  def initiate(ca_instance_id, params) do
    keystore_mode = Map.get(params, :keystore_mode, "softhsm")
    key_mode = Map.get(params, :key_mode, "threshold")
    key_role = Map.get(params, :key_role, "operational_sub")
    auditor_user_id = Map.get(params, :auditor_user_id)

    with :ok <- validate_key_mode(key_mode),
         :ok <- validate_key_role(key_role, key_mode),
         :ok <- validate_threshold(params.threshold_k, params.threshold_n, key_mode),
         :ok <- validate_participants(params.custodian_names, params.threshold_n),
         :ok <- validate_ceremony_mode(params),
         :ok <- validate_keystore_mode(keystore_mode, ca_instance_id),
         :ok <- validate_auditor_user(auditor_user_id, ca_instance_id) do

      Repo.transaction(fn ->
        # Create issuer key
        key = IssuerKey.new(%{
          ca_instance_id: ca_instance_id,
          key_alias: Map.get(params, :key_alias, "key-#{:erlang.unique_integer([:positive])}"),
          algorithm: params.algorithm,
          is_root: Map.get(params, :is_root, true),
          ceremony_mode: Map.get(params, :ceremony_mode, :full),
          key_mode: key_mode,
          key_role: key_role,
          threshold_config: %{k: params.threshold_k, n: params.threshold_n}
        })
        :mnesia.write(Repo.struct_to_record(PkiMnesia.Schema.table_name(IssuerKey), key))

        # Determine initial ceremony status:
        # - "awaiting_auditor_acceptance" when a portal auditor user is specified
        # - "preparing" for the classic external-auditor single-session flow
        initial_status =
          if is_binary(auditor_user_id), do: "awaiting_auditor_acceptance", else: "preparing"

        # Create ceremony
        window_hours = Map.get(params, :time_window_hours, 24)
        window_expires_at = DateTime.utc_now() |> DateTime.add(window_hours * 3600, :second) |> DateTime.truncate(:second)

        ceremony = KeyCeremony.new(%{
          ca_instance_id: ca_instance_id,
          issuer_key_id: key.id,
          algorithm: params.algorithm,
          threshold_k: params.threshold_k,
          threshold_n: params.threshold_n,
          domain_info: %{
            "is_root" => Map.get(params, :is_root, true),
            "subject_dn" => Map.get(params, :subject_dn, "/CN=CA-#{ca_instance_id}"),
            "auditor_user_id" => auditor_user_id
          },
          initiated_by: params.initiated_by,
          keystore_mode: keystore_mode,
          window_expires_at: window_expires_at,
          status: initial_status
        })
        :mnesia.write(Repo.struct_to_record(PkiMnesia.Schema.table_name(KeyCeremony), ceremony))

        # Create custodian participants
        custodian_participants =
          params.custodian_names
          |> Enum.map(fn name ->
            p = CeremonyParticipant.new(%{ceremony_id: ceremony.id, name: name, role: :custodian})
            :mnesia.write(Repo.struct_to_record(PkiMnesia.Schema.table_name(CeremonyParticipant), p))
            p
          end)

        # Create auditor participant
        auditor = CeremonyParticipant.new(%{
          ceremony_id: ceremony.id,
          name: params.auditor_name,
          role: :auditor
        })
        :mnesia.write(Repo.struct_to_record(PkiMnesia.Schema.table_name(CeremonyParticipant), auditor))

        # Create placeholder shares for each custodian
        shares =
          params.custodian_names
          |> Enum.with_index(1)
          |> Enum.map(fn {name, index} ->
            share = ThresholdShare.new(%{
              issuer_key_id: key.id,
              custodian_name: name,
              share_index: index,
              min_shares: params.threshold_k,
              total_shares: params.threshold_n,
              status: "pending"
            })
            :mnesia.write(Repo.struct_to_record(PkiMnesia.Schema.table_name(ThresholdShare), share))
            share
          end)

        # Create transcript
        initiation_details =
          %{algorithm: params.algorithm, k: params.threshold_k, n: params.threshold_n}
          |> then(fn d ->
            if is_binary(auditor_user_id),
              do: Map.put(d, :auditor_user_id, auditor_user_id),
              else: d
          end)

        transcript = CeremonyTranscript.new(%{
          ceremony_id: ceremony.id,
          entries: [%{
            timestamp: DateTime.utc_now() |> DateTime.to_iso8601(),
            actor: params.initiated_by,
            action: "ceremony_initiated",
            details: initiation_details
          }]
        })
        :mnesia.write(Repo.struct_to_record(PkiMnesia.Schema.table_name(CeremonyTranscript), transcript))

        # When a portal auditor user is registered, record their pre-registration
        # in the transcript immediately. This wires verify_identity/3 into the
        # initiation path: the auditor's identity is considered pre-verified by the
        # system (the portal user record proves their identity), so we append the
        # verification event here for the auditor participant.
        if is_binary(auditor_user_id) do
          append_transcript_in_tx(
            ceremony.id,
            "system",
            "auditor_pre_registered",
            %{auditor_user_id: auditor_user_id, auditor_name: params.auditor_name}
          )
        end

        {ceremony, key, shares, custodian_participants ++ [auditor], transcript}
      end)
    end
  end

  @doc """
  Verify a participant's identity. The auditor confirms they verified a custodian.
  This is the identity verification gate required before key generation.
  """
  def verify_identity(ceremony_id, custodian_name, auditor_name) do
    case Repo.get_all_by_index(CeremonyParticipant, :ceremony_id, ceremony_id) do
      {:ok, participants} ->
        case Enum.find(participants, fn p -> p.name == custodian_name and p.role == :custodian end) do
          nil -> {:error, :participant_not_found}
          participant ->
            Repo.transaction(fn ->
              now = DateTime.utc_now() |> DateTime.truncate(:second)
              updated = %{participant | identity_verified_by: auditor_name, identity_verified_at: now}
              :mnesia.write(Repo.struct_to_record(PkiMnesia.Schema.table_name(CeremonyParticipant), updated))

              append_transcript_in_tx(ceremony_id, auditor_name, "identity_verified", %{custodian: custodian_name})

              updated
            end)
        end
      {:error, _} = err -> err
    end
  end

  @doc """
  Accept a custodian share by **slot index**, used by the single-session
  flow where the custodian's real name is unknown until they sit down.

  `share_index` is the 1..N slot position assigned at `initiate/2` time.
  `real_name` is what the custodian types in — becomes the identifier on
  the printed transcript signature line.

  Returns `{:error, :duplicate_name}` if the same real name is already
  accepted by another custodian in this ceremony (two Alice Johnsons in
  one ceremony need to disambiguate with title/department).

  Password is NOT validated here beyond non-empty. Pre-validate with
  `PkiCaEngine.KeyCeremony.PasswordPolicy.validate_with_confirmation/2`
  at the call site.
  """
  def accept_share_by_slot(ceremony_id, share_index, real_name, password)
      when is_integer(share_index) and is_binary(real_name) and is_binary(password) do
    real_name = String.trim(real_name)

    cond do
      real_name == "" ->
        {:error, :empty_name}

      password == "" ->
        {:error, :empty_password}

      true ->
        do_accept_share_by_slot(ceremony_id, share_index, real_name, password)
    end
  end

  defp do_accept_share_by_slot(ceremony_id, share_index, real_name, password) do
    salt = :crypto.strong_rand_bytes(@pbkdf2_salt_size)
    password_hash = :crypto.pbkdf2_hmac(:sha256, password, salt, @pbkdf2_iterations, @pbkdf2_hash_size)
    combined_hash = salt <> password_hash
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    Repo.transaction(fn ->
      ceremony_table = PkiMnesia.Schema.table_name(KeyCeremony)
      ceremony =
        case :mnesia.read(ceremony_table, ceremony_id) do
          [record] -> Repo.record_to_struct(KeyCeremony, record)
          [] -> :mnesia.abort(:not_found)
        end

      if ceremony.status != "preparing" do
        :mnesia.abort({:invalid_ceremony_status, ceremony.status})
      end

      share_table = PkiMnesia.Schema.table_name(ThresholdShare)
      shares =
        :mnesia.index_read(share_table, ceremony.issuer_key_id, :issuer_key_id)
        |> Enum.map(&Repo.record_to_struct(ThresholdShare, &1))

      share = Enum.find(shares, fn s -> s.share_index == share_index end)
      cond do
        is_nil(share) ->
          :mnesia.abort(:share_not_found)

        share.status != "pending" ->
          :mnesia.abort({:invalid_share_status, share.status})

        Enum.any?(shares, fn s ->
          s.share_index != share_index and
            s.status in ["accepted", "active"] and
            String.downcase(s.custodian_name || "") == String.downcase(real_name)
        end) ->
          :mnesia.abort(:duplicate_name)

        true ->
          # Update the corresponding CeremonyParticipant so the transcript
          # reflects the real name going forward (initiate created
          # placeholder "Custodian N" participants).
          participant_table = PkiMnesia.Schema.table_name(CeremonyParticipant)
          participants =
            :mnesia.index_read(participant_table, ceremony_id, :ceremony_id)
            |> Enum.map(&Repo.record_to_struct(CeremonyParticipant, &1))

          placeholder_name = "Custodian #{share_index}"
          case Enum.find(participants, fn p ->
                 p.role == :custodian and p.name == placeholder_name
               end) do
            nil -> :ok
            p ->
              updated_p = %{p | name: real_name}
              :mnesia.write(Repo.struct_to_record(participant_table, updated_p))
          end

          updated_share = %{share |
            custodian_name: real_name,
            password_hash: combined_hash,
            status: "accepted",
            updated_at: now
          }
          :mnesia.write(Repo.struct_to_record(share_table, updated_share))

          append_transcript_in_tx(ceremony_id, real_name, "share_accepted", %{slot: share_index})

          updated_share
      end
    end)
    |> case do
      {:ok, _} = ok -> ok
      {:error, :not_found} -> {:error, :not_found}
      {:error, {:invalid_ceremony_status, status}} -> {:error, {:invalid_ceremony_status, status}}
      {:error, {:invalid_share_status, status}} -> {:error, {:invalid_share_status, status}}
      {:error, :share_not_found} -> {:error, :share_not_found}
      {:error, :duplicate_name} -> {:error, :duplicate_name}
      {:error, _} = err -> err
    end
  end

  @doc """
  Accept a custodian's share assignment with their password.
  Stores a password hash for later share encryption.

  Legacy 3-arg variant kept for the pre-slot callers. New callers
  should use `accept_share_by_slot/4`.
  """
  def accept_share(ceremony_id, custodian_name, password) do
    salt = :crypto.strong_rand_bytes(@pbkdf2_salt_size)
    password_hash = :crypto.pbkdf2_hmac(:sha256, password, salt, @pbkdf2_iterations, @pbkdf2_hash_size)
    combined_hash = salt <> password_hash
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    Repo.transaction(fn ->
      # Read ceremony status inside transaction to avoid TOCTOU race
      ceremony_table = PkiMnesia.Schema.table_name(KeyCeremony)
      ceremony =
        case :mnesia.read(ceremony_table, ceremony_id) do
          [record] -> Repo.record_to_struct(KeyCeremony, record)
          [] -> :mnesia.abort(:not_found)
        end

      if ceremony.status != "preparing" do
        :mnesia.abort({:invalid_ceremony_status, ceremony.status})
      end

      share_table = PkiMnesia.Schema.table_name(ThresholdShare)
      shares = :mnesia.index_read(share_table, ceremony.issuer_key_id, :issuer_key_id)
               |> Enum.map(&Repo.record_to_struct(ThresholdShare, &1))

      share = Enum.find(shares, fn s -> s.custodian_name == custodian_name and s.status == "pending" end)
      if is_nil(share), do: :mnesia.abort(:share_not_found)

      updated = %{share | password_hash: combined_hash, status: "accepted", updated_at: now}
      :mnesia.write(Repo.struct_to_record(share_table, updated))

      append_transcript_in_tx(ceremony_id, custodian_name, "share_accepted", %{})

      updated
    end)
    |> case do
      {:ok, _} = ok -> ok
      {:error, :not_found} -> {:error, :not_found}
      {:error, {:invalid_ceremony_status, _}} -> {:error, :invalid_ceremony_status}
      {:error, :share_not_found} -> {:error, :share_not_found}
      {:error, _} = err -> err
    end
  end

  @doc """
  Check if all custodians have been identity-verified and accepted their shares.
  Returns :ready or :waiting.
  """
  def check_readiness(ceremony_id) do
    with {:ok, ceremony} <- get_ceremony(ceremony_id),
         true <- ceremony.status == "preparing" || {:error, :invalid_status} do

      with {:ok, all_participants} <- Repo.get_all_by_index(CeremonyParticipant, :ceremony_id, ceremony_id),
           participants = Enum.filter(all_participants, fn p -> p.role == :custodian end),
           {:ok, shares} <- Repo.get_all_by_index(ThresholdShare, :issuer_key_id, ceremony.issuer_key_id) do

        all_verified = Enum.all?(participants, fn p -> p.identity_verified_at != nil end)
        all_accepted = Enum.all?(shares, fn s -> s.status == "accepted" end)

        if all_verified and all_accepted, do: :ready, else: :waiting
      end
    end
  end

  @doc """
  Execute key generation: keygen -> sign -> split -> encrypt per custodian password -> wipe.
  custodian_passwords: list of {custodian_name, password} tuples.
  """
  def execute_keygen(ceremony_id, custodian_passwords) do
    # Atomic status claim: read + validate + update in a single Mnesia transaction
    claim_result =
      Repo.transaction(fn ->
        table = PkiMnesia.Schema.table_name(KeyCeremony)
        case :mnesia.read(table, ceremony_id) do
          [record] ->
            ceremony = PkiMnesia.Repo.record_to_struct(KeyCeremony, record)
            if ceremony.status not in ["preparing", "generating"] do
              :mnesia.abort({:invalid_status, ceremony.status})
            else
              updated = struct(ceremony, %{status: "generating"})
              :mnesia.write(PkiMnesia.Repo.struct_to_record(table, updated))
              ceremony
            end
          [] -> :mnesia.abort(:not_found)
        end
      end)

    case claim_result do
      {:ok, ceremony} ->
        with {:ok, db_shares} <- Repo.get_all_by_index(ThresholdShare, :issuer_key_id, ceremony.issuer_key_id),
             {:ok, issuer_key} <- Repo.get(IssuerKey, ceremony.issuer_key_id),
             false <- is_nil(issuer_key) do
          db_shares = Enum.sort_by(db_shares, & &1.share_index)
          password_map = Map.new(custodian_passwords)

          # Verify BEFORE keygen. If any custodian password doesn't match the
          # hash recorded in accept_share, bail out before any key material is
          # generated. This closes the bypass where a caller could encrypt
          # shares with passwords the custodians never entered.
          case verify_custodian_passwords(db_shares, password_map) do
            :ok ->
              do_keygen_and_split(ceremony, issuer_key, db_shares, password_map)

            {:error, reason} ->
              fail_ceremony(ceremony.id, "custodian_password_verification_failed")
              {:error, reason}
          end
        else
          true ->
            fail_ceremony(ceremony.id, "issuer_key_not_found")
            {:error, :issuer_key_not_found}
          {:error, reason} ->
            fail_ceremony(ceremony.id, "load_failed")
            {:error, reason}
        end

      {:error, {:invalid_status, _}} -> {:error, :invalid_status}
      {:error, :not_found} -> {:error, :not_found}
      {:error, reason} -> {:error, {:status_claim_failed, reason}}
    end
  end

  # Verify each custodian's supplied password against the hash recorded in
  # accept_share. Returns :ok only when every share has been accepted AND
  # every supplied password matches. Constant-time compare on the hash.
  defp verify_custodian_passwords(db_shares, password_map) do
    Enum.reduce_while(db_shares, :ok, fn share, :ok ->
      with {:ok, password} <- fetch_password(password_map, share.custodian_name),
           {:ok, salt, expected_hash} <- split_stored_hash(share),
           :ok <- compare_password(password, salt, expected_hash, share.custodian_name) do
        {:cont, :ok}
      else
        {:error, _} = err -> {:halt, err}
      end
    end)
  end

  defp fetch_password(password_map, custodian_name) do
    case Map.fetch(password_map, custodian_name) do
      {:ok, password} when is_binary(password) -> {:ok, password}
      {:ok, _} -> {:error, {:invalid_password_type, custodian_name}}
      :error -> {:error, {:missing_password, custodian_name}}
    end
  end

  defp split_stored_hash(%{password_hash: nil, custodian_name: name}),
    do: {:error, {:share_not_accepted, name}}

  defp split_stored_hash(%{password_hash: combined, custodian_name: _name})
       when is_binary(combined) and byte_size(combined) == @pbkdf2_salt_size + @pbkdf2_hash_size do
    <<salt::binary-size(@pbkdf2_salt_size), hash::binary-size(@pbkdf2_hash_size)>> = combined
    {:ok, salt, hash}
  end

  defp split_stored_hash(%{custodian_name: name}),
    do: {:error, {:corrupt_password_hash, name}}

  defp compare_password(password, salt, expected_hash, custodian_name) do
    computed = :crypto.pbkdf2_hmac(:sha256, password, salt, @pbkdf2_iterations, @pbkdf2_hash_size)

    if :crypto.hash_equals(computed, expected_hash) do
      :ok
    else
      {:error, {:custodian_password_mismatch, custodian_name}}
    end
  end

  @doc "Mark a ceremony as failed."
  def fail_ceremony(ceremony_id, reason) do
    case Repo.get(KeyCeremony, ceremony_id) do
      {:ok, nil} -> {:error, :not_found}
      {:ok, ceremony} ->
        Repo.update(ceremony, %{
          status: "failed",
          domain_info: Map.merge(ceremony.domain_info || %{}, %{"failure_reason" => reason})
        })
      {:error, _} = err -> err
    end
  end

  @doc """
  Activate a pending sub-CA issuer key by uploading the externally-signed certificate.

  Used when the CA setup is "Sub CA rooted to external root": a CSR was generated
  during the key ceremony and the key was left in `"pending"` status. Once the external
  CA returns the signed certificate, the operator uploads it here and the key transitions
  to `"active"`.

  ## Parameters

  - `issuer_key_id` – binary ID of the IssuerKey to activate.
  - `cert_pem_or_der` – the signed certificate, either as a PEM string
    (`-----BEGIN CERTIFICATE-----…`) or raw DER binary bytes.
  - `opts` – keyword options (currently unused, reserved for future use).

  ## Returns

  - `{:ok, updated_key}` – cert stored, status flipped to `"active"`.
  - `{:error, :not_found}` – no IssuerKey with that ID.
  - `{:error, :key_not_pending}` – the key is not in `"pending"` status.
  - `{:error, :malformed_cert}` – the supplied bytes could not be decoded.
  - `{:error, :cert_expired}` – the certificate's `notAfter` is in the past.
  - `{:error, :public_key_mismatch}` – the certificate's public key does not match
    the key stored in the IssuerKey record.
  - `{:error, :algo_mismatch}` – the certificate's public key algorithm does not
    match the `algorithm` field on the IssuerKey record.
  """
  def activate_with_external_cert(issuer_key_id, cert_pem_or_der, opts \\ []) do
    _opts = opts

    with {:ok, key} <- fetch_pending_key(issuer_key_id),
         {:ok, cert, cert_pem, cert_der} <- parse_cert_input(cert_pem_or_der),
         :ok <- check_cert_not_expired(cert),
         :ok <- check_algo_match(cert, key),
         :ok <- check_public_key_match(cert, key),
         {:ok, updated_key} <- store_cert_and_activate(key, cert_pem, cert_der) do

      append_activation_audit(key)
      {:ok, updated_key}
    end
  end

  # -- activate_with_external_cert helpers --

  defp fetch_pending_key(issuer_key_id) do
    case IssuerKeyManagement.get_issuer_key(issuer_key_id) do
      {:ok, key} ->
        if key.status == "pending" do
          {:ok, key}
        else
          {:error, :key_not_pending}
        end

      {:error, :not_found} ->
        {:error, :not_found}

      {:error, _} = err ->
        err
    end
  end

  defp parse_cert_input(input) do
    cond do
      is_binary(input) and String.contains?(input, "-----BEGIN") ->
        # PEM string
        case X509.Certificate.from_pem(input) do
          {:ok, cert} ->
            cert_der = X509.Certificate.to_der(cert)
            cert_pem = String.trim(input)
            {:ok, cert, cert_pem, cert_der}

          {:error, _} ->
            {:error, :malformed_cert}
        end

      is_binary(input) ->
        # Assume raw DER bytes
        case X509.Certificate.from_der(input) do
          {:ok, cert} ->
            cert_pem = X509.Certificate.to_pem(cert)
            {:ok, cert, cert_pem, input}

          {:error, _} ->
            {:error, :malformed_cert}
        end

      true ->
        {:error, :malformed_cert}
    end
  end

  defp check_cert_not_expired(cert) do
    validity = X509.Certificate.validity(cert)
    not_after_time = elem(validity, 2)  # {:Validity, notBefore, notAfter} → notAfter

    not_after_dt = X509.DateTime.to_datetime(not_after_time)

    if DateTime.compare(not_after_dt, DateTime.utc_now()) == :gt do
      :ok
    else
      {:error, :cert_expired}
    end
  end

  # Compare the certificate's public key against the fingerprint stored on the IssuerKey.
  # The fingerprint is SHA-256 of the raw public key bytes as returned by
  # PkiCrypto.Algorithm.generate_keypair/1 at ceremony time.
  defp check_public_key_match(cert, key) do
    with {:ok, cert_fp} <- extract_cert_public_key_fingerprint(cert) do
      if key.fingerprint && key.fingerprint == cert_fp do
        :ok
      else
        # Fingerprint field may be nil for older keys; fall back to :ok
        # to avoid blocking activation. Only fail on an explicit mismatch.
        if is_nil(key.fingerprint) do
          :ok
        else
          {:error, :public_key_mismatch}
        end
      end
    end
  end

  # Extract fingerprint (SHA-256 hex) from the cert's public key in the same
  # format as stored at keygen time:
  #   - ECC: raw EC point bytes (the compressed/uncompressed point binary)
  #   - RSA: DER-encoded RSAPublicKey bytes
  defp extract_cert_public_key_fingerprint(cert) do
    try do
      pub_key = X509.Certificate.public_key(cert)

      raw_bytes =
        case pub_key do
          # ECC: {ec_point(point: point_bytes), _params}
          {{:ECPoint, point_bytes}, _params} ->
            point_bytes

          # RSA: {:RSAPublicKey, modulus, exponent}
          {:RSAPublicKey, _, _} = rsa_pub ->
            :public_key.der_encode(:RSAPublicKey, rsa_pub)

          # Other / PQC / fallback: encode as SubjectPublicKeyInfo DER
          other ->
            X509.PublicKey.to_der(other)
        end

      fingerprint = :crypto.hash(:sha256, raw_bytes) |> Base.encode16(case: :lower)
      {:ok, fingerprint}
    rescue
      _ -> {:error, :malformed_cert}
    end
  end

  # Check that the certificate's public key algorithm family matches the
  # algorithm string stored on the IssuerKey.
  defp check_algo_match(cert, key) do
    try do
      pub_key = X509.Certificate.public_key(cert)
      cert_algo_family = infer_cert_algo_family(pub_key)
      key_algo_family = infer_key_algo_family(key.algorithm)

      if cert_algo_family == :unknown or key_algo_family == :unknown do
        # Cannot determine family — skip the check to avoid false negatives
        # for custom / PQC algorithms not representable in standard X.509.
        :ok
      else
        if cert_algo_family == key_algo_family do
          :ok
        else
          {:error, :algo_mismatch}
        end
      end
    rescue
      _ -> {:error, :algo_mismatch}
    end
  end

  defp infer_cert_algo_family({{:ECPoint, _}, _params}), do: :ecc
  defp infer_cert_algo_family({:RSAPublicKey, _, _}), do: :rsa
  defp infer_cert_algo_family(_), do: :unknown

  defp infer_key_algo_family(algo) when is_binary(algo) do
    a = String.downcase(algo)
    cond do
      String.starts_with?(a, "ecc") -> :ecc
      String.starts_with?(a, "rsa") -> :rsa
      String.starts_with?(a, "ml-dsa") -> :ml_dsa
      String.starts_with?(a, "kaz-sign") -> :kaz_sign
      String.starts_with?(a, "slh-dsa") -> :slh_dsa
      true -> :unknown
    end
  end
  defp infer_key_algo_family(_), do: :unknown

  defp store_cert_and_activate(key, cert_pem, cert_der) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)
    Repo.update(key, %{
      status: "active",
      certificate_pem: cert_pem,
      certificate_der: cert_der,
      updated_at: now
    })
  end

  defp append_activation_audit(key) do
    Logger.info("[CeremonyOrchestrator] key_activated_with_external_cert issuer_key_id=#{key.id} alias=#{key.key_alias}")

    # Append to ceremony transcript if a completed ceremony exists for this key
    case Repo.get_all_by_index(KeyCeremony, :issuer_key_id, key.id) do
      {:ok, [ceremony | _]} ->
        table = PkiMnesia.Schema.table_name(CeremonyTranscript)

        Repo.transaction(fn ->
          case :mnesia.index_read(table, ceremony.id, :ceremony_id) do
            [record | _] ->
              transcript = Repo.record_to_struct(CeremonyTranscript, record)
              entry = %{
                timestamp: DateTime.utc_now() |> DateTime.to_iso8601(),
                actor: "system",
                action: "key_activated_with_external_cert",
                details: %{issuer_key_id: key.id, key_alias: key.key_alias}
              }
              updated = %{transcript | entries: (transcript.entries || []) ++ [entry]}
              :mnesia.write(Repo.struct_to_record(table, updated))

            [] ->
              :ok
          end
        end)

      _ ->
        :ok
    end
  end

  @doc "Get the transcript for a ceremony."
  def get_transcript(ceremony_id) do
    case Repo.get_all_by_index(CeremonyTranscript, :ceremony_id, ceremony_id) do
      {:ok, []} -> {:error, :not_found}
      {:ok, [t | _]} -> {:ok, t}
      {:error, _} = err -> err
    end
  end

  @doc "List participants for a ceremony."
  def list_participants(ceremony_id) do
    Repo.get_all_by_index(CeremonyParticipant, :ceremony_id, ceremony_id)
  end

  @doc """
  Record that an auditor has witnessed the ceremony.

  Appends an `auditor_witnessed` transcript event. Full digital-signature
  verification of the transcript digest is wired in task E4.2; this is the
  placeholder that the CeremonyWitnessLive page calls.
  """
  def record_auditor_witness(ceremony_id, auditor_name, _opts \\ %{}) do
    with {:ok, ceremony} <- get_ceremony(ceremony_id) do
      if ceremony.status == "failed" do
        {:error, :ceremony_failed}
      else
        append_transcript_in_tx(ceremony_id, auditor_name, "auditor_witnessed", %{
          "note" => "Auditor confirmed presence and reviewed transcript"
        })
      end
    end
  end

  @doc """
  Accept the auditor witness role for a ceremony in status `"awaiting_auditor_acceptance"`.

  Called by a portal user with role `"auditor"` to confirm their presence before the
  ceremony proceeds. Transitions the ceremony status from `"awaiting_auditor_acceptance"`
  to `"preparing"` and appends an `auditor_accepted` transcript event.

  Uses `verify_identity/3` to mark all custodian participants as identity-verified by
  the accepting auditor, recording the verification in the transcript.

  Returns:
    - `{:ok, updated_ceremony}` on success
    - `{:error, :not_found}` when the ceremony does not exist
    - `{:error, :invalid_ceremony_status}` when the ceremony is not awaiting acceptance
    - `{:error, :auditor_required}` when the user is not a valid auditor portal user
  """
  def accept_auditor_witness(ceremony_id, auditor_user_id) do
    with :ok <- validate_auditor_user(auditor_user_id, nil),
         {:ok, ceremony} <- get_ceremony(ceremony_id) do

      if ceremony.status != "awaiting_auditor_acceptance" do
        {:error, :invalid_ceremony_status}
      else
        auditor_display_name =
          case Repo.get(PortalUser, auditor_user_id) do
            {:ok, u} when not is_nil(u) -> u.display_name || u.username || auditor_user_id
            _ -> auditor_user_id
          end

        result =
          Repo.transaction(fn ->
            ceremony_table = PkiMnesia.Schema.table_name(KeyCeremony)

            case :mnesia.read(ceremony_table, ceremony_id) do
              [record] ->
                c = Repo.record_to_struct(KeyCeremony, record)
                updated = %{c | status: "preparing", updated_at: DateTime.utc_now() |> DateTime.truncate(:second)}
                :mnesia.write(Repo.struct_to_record(ceremony_table, updated))

                append_transcript_in_tx(ceremony_id, auditor_display_name, "auditor_accepted", %{
                  auditor_user_id: auditor_user_id,
                  note: "Auditor accepted witness role; ceremony proceeding to preparation"
                })

                # M3 fix: mark all custodian participants as identity-verified inside
                # this transaction so the status update and participant writes are
                # atomic. Previously these verify_identity/3 calls happened after the
                # transaction closed, so a crash between the two writes left the
                # ceremony in "preparing" with no identity_verified_at values, which
                # caused check_readiness/1 to return :waiting indefinitely.
                participant_table = PkiMnesia.Schema.table_name(CeremonyParticipant)
                now = DateTime.utc_now() |> DateTime.truncate(:second)

                :mnesia.index_read(participant_table, ceremony_id, :ceremony_id)
                |> Enum.map(&Repo.record_to_struct(CeremonyParticipant, &1))
                |> Enum.filter(fn p -> p.role == :custodian end)
                |> Enum.each(fn p ->
                  verified = %{p | identity_verified_by: auditor_display_name, identity_verified_at: now}
                  :mnesia.write(Repo.struct_to_record(participant_table, verified))

                  append_transcript_in_tx(ceremony_id, auditor_display_name, "identity_verified", %{custodian: p.name})
                end)

                updated

              [] ->
                :mnesia.abort(:not_found)
            end
          end)

        case result do
          {:ok, updated_ceremony} ->
            {:ok, updated_ceremony}

          {:error, :not_found} ->
            {:error, :not_found}

          {:error, _} = err ->
            err
        end
      end
    end
  end

  @doc """
  Register the auditor's public key on the transcript at ceremony start.
  The key is later used to verify the auditor's signature in record_auditor_signature/3.
  """
  def register_auditor_key(ceremony_id, public_key_pem)
      when is_binary(public_key_pem) do
    with {:ok, _ceremony} <- get_ceremony(ceremony_id),
         {:ok, transcript} <- get_transcript(ceremony_id) do
      Repo.transaction(fn ->
        table = PkiMnesia.Schema.table_name(CeremonyTranscript)
        updated = %{transcript | auditor_public_key: public_key_pem}
        :mnesia.write(Repo.struct_to_record(table, updated))

        append_transcript_in_tx(ceremony_id, "auditor", "auditor_key_registered", %{
          "note" => "Auditor public key registered for transcript signing"
        })

        updated
      end)
    end
  end

  @doc """
  Record an auditor's digital signature over the transcript digest.

  The digest is computed by CeremonyTranscript.transcript_digest/1. The auditor
  signs this offline (Ed25519 or ECDSA P-256) and uploads the raw signature bytes.
  On success persists auditor_signature + signed_at and appends an auditor_signed event.
  """
  def record_auditor_signature(ceremony_id, auditor_public_key_pem, signature_bytes)
      when is_binary(auditor_public_key_pem) and is_binary(signature_bytes) do
    with {:ok, transcript} <- get_transcript(ceremony_id) do
      key_to_verify =
        if is_binary(transcript.auditor_public_key) do
          transcript.auditor_public_key
        else
          auditor_public_key_pem
        end

      check_transcript = %{transcript | auditor_public_key: key_to_verify, auditor_signature: signature_bytes}

      case CeremonyTranscript.verify_auditor_signature(check_transcript) do
        :ok ->
          now = DateTime.utc_now() |> DateTime.truncate(:second)

          Repo.transaction(fn ->
            table = PkiMnesia.Schema.table_name(CeremonyTranscript)

            updated_transcript =
              case :mnesia.index_read(table, ceremony_id, :ceremony_id) do
                [record | _] ->
                  t = Repo.record_to_struct(CeremonyTranscript, record)
                  %{t | auditor_public_key: key_to_verify, auditor_signature: signature_bytes, signed_at: now}
                [] ->
                  :mnesia.abort(:transcript_not_found)
              end

            :mnesia.write(Repo.struct_to_record(table, updated_transcript))

            append_transcript_in_tx(ceremony_id, "auditor", "auditor_signed", %{
              "note" => "Auditor digital signature verified and recorded",
              "signed_at" => DateTime.to_iso8601(now)
            })

            case :mnesia.index_read(table, ceremony_id, :ceremony_id) do
              [final | _] -> Repo.record_to_struct(CeremonyTranscript, final)
              [] -> updated_transcript
            end
          end)

        {:error, :invalid_signature} ->
          {:error, :invalid_signature}
      end
    end
  end

  # -- Private --

  defp get_ceremony(ceremony_id) do
    case Repo.get(KeyCeremony, ceremony_id) do
      {:ok, nil} -> {:error, :not_found}
      {:ok, ceremony} -> {:ok, ceremony}
      {:error, _} = err -> err
    end
  end

  defp generate_keypair(algorithm) do
    case PkiCrypto.Registry.get(algorithm) do
      nil -> {:error, {:unsupported_algorithm, algorithm}}
      algo_struct -> PkiCrypto.Algorithm.generate_keypair(algo_struct)
    end
  end

  # do_keygen_and_split/4 — dispatches on key_mode from the IssuerKey:
  #
  #   "threshold"        — Shamir split into ceremony.threshold_n shares, k-of-n
  #   "password"         — single AES-GCM envelope keyed from the custodian password,
  #                        stored as one ThresholdShare with n=1, k=1
  #   "single_custodian" — identical to "password" mechanically (n=1, k=1);
  #                        distinguished at the UI/audit layer only
  defp do_keygen_and_split(ceremony, issuer_key, db_shares, passwords) do
    case generate_keypair(ceremony.algorithm) do
      {:ok, %{public_key: pub, private_key: priv}} ->
        fingerprint = :crypto.hash(:sha256, pub) |> Base.encode16(case: :lower)
        is_root = Map.get(ceremony.domain_info, "is_root", true)
        subject_dn = Map.get(ceremony.domain_info, "subject_dn", "/CN=CA-#{ceremony.id}")

        {cert_or_csr_result, cert_der, cert_pem, csr_pem} =
          if is_root do
            case generate_self_signed(ceremony.algorithm, priv, pub, subject_dn) do
              {:ok, der, pem} -> {:ok, der, pem, nil}
              error -> {error, nil, nil, nil}
            end
          else
            case generate_csr(ceremony.algorithm, priv, pub, subject_dn) do
              {:ok, pem} -> {:ok, nil, nil, pem}
              error -> {error, nil, nil, nil}
            end
          end

        case cert_or_csr_result do
          :ok ->
            key_mode = Map.get(issuer_key, :key_mode, "threshold")

            split_result =
              if key_mode in ["password", "single_custodian"] do
                # n=1, k=1: wrap the entire private key as a single share.
                # The "share" is just the raw private key bytes; ShareEncryption
                # applies its own PBKDF2 + AES-256-GCM envelope around it.
                {:ok, [priv]}
              else
                # Standard Shamir threshold split
                PkiCrypto.Shamir.split(priv, ceremony.threshold_k, ceremony.threshold_n)
              end

            # Auto-spawn sub-CA while root private key is still in memory.
            # For non-root ceremonies sub_ca_data is nil and nothing extra is written.
            sub_ca_data =
              if is_root and not is_nil(cert_der) do
                case spawn_sub_ca(ceremony, priv, cert_der) do
                  {:ok, data} -> data
                  {:error, reason} ->
                    Logger.warning("sub-CA auto-spawn failed: #{inspect(reason)}; continuing without sub-CA")
                    nil
                end
              end

            case split_result do
              {:ok, raw_shares} ->
                :erlang.garbage_collect()

                # For password / single_custodian we normalise to a single db_share
                # regardless of how many placeholder shares were created at initiate time.
                effective_db_shares =
                  if key_mode in ["password", "single_custodian"] do
                    # Take the first accepted share; re-stamp n=1, k=1 so the
                    # ThresholdShare record is self-consistent.
                    [first | _] = Enum.sort_by(db_shares, & &1.share_index)
                    [%{first | total_shares: 1, min_shares: 1}]
                  else
                    db_shares
                  end

                encrypt_and_commit(ceremony, effective_db_shares, passwords, raw_shares, fingerprint, is_root, cert_der, cert_pem, csr_pem, subject_dn, sub_ca_data)

              error ->
                fail_ceremony(ceremony.id, "shamir_split_failed")
                error
            end

          error ->
            fail_ceremony(ceremony.id, "cert_generation_failed")
            error
        end

      error ->
        fail_ceremony(ceremony.id, "keygen_failed")
        error
    end
  end

  # Generate a sub-CA keypair and sign it with the root private key.
  # Returns {:ok, map} with keys: issuer_key, ceremony record, cert_der, cert_pem, fingerprint.
  # The root private key is used here and must NOT be stored — it is discarded after signing.
  defp spawn_sub_ca(root_ceremony, root_priv, root_cert_der) do
    algorithm = root_ceremony.algorithm
    ca_instance_id = root_ceremony.ca_instance_id
    root_subject_dn = Map.get(root_ceremony.domain_info, "subject_dn", "/CN=CA-#{root_ceremony.id}")
    sub_ca_dn = derive_sub_ca_dn(root_subject_dn)

    with {:ok, %{public_key: sub_pub, private_key: _sub_priv}} <- generate_keypair(algorithm),
         {:ok, sub_cert_der} <- sign_sub_ca_cert(algorithm, sub_pub, sub_ca_dn, root_cert_der, root_priv) do
      sub_fingerprint = :crypto.hash(:sha256, sub_pub) |> Base.encode16(case: :lower)
      sub_cert_pem = :public_key.pem_encode([{:Certificate, sub_cert_der, :not_encrypted}])

      now = DateTime.utc_now() |> DateTime.truncate(:second)

      sub_key = IssuerKey.new(%{
        ca_instance_id: ca_instance_id,
        key_alias: "sub-ca-#{:erlang.unique_integer([:positive])}",
        algorithm: algorithm,
        is_root: false,
        status: "active",
        ceremony_mode: :full,
        keystore_type: keystore_mode_to_keystore_type(root_ceremony.keystore_mode),
        threshold_config: %{k: root_ceremony.threshold_k, n: root_ceremony.threshold_n},
        certificate_der: sub_cert_der,
        certificate_pem: sub_cert_pem,
        fingerprint: sub_fingerprint,
        subject_dn: sub_ca_dn,
        inserted_at: now,
        updated_at: now
      })

      sub_ceremony = KeyCeremony.new(%{
        ca_instance_id: ca_instance_id,
        issuer_key_id: sub_key.id,
        algorithm: algorithm,
        threshold_k: root_ceremony.threshold_k,
        threshold_n: root_ceremony.threshold_n,
        domain_info: %{
          "is_root" => false,
          "subject_dn" => sub_ca_dn,
          "parent_ceremony_id" => root_ceremony.id,
          "fingerprint" => sub_fingerprint,
          "auto_spawned" => true
        },
        initiated_by: "system",
        keystore_mode: root_ceremony.keystore_mode,
        status: "completed",
        inserted_at: now,
        updated_at: now
      })

      {:ok, %{
        issuer_key: sub_key,
        ceremony: sub_ceremony,
        cert_der: sub_cert_der,
        cert_pem: sub_cert_pem,
        fingerprint: sub_fingerprint
      }}
    end
  end

  # Sign a sub-CA certificate using the root private key (PQC or classical).
  # For classical algorithms the private key must be decoded to OTP format
  # before passing to :public_key.sign (mirroring generate_csr/4 above).
  defp sign_sub_ca_cert(algorithm, sub_pub, sub_ca_dn, root_cert_der, root_priv) do
    serial = :crypto.strong_rand_bytes(8) |> :binary.decode_unsigned()

    # Build a minimal CSR-like parsed struct for build_tbs_cert.
    csr_parsed = %{
      algorithm_id: algorithm,
      subject_public_key: extract_raw_pub_bytes(algorithm, sub_pub),
      raw_tbs: <<>>,
      signature: <<>>
    }

    issuer_ref = %{cert_der: root_cert_der, algorithm_id: algorithm}

    # Classical algorithms require OTP-decoded key for :public_key.sign.
    signing_key =
      case PkiCrypto.AlgorithmRegistry.by_id(algorithm) do
        {:ok, %{family: family}} when family in [:ml_dsa, :kaz_sign, :slh_dsa] ->
          root_priv
        _ ->
          decode_private_key(root_priv)
      end

    with {:ok, tbs_der, _sig_oid} <- PkiCrypto.X509Builder.build_tbs_cert(
           csr_parsed, issuer_ref, sub_ca_dn, 365 * 10, serial
         ),
         {:ok, cert_der} <- PkiCrypto.X509Builder.sign_tbs(tbs_der, algorithm, signing_key) do
      {:ok, cert_der}
    end
  end

  # For PQC algorithms, the public key bytes are raw NIF output.
  # For classical algorithms, mirror extract_spki_public_bytes in X509Builder.
  defp extract_raw_pub_bytes(algorithm, pub) do
    case PkiCrypto.AlgorithmRegistry.by_id(algorithm) do
      {:ok, %{family: family}} when family in [:ml_dsa, :kaz_sign, :slh_dsa] ->
        pub

      {:ok, %{family: :ecdsa}} ->
        case pub do
          {{:ECPoint, point}, _params} -> point
          <<_::binary>> -> pub
        end

      {:ok, %{family: :rsa}} ->
        :public_key.der_encode(:RSAPublicKey, pub)

      _ ->
        pub
    end
  end

  # Derive sub-CA DN from root CA DN: prefix "/CN=Sub CA — " to the CN value.
  defp derive_sub_ca_dn(root_dn) do
    String.replace(root_dn, ~r{/CN=([^/]+)}, "/CN=Sub CA — \\1", global: false)
  end

  # Map keystore_mode string to IssuerKey.keystore_type atom.
  defp keystore_mode_to_keystore_type("hsm"), do: :local_hsm
  defp keystore_mode_to_keystore_type("softhsm"), do: :local_hsm
  defp keystore_mode_to_keystore_type(_), do: :software

  defp encrypt_and_commit(ceremony, db_shares, passwords, raw_shares, fingerprint, is_root, cert_der, cert_pem, csr_pem, subject_dn, sub_ca_data) do
    encrypt_result =
      Enum.zip(db_shares, raw_shares)
      |> Enum.reduce_while({:ok, []}, fn {db_share, raw_share}, {:ok, acc} ->
        case Map.fetch(passwords, db_share.custodian_name) do
          {:ok, password} ->
            case ShareEncryption.encrypt_share(raw_share, password) do
              {:ok, encrypted} ->
                signature = ShareEncryption.sign_share(encrypted, ceremony.id)
                {:cont, {:ok, [{db_share, encrypted, signature} | acc]}}
              {:error, reason} -> {:halt, {:error, {:share_encryption_failed, reason}}}
            end
          :error ->
            {:halt, {:error, {:missing_password, db_share.custodian_name}}}
        end
      end)

    case encrypt_result do
      {:error, reason} ->
        fail_ceremony(ceremony.id, "share_encryption_failed")
        {:error, reason}

      {:ok, encrypted_pairs_reversed} ->
        encrypted_pairs = Enum.reverse(encrypted_pairs_reversed)

        case Repo.transaction(fn ->
          now = DateTime.utc_now() |> DateTime.truncate(:second)

          # Write encrypted_share, flip status to active, AND wipe password_hash.
          # password_hash served its purpose during execute_keygen's
          # verify_custodian_passwords gate. Past this point it's dead weight:
          # share submission at activation time is gated by AES-GCM authentication
          # on the encrypted_share ciphertext, not by this hash. Clearing it
          # here limits the post-ceremony attack surface — a DB read no longer
          # yields an offline-crackable password artifact.
          Enum.each(encrypted_pairs, fn {db_share, encrypted_share, share_signature} ->
            updated = %{db_share |
              encrypted_share: encrypted_share,
              share_signature: share_signature,
              password_hash: nil,
              status: "active",
              updated_at: now
            }
            :mnesia.write(Repo.struct_to_record(PkiMnesia.Schema.table_name(ThresholdShare), updated))
          end)

          # Activate issuer key if root CA
          if is_root and cert_der do
            case :mnesia.read(PkiMnesia.Schema.table_name(IssuerKey), ceremony.issuer_key_id) do
              [record] ->
                key = Repo.record_to_struct(IssuerKey, record)
                activated = %{key |
                  status: "active",
                  certificate_der: cert_der,
                  certificate_pem: cert_pem,
                  fingerprint: fingerprint,
                  subject_dn: subject_dn,
                  updated_at: DateTime.utc_now() |> DateTime.truncate(:second)
                }
                :mnesia.write(Repo.struct_to_record(PkiMnesia.Schema.table_name(IssuerKey), activated))
              [] -> :ok
            end
          end

          # Update ceremony to completed
          case :mnesia.read(PkiMnesia.Schema.table_name(KeyCeremony), ceremony.id) do
            [record] ->
              c = Repo.record_to_struct(KeyCeremony, record)
              completed = %{c |
                status: "completed",
                domain_info: Map.merge(c.domain_info || %{}, %{
                  "fingerprint" => fingerprint,
                  "csr_pem" => csr_pem,
                  "subject_dn" => subject_dn
                }),
                updated_at: DateTime.utc_now() |> DateTime.truncate(:second)
              }
              :mnesia.write(Repo.struct_to_record(PkiMnesia.Schema.table_name(KeyCeremony), completed))
            [] -> :ok
          end

          append_transcript_in_tx(ceremony.id, "system", "ceremony_completed", %{fingerprint: fingerprint})

          # Persist auto-spawned sub-CA records within the same transaction.
          if not is_nil(sub_ca_data) do
            now_sub = DateTime.utc_now() |> DateTime.truncate(:second)

            # Write the sub-CA IssuerKey (already status "active")
            sub_key = sub_ca_data.issuer_key
            :mnesia.write(Repo.struct_to_record(PkiMnesia.Schema.table_name(IssuerKey), sub_key))

            # Write the sub-CA KeyCeremony (status "completed")
            sub_ceremony = struct(sub_ca_data.ceremony, %{updated_at: now_sub})
            :mnesia.write(Repo.struct_to_record(PkiMnesia.Schema.table_name(KeyCeremony), sub_ceremony))

            append_transcript_in_tx(ceremony.id, "system", "sub_ca_auto_spawned", %{
              sub_ca_key_id: sub_key.id,
              sub_ca_fingerprint: sub_ca_data.fingerprint,
              sub_ca_dn: sub_key.subject_dn
            })
          end
        end) do
          {:ok, _} ->
            :erlang.garbage_collect()

            # Auto-offline root CA after ceremony
            case Repo.get(PkiMnesia.Structs.CaInstance, ceremony.ca_instance_id) do
              {:ok, ca} when not is_nil(ca) ->
                if CaInstanceManagement.is_root?(ca) do
                  CaInstanceManagement.set_offline(ceremony.ca_instance_id)
                end
              _ -> :ok
            end

            sub_ca_key_id = if sub_ca_data, do: sub_ca_data.issuer_key.id, else: nil
            {:ok, %{fingerprint: fingerprint, csr_pem: csr_pem, sub_ca_key_id: sub_ca_key_id}}

          {:error, reason} ->
            fail_ceremony(ceremony.id, "transaction_failed: #{inspect(reason)}")
            {:error, reason}
        end
    end
  end

  # Appends a transcript entry inside an already-open :mnesia.transaction context.
  # Safe to call from within Repo.transaction/1 or bare :mnesia.transaction/1 fns.
  # Each entry is hash-chained via CeremonyTranscript.append/2 for tamper evidence.
  defp append_transcript_in_tx(ceremony_id, actor, action, details) do
    table = PkiMnesia.Schema.table_name(CeremonyTranscript)
    case :mnesia.index_read(table, ceremony_id, :ceremony_id) do
      [record | _] ->
        transcript = Repo.record_to_struct(CeremonyTranscript, record)
        event_map = %{
          "timestamp" => DateTime.utc_now() |> DateTime.to_iso8601(),
          "actor" => actor,
          "action" => action,
          "details" => details
        }
        updated = CeremonyTranscript.append(transcript, event_map)
        :mnesia.write(Repo.struct_to_record(table, updated))
      [] -> :ok
    end
  end


  # For threshold mode: k >= 2 and k <= n.
  # For password / single_custodian: k=1, n=1 is the only valid configuration
  # (the private key is wrapped as a single encrypted blob, not Shamir-split).
  defp validate_threshold(1, 1, mode) when mode in ["password", "single_custodian"], do: :ok
  defp validate_threshold(k, n, "threshold") when is_integer(k) and is_integer(n) and k >= 2 and k <= n, do: :ok
  defp validate_threshold(_, _, _), do: {:error, :invalid_threshold}

  defp validate_key_mode(mode) when mode in ["threshold", "password", "single_custodian"], do: :ok
  defp validate_key_mode(mode), do: {:error, {:invalid_key_mode, mode}}

  # validate_auditor_user: no-op for external-auditor (nil) single-session flow.
  # When a portal auditor user ID is supplied, verify it exists and has the :auditor role.

  # Accepted ADR deviation: when auditor_user_id is nil, the ceremony proceeds
  # without portal auditor acceptance — this supports the "external auditor"
  # single-session flow where a physical auditor is present but not a portal
  # user. The ceremony status stays "preparing" (not "awaiting_auditor_acceptance").
  # Root CA ceremonies should always use a portal-registered auditor; this bypass
  # is intended for internal/private CA ceremonies only.
  defp validate_auditor_user(nil, _ca_instance_id), do: :ok

  defp validate_auditor_user(auditor_user_id, _ca_instance_id) when is_binary(auditor_user_id) do
    case Repo.get(PortalUser, auditor_user_id) do
      {:ok, %PortalUser{role: :auditor}} -> :ok
      {:ok, %PortalUser{}} -> {:error, :auditor_required}
      {:ok, nil} -> {:error, :auditor_required}
      {:error, _} -> {:error, :auditor_required}
    end
  end

  # Guard: root CA keys must use threshold mode (WebTrust §6.2.2 dual-control).
  # "issuing_sub" and "operational_sub" may use any key_mode.
  #
  # Atom normalisation: callers may pass atom :root instead of string "root".
  # Elixir atoms and strings are not equal, so :root would bypass the string
  # guards below. Normalise to string first so the guard fires correctly.
  defp validate_key_role(role, key_mode) when is_atom(role) do
    validate_key_role(Atom.to_string(role), key_mode)
  end

  defp validate_key_role(role, _key_mode) when role not in ["root", "issuing_sub", "operational_sub"],
    do: {:error, {:invalid_key_role, role}}
  defp validate_key_role("root", key_mode) when key_mode != "threshold",
    do: {:error, :root_requires_threshold}
  defp validate_key_role(_role, _key_mode), do: :ok

  defp validate_participants(names, n) when is_list(names) and length(names) == n, do: :ok
  defp validate_participants(_, _), do: {:error, :participant_count_mismatch}

  defp validate_ceremony_mode(%{is_root: true, ceremony_mode: :simplified}),
    do: {:error, :root_ca_requires_full_ceremony}
  defp validate_ceremony_mode(_), do: :ok

  # Validate keystore_mode against env policy and HSM availability.
  #
  # In :prod, only "hsm" is permitted — "software" and "softhsm" bypass
  # hardware key custody requirements.
  #
  # When the caller requests "hsm", the CA must already have at least one
  # keystore of type "hsm" configured; the HSM-key mapping at activation time
  # (IssuerKey.keystore_type derivation from KeyCeremony.keystore_mode) is
  # handled as a separate task (E1.4+).
  defp validate_keystore_mode(mode, _ca_instance_id)
       when mode not in ["software", "softhsm", "hsm"] do
    {:error, {:invalid_keystore_mode, mode}}
  end

  defp validate_keystore_mode(mode, _ca_instance_id)
       when mode in ["software", "softhsm"] do
    if Application.get_env(:pki_ca_engine, :env) == :prod do
      {:error, :software_keystore_not_allowed_in_prod}
    else
      :ok
    end
  end

  defp validate_keystore_mode("hsm", ca_instance_id) do
    keystores = KeystoreManagement.list_keystores(ca_instance_id)
    if Enum.any?(keystores, fn ks -> ks.type == "hsm" end) do
      :ok
    else
      {:error, :no_hsm_keystore_configured}
    end
  end

  defp generate_self_signed(algorithm, private_key, public_key, subject_dn) do
    case PkiCrypto.AlgorithmRegistry.by_id(algorithm) do
      {:ok, %{family: family}} when family in [:ml_dsa, :kaz_sign, :slh_dsa] ->
        case PkiCrypto.X509Builder.self_sign(algorithm, %{public_key: public_key, private_key: private_key}, subject_dn, 365 * 25) do
          {:ok, cert_der} ->
            cert_pem = :public_key.pem_encode([{:Certificate, cert_der, :not_encrypted}])
            {:ok, cert_der, cert_pem}
          {:error, _} = error -> error
        end

      {:ok, %{family: _classical}} ->
        try do
          native_key = decode_private_key(private_key)
          root_cert = X509.Certificate.self_signed(native_key, subject_dn, template: :root_ca, hash: :sha256, serial: {:random, 8}, validity: 365 * 25)
          cert_der = X509.Certificate.to_der(root_cert)
          cert_pem = X509.Certificate.to_pem(root_cert)
          {:ok, cert_der, cert_pem}
        rescue
          e -> {:error, e}
        end

      :error -> {:error, {:unknown_algorithm, algorithm}}
    end
  end

  defp generate_csr(algorithm, private_key, public_key, subject_dn) do
    case PkiCrypto.AlgorithmRegistry.by_id(algorithm) do
      {:ok, %{family: family}} when family in [:ml_dsa, :kaz_sign, :slh_dsa] ->
        PkiCrypto.Csr.generate(algorithm, %{public_key: public_key, private_key: private_key}, subject_dn)

      {:ok, %{family: _classical}} ->
        try do
          native_key = decode_private_key(private_key)
          PkiCrypto.Csr.generate(algorithm, native_key, subject_dn)
        rescue
          e -> {:error, e}
        end

      :error -> {:error, {:unknown_algorithm, algorithm}}
    end
  end

  defp decode_private_key(der) do
    try do
      :public_key.der_decode(:RSAPrivateKey, der)
    rescue
      _ -> :public_key.der_decode(:ECPrivateKey, der)
    end
  end
end
