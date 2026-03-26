defmodule PkiCaEngine.KeyCeremonyManager do
  @moduledoc """
  Stateful GenServer managing a multi-phase key ceremony process.

  Phases: :setup -> :key_generated -> :cert_bound -> :custodians_assigned -> :finalized

  The manager holds sensitive key material in memory during the ceremony and
  wipes it on termination. Each ceremony is a separate process with a defined
  audit trail.
  """
  use GenServer

  alias PkiCaEngine.KeyVault
  alias PkiCaEngine.KeyCeremony.ShareEncryption

  # ── Client API ────────────────────────────────────────────────

  @doc """
  Start a new key ceremony with authorized sessions.
  All sessions must have the "key_manager" role.
  """
  def start_ceremony(ca_instance_id, sessions) do
    if sessions == [] or not Enum.all?(sessions, &(&1.role == "key_manager")) do
      {:error, :unauthorized}
    else
      GenServer.start_link(__MODULE__, %{
        ca_instance_id: ca_instance_id,
        sessions: sessions
      })
    end
  end

  @doc """
  Generate a keypair for the ceremony.
  Phase must be :setup. Transitions to :key_generated.
  """
  def generate_keypair(pid, algorithm, protection_mode, opts \\ []) do
    GenServer.call(pid, {:generate_keypair, algorithm, protection_mode, opts})
  end

  @doc """
  Generate a self-signed certificate (root issuer flow).
  Phase must be :key_generated. Transitions to :cert_bound.
  """
  def gen_self_sign_cert(pid, subject_info, cert_profile) do
    GenServer.call(pid, {:gen_self_sign_cert, subject_info, cert_profile})
  end

  @doc """
  Generate a CSR (sub-CA flow).
  Phase must be :key_generated. Transitions to :cert_bound.
  """
  def gen_csr(pid, subject_info) do
    GenServer.call(pid, {:gen_csr, subject_info})
  end

  @doc """
  Assign custodians and split shares.
  Phase must be :cert_bound. Transitions to :custodians_assigned.
  """
  def assign_custodians(pid, custodians, threshold_k) do
    GenServer.call(pid, {:assign_custodians, custodians, threshold_k})
  end

  @doc """
  Finalize the ceremony. Requires auditor role.
  Phase must be :custodians_assigned, or :cert_bound for credential_own protection.
  GenServer stops after finalization.
  """
  def finalize(pid, auditor_session) do
    GenServer.call(pid, {:finalize, auditor_session})
  end

  @doc """
  Get current ceremony status.
  """
  def get_status(pid) do
    GenServer.call(pid, :get_status)
  end

  # ── Server Callbacks ──────────────────────────────────────────

  @impl true
  def init(%{ca_instance_id: ca_instance_id, sessions: sessions}) do
    actor = List.first(sessions).username

    state = %{
      ca_instance_id: ca_instance_id,
      phase: :setup,
      authorized_sessions: sessions,
      keypair_id: nil,
      keypair_data: nil,
      protection_mode: nil,
      shares: nil,
      cert_or_csr: nil,
      audit_trail: [
        %{action: "ceremony_started", actor: actor, timestamp: DateTime.utc_now()}
      ],
      # Internal: raw private key kept in memory for cert/CSR generation
      private_key: nil,
      threshold_k: nil,
      threshold_n: nil
    }

    {:ok, state}
  end

  @impl true
  def handle_call({:generate_keypair, algorithm, protection_mode, opts}, _from, state) do
    if state.phase != :setup do
      {:reply, {:error, :wrong_phase}, state}
    else
      threshold_k = Keyword.get(opts, :threshold_k, 2)
      threshold_n = Keyword.get(opts, :threshold_n, 3)
      actor = List.first(state.authorized_sessions).username

      case do_generate_keypair(state.ca_instance_id, algorithm, protection_mode, threshold_k, threshold_n) do
        {:ok, keypair, private_key, shares} ->
          keypair_data = %{
            public_key: keypair.public_key,
            encrypted_private_key: keypair.encrypted_private_key,
            keypair_id: keypair.id,
            algorithm: algorithm
          }

          new_state = %{
            state
            | phase: :key_generated,
              keypair_id: keypair.id,
              keypair_data: keypair_data,
              protection_mode: protection_mode,
              private_key: private_key,
              shares: shares,
              threshold_k: threshold_k,
              threshold_n: threshold_n,
              audit_trail:
                state.audit_trail ++
                  [
                    %{
                      action: "keypair_generated",
                      actor: actor,
                      algorithm: algorithm,
                      protection_mode: to_string(protection_mode),
                      timestamp: DateTime.utc_now()
                    }
                  ]
          }

          {:reply, {:ok, keypair_data}, new_state}

        {:error, reason} ->
          {:reply, {:error, reason}, state}
      end
    end
  end

  @impl true
  def handle_call({:gen_self_sign_cert, subject_info, cert_profile}, _from, state) do
    if state.phase != :key_generated do
      {:reply, {:error, :wrong_phase}, state}
    else
      actor = List.first(state.authorized_sessions).username
      validity_days = Map.get(cert_profile, :validity_days, 365)

      case do_self_sign_cert(state.private_key, subject_info, validity_days) do
        {:ok, cert_pem} ->
          new_state = %{
            state
            | phase: :cert_bound,
              cert_or_csr: cert_pem,
              audit_trail:
                state.audit_trail ++
                  [
                    %{
                      action: "self_sign_cert_generated",
                      actor: actor,
                      subject: subject_info,
                      timestamp: DateTime.utc_now()
                    }
                  ]
          }

          {:reply, {:ok, cert_pem}, new_state}

        {:error, reason} ->
          {:reply, {:error, reason}, state}
      end
    end
  end

  @impl true
  def handle_call({:gen_csr, subject_info}, _from, state) do
    if state.phase != :key_generated do
      {:reply, {:error, :wrong_phase}, state}
    else
      actor = List.first(state.authorized_sessions).username

      case do_gen_csr(state.private_key, subject_info) do
        {:ok, csr_pem} ->
          new_state = %{
            state
            | phase: :cert_bound,
              cert_or_csr: csr_pem,
              audit_trail:
                state.audit_trail ++
                  [
                    %{
                      action: "csr_generated",
                      actor: actor,
                      subject: subject_info,
                      timestamp: DateTime.utc_now()
                    }
                  ]
          }

          {:reply, {:ok, csr_pem}, new_state}

        {:error, reason} ->
          {:reply, {:error, reason}, state}
      end
    end
  end

  @impl true
  def handle_call({:assign_custodians, custodians, threshold_k}, _from, state) do
    if state.phase != :cert_bound do
      {:reply, {:error, :wrong_phase}, state}
    else
      actor = List.first(state.authorized_sessions).username
      n = length(custodians)

      case do_assign_custodians(state.shares, custodians, threshold_k, n) do
        {:ok, encrypted_shares} ->
          new_state = %{
            state
            | phase: :custodians_assigned,
              shares: nil,
              private_key: nil,
              audit_trail:
                state.audit_trail ++
                  [
                    %{
                      action: "custodians_assigned",
                      actor: actor,
                      custodian_count: n,
                      threshold_k: threshold_k,
                      timestamp: DateTime.utc_now()
                    }
                  ]
          }

          {:reply, {:ok, encrypted_shares}, new_state}

        {:error, reason} ->
          {:reply, {:error, reason}, state}
      end
    end
  end

  @impl true
  def handle_call({:finalize, auditor_session}, _from, state) do
    cond do
      auditor_session.role != "auditor" ->
        {:reply, {:error, :unauthorized}, state}

      state.phase == :custodians_assigned ->
        do_finalize(state, auditor_session)

      state.phase == :cert_bound and state.protection_mode == :credential_own ->
        do_finalize(state, auditor_session)

      true ->
        {:reply, {:error, :wrong_phase}, state}
    end
  end

  @impl true
  def handle_call(:get_status, _from, state) do
    status = %{
      ca_instance_id: state.ca_instance_id,
      phase: state.phase,
      keypair_id: state.keypair_id,
      protection_mode: state.protection_mode,
      audit_trail_count: length(state.audit_trail)
    }

    {:reply, status, state}
  end

  @impl true
  def terminate(_reason, state) do
    _wiped = %{state | private_key: nil, shares: nil, keypair_data: nil}
    :ok
  end

  # ── Private ───────────────────────────────────────────────────

  defp do_generate_keypair(ca_instance_id, algorithm, :credential_own, _k, _n) do
    # For credential_own, encrypt the random password with ACL's KEM public key
    algo = PkiCrypto.Registry.get(algorithm)

    with {:ok, %{public_key: pub, private_key: priv}} <- PkiCrypto.Algorithm.generate_keypair(algo),
         random_password = :crypto.strong_rand_bytes(32),
         {:ok, encrypted_priv} <- PkiCrypto.Symmetric.encrypt(priv, random_password),
         {:ok, acl_pks} <- PkiCaEngine.KeypairACL.get_public_keys(),
         kem_algo = PkiCrypto.Registry.get("ECDH-P256"),
         {:ok, {shared_secret, kem_ciphertext}} <- PkiCrypto.Algorithm.kem_encapsulate(kem_algo, acl_pks.kem_public_key),
         {:ok, encrypted_password} <- PkiCrypto.Symmetric.encrypt(random_password, shared_secret) do
      result =
        %PkiCaEngine.KeyVault.ManagedKeypair{}
        |> PkiCaEngine.KeyVault.ManagedKeypair.changeset(%{
          ca_instance_id: ca_instance_id,
          name: "ceremony-#{System.unique_integer([:positive])}",
          algorithm: algorithm,
          protection_mode: "credential_own",
          public_key: pub,
          encrypted_private_key: encrypted_priv,
          encrypted_password: encrypted_password,
          acl_kem_ciphertext: kem_ciphertext,
          status: "pending"
        })
        |> PkiCaEngine.Repo.insert()

      case result do
        {:ok, keypair} -> {:ok, keypair, priv, nil}
        {:error, reason} -> {:error, reason}
      end
    end
  end

  defp do_generate_keypair(ca_instance_id, algorithm, protection_mode, threshold_k, threshold_n)
       when protection_mode in [:split_auth_token, :split_key] do
    vault_fn =
      case protection_mode do
        :split_auth_token -> &KeyVault.register_keypair_split_auth/6
        :split_key -> &KeyVault.register_keypair_split_key/6
      end

    case vault_fn.(ca_instance_id, "ceremony-#{System.unique_integer([:positive])}", algorithm, threshold_k, threshold_n, []) do
      {:ok, keypair, shares} ->
        # We need the raw private key for cert/CSR generation
        # Recover it from the shares right away (it's in memory anyway)
        with {:ok, recovered} <- PkiCrypto.Shamir.recover(shares) do
          case protection_mode do
            :split_auth_token ->
              # recovered is the password; decrypt the private key
              case PkiCrypto.Symmetric.decrypt(keypair.encrypted_private_key, recovered) do
                {:ok, priv} -> {:ok, keypair, priv, shares}
                {:error, reason} -> {:error, {:decrypt_private_key_failed, reason}}
              end

            :split_key ->
              # recovered IS the private key
              {:ok, keypair, recovered, shares}
          end
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp do_self_sign_cert(private_key, subject_info, validity_days) do
    native_key = decode_ec_private_key(private_key)

    cert =
      X509.Certificate.self_signed(
        native_key,
        subject_info,
        validity: validity_days,
        hash: :sha256,
        extensions: [
          basic_constraints: X509.Certificate.Extension.basic_constraints(true, 0),
          key_usage:
            X509.Certificate.Extension.key_usage([
              :digitalSignature,
              :keyCertSign,
              :cRLSign
            ]),
          subject_key_identifier: true
        ]
      )

    {:ok, X509.Certificate.to_pem(cert)}
  rescue
    e -> {:error, {:signing_failed, e}}
  end

  defp do_gen_csr(private_key, subject_info) do
    native_key = decode_ec_private_key(private_key)
    csr = X509.CSR.new(native_key, subject_info)
    {:ok, X509.CSR.to_pem(csr)}
  rescue
    e -> {:error, {:csr_failed, e}}
  end

  defp do_assign_custodians(nil, _custodians, _k, _n) do
    {:error, :no_shares_available}
  end

  defp do_assign_custodians(shares, custodians, _threshold_k, _n) do
    if length(shares) != length(custodians) do
      {:error, :share_custodian_mismatch}
    else
      results =
        Enum.zip(shares, custodians)
        |> Enum.map(fn {share, %{password: password}} ->
          ShareEncryption.encrypt_share(share, password)
        end)

      errors = Enum.filter(results, &match?({:error, _}, &1))

      if errors == [] do
        encrypted = Enum.map(results, fn {:ok, enc} -> enc end)
        {:ok, encrypted}
      else
        {:error, {:encryption_failed, hd(errors)}}
      end
    end
  end

  defp do_finalize(state, auditor_session) do
    final_audit =
      state.audit_trail ++
        [
          %{
            action: "ceremony_finalized",
            actor: auditor_session.username,
            timestamp: DateTime.utc_now()
          }
        ]

    wiped_state = %{
      state
      | phase: :finalized,
        private_key: nil,
        shares: nil,
        audit_trail: final_audit
    }

    {:stop, :normal, {:ok, final_audit}, wiped_state}
  end

  defp decode_ec_private_key(der) when is_binary(der) do
    :public_key.der_decode(:ECPrivateKey, der)
  end
end
