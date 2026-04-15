defmodule PkiCaPortal.CaEngineClient.Direct do
  @moduledoc """
  Direct (in-process) implementation of the CA engine client.

  Calls CA engine modules directly via Elixir function calls instead of HTTP.
  Converts Ecto structs to plain maps with atom keys to maintain the same
  interface contract as the HTTP implementation.
  """

  @behaviour PkiCaPortal.CaEngineClient

  require Logger

  import Ecto.Query

  alias PkiCaEngine.UserManagement
  alias PkiCaEngine.CaInstanceManagement
  alias PkiCaEngine.KeystoreManagement
  alias PkiCaEngine.HsmDeviceManagement
  alias PkiCaEngine.IssuerKeyManagement
  alias PkiCaEngine.KeyCeremony.SyncCeremony
  alias PkiCaEngine.TenantRepo
  alias PkiCaEngine.Schema.KeyCeremony
  alias PkiCaEngine.Schema.ThresholdShare

  # ---------------------------------------------------------------------------
  # Authentication
  # ---------------------------------------------------------------------------

  @impl true
  def authenticate(username, password, _opts \\ []) do
    case PkiPlatformEngine.PlatformAuth.authenticate_for_portal(username, password, "ca") do
      {:ok, user, role} ->
        {:ok, %{
          id: user.id,
          username: user.username,
          role: role.role,
          display_name: user.display_name,
          tenant_id: role.tenant_id,
          ca_instance_id: role.ca_instance_id,
          must_change_password: user.must_change_password,
          credential_expires_at: user.credential_expires_at
        }}

      {:error, :invalid_credentials} = err -> err
      {:error, :no_tenant_assigned} -> {:error, :invalid_credentials}
    end
  end

  @impl true
  def authenticate_with_session(username, password, _opts \\ []) do
    case PkiPlatformEngine.PlatformAuth.authenticate_for_portal(username, password, "ca") do
      {:ok, user, role} ->
        user_map = %{
          id: user.id,
          username: user.username,
          email: user.email,
          role: role.role,
          display_name: user.display_name,
          tenant_id: role.tenant_id,
          ca_instance_id: role.ca_instance_id,
          must_change_password: user.must_change_password,
          credential_expires_at: user.credential_expires_at
        }
        {:ok, user_map, %{}}

      {:error, :invalid_credentials} = err -> err
      {:error, :no_tenant_assigned} -> {:error, :invalid_credentials}
    end
  end

  @impl true
  def register_user(ca_instance_id, attrs, opts \\ []) do
    tenant_id = opts[:tenant_id]

    case UserManagement.register_user(tenant_id, ca_instance_id, attrs) do
      {:ok, user} -> {:ok, to_map(user)}
      {:error, _reason} = err -> err
    end
  end

  @impl true
  def needs_setup?(_ca_instance_id, opts \\ []) do
    tenant_id = opts[:tenant_id]

    if tenant_id do
      count = PkiPlatformEngine.PlatformRepo.one(
        from r in PkiPlatformEngine.UserTenantRole,
          where: r.tenant_id == ^tenant_id and r.portal == "ca" and r.status == "active",
          select: count(r.id)
      )
      count == 0
    else
      true
    end
  end

  @impl true
  def get_user_by_username(username, ca_instance_id, opts \\ []) do
    tenant_id = opts[:tenant_id]

    case UserManagement.get_user_by_username(tenant_id, username, ca_instance_id) do
      {:ok, user} -> {:ok, to_map(user)}
      {:error, _reason} = err -> err
    end
  end

  @impl true
  def update_user_profile(user_id, attrs, opts \\ []) do
    # Try platform DB first (unified identity store), fall back to tenant DB
    alias PkiPlatformEngine.{PlatformRepo, UserProfile}

    case PlatformRepo.get(UserProfile, user_id) do
      nil ->
        # Fallback: try tenant DB for legacy users
        tenant_id = opts[:tenant_id]
        case UserManagement.update_user_profile(tenant_id, user_id, attrs) do
          {:ok, user} -> {:ok, to_map(user)}
          {:error, :not_found} = err -> err
          {:error, %Ecto.Changeset{} = cs} -> {:error, {:validation_error, changeset_errors(cs)}}
          {:error, _reason} = err -> err
        end

      user ->
        user
        |> UserProfile.changeset(Map.take(attrs, [:display_name, :email, "display_name", "email"]))
        |> PlatformRepo.update()
        |> case do
          {:ok, updated} -> {:ok, to_map(updated)}
          {:error, %Ecto.Changeset{} = cs} -> {:error, {:validation_error, changeset_errors(cs)}}
        end
    end
  end

  @impl true
  def verify_and_change_password(user_id, current_password, new_password, opts \\ []) do
    # Try platform DB first (unified identity store), fall back to tenant DB
    alias PkiPlatformEngine.{PlatformRepo, UserProfile}

    case PlatformRepo.get(UserProfile, user_id) do
      nil ->
        # Fallback: try tenant DB for legacy users
        tenant_id = opts[:tenant_id]
        case UserManagement.verify_and_change_password(tenant_id, user_id, current_password, new_password) do
          {:ok, user} -> {:ok, to_map(user)}
          {:error, :not_found} = err -> err
          {:error, :invalid_current_password} = err -> err
          {:error, %Ecto.Changeset{} = cs} -> {:error, {:validation_error, changeset_errors(cs)}}
          {:error, _reason} = err -> err
        end

      user ->
        if Argon2.verify_pass(current_password, user.password_hash) do
          user
          |> UserProfile.password_changeset(%{password: new_password, must_change_password: false})
          |> PlatformRepo.update()
          |> case do
            {:ok, updated} -> {:ok, to_map(updated)}
            {:error, %Ecto.Changeset{} = cs} -> {:error, {:validation_error, changeset_errors(cs)}}
          end
        else
          {:error, :invalid_current_password}
        end
    end
  end

  @impl true
  def reset_password(user_id, new_password, opts \\ []) do
    # Try platform DB first
    case PkiPlatformEngine.PlatformAuth.reset_password(user_id, new_password, must_change_password: false) do
      {:ok, _} -> :ok
      {:error, :not_found} ->
        # Fallback: try tenant DB for legacy users
        tenant_id = opts[:tenant_id]
        with {:ok, user} <- UserManagement.get_user(tenant_id, user_id),
             {:ok, _} <- UserManagement.update_user_password(tenant_id, user, %{password: new_password}) do
          :ok
        end
      {:error, _} = err -> err
    end
  end

  # ---------------------------------------------------------------------------
  # User Management
  # ---------------------------------------------------------------------------

  @impl true
  def list_users(ca_instance_id, opts \\ []) do
    tenant_id = opts[:tenant_id]
    filter_opts = Keyword.drop(opts, [:tenant_id])
    users = UserManagement.list_users(tenant_id, ca_instance_id, filter_opts)
    {:ok, Enum.map(users || [], &to_map/1)}
  end

  @impl true
  def create_user(ca_instance_id, attrs, opts \\ []) do
    tenant_id = opts[:tenant_id]

    case UserManagement.create_user(tenant_id, ca_instance_id, attrs) do
      {:ok, user} -> {:ok, to_map(user)}
      {:error, %Ecto.Changeset{} = cs} -> {:error, {:validation_error, changeset_errors(cs)}}
      {:error, _reason} = err -> err
    end
  end

  @impl true
  def create_user_with_admin(ca_instance_id, attrs, admin_context, opts \\ []) do
    tenant_id = opts[:tenant_id]
    password = admin_context[:password] || admin_context["password"]

    case UserManagement.create_user_with_credentials(tenant_id, ca_instance_id, attrs, password) do
      {:ok, user} -> {:ok, to_map(user)}
      {:error, %Ecto.Changeset{} = cs} -> {:error, {:validation_error, changeset_errors(cs)}}
      {:error, _reason} = err -> err
    end
  end

  @impl true
  def get_user(id, opts \\ []) do
    tenant_id = opts[:tenant_id]

    case UserManagement.get_user(tenant_id, id) do
      {:ok, user} -> {:ok, to_map(user)}
      {:error, :not_found} = err -> err
    end
  end

  @impl true
  def delete_user(id, opts \\ []) do
    tenant_id = opts[:tenant_id]

    case UserManagement.delete_user(tenant_id, id) do
      {:ok, user} -> {:ok, to_map(user)}
      {:error, :not_found} = err -> err
      {:error, _reason} = err -> err
    end
  end

  # ---------------------------------------------------------------------------
  # Keystore Management
  # ---------------------------------------------------------------------------

  @impl true
  def list_keystores(ca_instance_id, opts \\ []) do
    tenant_id = opts[:tenant_id]
    keystores = KeystoreManagement.list_keystores(tenant_id, ca_instance_id)

    # Enrich with CA instance names
    instance_names = flatten_tree(CaInstanceManagement.list_hierarchy(tenant_id))
      |> Map.new(fn i -> {i[:id], i[:name]} end)

    enriched = Enum.map(keystores, fn ks ->
      map = to_map(ks)
      Map.put(map, :ca_instance_name, Map.get(instance_names, map[:ca_instance_id], "-"))
    end)

    {:ok, enriched}
  end

  @impl true
  def configure_keystore(ca_instance_id, attrs, opts \\ []) do
    tenant_id = opts[:tenant_id]

    case KeystoreManagement.configure_keystore(tenant_id, ca_instance_id, attrs) do
      {:ok, keystore} -> {:ok, to_map(keystore)}
      {:error, %Ecto.Changeset{} = cs} -> {:error, {:validation_error, changeset_errors(cs)}}
      {:error, _reason} = err -> err
    end
  end

  # ---------------------------------------------------------------------------
  # Issuer Key Management
  # ---------------------------------------------------------------------------

  @impl true
  def list_issuer_keys(ca_instance_id, opts \\ []) do
    tenant_id = opts[:tenant_id]
    keys = IssuerKeyManagement.list_issuer_keys(tenant_id, ca_instance_id, opts)
    {:ok, Enum.map(keys, &to_map/1)}
  end

  # ---------------------------------------------------------------------------
  # Engine Status
  # ---------------------------------------------------------------------------

  @impl true
  def get_engine_status(ca_instance_id, opts \\ []) do
    tenant_id = opts[:tenant_id]

    issuer_keys = IssuerKeyManagement.list_issuer_keys(tenant_id, ca_instance_id)
    keystores = KeystoreManagement.list_keystores(tenant_id, ca_instance_id)

    active_keys = Enum.count(issuer_keys, fn k -> k.status == "active" end)

    status = %{
      status: "running",
      uptime_seconds: 0,
      ca_instance_id: ca_instance_id,
      issuer_keys: %{
        total: length(issuer_keys),
        active: active_keys
      },
      keystores: %{
        total: length(keystores)
      },
      active_keys: active_keys
    }

    {:ok, status}
  end

  # ---------------------------------------------------------------------------
  # Key Ceremony
  # ---------------------------------------------------------------------------

  @impl true
  def initiate_ceremony(ca_instance_id, params, opts \\ []) do
    ceremony_params = %{
      algorithm: params[:algorithm] || params["algorithm"],
      keystore_id: params[:keystore_id] || params["keystore_id"],
      threshold_k: parse_int(params[:threshold_k] || params["threshold_k"]),
      threshold_n: parse_int(params[:threshold_n] || params["threshold_n"]),
      initiated_by: params[:initiated_by] || params["initiated_by"],
      domain_info: params[:domain_info] || params["domain_info"] || %{},
      key_alias: params[:key_alias] || params["key_alias"],
      is_root: params[:is_root] || params["is_root"]
    }

    tenant_id = opts[:tenant_id]

    case SyncCeremony.initiate(tenant_id, ca_instance_id, ceremony_params) do
      {:ok, {ceremony, _issuer_key}} ->
        {:ok, to_map(ceremony)}

      {:error, :invalid_threshold} ->
        {:error, {:validation_error, %{threshold: ["k must be >= 2 and <= n"]}}}

      {:error, :not_found} ->
        {:error, :not_found}

      {:error, %Ecto.Changeset{} = cs} ->
        {:error, {:validation_error, changeset_errors(cs)}}

      {:error, _reason} = err ->
        err
    end
  end

  @impl true
  def get_ceremony(ceremony_id, opts \\ []) do
    tenant_id = opts[:tenant_id]
    repo = TenantRepo.ca_repo(tenant_id)

    case repo.get(KeyCeremony, ceremony_id) do
      nil ->
        {:error, :not_found}

      ceremony ->
        ceremony_map = to_map(ceremony)

        # Load threshold shares for this ceremony's issuer key
        shares =
          if ceremony.issuer_key_id do
            repo.all(
              from s in ThresholdShare,
                where: s.issuer_key_id == ^ceremony.issuer_key_id,
                order_by: [asc: s.share_index]
            )
            |> Enum.map(fn share ->
              share_map = to_map(share)
              # Resolve username from platform user profile
              username = resolve_username(share.custodian_user_id, tenant_id)
              Map.put(share_map, :username, username)
            end)
          else
            []
          end

        # Resolve auditor username
        auditor_username =
          if ceremony.auditor_user_id do
            resolve_username(ceremony.auditor_user_id, tenant_id)
          end

        ceremony_map
        |> Map.put(:shares, shares)
        |> Map.put(:auditor_username, auditor_username)
        |> then(&{:ok, &1})
    end
  end

  @impl true
  def generate_ceremony_keypair(algorithm, _opts \\ []) do
    case SyncCeremony.generate_keypair(algorithm) do
      {:ok, _} = ok ->
        ok

      {:error, {:unsupported_algorithm, _}} ->
        # KAZ-SIGN: use native C NIF (fast, no JRuby needed)
        case kaz_sign_level(algorithm) do
          {:ok, level} -> generate_kaz_sign_keypair(level)
          :error ->
            # ML-DSA, SLH-DSA: fall back to ApJavaCrypto (JRuby/BouncyCastle)
            case pqc_algo_atom(algorithm) do
              nil -> {:error, {:unsupported_algorithm, algorithm}}
              algo_atom -> generate_pqc_keypair(algo_atom)
            end
        end

      {:error, _} = err ->
        err
    end
  end

  @impl true
  def distribute_ceremony_shares(ceremony_id, private_key, custodian_passwords, opts \\ []) do
    tenant_id = opts[:tenant_id]
    repo = TenantRepo.ca_repo(tenant_id)

    case repo.get(KeyCeremony, ceremony_id) do
      nil ->
        {:error, :not_found}

      ceremony ->
        case SyncCeremony.distribute_shares(tenant_id, ceremony, private_key, custodian_passwords) do
          {:ok, count} ->
            case ceremony |> Ecto.Changeset.change(status: "in_progress") |> repo.update() do
              {:ok, _} -> {:ok, count}
              {:error, reason} -> {:error, {:status_update_failed, reason}}
            end

          {:error, _} = err ->
            err
        end
    end
  end

  @impl true
  def complete_ceremony_root(ceremony_id, private_key, subject_dn, opts \\ []) do
    tenant_id = opts[:tenant_id]
    repo = TenantRepo.ca_repo(tenant_id)

    case repo.get(KeyCeremony, ceremony_id) do
      nil ->
        {:error, :not_found}

      ceremony ->
        case self_sign_root_cert(private_key, ceremony.algorithm, subject_dn, opts) do
          {:ok, cert_der, cert_pem} ->
            case SyncCeremony.complete_as_root(tenant_id, ceremony, cert_der, cert_pem) do
              {:ok, updated} -> {:ok, to_map(updated)}
              {:error, _} = err -> err
            end

          {:error, _} = err ->
            err
        end
    end
  end

  @impl true
  def complete_ceremony_sub_ca(ceremony_id, private_key, opts \\ []) do
    tenant_id = opts[:tenant_id]
    repo = TenantRepo.ca_repo(tenant_id)

    case repo.get(KeyCeremony, ceremony_id) do
      nil ->
        {:error, :not_found}

      ceremony ->
        case kaz_sign_level(ceremony.algorithm) do
          {:ok, level} ->
            # KAZ-SIGN: use NIF for CSR generation
            complete_sub_ca_kaz(tenant_id, repo, ceremony, private_key, level, opts)

          :error ->
            # Classical/other: use X509 library
            case SyncCeremony.complete_as_sub_ca(tenant_id, ceremony, private_key) do
              {:ok, {updated, csr_pem}} -> {:ok, {to_map(updated), csr_pem}}
              {:error, _} = err -> err
            end
        end
    end
  end

  defp complete_sub_ca_kaz(_tenant_id, _repo, _ceremony, nil, _level, _opts) do
    {:error, "Private key not available. The ceremony must be restarted — keys are held in memory only and were lost."}
  end

  defp complete_sub_ca_kaz(tenant_id, repo, ceremony, private_key, level, opts) do
    public_key = opts[:public_key]

    unless public_key do
      {:error, "Public key not available. The ceremony must be restarted."}
    else
      subject_dn = opts[:subject_dn] || get_in(ceremony.domain_info, ["subject_dn"]) || "/CN=Sub-CA-#{ceremony.ca_instance_id}"

      algorithm_id = "KAZ-SIGN-#{level}"

      case PkiCrypto.Csr.generate(
             algorithm_id,
             %{public_key: public_key, private_key: private_key},
             subject_dn
           ) do
        {:ok, csr_pem} ->
          # Mark ceremony completed
          case ceremony |> Ecto.Changeset.change(status: "completed") |> repo.update() do
            {:ok, updated} -> {:ok, {to_map(updated), csr_pem}}
            {:error, reason} -> {:error, {:completion_failed, reason}}
          end

        {:error, _} = err ->
          err
      end
    end
  rescue
    e ->
      Logger.error("[ca_engine_client] KAZ-SIGN CSR generation failed: #{Exception.message(e)}")
      {:error, "KAZ-SIGN CSR generation failed"}
  end

  @impl true
  def cancel_ceremony(ceremony_id, opts \\ []) do
    tenant_id = opts[:tenant_id]
    repo = TenantRepo.ca_repo(tenant_id)

    case repo.get(KeyCeremony, ceremony_id) do
      nil ->
        {:error, :not_found}

      %{status: "completed"} ->
        {:error, :already_completed}

      %{status: "failed"} ->
        {:error, :already_cancelled}

      ceremony ->
        repo.transaction(fn ->
          # Mark ceremony as failed
          case ceremony |> Ecto.Changeset.change(status: "failed") |> repo.update() do
            {:ok, updated} ->
              # Clean up the pending issuer key if it exists and is still pending
              if ceremony.issuer_key_id do
                case repo.get(PkiCaEngine.Schema.IssuerKey, ceremony.issuer_key_id) do
                  %{status: "pending"} = key -> repo.delete(key)
                  _ -> :ok
                end
              end

              updated

            {:error, reason} ->
              repo.rollback(reason)
          end
        end)
        |> case do
          {:ok, updated} -> {:ok, to_map(updated)}
          {:error, _} = err -> err
        end
    end
  end

  @impl true
  def delete_ceremony(ceremony_id, opts \\ []) do
    tenant_id = opts[:tenant_id]
    repo = TenantRepo.ca_repo(tenant_id)

    case repo.get(KeyCeremony, ceremony_id) do
      nil ->
        {:error, :not_found}

      %{status: "completed"} ->
        {:error, :cannot_delete_completed}

      ceremony ->
        repo.transaction(fn ->
          # Delete threshold shares for this ceremony's issuer key
          if ceremony.issuer_key_id do
            from(s in PkiCaEngine.Schema.ThresholdShare,
              where: s.issuer_key_id == ^ceremony.issuer_key_id
            )
            |> repo.delete_all()

            # Delete the pending issuer key
            case repo.get(PkiCaEngine.Schema.IssuerKey, ceremony.issuer_key_id) do
              %{status: "pending"} = key -> repo.delete(key)
              _ -> :ok
            end
          end

          case repo.delete(ceremony) do
            {:ok, _} -> :ok
            {:error, reason} -> repo.rollback(reason)
          end
        end)
        |> case do
          {:ok, :ok} -> :ok
          {:error, _} = err -> err
        end
    end
  end

  # ---------------------------------------------------------------------------
  # Issuer Key Operations
  # ---------------------------------------------------------------------------

  @impl true
  def get_issuer_key(id, opts \\ []) do
    tenant_id = opts[:tenant_id]

    case IssuerKeyManagement.get_issuer_key(tenant_id, id) do
      {:ok, key} -> {:ok, to_map(key)}
      {:error, _} = err -> err
    end
  end

  @impl true
  def list_threshold_shares(issuer_key_id, opts \\ []) do
    tenant_id = opts[:tenant_id]
    repo = TenantRepo.ca_repo(tenant_id)

    shares =
      from(s in PkiCaEngine.Schema.ThresholdShare,
        where: s.issuer_key_id == ^issuer_key_id,
        order_by: [asc: s.share_index]
      )
      |> repo.all()
      |> Enum.map(fn share ->
        username = resolve_username(share.custodian_user_id, tenant_id)
        share |> to_map() |> Map.put(:custodian_username, username)
      end)

    {:ok, shares}
  end

  @impl true
  def reconstruct_key(issuer_key_id, custodian_passwords, opts \\ []) do
    tenant_id = opts[:tenant_id]
    repo = TenantRepo.ca_repo(tenant_id)
    alias PkiCaEngine.KeyCeremony.ShareEncryption

    # Fetch encrypted shares from DB for each custodian
    results =
      Enum.map(custodian_passwords, fn {user_id, password} ->
        share_record =
          repo.one(
            from s in PkiCaEngine.Schema.ThresholdShare,
              where: s.issuer_key_id == ^issuer_key_id and s.custodian_user_id == ^user_id
          )

        case share_record do
          nil -> {:error, {:share_not_found, user_id}}
          record ->
            case ShareEncryption.decrypt_share(record.encrypted_share, password) do
              {:ok, share} -> {:ok, share}
              {:error, _} -> {:error, {:decryption_failed, user_id}}
            end
        end
      end)

    errors = Enum.filter(results, &match?({:error, _}, &1))

    if errors != [] do
      {:error, elem(hd(errors), 1)}
    else
      shares = Enum.map(results, fn {:ok, s} -> s end)

      case PkiCrypto.Shamir.recover(shares) do
        {:ok, secret} -> {:ok, secret}
        {:error, reason} -> {:error, {:reconstruction_failed, reason}}
      end
    end
  end

  @impl true
  def sign_csr(issuer_key_id, private_key, csr_pem, cert_profile, opts \\ []) do
    tenant_id = opts[:tenant_id]
    repo = TenantRepo.ca_repo(tenant_id)

    case repo.get(PkiCaEngine.Schema.IssuerKey, issuer_key_id) do
      nil ->
        {:error, :issuer_key_not_found}

      issuer_key ->
        algorithm = issuer_key.algorithm

        case kaz_sign_level(algorithm) do
          {:ok, level} ->
            sign_csr_kaz(level, issuer_key, private_key, csr_pem, cert_profile, opts)

          :error ->
            sign_csr_classical(tenant_id, issuer_key, private_key, csr_pem, cert_profile, opts)
        end
    end
  end

  defp sign_csr_kaz(level, issuer_key, private_key, csr_pem, cert_profile, _opts) do
    # Parse CSR from PEM to DER
    csr_b64 =
      csr_pem
      |> String.replace("-----BEGIN CERTIFICATE REQUEST-----", "")
      |> String.replace("-----END CERTIFICATE REQUEST-----", "")
      |> String.replace(~r/\s/, "")

    case Base.decode64(csr_b64) do
      :error -> {:error, :invalid_csr_pem}
      {:ok, csr_der} ->

    issuer_name = cert_profile[:issuer_name] || cert_profile["issuer_name"] || "/CN=Root-CA"
    validity_days = cert_profile[:validity_days] || cert_profile["validity_days"] || 3650
    serial = :crypto.strong_rand_bytes(8) |> :binary.decode_unsigned()
    is_ca = cert_profile[:is_ca] || cert_profile["is_ca"] || false

    # Extract public key from issuer's certificate for the issuer_pk param
    issuer_pk =
      if issuer_key.certificate_der do
        case KazSign.extract_pubkey(level, issuer_key.certificate_der) do
          {:ok, pk} -> pk
          _ -> nil
        end
      end

    # If no issuer public key from cert, we can't sign
    unless issuer_pk do
      {:error, "Issuer key has no certificate — cannot determine public key for signing."}
    else
      with :ok <- KazSign.init(level),
           {:ok, cert_der} <-
             KazSign.issue_certificate(level, private_key, issuer_pk, csr_der,
               issuer_name: issuer_name,
               serial: serial,
               days: validity_days
             ) do
        cert_b64 = Base.encode64(cert_der, padding: true)
        cert_pem = "-----BEGIN CERTIFICATE-----\n#{wrap_pem(cert_b64)}\n-----END CERTIFICATE-----\n"

        {:ok, %{
          certificate_der: cert_der,
          certificate_pem: cert_pem,
          serial: Integer.to_string(serial, 16) |> String.downcase(),
          algorithm: issuer_key.algorithm,
          is_ca: is_ca
        }}
      end
    end
    end
  rescue
    e ->
      Logger.error("[ca_engine_client] KAZ-SIGN CSR signing failed: #{Exception.message(e)}")
      {:error, "KAZ-SIGN CSR signing failed"}
  end

  defp sign_csr_classical(tenant_id, issuer_key, private_key_der, csr_pem, cert_profile, _opts) do
    # Use the existing CertificateSigning module for classical algorithms
    # But we need to temporarily make the key available via KeyActivation
    # Instead, do it directly with X509
    algorithm = issuer_key.algorithm
    validity_days = cert_profile[:validity_days] || cert_profile["validity_days"] || 3650
    subject_dn = cert_profile[:subject_dn] || cert_profile["subject_dn"]
    is_ca = cert_profile[:is_ca] || cert_profile["is_ca"] || false
    serial = :crypto.strong_rand_bytes(8) |> :binary.decode_unsigned()

    algo = String.downcase(algorithm)
    native_key =
      cond do
        algo in ["rsa-2048", "rsa-4096"] -> :public_key.der_decode(:RSAPrivateKey, private_key_der)
        algo in ["ecc-p256", "ecc-p384"] -> :public_key.der_decode(:ECPrivateKey, private_key_der)
        true -> nil
      end

    unless native_key do
      {:error, {:unsupported_algorithm, algorithm}}
    else
      case X509.CSR.from_pem(csr_pem) do
        {:ok, csr} ->
          unless X509.CSR.valid?(csr) do
            {:error, :invalid_csr}
          else
            public_key = X509.CSR.public_key(csr)
            subject = subject_dn || X509.RDNSequence.to_string(X509.CSR.subject(csr))

            extensions =
              if is_ca do
                [
                  basic_constraints: X509.Certificate.Extension.basic_constraints(true, 0),
                  key_usage: X509.Certificate.Extension.key_usage([:digitalSignature, :keyCertSign, :cRLSign]),
                  subject_key_identifier: true,
                  authority_key_identifier: true
                ]
              else
                [
                  basic_constraints: X509.Certificate.Extension.basic_constraints(false),
                  key_usage: X509.Certificate.Extension.key_usage([:digitalSignature, :keyEncipherment]),
                  subject_key_identifier: true,
                  authority_key_identifier: true
                ]
              end

            issuer_cert =
              if issuer_key.certificate_der do
                X509.Certificate.from_der!(issuer_key.certificate_der)
              else
                nil
              end

            cert =
              if issuer_cert do
                X509.Certificate.new(public_key, subject, issuer_cert, native_key,
                  serial: serial, hash: :sha256, validity: validity_days, extensions: extensions)
              else
                X509.Certificate.self_signed(native_key, subject,
                  serial: serial, hash: :sha256, validity: validity_days, extensions: extensions)
              end

            cert_der = X509.Certificate.to_der(cert)
            cert_pem = X509.Certificate.to_pem(cert)

            {:ok, %{
              certificate_der: cert_der,
              certificate_pem: cert_pem,
              serial: Integer.to_string(serial, 16) |> String.downcase(),
              algorithm: algorithm,
              is_ca: is_ca
            }}
          end

        _ ->
          {:error, :invalid_csr_pem}
      end
    end
  rescue
    e ->
      Logger.error("[ca_engine_client] Certificate signing failed: #{Exception.message(e)}")
      {:error, "Certificate signing failed"}
  end

  @impl true
  def activate_issuer_key(issuer_key_id, cert_attrs, opts \\ []) do
    tenant_id = opts[:tenant_id]

    case IssuerKeyManagement.get_issuer_key(tenant_id, issuer_key_id) do
      {:ok, key} ->
        case IssuerKeyManagement.activate_by_certificate(tenant_id, key, cert_attrs) do
          {:ok, updated} -> {:ok, to_map(updated)}
          {:error, _} = err -> err
        end

      {:error, _} = err ->
        err
    end
  end

  @impl true
  def suspend_issuer_key(issuer_key_id, opts) do
    tenant_id = opts[:tenant_id]

    case IssuerKeyManagement.get_issuer_key(tenant_id, issuer_key_id) do
      {:ok, key} ->
        case IssuerKeyManagement.update_status(tenant_id, key, "suspended") do
          {:ok, updated} -> {:ok, to_map(updated)}
          {:error, _} = err -> err
        end

      error ->
        error
    end
  end

  @impl true
  def reactivate_issuer_key(issuer_key_id, opts) do
    tenant_id = opts[:tenant_id]

    case IssuerKeyManagement.get_issuer_key(tenant_id, issuer_key_id) do
      {:ok, key} ->
        case IssuerKeyManagement.update_status(tenant_id, key, "active") do
          {:ok, updated} -> {:ok, to_map(updated)}
          {:error, _} = err -> err
        end

      error ->
        error
    end
  end

  @impl true
  def retire_issuer_key(issuer_key_id, opts) do
    tenant_id = opts[:tenant_id]

    case IssuerKeyManagement.get_issuer_key(tenant_id, issuer_key_id) do
      {:ok, key} ->
        case IssuerKeyManagement.retire_key(tenant_id, key) do
          {:ok, updated} -> {:ok, to_map(updated)}
          {:error, _} = err -> err
        end

      error ->
        error
    end
  end

  @impl true
  def archive_issuer_key(issuer_key_id, opts) do
    tenant_id = opts[:tenant_id]

    case IssuerKeyManagement.get_issuer_key(tenant_id, issuer_key_id) do
      {:ok, key} ->
        case IssuerKeyManagement.update_status(tenant_id, key, "archived") do
          {:ok, updated} -> {:ok, to_map(updated)}
          {:error, _} = err -> err
        end

      error ->
        error
    end
  end

  @impl true
  def list_ceremonies(ca_instance_id, opts \\ []) do
    tenant_id = opts[:tenant_id]
    repo = TenantRepo.ca_repo(tenant_id)

    ceremonies =
      from(c in KeyCeremony,
        where: c.ca_instance_id == ^ca_instance_id,
        order_by: [desc: c.inserted_at],
        preload: [:issuer_key]
      )
      |> repo.all()

    mapped =
      Enum.map(ceremonies, fn c ->
        c
        |> to_map()
        |> Map.put(:key_alias, c.issuer_key && c.issuer_key.key_alias)
      end)

    {:ok, mapped}
  end

  # ---------------------------------------------------------------------------
  # CA Instance Management
  # ---------------------------------------------------------------------------

  @impl true
  def list_ca_instances(opts \\ []) do
    tenant_id = opts[:tenant_id]
    instances = CaInstanceManagement.list_hierarchy(tenant_id)
    {:ok, flatten_tree(instances)}
  end

  @impl true
  def create_ca_instance(attrs, opts \\ []) do
    tenant_id = opts[:tenant_id]

    case CaInstanceManagement.create_ca_instance(tenant_id, attrs, actor: opts[:actor]) do
      {:ok, instance} -> {:ok, to_map(instance)}
      {:error, %Ecto.Changeset{} = cs} -> {:error, {:validation_error, changeset_errors(cs)}}
      {:error, _reason} = err -> err
    end
  end

  @impl true
  def update_ca_instance(id, attrs, opts \\ []) do
    tenant_id = opts[:tenant_id]

    result =
      cond do
        Map.has_key?(attrs, :status) || Map.has_key?(attrs, "status") ->
          status = attrs[:status] || attrs["status"]
          CaInstanceManagement.update_status(tenant_id, id, status, actor: opts[:actor])

        Map.has_key?(attrs, :name) || Map.has_key?(attrs, "name") ->
          name = attrs[:name] || attrs["name"]
          CaInstanceManagement.rename(tenant_id, id, name)

        Map.has_key?(attrs, :is_offline) || Map.has_key?(attrs, "is_offline") ->
          is_offline = attrs[:is_offline] || attrs["is_offline"]
          repo = TenantRepo.ca_repo(tenant_id)

          case repo.get(PkiCaEngine.Schema.CaInstance, id) do
            nil -> {:error, :not_found}
            instance ->
              instance
              |> PkiCaEngine.Schema.CaInstance.changeset(%{is_offline: is_offline})
              |> repo.update()
          end

        true ->
          {:error, :no_updatable_fields}
      end

    case result do
      {:ok, instance} -> {:ok, to_map(instance)}
      {:error, :not_found} = err -> err
      {:error, %Ecto.Changeset{} = cs} -> {:error, {:validation_error, changeset_errors(cs)}}
      {:error, _reason} = err -> err
    end
  end

  # ---------------------------------------------------------------------------
  # Platform-level User Management
  # ---------------------------------------------------------------------------

  @impl true
  def list_portal_users(opts \\ []) do
    tenant_id = opts[:tenant_id]
    {:ok, PkiPlatformEngine.PlatformAuth.list_users_for_portal(tenant_id, "ca")}
  end

  @impl true
  def create_portal_user(attrs, opts \\ []) do
    tenant_id = opts[:tenant_id]
    portal_url = Application.get_env(:pki_ca_portal, :portal_url, "")
    tenant_name = get_tenant_name(tenant_id)

    case PkiPlatformEngine.PlatformAuth.create_user_for_portal(tenant_id, "ca", attrs,
      portal_url: portal_url,
      tenant_name: tenant_name
    ) do
      {:ok, user} ->
        PkiPlatformEngine.PlatformAudit.log("user_created", %{
          actor_id: opts[:actor_id],
          actor_username: opts[:actor_username],
          target_type: "user_profile",
          target_id: user.id,
          tenant_id: tenant_id,
          portal: "ca",
          details: %{username: user.username, role: attrs[:role] || attrs["role"]}
        })
        {:ok, %{id: user.id, username: user.username, display_name: user.display_name, email: user.email}}

      {:error, %Ecto.Changeset{} = cs} -> {:error, {:validation_error, changeset_errors(cs)}}
      {:error, reason} -> {:error, reason}
    end
  end

  @impl true
  def suspend_user_role(role_id, opts \\ []) do
    case PkiPlatformEngine.PlatformAuth.suspend_user_role(role_id) do
      {:ok, role} ->
        PkiPlatformEngine.PlatformAudit.log("user_suspended", %{
          actor_id: opts[:actor_id],
          actor_username: opts[:actor_username],
          target_type: "user_tenant_role",
          target_id: role_id,
          tenant_id: opts[:tenant_id],
          portal: "ca"
        })
        {:ok, %{id: role.id, status: role.status}}

      {:error, _} = err -> err
    end
  end

  @impl true
  def activate_user_role(role_id, opts \\ []) do
    case PkiPlatformEngine.PlatformAuth.activate_user_role(role_id) do
      {:ok, role} ->
        PkiPlatformEngine.PlatformAudit.log("user_activated", %{
          actor_id: opts[:actor_id],
          actor_username: opts[:actor_username],
          target_type: "user_tenant_role",
          target_id: role_id,
          tenant_id: opts[:tenant_id],
          portal: "ca"
        })
        {:ok, %{id: role.id, status: role.status}}

      {:error, _} = err -> err
    end
  end

  @impl true
  def delete_user_role(role_id, opts \\ []) do
    case PkiPlatformEngine.PlatformAuth.delete_user_role(role_id) do
      {:ok, _} ->
        PkiPlatformEngine.PlatformAudit.log("user_deleted", %{
          actor_id: opts[:actor_id],
          actor_username: opts[:actor_username],
          target_type: "user_tenant_role",
          target_id: role_id,
          tenant_id: opts[:tenant_id],
          portal: "ca"
        })
        {:ok, %{id: role_id}}

      {:error, _} = err -> err
    end
  end

  @impl true
  def reset_user_password(user_id, opts \\ []) do
    tenant_id = opts[:tenant_id]
    portal_url = Application.get_env(:pki_ca_portal, :portal_url, "")
    tenant_name = get_tenant_name(tenant_id)

    role_label = case PkiPlatformEngine.PlatformAuth.get_tenant_roles_any_status(user_id, portal: "ca") do
      [role | _] -> PkiPlatformEngine.PlatformAuth.format_role_label(role.role, "ca")
      [] -> "CA User"
    end

    case PkiPlatformEngine.PlatformAuth.reset_user_password(user_id, "ca",
      portal_url: portal_url,
      tenant_name: tenant_name,
      role_label: role_label
    ) do
      {:ok, _} ->
        PkiPlatformEngine.PlatformAudit.log("password_reset", %{
          actor_id: opts[:actor_id],
          actor_username: opts[:actor_username],
          target_type: "user_profile",
          target_id: user_id,
          tenant_id: tenant_id,
          portal: "ca"
        })
        :ok

      {:error, _} = err -> err
    end
  end

  @impl true
  def resend_invitation(user_id, opts \\ []) do
    tenant_id = opts[:tenant_id]
    portal_url = Application.get_env(:pki_ca_portal, :portal_url, "")
    tenant_name = get_tenant_name(tenant_id)

    case PkiPlatformEngine.PlatformAuth.resend_invitation(user_id, "ca",
      portal_url: portal_url,
      tenant_name: tenant_name
    ) do
      {:ok, _} ->
        PkiPlatformEngine.PlatformAudit.log("invitation_resent", %{
          actor_id: opts[:actor_id],
          actor_username: opts[:actor_username],
          target_type: "user_profile",
          target_id: user_id,
          tenant_id: tenant_id,
          portal: "ca"
        })
        :ok

      {:error, _} = err -> err
    end
  end

  # ---------------------------------------------------------------------------
  # HSM Device Management
  # ---------------------------------------------------------------------------

  @impl true
  def list_hsm_devices(opts \\ []) do
    case opts[:tenant_id] do
      nil -> {:ok, []}
      tenant_id ->
        devices = HsmDeviceManagement.list_devices_for_tenant(tenant_id)
        {:ok, Enum.map(devices, &to_map/1)}
    end
  end

  @impl true
  def register_hsm_device(_attrs, _opts \\ []), do: {:error, :not_permitted}

  @impl true
  def probe_hsm_device(id, opts \\ []) do
    case opts[:tenant_id] do
      nil -> {:error, :tenant_id_required}
      tenant_id ->
        case HsmDeviceManagement.probe_device_for_tenant(tenant_id, id) do
          {:ok, device} -> {:ok, to_map(device)}
          {:error, _} = err -> err
        end
    end
  end

  @impl true
  def deactivate_hsm_device(_id, _opts \\ []), do: {:error, :not_permitted}

  # ---------------------------------------------------------------------------
  # Certificate Management
  # ---------------------------------------------------------------------------

  @impl true
  def list_certificates(issuer_key_id, opts) do
    tenant_id = Keyword.get(opts, :tenant_id)
    filters = Keyword.get(opts, :filters, [])
    certs = PkiCaEngine.CertificateSigning.list_certificates(tenant_id, issuer_key_id, filters)
    {:ok, Enum.map(certs, &to_map/1)}
  rescue
    e ->
      Logger.error("[ca_engine_client] list_certificates failed: #{Exception.message(e)}")
      {:ok, []}
  end

  @impl true
  def list_certificates_by_ca(ca_instance_id, opts) do
    tenant_id = Keyword.get(opts, :tenant_id)
    filters = Keyword.get(opts, :filters, [])
    certs = PkiCaEngine.CertificateSigning.list_certificates_by_ca(tenant_id, ca_instance_id, filters)
    {:ok, Enum.map(certs, &to_map/1)}
  rescue
    e ->
      Logger.error("[ca_engine_client] list_certificates_by_ca failed: #{Exception.message(e)}")
      {:ok, []}
  end

  @impl true
  def get_certificate(serial_number, opts) do
    tenant_id = Keyword.get(opts, :tenant_id)
    case PkiCaEngine.CertificateSigning.get_certificate(tenant_id, serial_number) do
      {:ok, cert} -> {:ok, to_map(cert)}
      error -> error
    end
  end

  @impl true
  def revoke_certificate(serial_number, reason, opts) do
    tenant_id = Keyword.get(opts, :tenant_id)
    PkiCaEngine.CertificateSigning.revoke_certificate(tenant_id, serial_number, reason)
  end

  @impl true
  def list_audit_events(filters, opts \\ []) do
    tenant_id = opts[:tenant_id]
    full_filters = [{:tenant_id, tenant_id} | filters]
    events = PkiPlatformEngine.PlatformAudit.list_events(full_filters)
    {:ok, Enum.map(events, &to_map/1)}
  end

  defp get_tenant_name(nil), do: ""
  defp get_tenant_name(tenant_id) do
    case PkiPlatformEngine.PlatformRepo.get(PkiPlatformEngine.Tenant, tenant_id) do
      nil -> ""
      tenant -> tenant.name
    end
  end

  # ---------------------------------------------------------------------------
  # Audit Log
  # ---------------------------------------------------------------------------

  @impl true
  def query_audit_log(filters, opts \\ []) do
    tenant_id = opts[:tenant_id]

    audit_filters = build_audit_filters(filters)

    # TODO: pass tenant_id to PkiAuditTrail.query when audit trail is made tenant-aware
    _ = tenant_id
    events = PkiAuditTrail.query(audit_filters)
    {:ok, Enum.map(events, &to_map/1)}
  rescue
    e ->
      Logger.error("Audit trail query error: #{Exception.message(e)}")
      {:error, :query_failed}
  end

  # ---------------------------------------------------------------------------
  # Private Helpers
  # ---------------------------------------------------------------------------

  defp to_map(%{__struct__: _} = struct) do
    struct
    |> Map.from_struct()
    |> Map.drop([:__meta__])
    |> Map.new(fn {k, v} -> {k, to_map_value(v)} end)
  end

  defp to_map(other), do: other

  defp to_map_value(%{__struct__: Ecto.Association.NotLoaded}), do: nil
  defp to_map_value(%{__struct__: _} = s), do: to_map(s)
  defp to_map_value(list) when is_list(list), do: Enum.map(list, &to_map_value/1)
  defp to_map_value(other), do: other

  defp resolve_username(nil, _tenant_id), do: nil
  defp resolve_username(user_id, _tenant_id) do
    case PkiPlatformEngine.PlatformAuth.get_user_profile(user_id) do
      {:ok, profile} -> profile.display_name || profile.username
      {:error, _} -> String.slice(user_id, 0..7)
    end
  end

  # Flatten a tree of CA instances (with nested :children) into a flat list
  defp flatten_tree(instances) do
    Enum.flat_map(instances, fn instance ->
      map = to_map(instance) |> put_role(instance) |> put_issuer_key_count(instance)
      children_structs = if Ecto.assoc_loaded?(instance.children), do: instance.children, else: []
      children_maps = map[:children] || []
      parent = Map.put(map, :children, nil)
      [parent | flatten_tree_children(children_structs, children_maps)]
    end)
  end

  defp flatten_tree_children(structs, maps) when is_list(structs) and is_list(maps) do
    Enum.zip(structs, maps)
    |> Enum.flat_map(fn {struct, map} ->
      map = put_role(map, struct) |> put_issuer_key_count(struct)
      grandchildren_structs = if Ecto.assoc_loaded?(struct.children), do: struct.children, else: []
      grandchildren_maps = map[:children] || []
      [Map.put(map, :children, nil) | flatten_tree_children(grandchildren_structs, grandchildren_maps)]
    end)
  end

  defp flatten_tree_children(_, _), do: []

  defp put_role(map, %{parent_id: nil}), do: Map.put(map, :role, "root")
  defp put_role(map, struct) do
    children = if Ecto.assoc_loaded?(struct.children), do: struct.children, else: nil
    role = cond do
      children != nil and children == [] -> "issuing"
      children != nil -> "intermediate"
      true -> "issuing"
    end
    Map.put(map, :role, role)
  end

  defp put_issuer_key_count(map, struct) do
    count =
      if Ecto.assoc_loaded?(struct.issuer_keys),
        do: length(struct.issuer_keys),
        else: 0

    Map.put(map, :issuer_key_count, count)
  end

  defp changeset_errors(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Regex.replace(~r"%{(\w+)}", msg, fn _, key ->
        atom_key = try do
          String.to_existing_atom(key)
        rescue
          ArgumentError -> nil
        end
        case atom_key && Keyword.get(opts, atom_key) do
          nil -> key
          val -> to_string(val)
        end
      end)
    end)
  end

  # PQC keygen via JRuby/BouncyCastle can be slow (30s+ on cold start)
  @pqc_keygen_timeout 120_000

  defp generate_pqc_keypair(algo_atom) do
    pid = find_ap_java_crypto_pid()

    if pid do
      case GenServer.call(pid, {:gen_keypair, algo_atom, %{}}, @pqc_keygen_timeout) do
        {:ok, {_algo, :private_key, priv}, {_algo2, :public_key, pub}} ->
          {:ok, %{public_key: pub, private_key: priv}}

        {:ok, {_algo, :private_key, priv}, {_algo2, :public_key, pub}, _extra} ->
          {:ok, %{public_key: pub, private_key: priv}}

        {:error, _} = err ->
          err

        other ->
          {:error, {:unexpected_keypair_result, other}}
      end
    else
      {:error, "PQC crypto service (ApJavaCrypto) is not running. Use a classical algorithm (ECC-P256, ECC-P384, RSA-4096) or start the JRuby service."}
    end
  rescue
    e ->
      Logger.error("[ca_engine_client] PQC keygen failed: #{Exception.message(e)}")
      {:error, "PQC key generation failed"}
  catch
    :exit, {:timeout, _} ->
      {:error, "PQC key generation timed out. The JRuby/Java service may be starting up — please try again."}
    :exit, reason ->
      Logger.error("[ca_engine_client] PQC keygen process error: #{inspect(reason)}")
      {:error, "PQC key generation failed"}
  end

  defp kaz_sign_level(algorithm) do
    case String.downcase(algorithm) do
      "kaz-sign-128" -> {:ok, 128}
      "kaz-sign-192" -> {:ok, 192}
      "kaz-sign-256" -> {:ok, 256}
      _ -> :error
    end
  end

  defp generate_kaz_sign_keypair(level) do
    with :ok <- KazSign.init(level),
         {:ok, keypair} <- KazSign.keypair(level) do
      {:ok, %{public_key: keypair.public_key, private_key: keypair.private_key}}
    end
  rescue
    e ->
      Logger.error("[ca_engine_client] KAZ-SIGN keygen failed: #{Exception.message(e)}")
      {:error, "KAZ-SIGN key generation failed"}
  end

  defp find_ap_java_crypto_pid do
    # Walk the ApJavaCrypto.Supervisor children to find the GenServer
    case Process.whereis(ApJavaCrypto.Supervisor) do
      nil -> nil
      sup_pid ->
        case Supervisor.which_children(sup_pid) do
          children when is_list(children) ->
            Enum.find_value(children, fn
              {ApJavaCrypto, pid, :worker, _} when is_pid(pid) -> pid
              _ -> nil
            end)
          _ -> nil
        end
    end
  end

  defp pqc_algo_atom(algorithm) do
    case String.downcase(algorithm) do
      "kaz-sign-128" -> :kaz_sign_128
      "kaz-sign-192" -> :kaz_sign_192
      "kaz-sign-256" -> :kaz_sign_256
      "ml-dsa-44" -> :ml_dsa_44
      "ml-dsa-65" -> :ml_dsa_65
      "ml-dsa-87" -> :ml_dsa_87
      "slh-dsa-sha2-128f" -> :slh_dsa_sha2_128f
      "slh-dsa-sha2-128s" -> :slh_dsa_sha2_128s
      "slh-dsa-sha2-192f" -> :slh_dsa_sha2_192f
      "slh-dsa-sha2-192s" -> :slh_dsa_sha2_192s
      "slh-dsa-sha2-256f" -> :slh_dsa_sha2_256f
      "slh-dsa-sha2-256s" -> :slh_dsa_sha2_256s
      _ -> nil
    end
  end

  defp self_sign_root_cert(private_key_der, algorithm, subject_dn, opts) do
    algo = String.downcase(algorithm)

    cond do
      algo in ["rsa-2048", "rsa-4096"] ->
        native_key = :public_key.der_decode(:RSAPrivateKey, private_key_der)
        do_self_sign_x509(native_key, subject_dn)

      algo in ["ecc-p256", "ecc-p384"] ->
        native_key = :public_key.der_decode(:ECPrivateKey, private_key_der)
        do_self_sign_x509(native_key, subject_dn)

      String.starts_with?(algo, "kaz-sign") ->
        public_key = opts[:public_key]
        do_self_sign_kaz(private_key_der, public_key, algorithm, subject_dn)

      String.starts_with?(algo, "ml-dsa") or String.starts_with?(algo, "slh-dsa") ->
        public_key = opts[:public_key]
        do_self_sign_pqc(private_key_der, public_key, algorithm, subject_dn)

      true ->
        {:error, {:unsupported_algorithm, algorithm}}
    end
  rescue
    e -> {:error, {:self_sign_failed, e}}
  end

  defp do_self_sign_x509(native_key, subject_dn) do
    cert =
      X509.Certificate.self_signed(
        native_key,
        subject_dn,
        validity: 3650,
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

    cert_der = X509.Certificate.to_der(cert)
    cert_pem = X509.Certificate.to_pem(cert)
    {:ok, cert_der, cert_pem}
  end

  defp do_self_sign_kaz(private_key, public_key, algorithm, subject_dn) do
    {:ok, level} = kaz_sign_level(algorithm)

    algorithm_id = "KAZ-SIGN-#{level}"

    with {:ok, csr_pem} <-
           PkiCrypto.Csr.generate(
             algorithm_id,
             %{public_key: public_key, private_key: private_key},
             subject_dn
           ),
         # Generate a self-signed CSR first, then issue a self-signed cert
         csr_der = pem_to_der(csr_pem),
         :ok <- KazSign.init(level),
         {:ok, cert_der} <-
           KazSign.issue_certificate(level, private_key, public_key, csr_der,
             issuer_name: subject_dn,
             serial: :crypto.strong_rand_bytes(8) |> :binary.decode_unsigned(),
             days: 3650
           ) do
      # Convert DER to PEM
      cert_b64 = Base.encode64(cert_der, padding: true)
      cert_pem = "-----BEGIN CERTIFICATE-----\n#{wrap_pem(cert_b64)}\n-----END CERTIFICATE-----\n"
      {:ok, cert_der, cert_pem}
    end
  rescue
    e ->
      Logger.error("[ca_engine_client] KAZ-SIGN self-sign failed: #{Exception.message(e)}")
      {:error, {:kaz_sign_self_sign_failed, "self-sign operation failed"}}
  end

  defp pem_to_der(pem) do
    [{_, der, _}] = :public_key.pem_decode(pem)
    der
  end

  defp wrap_pem(b64) do
    b64 |> String.graphemes() |> Enum.chunk_every(64) |> Enum.map(&Enum.join/1) |> Enum.join("\n")
  end

  defp do_self_sign_pqc(private_key_bytes, public_key_bytes, algorithm, subject_dn) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)
    not_after = DateTime.add(now, 3650 * 86400, :second)
    serial = :crypto.strong_rand_bytes(8) |> Base.encode16(case: :lower)

    public_key_b64 = if public_key_bytes, do: Base.encode64(public_key_bytes), else: nil

    tbs = %{
      version: 3,
      serial: serial,
      algorithm: algorithm,
      issuer: subject_dn,
      not_before: DateTime.to_iso8601(now),
      not_after: DateTime.to_iso8601(not_after),
      subject: subject_dn,
      public_key: public_key_b64,
      is_ca: true
    }

    tbs_json = Jason.encode!(tbs)
    digest = :crypto.hash(:sha3_256, tbs_json)

    variant = pqc_algo_atom(algorithm)

    unless variant do
      throw {:error, {:unsupported_pqc_variant, algorithm}}
    end

    case ApJavaCrypto.sign(digest, {variant, :private_key, private_key_bytes}) do
      {:ok, signature} ->
        cert_map = Map.put(tbs, :signature, Base.encode64(signature))
        cert_json = Jason.encode!(cert_map)
        cert_pem = "-----BEGIN PKI CERTIFICATE-----\n#{Base.encode64(cert_json)}\n-----END PKI CERTIFICATE-----\n"
        {:ok, cert_json, cert_pem}

      {:error, reason} ->
        {:error, {:pqc_sign_failed, reason}}
    end
  end

  defp parse_int(v) when is_integer(v), do: v

  defp parse_int(v) when is_binary(v) do
    case Integer.parse(v) do
      {n, _} -> n
      :error -> nil
    end
  end

  defp parse_int(_), do: nil

  defp build_audit_filters(filters) do
    Enum.reduce(filters, [], fn
      {:action, v}, acc when is_binary(v) and v != "" -> [{:action, v} | acc]
      {:actor_did, v}, acc when is_binary(v) and v != "" -> [{:actor_did, v} | acc]
      {:resource_type, v}, acc when is_binary(v) and v != "" -> [{:resource_type, v} | acc]
      {:resource_id, v}, acc when is_binary(v) and v != "" -> [{:resource_id, v} | acc]
      {:date_from, v}, acc when is_binary(v) and v != "" -> maybe_parse_date(:since, v, acc)
      {:date_to, v}, acc when is_binary(v) and v != "" -> maybe_parse_date(:until, v, acc)
      {"action", v}, acc when is_binary(v) and v != "" -> [{:action, v} | acc]
      {"actor_did", v}, acc when is_binary(v) and v != "" -> [{:actor_did, v} | acc]
      {"resource_type", v}, acc when is_binary(v) and v != "" -> [{:resource_type, v} | acc]
      {"resource_id", v}, acc when is_binary(v) and v != "" -> [{:resource_id, v} | acc]
      {"date_from", v}, acc when is_binary(v) and v != "" -> maybe_parse_date(:since, v, acc)
      {"date_to", v}, acc when is_binary(v) and v != "" -> maybe_parse_date(:until, v, acc)
      _, acc -> acc
    end)
  end

  defp maybe_parse_date(key, date_string, acc) do
    case DateTime.from_iso8601(date_string) do
      {:ok, datetime, _offset} ->
        [{key, datetime} | acc]

      {:error, _} ->
        case Date.from_iso8601(date_string) do
          {:ok, date} ->
            datetime =
              case key do
                :since -> DateTime.new!(date, ~T[00:00:00], "Etc/UTC")
                :until -> DateTime.new!(date, ~T[23:59:59], "Etc/UTC")
              end

            [{key, datetime} | acc]

          {:error, _} ->
            Logger.warning("Invalid date filter #{key}: #{inspect(date_string)}")
            acc
        end
    end
  end

  @impl true
  def list_active_ceremonies do
    # Query all CA instances for active ceremonies
    case list_ca_instances([]) do
      {:ok, instances} ->
        ceremonies =
          Enum.flat_map(instances, fn instance ->
            case list_ceremonies(instance[:id] || instance["id"], []) do
              {:ok, cers} -> cers
              _ -> []
            end
          end)
          |> Enum.filter(fn c ->
            status = c[:status] || c["status"]
            status in ["preparing", "generating"]
          end)

        {:ok, ceremonies}

      error ->
        error
    end
  end

  @impl true
  def fail_ceremony(ceremony_id, reason) do
    cancel_ceremony(ceremony_id, [])
    |> case do
      {:ok, ceremony} -> {:ok, Map.put(ceremony, :failure_reason, reason)}
      error -> error
    end
  end

  @impl true
  def initiate_witnessed_ceremony(ca_instance_id, params, opts) do
    tenant_id = Keyword.get(opts, :tenant_id)

    case PkiCaEngine.CeremonyOrchestrator.initiate(tenant_id, ca_instance_id, params) do
      {:ok, {ceremony, _issuer_key, _shares}} -> {:ok, to_map(ceremony)}
      {:ok, {ceremony, _issuer_key}} -> {:ok, to_map(ceremony)}
      {:error, _} = err -> err
    end
  end

  @impl true
  def accept_ceremony_share(ceremony_id, user_id, key_label, opts) do
    tenant_id = Keyword.get(opts, :tenant_id)
    password = Keyword.get(opts, :password)
    PkiCaEngine.CeremonyOrchestrator.accept_share(tenant_id, ceremony_id, user_id, key_label, password)
  end

  @impl true
  def attest_ceremony(ceremony_id, auditor_user_id, phase, details, opts) do
    tenant_id = Keyword.get(opts, :tenant_id)
    PkiCaEngine.CeremonyOrchestrator.attest(tenant_id, ceremony_id, auditor_user_id, phase, details)
  end

  @impl true
  def check_ceremony_readiness(ceremony_id, opts) do
    tenant_id = Keyword.get(opts, :tenant_id)
    PkiCaEngine.CeremonyOrchestrator.check_readiness(tenant_id, ceremony_id)
  end

  @impl true
  def execute_ceremony_keygen(ceremony_id, custodian_passwords, opts) do
    tenant_id = Keyword.get(opts, :tenant_id)
    PkiCaEngine.CeremonyOrchestrator.execute_keygen(tenant_id, ceremony_id, custodian_passwords)
  end

  @impl true
  def list_ceremony_attestations(ceremony_id, opts) do
    tenant_id = Keyword.get(opts, :tenant_id)
    attestations = PkiCaEngine.CeremonyOrchestrator.list_attestations(tenant_id, ceremony_id)
    {:ok, Enum.map(attestations, &to_map/1)}
  end

  @impl true
  def get_ceremony_by_issuer_key(issuer_key_id, opts) do
    tenant_id = Keyword.get(opts, :tenant_id)
    repo = PkiCaEngine.TenantRepo.ca_repo(tenant_id)

    case repo.one(from c in KeyCeremony, where: c.issuer_key_id == ^issuer_key_id, order_by: [desc: c.inserted_at], limit: 1) do
      nil -> {:error, :not_found}
      ceremony -> {:ok, to_map(ceremony)}
    end
  end

  @impl true
  def list_my_ceremony_shares(user_id, opts) do
    tenant_id = Keyword.get(opts, :tenant_id)
    repo = PkiCaEngine.TenantRepo.ca_repo(tenant_id)

    shares = repo.all(
      from s in PkiCaEngine.Schema.ThresholdShare,
        join: c in PkiCaEngine.Schema.KeyCeremony, on: c.issuer_key_id == s.issuer_key_id,
        left_join: ca in PkiCaEngine.Schema.CaInstance, on: ca.id == c.ca_instance_id,
        where: s.custodian_user_id == ^user_id and c.status in ["preparing", "generating", "completed"],
        select: %{
          ceremony_id: c.id,
          ceremony_status: c.status,
          algorithm: c.algorithm,
          threshold_k: c.threshold_k,
          threshold_n: c.threshold_n,
          window_expires_at: c.window_expires_at,
          share_index: s.share_index,
          share_status: s.status,
          key_label: s.key_label,
          accepted_at: s.accepted_at,
          domain_info: c.domain_info,
          ca_instance_id: c.ca_instance_id,
          ca_instance_name: ca.name
        }
    )

    {:ok, shares}
  end

  @impl true
  def list_my_witness_ceremonies(auditor_user_id, opts) do
    tenant_id = Keyword.get(opts, :tenant_id)
    repo = PkiCaEngine.TenantRepo.ca_repo(tenant_id)

    ceremonies = repo.all(
      from c in PkiCaEngine.Schema.KeyCeremony,
        left_join: ca in PkiCaEngine.Schema.CaInstance, on: ca.id == c.ca_instance_id,
        where: c.auditor_user_id == ^auditor_user_id and c.status in ["preparing", "generating", "completed"],
        order_by: [desc: c.inserted_at],
        select: {c, ca.name}
    )

    {:ok, Enum.map(ceremonies, fn {c, ca_name} ->
      c |> to_map() |> Map.put(:ca_instance_name, ca_name)
    end)}
  end
end
