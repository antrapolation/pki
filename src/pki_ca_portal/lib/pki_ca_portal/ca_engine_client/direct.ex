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
    tenant_id = opts[:tenant_id]

    case UserManagement.update_user_profile(tenant_id, user_id, attrs) do
      {:ok, user} -> {:ok, to_map(user)}
      {:error, :not_found} = err -> err
      {:error, %Ecto.Changeset{} = cs} -> {:error, {:validation_error, changeset_errors(cs)}}
      {:error, _reason} = err -> err
    end
  end

  @impl true
  def verify_and_change_password(user_id, current_password, new_password, opts \\ []) do
    tenant_id = opts[:tenant_id]

    case UserManagement.verify_and_change_password(tenant_id, user_id, current_password, new_password) do
      {:ok, user} -> {:ok, to_map(user)}
      {:error, :not_found} = err -> err
      {:error, :invalid_current_password} = err -> err
      {:error, %Ecto.Changeset{} = cs} -> {:error, {:validation_error, changeset_errors(cs)}}
      {:error, _reason} = err -> err
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
      nil -> {:error, :not_found}
      ceremony -> {:ok, to_map(ceremony)}
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

      with :ok <- KazSign.init(level),
           {:ok, csr_der} <- KazSign.generate_csr(level, private_key, public_key, subject_dn) do
      csr_b64 = Base.encode64(csr_der, padding: true)
      csr_pem = "-----BEGIN CERTIFICATE REQUEST-----\n#{wrap_pem(csr_b64)}\n-----END CERTIFICATE REQUEST-----\n"

      # Mark ceremony completed
      case ceremony |> Ecto.Changeset.change(status: "completed") |> repo.update() do
        {:ok, updated} -> {:ok, {to_map(updated), csr_pem}}
        {:error, reason} -> {:error, {:completion_failed, reason}}
      end
    end
    end
  rescue
    e -> {:error, "KAZ-SIGN CSR generation failed: #{Exception.message(e)}"}
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

    {:ok, Enum.map(shares, &to_map/1)}
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
    csr_der =
      csr_pem
      |> String.replace("-----BEGIN CERTIFICATE REQUEST-----", "")
      |> String.replace("-----END CERTIFICATE REQUEST-----", "")
      |> String.replace(~r/\s/, "")
      |> Base.decode64!()

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
  rescue
    e -> {:error, "KAZ-SIGN CSR signing failed: #{Exception.message(e)}"}
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
    e -> {:error, "Certificate signing failed: #{Exception.message(e)}"}
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
  def list_ceremonies(ca_instance_id, opts \\ []) do
    tenant_id = opts[:tenant_id]
    repo = TenantRepo.ca_repo(tenant_id)

    ceremonies =
      from(c in KeyCeremony,
        where: c.ca_instance_id == ^ca_instance_id,
        order_by: [desc: c.inserted_at]
      )
      |> repo.all()

    {:ok, Enum.map(ceremonies, &to_map/1)}
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

        true ->
          # For general updates, try status first as the most common case
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

  # Flatten a tree of CA instances (with nested :children) into a flat list
  defp flatten_tree(instances) do
    Enum.flat_map(instances, fn instance ->
      map = to_map(instance)
      children = map[:children] || []
      parent = Map.put(map, :children, nil)
      [parent | flatten_tree_maps(children)]
    end)
  end

  defp flatten_tree_maps(nil), do: []
  defp flatten_tree_maps(children) when is_list(children) do
    Enum.flat_map(children, fn child ->
      grandchildren = child[:children] || []
      [Map.put(child, :children, nil) | flatten_tree_maps(grandchildren)]
    end)
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
    e -> {:error, "PQC keygen failed: #{Exception.message(e)}"}
  catch
    :exit, {:timeout, _} ->
      {:error, "PQC key generation timed out. The JRuby/Java service may be starting up — please try again."}
    :exit, reason ->
      {:error, "PQC keygen process error: #{inspect(reason)}"}
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
    e -> {:error, "KAZ-SIGN keygen failed: #{Exception.message(e)}"}
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

    with :ok <- KazSign.init(level),
         # Generate a self-signed CSR first, then issue a self-signed cert
         {:ok, csr_der} <- KazSign.generate_csr(level, private_key, public_key, subject_dn),
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
    e -> {:error, {:kaz_sign_self_sign_failed, Exception.message(e)}}
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
end
