defmodule PkiCaEngine.Api.CeremonyController do
  @moduledoc """
  Handles key ceremony endpoints.
  """

  import Plug.Conn
  import Ecto.Query
  alias PkiCaEngine.TenantRepo
  alias PkiCaEngine.Schema.KeyCeremony
  alias PkiCaEngine.KeyCeremony.SyncCeremony
  alias PkiCaEngine.KeyCeremonyManager
  alias PkiCaEngine.Api.Helpers

  defp register_ceremony(ceremony_id, pid) do
    PkiCaEngine.CeremonyRegistry.register(ceremony_id, pid)
  end

  defp lookup_ceremony(ceremony_id) do
    PkiCaEngine.CeremonyRegistry.lookup(ceremony_id)
  end

  defp unregister_ceremony(ceremony_id) do
    PkiCaEngine.CeremonyRegistry.unregister(ceremony_id)
  end

  def index(conn) do
    tenant_id = conn.assigns[:tenant_id]
    ca_instance_id = Helpers.resolve_instance_id(conn.query_params)
    repo = TenantRepo.ca_repo(tenant_id)

    ceremonies =
      from(c in KeyCeremony, where: c.ca_instance_id == ^ca_instance_id, order_by: [desc: c.inserted_at])
      |> repo.all()

    json(conn, 200, Enum.map(ceremonies, &serialize_ceremony/1))
  end

  def create(conn) do
    tenant_id = conn.assigns[:tenant_id]
    ca_instance_id = Helpers.resolve_instance_id(conn.body_params)

    params = %{
      algorithm: conn.body_params["algorithm"],
      keystore_id: conn.body_params["keystore_id"],
      threshold_k: parse_int(conn.body_params["threshold_k"]),
      threshold_n: parse_int(conn.body_params["threshold_n"]),
      initiated_by: conn.body_params["initiated_by"],
      domain_info: conn.body_params["domain_info"] || %{},
      key_alias: conn.body_params["key_alias"],
      is_root: conn.body_params["is_root"]
    }

    case SyncCeremony.initiate(tenant_id, ca_instance_id, params) do
      {:ok, {ceremony, issuer_key}} ->
        json(conn, 201, %{
          ceremony: serialize_ceremony(ceremony),
          issuer_key: %{
            id: issuer_key.id,
            key_alias: issuer_key.key_alias,
            algorithm: issuer_key.algorithm,
            status: issuer_key.status
          }
        })

      {:error, :invalid_threshold} ->
        json(conn, 422, %{error: "invalid_threshold", message: "k must be >= 2 and <= n"})

      {:error, :not_found} ->
        json(conn, 404, %{error: "not_found", message: "keystore not found"})

      {:error, %Ecto.Changeset{} = changeset} ->
        json(conn, 422, %{error: "validation_error", details: changeset_errors(changeset)})

      {:error, reason} ->
        json(conn, 500, %{error: "internal_error", message: format_error(reason)})
    end
  end

  def start_ceremony(conn) do
    sessions = conn.body_params["sessions"] || []
    ca_instance_id = Helpers.resolve_instance_id(conn.body_params)

    # Convert session maps to structs expected by KeyCeremonyManager
    parsed_sessions =
      Enum.map(sessions, fn s ->
        %{username: s["username"], role: s["role"]}
      end)

    case KeyCeremonyManager.start_ceremony(ca_instance_id, parsed_sessions) do
      {:ok, pid} ->
        ceremony_id = Ecto.UUID.generate()
        register_ceremony(ceremony_id, pid)
        json(conn, 201, %{ceremony_id: ceremony_id})

      {:error, reason} ->
        json(conn, 422, %{error: format_error(reason)})
    end
  end

  def generate_keypair(conn, ceremony_id) do
    with {:ok, pid} <- lookup_ceremony(ceremony_id),
         {:ok, protection_mode} <- parse_protection_mode(conn.body_params["protection_mode"]) do
      algorithm = conn.body_params["algorithm"]
      opts = [
        threshold_k: conn.body_params["threshold_k"] || 2,
        threshold_n: conn.body_params["threshold_n"] || 3
      ]

      case KeyCeremonyManager.generate_keypair(pid, algorithm, protection_mode, opts) do
        {:ok, keypair_data} ->
          json(conn, 200, %{
            keypair_id: keypair_data.keypair_id,
            algorithm: keypair_data.algorithm,
            public_key: Base.encode64(keypair_data.public_key)
          })

        {:error, reason} ->
          json(conn, 422, %{error: format_error(reason)})
      end
    else
      {:error, :not_found} -> json(conn, 404, %{error: "ceremony_not_found"})
      {:error, :invalid_protection_mode} -> json(conn, 422, %{error: "invalid_protection_mode"})
    end
  end

  def self_sign(conn, ceremony_id) do
    with {:ok, pid} <- lookup_ceremony(ceremony_id) do
      subject_info = conn.body_params["subject_info"] || "/CN=Root CA"
      cert_profile = %{validity_days: conn.body_params["validity_days"] || 3650}

      case KeyCeremonyManager.gen_self_sign_cert(pid, subject_info, cert_profile) do
        {:ok, cert_pem} ->
          json(conn, 200, %{certificate_pem: cert_pem})

        {:error, reason} ->
          json(conn, 422, %{error: format_error(reason)})
      end
    else
      {:error, :not_found} -> json(conn, 404, %{error: "ceremony_not_found"})
    end
  end

  def gen_csr(conn, ceremony_id) do
    with {:ok, pid} <- lookup_ceremony(ceremony_id) do
      subject_info = conn.body_params["subject_info"] || "/CN=Sub CA"

      case KeyCeremonyManager.gen_csr(pid, subject_info) do
        {:ok, csr_pem} ->
          json(conn, 200, %{csr_pem: csr_pem})

        {:error, reason} ->
          json(conn, 422, %{error: format_error(reason)})
      end
    else
      {:error, :not_found} -> json(conn, 404, %{error: "ceremony_not_found"})
    end
  end

  def assign_custodians(conn, ceremony_id) do
    with {:ok, pid} <- lookup_ceremony(ceremony_id) do
      custodians =
        (conn.body_params["custodians"] || [])
        |> Enum.map(fn c -> %{password: c["password"]} end)

      threshold_k = conn.body_params["threshold_k"] || 2

      case KeyCeremonyManager.assign_custodians(pid, custodians, threshold_k) do
        {:ok, _encrypted_shares} ->
          json(conn, 200, %{status: "custodians_assigned"})

        {:error, reason} ->
          json(conn, 422, %{error: format_error(reason)})
      end
    else
      {:error, :not_found} -> json(conn, 404, %{error: "ceremony_not_found"})
    end
  end

  def finalize(conn, ceremony_id) do
    with {:ok, pid} <- lookup_ceremony(ceremony_id) do
      auditor_session = %{
        username: conn.body_params["auditor_username"],
        role: conn.body_params["auditor_role"] || "auditor"
      }

      case KeyCeremonyManager.finalize(pid, auditor_session) do
        {:ok, audit_trail} ->
          unregister_ceremony(ceremony_id)
          json(conn, 200, %{status: "finalized", audit_trail_count: length(audit_trail)})

        {:error, reason} ->
          json(conn, 422, %{error: format_error(reason)})
      end
    else
      {:error, :not_found} -> json(conn, 404, %{error: "ceremony_not_found"})
    end
  end

  def status(conn, ceremony_id) do
    with {:ok, pid} <- lookup_ceremony(ceremony_id) do
      status = KeyCeremonyManager.get_status(pid)
      json(conn, 200, %{
        phase: status.phase,
        ca_instance_id: status.ca_instance_id,
        keypair_id: status.keypair_id,
        protection_mode: status.protection_mode,
        audit_trail_count: status.audit_trail_count
      })
    else
      {:error, :not_found} -> json(conn, 404, %{error: "ceremony_not_found"})
    end
  end

  defp serialize_ceremony(ceremony) do
    %{
      id: ceremony.id,
      ca_instance_id: ceremony.ca_instance_id,
      issuer_key_id: ceremony.issuer_key_id,
      ceremony_type: ceremony.ceremony_type,
      status: ceremony.status,
      algorithm: ceremony.algorithm,
      keystore_id: ceremony.keystore_id,
      threshold_k: ceremony.threshold_k,
      threshold_n: ceremony.threshold_n,
      domain_info: ceremony.domain_info,
      initiated_by: ceremony.initiated_by,
      inserted_at: ceremony.inserted_at,
      updated_at: ceremony.updated_at
    }
  end

  defp parse_int(v) when is_integer(v), do: v
  defp parse_int(v) when is_binary(v) do
    case Integer.parse(v) do
      {n, _} -> n
      :error -> nil
    end
  end
  defp parse_int(_), do: nil

  defp parse_protection_mode(nil), do: {:ok, :split_auth_token}
  defp parse_protection_mode("credential_own"), do: {:ok, :credential_own}
  defp parse_protection_mode("split_auth_token"), do: {:ok, :split_auth_token}
  defp parse_protection_mode("split_key"), do: {:ok, :split_key}
  defp parse_protection_mode(_), do: {:error, :invalid_protection_mode}

  defp format_error(reason) when is_atom(reason), do: Atom.to_string(reason)
  defp format_error({key, details}), do: "#{key}: #{inspect(details)}"
  defp format_error(reason), do: inspect(reason)

  defp changeset_errors(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Regex.replace(~r"%{(\w+)}", msg, fn _, key ->
        opts |> Keyword.get(String.to_existing_atom(key), key) |> to_string()
      end)
    end)
  end

  defp json(conn, status, body) do
    conn
    |> put_resp_content_type("application/json")
    |> send_resp(status, Jason.encode!(body))
  end
end
