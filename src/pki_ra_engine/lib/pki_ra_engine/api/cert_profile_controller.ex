defmodule PkiRaEngine.Api.CertProfileController do
  @moduledoc """
  Handles certificate profile CRUD endpoints (protected by InternalAuthPlug).
  """

  import Plug.Conn
  alias PkiRaEngine.CertProfileConfig

  def index(conn) do
    profiles = CertProfileConfig.list_profiles()
    json(conn, 200, Enum.map(profiles, &serialize_profile/1))
  end

  def create(conn) do
    attrs = conn.body_params

    case CertProfileConfig.create_profile(attrs) do
      {:ok, profile} ->
        json(conn, 201, serialize_profile(profile))

      {:error, %Ecto.Changeset{} = changeset} ->
        json(conn, 422, %{error: "validation_error", details: changeset_errors(changeset)})
    end
  end

  def update(conn, id) do
    case CertProfileConfig.update_profile(id, conn.body_params) do
      {:ok, profile} ->
        json(conn, 200, serialize_profile(profile))

      {:error, :not_found} ->
        json(conn, 404, %{error: "not_found"})

      {:error, %Ecto.Changeset{} = changeset} ->
        json(conn, 422, %{error: "validation_error", details: changeset_errors(changeset)})
    end
  end

  def delete(conn, id) do
    case CertProfileConfig.delete_profile(id) do
      {:ok, profile} ->
        json(conn, 200, serialize_profile(profile))

      {:error, :not_found} ->
        json(conn, 404, %{error: "not_found"})
    end
  end

  defp serialize_profile(profile) do
    %{
      id: profile.id,
      name: profile.name,
      subject_dn_policy: profile.subject_dn_policy,
      issuer_policy: profile.issuer_policy,
      key_usage: profile.key_usage,
      ext_key_usage: profile.ext_key_usage,
      digest_algo: profile.digest_algo,
      validity_policy: profile.validity_policy,
      timestamping_policy: profile.timestamping_policy,
      crl_policy: profile.crl_policy,
      ocsp_policy: profile.ocsp_policy,
      ca_repository_url: profile.ca_repository_url,
      issuer_url: profile.issuer_url,
      included_extensions: profile.included_extensions,
      renewal_policy: profile.renewal_policy,
      notification_profile: profile.notification_profile,
      cert_publish_policy: profile.cert_publish_policy,
      inserted_at: profile.inserted_at,
      updated_at: profile.updated_at
    }
  end

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
