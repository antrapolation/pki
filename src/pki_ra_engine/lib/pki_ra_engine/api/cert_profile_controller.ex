defmodule PkiRaEngine.Api.CertProfileController do
  @moduledoc """
  Handles certificate profile CRUD endpoints (protected by InternalAuthPlug).
  """

  import Plug.Conn
  alias PkiRaEngine.CertProfileConfig

  def index(conn) do
    tenant_id = conn.assigns[:tenant_id]
    profiles = CertProfileConfig.list_profiles(tenant_id)
    json(conn, 200, Enum.map(profiles, &serialize_profile/1))
  end

  def create(conn) do
    tenant_id = conn.assigns[:tenant_id]
    attrs = normalize_profile_attrs(conn.body_params)

    case CertProfileConfig.create_profile(tenant_id, attrs) do
      {:ok, profile} ->
        json(conn, 201, serialize_profile(profile))

      {:error, %Ecto.Changeset{} = changeset} ->
        json(conn, 422, %{error: "validation_error", details: changeset_errors(changeset)})
    end
  end

  def update(conn, id) do
    tenant_id = conn.assigns[:tenant_id]
    case CertProfileConfig.update_profile(tenant_id, id, normalize_profile_attrs(conn.body_params)) do
      {:ok, profile} ->
        json(conn, 200, serialize_profile(profile))

      {:error, :not_found} ->
        json(conn, 404, %{error: "not_found"})

      {:error, %Ecto.Changeset{} = changeset} ->
        json(conn, 422, %{error: "validation_error", details: changeset_errors(changeset)})
    end
  end

  def delete(conn, id) do
    tenant_id = conn.assigns[:tenant_id]
    case CertProfileConfig.delete_profile(tenant_id, id) do
      {:ok, profile} ->
        json(conn, 200, serialize_profile(profile))

      {:error, :not_found} ->
        json(conn, 404, %{error: "not_found"})
    end
  end

  @pqc_algorithms ~w(KAZ-SIGN KAZ-SIGN-128 KAZ-SIGN-192 KAZ-SIGN-256 ML-DSA-44 ML-DSA-65 ML-DSA-87 Ed25519 Ed448)

  defp normalize_profile_attrs(params) do
    params
    |> normalize_validity_days()
    |> normalize_digest_algo()
  end

  defp normalize_validity_days(params) do
    case Map.get(params, "validity_days") do
      nil -> params
      days ->
        days_int = case days do
          d when is_integer(d) -> d
          d when is_binary(d) -> case Integer.parse(d) do {n, _} -> n; :error -> 365 end
          _ -> 365
        end
        Map.put(params, "validity_policy", Map.merge(Map.get(params, "validity_policy", %{}), %{"days" => days_int}))
    end
  end

  # If digest_algo is nil/empty and issuer_key is PQC, default to "algorithm-default"
  defp normalize_digest_algo(params) do
    digest = Map.get(params, "digest_algo")

    if is_nil(digest) or digest == "" do
      # Look up the issuer key algorithm to determine if PQC
      issuer_key_id = Map.get(params, "issuer_key_id")
      if is_binary(issuer_key_id) and issuer_key_id != "" do
        Map.put(params, "digest_algo", "algorithm-default")
      else
        Map.put(params, "digest_algo", "SHA-256")
      end
    else
      params
    end
  end

  defp serialize_profile(profile) do
    validity_days = get_in(profile.validity_policy, ["days"])

    %{
      id: profile.id,
      name: profile.name,
      subject_dn_policy: profile.subject_dn_policy,
      issuer_policy: profile.issuer_policy,
      key_usage: profile.key_usage,
      ext_key_usage: profile.ext_key_usage,
      digest_algo: profile.digest_algo,
      validity_days: validity_days,
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
