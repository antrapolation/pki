defmodule PkiRaEngine.Api.DcvController do
  @moduledoc """
  REST controller for Domain Control Validation (DCV) endpoints.
  """

  import Plug.Conn

  alias PkiRaEngine.DcvChallenge

  def create(conn, csr_id) do
    tenant_id = conn.assigns[:tenant_id]

    with {:ok, method} <- fetch_param(conn.body_params, "method"),
         {:ok, domain} <- fetch_param(conn.body_params, "domain") do
      initiated_by = Map.get(conn.body_params, "initiated_by")
      timeout_hours = Map.get(conn.body_params, "timeout_hours", 24)

      case DcvChallenge.create(tenant_id, csr_id, domain, method, initiated_by, timeout_hours) do
        {:ok, challenge} ->
          json_resp(conn, 201, serialize_challenge(challenge))

        {:error, %Ecto.Changeset{} = changeset} ->
          unprocessable(conn, format_errors(changeset))

        {:error, reason} ->
          unprocessable(conn, inspect(reason))
      end
    else
      {:error, missing_field} ->
        unprocessable(conn, "missing required field: #{missing_field}")
    end
  end

  def verify(conn, csr_id) do
    tenant_id = conn.assigns[:tenant_id]

    challenges = DcvChallenge.get_for_csr(tenant_id, csr_id)
    pending = Enum.filter(challenges, &(&1.status == "pending"))

    results =
      Enum.map(pending, fn challenge ->
        case DcvChallenge.verify(tenant_id, challenge.id) do
          {:ok, updated} -> serialize_challenge(updated)
          {:error, _} -> serialize_challenge(challenge)
        end
      end)

    json_resp(conn, 200, results)
  end

  def show(conn, csr_id) do
    tenant_id = conn.assigns[:tenant_id]
    challenges = DcvChallenge.get_for_csr(tenant_id, csr_id)
    json_resp(conn, 200, Enum.map(challenges, &serialize_challenge/1))
  end

  # -- Private --

  defp fetch_param(params, key) do
    case Map.fetch(params, key) do
      {:ok, value} -> {:ok, value}
      :error -> {:error, key}
    end
  end

  defp serialize_challenge(challenge) do
    %{
      id: challenge.id,
      csr_id: challenge.csr_id,
      domain: challenge.domain,
      method: challenge.method,
      token: challenge.token,
      token_value: challenge.token_value,
      status: challenge.status,
      initiated_by: challenge.initiated_by,
      verified_at: challenge.verified_at && DateTime.to_iso8601(challenge.verified_at),
      expires_at: challenge.expires_at && DateTime.to_iso8601(challenge.expires_at),
      attempts: challenge.attempts,
      last_checked_at: challenge.last_checked_at && DateTime.to_iso8601(challenge.last_checked_at),
      error_details: challenge.error_details,
      inserted_at: challenge.inserted_at && NaiveDateTime.to_iso8601(challenge.inserted_at),
      updated_at: challenge.updated_at && NaiveDateTime.to_iso8601(challenge.updated_at)
    }
  end

  defp format_errors(%Ecto.Changeset{} = changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Regex.replace(~r"%{(\w+)}", msg, fn _, key ->
        opts |> Keyword.get(String.to_existing_atom(key), key) |> to_string()
      end)
    end)
  end

  defp json_resp(conn, status, body) do
    conn
    |> put_resp_content_type("application/json")
    |> send_resp(status, Jason.encode!(body))
  end

  defp unprocessable(conn, reason), do: json_resp(conn, 422, %{error: reason})
end
