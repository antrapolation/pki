defmodule PkiTenantWeb.Ca.CeremonyTranscriptController do
  @moduledoc """
  Renders the **printable** ceremony transcript — the authoritative
  artifact the external auditor prints, then custodians sign in pen,
  then the auditor signs.

  Layout is bypassed (no portal chrome) so the page prints cleanly on
  A4/letter. Styling lives inside the template using `@media print`
  rules and base serif styling.

  Read-only: renders whatever the current Mnesia state says. Does not
  allow edits, does not expose secrets (no password_hash, no encrypted
  shares — only signature-gathering metadata).
  """
  use PkiTenantWeb, :controller

  alias PkiMnesia.Repo
  alias PkiMnesia.Structs.{KeyCeremony, IssuerKey, ThresholdShare, CeremonyParticipant, CeremonyTranscript}
  alias PkiTenantWeb.SessionStore

  plug :require_authenticated_ca_user

  def show(conn, %{"id" => ceremony_id}) do
    with {:ok, ceremony} when not is_nil(ceremony) <- fetch(KeyCeremony, ceremony_id),
         {:ok, issuer_key} <- fetch_issuer_key(ceremony.issuer_key_id),
         shares = fetch_shares(ceremony.issuer_key_id),
         participants = fetch_participants(ceremony_id),
         transcript = fetch_transcript(ceremony_id) do
      conn
      |> put_root_layout(false)
      |> put_layout(false)
      |> render(:show,
        ceremony: ceremony,
        issuer_key: issuer_key,
        shares: Enum.sort_by(shares, & &1.share_index),
        custodians: Enum.filter(participants, &(&1.role == :custodian)),
        auditor: Enum.find(participants, &(&1.role == :auditor)),
        transcript: transcript
      )
    else
      {:ok, nil} ->
        conn |> put_status(:not_found) |> text("Ceremony not found.")

      {:error, :not_found} ->
        conn |> put_status(:not_found) |> text("Ceremony not found.")

      _ ->
        conn |> put_status(:internal_server_error) |> text("Failed to render transcript.")
    end
  end

  defp fetch(schema, id) do
    case Repo.get(schema, id) do
      {:ok, nil} -> {:error, :not_found}
      {:ok, record} -> {:ok, record}
      err -> err
    end
  end

  defp fetch_issuer_key(nil), do: {:ok, nil}
  defp fetch_issuer_key(id), do: fetch(IssuerKey, id)

  defp fetch_shares(nil), do: []

  defp fetch_shares(issuer_key_id) do
    case Repo.get_all_by_index(ThresholdShare, :issuer_key_id, issuer_key_id) do
      {:ok, list} -> list
      _ -> []
    end
  end

  defp fetch_participants(ceremony_id) do
    case Repo.get_all_by_index(CeremonyParticipant, :ceremony_id, ceremony_id) do
      {:ok, list} -> list
      _ -> []
    end
  end

  defp fetch_transcript(ceremony_id) do
    case Repo.get_all_by_index(CeremonyTranscript, :ceremony_id, ceremony_id) do
      {:ok, [t | _]} -> t
      _ -> nil
    end
  end

  # Plug — mirrors the LiveView AuthHook but for the plain-controller
  # path. Rejects with a 302 to /login if the session cookie is missing
  # or the session has been evicted from the SessionStore. Role gating
  # is deliberately loose (any authenticated tenant user can print a
  # transcript); field-level access control lives in the orchestrator,
  # not in the print view.
  defp require_authenticated_ca_user(conn, _opts) do
    session_id = Plug.Conn.get_session(conn, :session_id)

    case session_id && SessionStore.lookup(session_id) do
      {:ok, _session} ->
        conn

      _ ->
        conn
        |> Phoenix.Controller.redirect(to: "/login")
        |> Plug.Conn.halt()
    end
  end
end
