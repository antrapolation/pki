defmodule PkiTenantWeb.Ca.CeremonyTranscriptHTML do
  @moduledoc false
  use PkiTenantWeb, :html

  embed_templates "ceremony_transcript_html/*"

  @doc """
  Format a DateTime-ish value into a locally-readable string for the
  printed transcript. Accepts DateTime, NaiveDateTime, an ISO 8601
  string, or nil.
  """
  def fmt_time(nil), do: "—"

  def fmt_time(%DateTime{} = dt) do
    dt
    |> DateTime.truncate(:second)
    |> DateTime.to_iso8601()
  end

  def fmt_time(%NaiveDateTime{} = ndt) do
    ndt
    |> NaiveDateTime.truncate(:second)
    |> NaiveDateTime.to_iso8601()
  end

  def fmt_time(s) when is_binary(s), do: s
  def fmt_time(_), do: "—"

  @doc "Render the action string from a transcript entry into a human label."
  def humanize_action("ceremony_initiated"), do: "Ceremony initiated"
  def humanize_action("identity_verified"), do: "Auditor verified custodian identity"
  def humanize_action("share_accepted"), do: "Custodian accepted share"
  def humanize_action("ceremony_completed"), do: "Key generated, shares encrypted, ceremony completed"
  def humanize_action("cancelled_by_admin"), do: "Ceremony cancelled"
  def humanize_action(other) when is_binary(other), do: other |> String.replace("_", " ") |> String.capitalize()
  def humanize_action(_), do: "Event"

  @doc "Short details line for a transcript entry (right column)."
  def describe_details(nil), do: ""
  def describe_details(%{} = map) when map_size(map) == 0, do: ""

  def describe_details(%{} = map) do
    map
    |> Enum.map(fn {k, v} -> "#{k}: #{inspect(v, limit: :infinity)}" end)
    |> Enum.join(", ")
  end

  def describe_details(_), do: ""

  @doc "Best-effort fingerprint fetch from the ceremony's domain_info."
  def fingerprint(%{domain_info: %{} = info}), do: Map.get(info, "fingerprint") || "—"
  def fingerprint(_), do: "—"

  @doc "Subject DN from domain_info."
  def subject_dn(%{domain_info: %{} = info}), do: Map.get(info, "subject_dn") || "—"
  def subject_dn(_), do: "—"

  @doc "Is-root flag from domain_info (true/false)."
  def is_root?(%{domain_info: %{} = info}), do: Map.get(info, "is_root", true)
  def is_root?(_), do: true
end
