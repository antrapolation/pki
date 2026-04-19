defmodule PkiTenantWeb.ErrorHelpers do
  @moduledoc """
  Sanitizes error messages for user-facing display.
  Keeps known actionable errors specific, falls back to generic for internals.
  """

  def sanitize_error(context, :not_found), do: "#{context}: record not found."
  def sanitize_error(context, :duplicate), do: "#{context}: already exists."
  def sanitize_error(context, :duplicate_key_alias), do: "#{context}: a key with that alias already exists."
  def sanitize_error(context, :invalid_credentials), do: "Invalid username or password."
  def sanitize_error(context, :unauthorized), do: "You don't have permission for this action."
  def sanitize_error(context, :rate_limited), do: "Too many attempts. Please wait."
  def sanitize_error(context, :invalid_threshold), do: "#{context}: invalid threshold configuration."
  def sanitize_error(context, :share_not_found), do: "#{context}: share not found."
  def sanitize_error(context, :already_exists), do: "#{context}: already exists."
  def sanitize_error(_context, :invalid_password), do: "Invalid password."
  def sanitize_error(context, reason) when is_atom(reason), do: "#{context}: #{Phoenix.Naming.humanize(reason)}."
  def sanitize_error(context, reason) when is_binary(reason), do: "#{context}: #{reason}"
  def sanitize_error(context, _reason), do: "#{context}. Please try again or contact your administrator."
end
