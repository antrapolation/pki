defmodule PkiRaPortalWeb.ErrorHelpers do
  @moduledoc """
  Sanitizes error messages for user-facing display.
  """

  def sanitize_error(context, :not_found), do: "#{context}: record not found."
  def sanitize_error(context, :duplicate), do: "#{context}: already exists."
  def sanitize_error(_context, :invalid_credentials), do: "Invalid username or password."
  def sanitize_error(_context, :unauthorized), do: "You don't have permission for this action."
  def sanitize_error(_context, :rate_limited), do: "Too many attempts. Please wait."
  def sanitize_error(context, :already_exists), do: "#{context}: already exists."
  def sanitize_error(_context, :invalid_password), do: "Invalid password."
  def sanitize_error(context, %Ecto.Changeset{} = cs), do: "#{context}: #{format_changeset(cs)}"
  def sanitize_error(context, reason) when is_atom(reason), do: "#{context}: #{Phoenix.Naming.humanize(reason)}."
  def sanitize_error(context, reason) when is_binary(reason), do: "#{context}: #{reason}"
  def sanitize_error(context, _reason), do: "#{context}. Please try again or contact your administrator."

  defp format_changeset(%Ecto.Changeset{} = cs) do
    Ecto.Changeset.traverse_errors(cs, fn {msg, opts} ->
      Regex.replace(~r"%{(\w+)}", msg, fn _, key ->
        opts |> Keyword.get(String.to_existing_atom(key), key) |> to_string()
      end)
    end)
    |> Enum.map(fn {field, msgs} -> "#{field} #{Enum.join(msgs, ", ")}" end)
    |> Enum.join("; ")
  end
end
