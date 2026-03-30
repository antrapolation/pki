defmodule PkiPlatformPortalWeb.ErrorHTML do
  @moduledoc """
  This module is invoked by your endpoint in case of errors on HTML requests.
  """
  use PkiPlatformPortalWeb, :html

  embed_templates "error_html/*"

  def render(template, assigns) do
    status =
      case Integer.parse(String.trim_trailing(template, ".html")) do
        {code, ""} -> code
        _ -> 500
      end

    assigns =
      assigns
      |> Map.put(:status, status)
      |> Map.put(:title, title_for(status))
      |> Map.put(:message, message_for(status))

    render("error.html", assigns)
  end

  defp title_for(400), do: "Bad Request"
  defp title_for(403), do: "Forbidden"
  defp title_for(404), do: "Not Found"
  defp title_for(500), do: "Server Error"
  defp title_for(_), do: "Error"

  defp message_for(400), do: "The request could not be understood. Please try again."
  defp message_for(403), do: "You don't have permission to access this page."
  defp message_for(404), do: "The page you're looking for doesn't exist or has been moved."
  defp message_for(500), do: "Something went wrong on our end. Please try again later."
  defp message_for(_), do: "An unexpected error occurred."
end
