defmodule PkiPlatformEngine.Mailer do
  require Logger

  @resend_url "https://api.resend.com/emails"

  def send_email(to, subject, html_body) do
    api_key = System.get_env("RESEND_API_KEY")
    from = System.get_env("MAILER_FROM", "PQC PKI Platform <noreply@straptrust.com>")

    unless api_key do
      Logger.warning("RESEND_API_KEY not set — email not sent to #{to}")
      {:ok, :skipped}
    else
      body = Jason.encode!(%{
        from: from,
        to: [to],
        subject: subject,
        html: html_body
      })

      case Req.post(@resend_url,
             headers: [
               {"authorization", "Bearer #{api_key}"},
               {"content-type", "application/json"}
             ],
             body: body
           ) do
        {:ok, %{status: status}} when status in 200..299 ->
          Logger.info("Email sent to #{to}: #{subject}")
          {:ok, :sent}

        {:ok, %{status: status, body: resp_body}} ->
          Logger.error("Resend API error #{status}: #{inspect(resp_body)}")
          {:error, {:resend_error, status, resp_body}}

        {:error, reason} ->
          Logger.error("Failed to send email: #{inspect(reason)}")
          {:error, reason}
      end
    end
  end
end
