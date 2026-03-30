defmodule PkiCaPortalWeb.PasswordController do
  use PkiCaPortalWeb, :controller

  def edit(conn, _params) do
    unless get_session(conn, :must_change_password) do
      redirect(conn, to: "/")
    else
      render(conn, :change_password, layout: false, error: nil)
    end
  end

  def update(conn, %{"password" => password, "password_confirmation" => confirmation}) do
    user = get_session(conn, :current_user)

    cond do
      String.length(password) < 8 ->
        render(conn, :change_password, layout: false, error: "Password must be at least 8 characters.")

      password != confirmation ->
        render(conn, :change_password, layout: false, error: "Passwords do not match.")

      true ->
        case update_user_password(user, password) do
          :ok ->
            conn
            |> delete_session(:must_change_password)
            |> put_flash(:info, "Password changed successfully.")
            |> redirect(to: "/")

          {:error, reason} ->
            render(conn, :change_password, layout: false, error: "Failed to change password: #{inspect(reason)}")
        end
    end
  end

  def update(conn, _params) do
    render(conn, :change_password, layout: false, error: "Password and confirmation are required.")
  end

  defp update_user_password(user, new_password) do
    secret =
      Application.get_env(:pki_ca_portal, :internal_api_secret) ||
        System.get_env("INTERNAL_API_SECRET", "")

    base_url =
      Application.get_env(:pki_ca_portal, :ca_engine_url) ||
        "http://127.0.0.1:4001"

    user_id = user["id"] || user[:id]

    case Req.put("#{base_url}/api/v1/users/#{user_id}/password",
           json: %{password: new_password, must_change_password: false},
           headers: [{"authorization", "Bearer #{secret}"}]
         ) do
      {:ok, %{status: status}} when status in 200..299 -> :ok
      {:ok, %{status: status, body: body}} -> {:error, "API error #{status}: #{inspect(body)}"}
      {:error, reason} -> {:error, reason}
    end
  end
end
