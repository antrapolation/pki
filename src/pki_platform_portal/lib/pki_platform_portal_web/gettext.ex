defmodule PkiPlatformPortalWeb.Gettext do
  @moduledoc """
  A module providing Internationalization with a gettext-based API.

  By using [Gettext](https://hexdocs.pm/gettext), your module compiles translations
  that you can use in your application.
  """
  use Gettext.Backend, otp_app: :pki_platform_portal
end
