# Stop the application if it was auto-started — tests manage their own Mnesia.
Application.stop(:pki_tenant)
ExUnit.start()
