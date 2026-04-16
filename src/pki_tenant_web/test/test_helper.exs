# Stop apps that auto-start but aren't needed for web tests
for app <- [:pki_validation, :pki_ca_engine, :pki_ra_engine, :pki_tenant] do
  Application.stop(app)
end

ExUnit.start()
