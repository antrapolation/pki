defmodule PkiRaEngine.Test.CaEngineStub do
  @moduledoc """
  Simulates pki_ca_engine responses for RA→CA integration testing.

  Provides a `sign_certificate/2` function that returns realistic certificate
  data without requiring the actual CA engine or its Postgres database.
  """

  @behaviour PkiRaEngine.CaClient

  @impl true
  def sign_certificate(_tenant_id, _issuer_key_id, _csr_pem, _cert_profile) do
    serial = :crypto.strong_rand_bytes(8) |> Base.encode16(case: :lower)

    {:ok,
     %{
       serial_number: serial,
       cert_der: "SIGNED_CERT_DER_#{serial}",
       cert_pem:
         "-----BEGIN CERTIFICATE-----\nSIGNED_#{serial}\n-----END CERTIFICATE-----",
       subject_dn: "CN=test.example.com,O=Test",
       not_before: DateTime.utc_now(),
       not_after: DateTime.add(DateTime.utc_now(), 365 * 86400, :second)
     }}
  end
end
