#!/usr/bin/env elixir
# DEV ONLY: Activate an issuer key by generating a fresh keypair
# and injecting it into KeyActivation.
#
# This bypasses the threshold ceremony for development/testing.
# The generated key has NO relation to the original ceremony key.
# Certificates signed with this key will NOT chain to the real CA.
#
# Usage from pki_ra_portal:
#   elixir --sname dev_activate -S mix run ../../scripts/dev_activate_key.exs

IO.puts("\n=== DEV Key Activation ===\n")

tenant_id = "019d3f8c-7085-776d-a865-009b4b1deac7"
issuer_key_id = "019d581f-1dc8-7e0a-9889-470a9c3acfed"

# Wait for tenant and KeyActivation to be ready
IO.write("Waiting for services...")
Process.sleep(3000)
IO.puts(" OK")

# Check if already active
case PkiCaEngine.KeyActivation.is_active?(issuer_key_id) do
  true ->
    IO.puts("Key #{issuer_key_id} is already active. Nothing to do.")

  false ->
    IO.puts("Key #{issuer_key_id} is NOT active. Generating dev keypair...")

    # Look up the algorithm
    repo = PkiCaEngine.TenantRepo.ca_repo(tenant_id)
    issuer_key = repo.get!(PkiCaEngine.Schema.IssuerKey, issuer_key_id)
    algo = issuer_key.algorithm
    IO.puts("Algorithm: #{algo}")

    # For dev testing, generate an RSA 2048 key (PQC algorithms need JRuby bridge)
    # The key won't match the original algorithm but will allow signing to proceed
    IO.puts("Generating RSA 2048 dev key (PQC bridge not available in standalone mode)...")
    rsa_key = X509.PrivateKey.new_rsa(2048)
    rsa_der = X509.PrivateKey.to_der(rsa_key)

    case PkiCaEngine.KeyActivation.dev_activate(issuer_key_id, rsa_der) do
      {:ok, :dev_activated} ->
        IO.puts("\n✓ Key #{issuer_key_id} activated for dev!")
        IO.puts("  Original algorithm: #{algo}")
        IO.puts("  Dev key: RSA 2048 (signing will use RSA regardless)")
        IO.puts("  WARNING: Certificates signed with this dev key won't chain to the real CA.\n")

      {:error, reason} ->
        IO.puts("✗ Activation failed: #{inspect(reason)}")
    end
end
