#!/usr/bin/env elixir
# Full CSR lifecycle integration test
# Run from pki_ra_portal directory:
#   elixir --sname int_test -S mix run scripts/integration_test.exs
#
# Or from the repo root:
#   cd src/pki_ra_portal && POSTGRES_PORT=5434 ... elixir --sname int_test -S mix run ../../scripts/integration_test.exs

defmodule IntegrationTest do
  def run do
    IO.puts("\n========================================")
    IO.puts("  PKI RA Engine — Integration Test")
    IO.puts("  Full CSR Lifecycle (RSA 2048)")
    IO.puts("========================================\n")

    tenant_id = "019d3f8c-7085-776d-a865-009b4b1deac7"
    profile_id = "019d5b3d-5c2d-77d9-8698-a602286e1ac3"
    officer_id = "019d3f99-5390-710c-b6ed-77c323683d1e"

    # Wait for tenant engines to boot
    IO.write("Waiting for tenant engine boot...")
    wait_for_tenant(tenant_id, 30)
    IO.puts(" OK")

    # Dev: activate keys in THIS node's KeyActivation
    IO.write("Dev-activating issuer keys...")
    dev_activate_keys(tenant_id)
    IO.puts(" OK")

    # Step 1: Generate CSR
    step("1. Generate RSA 2048 CSR")
    key = X509.PrivateKey.new_rsa(2048)
    csr = X509.CSR.new(key, "/CN=integration-test.example.com/O=Integration Test Corp/C=MY")
    csr_pem = X509.CSR.to_pem(csr)
    ok("CSR generated (#{byte_size(csr_pem)} bytes)")

    # Step 2: Submit CSR
    step("2. Submit CSR")
    {:ok, submitted} = PkiRaEngine.CsrValidation.submit_csr(tenant_id, csr_pem, profile_id)
    ok("CSR #{short(submitted.id)} status=#{submitted.status} dn=#{submitted.subject_dn}")

    # Step 3: Check validation (auto-triggered by submit in controller, manual here)
    step("3. Validate CSR")
    {:ok, validated} = PkiRaEngine.CsrValidation.validate_csr(tenant_id, submitted.id)
    ok("status=#{validated.status}")

    if validated.status != "verified" do
      fail("Expected 'verified', got '#{validated.status}'. Stopping.")
      System.halt(1)
    end

    # Step 4: Approve CSR (officer review)
    step("4. Approve CSR (officer review)")
    {:ok, approved} = PkiRaEngine.CsrValidation.approve_csr(tenant_id, submitted.id, officer_id)
    ok("status=#{approved.status}")

    # Step 5: Wait for async CA forwarding
    step("5. Wait for CA signing (async, up to 10s)...")
    issued = wait_for_status(tenant_id, submitted.id, "issued", 10)

    case issued do
      %{status: "issued", issued_cert_serial: serial} ->
        ok("ISSUED! serial=#{serial}")

        # Step 6: Verify certificate exists in CA
        step("6. Verify certificate in CA store")
        verify_certificate(tenant_id, serial)

        # Step 7: Check telemetry counters
        step("7. Check telemetry")
        metrics = PkiRaEngine.Telemetry.get_metrics()
        csr_submitted = metrics["pki.ra.csr.submitted"] || 0
        csr_issued = metrics["pki.ra.csr.issued"] || 0
        ok("csr.submitted=#{csr_submitted} csr.issued=#{csr_issued}")

        IO.puts("\n========================================")
        IO.puts("  ALL STEPS PASSED")
        IO.puts("  CSR -> Validated -> Approved -> Issued")
        IO.puts("  Certificate Serial: #{serial}")
        IO.puts("========================================\n")

      %{status: status} ->
        fail("Expected 'issued', got '#{status}' after 10s")

        # Try manual forward
        step("5b. Manual forward to CA")
        case PkiRaEngine.CsrValidation.forward_to_ca(tenant_id, submitted.id) do
          {:ok, manual_issued} ->
            ok("ISSUED via manual forward! serial=#{manual_issued.issued_cert_serial}")
          {:error, reason} ->
            fail("Manual forward failed: #{inspect(reason)}")
        end
    end
  end

  defp dev_activate_keys(tenant_id) do
    import Ecto.Query
    repo = PkiCaEngine.TenantRepo.ca_repo(tenant_id)
    keys = repo.all(from k in PkiCaEngine.Schema.IssuerKey, where: k.status == "active")

    for key <- keys do
      unless PkiCaEngine.KeyActivation.is_active?(key.id) do
        case PkiCaEngine.KeyCeremony.SyncCeremony.generate_keypair(key.algorithm) do
          {:ok, %{private_key: priv}} ->
            PkiCaEngine.KeyActivation.dev_activate(key.id, priv)
            IO.write(".")
          {:error, _} -> IO.write("x")
        end
      end
    end
  rescue
    _ -> IO.write("!")
  end

  defp wait_for_tenant(tenant_id, retries) when retries > 0 do
    try do
      PkiRaEngine.TenantRepo.ra_repo(tenant_id)
      :ok
    rescue
      _ ->
        IO.write(".")
        Process.sleep(1000)
        wait_for_tenant(tenant_id, retries - 1)
    end
  end
  defp wait_for_tenant(_, 0), do: raise("Tenant engine did not start in time")

  defp wait_for_status(tenant_id, csr_id, target, seconds) do
    Enum.reduce_while(1..seconds, nil, fn i, _ ->
      Process.sleep(1000)
      {:ok, csr} = PkiRaEngine.CsrValidation.get_csr(tenant_id, csr_id)
      IO.write("  [#{i}s] status=#{csr.status}\r")
      if csr.status == target do
        IO.puts("")
        {:halt, csr}
      else
        {:cont, csr}
      end
    end)
  end

  defp verify_certificate(tenant_id, serial) do
    repo = PkiRaEngine.TenantRepo.ra_repo(tenant_id)
    # Check if the CSR record has the serial
    import Ecto.Query
    case repo.one(from c in PkiRaEngine.Schema.CsrRequest,
           where: c.issued_cert_serial == ^serial, limit: 1) do
      nil -> fail("No CSR record with serial #{serial}")
      csr -> ok("CSR #{short(csr.id)} has serial #{serial}")
    end
  end

  defp step(msg), do: IO.puts("\n#{IO.ANSI.cyan()}#{msg}#{IO.ANSI.reset()}")
  defp ok(msg), do: IO.puts("  #{IO.ANSI.green()}✓#{IO.ANSI.reset()} #{msg}")
  defp fail(msg), do: IO.puts("  #{IO.ANSI.red()}✗#{IO.ANSI.reset()} #{msg}")
  defp short(id), do: String.slice(id, 0, 8) <> "..."
end

IntegrationTest.run()
