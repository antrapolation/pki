defmodule PkiValidation.CrlPublisherTest do
  use ExUnit.Case, async: false

  alias PkiMnesia.{TestHelper, Repo}
  alias PkiMnesia.Structs.{CertificateStatus, IssuerKey}
  alias PkiValidation.CrlPublisher

  setup do
    dir = TestHelper.setup_mnesia()
    {:ok, pid} = CrlPublisher.start_link(name: :test_crl, interval: :timer.hours(24))
    on_exit(fn ->
      if Process.alive?(pid), do: GenServer.stop(pid)
      TestHelper.teardown_mnesia(dir)
    end)
    %{crl: :test_crl}
  end

  test "get_current_crls returns empty map initially (no issuer keys)", %{crl: crl} do
    Process.sleep(200)
    {:ok, crls} = CrlPublisher.get_current_crls(crl)
    assert crls == %{}
  end

  test "regenerate returns per-issuer CRL map", %{crl: crl} do
    key_id = "key-regen-#{System.unique_integer()}"
    key = IssuerKey.new(%{
      id: key_id, ca_instance_id: "ca-1", key_alias: "regen-key",
      algorithm: "ECC_P256", status: "active", crl_strategy: "per_interval"
    })
    {:ok, _} = Repo.insert(key)

    {:ok, crls} = CrlPublisher.regenerate(crl)
    assert Map.has_key?(crls, key_id)
    assert crls[key_id].type == "X509CRL"
    assert crls[key_id].total_revoked == 0
  end

  test "regenerate scopes revoked certs per issuer", %{crl: crl} do
    now = DateTime.utc_now() |> DateTime.truncate(:second)
    key_a = "key-a-#{System.unique_integer()}"
    key_b = "key-b-#{System.unique_integer()}"

    for {key_id, alias_name} <- [{key_a, "key-a"}, {key_b, "key-b"}] do
      key = IssuerKey.new(%{
        id: key_id, ca_instance_id: "ca-1", key_alias: alias_name,
        algorithm: "ECC_P256", status: "active", crl_strategy: "per_interval"
      })
      {:ok, _} = Repo.insert(key)
    end

    {:ok, _} = Repo.insert(CertificateStatus.new(%{
      serial_number: "revoked-a", issuer_key_id: key_a,
      status: "revoked", revoked_at: now, revocation_reason: "keyCompromise"
    }))
    {:ok, _} = Repo.insert(CertificateStatus.new(%{
      serial_number: "revoked-b", issuer_key_id: key_b,
      status: "revoked", revoked_at: now, revocation_reason: "cessationOfOperation"
    }))

    {:ok, crls} = CrlPublisher.regenerate(crl)

    assert crls[key_a].total_revoked == 1
    assert Enum.any?(crls[key_a].revoked_certificates, &(&1.serial_number == "revoked-a"))
    refute Enum.any?(crls[key_a].revoked_certificates, &(&1.serial_number == "revoked-b"))

    assert crls[key_b].total_revoked == 1
    assert Enum.any?(crls[key_b].revoked_certificates, &(&1.serial_number == "revoked-b"))
    refute Enum.any?(crls[key_b].revoked_certificates, &(&1.serial_number == "revoked-a"))
  end

  test "inactive issuer key is skipped in CRL generation", %{crl: crl} do
    key_id = "key-inactive-#{System.unique_integer()}"
    key = IssuerKey.new(%{
      id: key_id, ca_instance_id: "ca-1", key_alias: "inactive-key",
      algorithm: "ECC_P256", status: "suspended", crl_strategy: "per_interval"
    })
    {:ok, _} = Repo.insert(key)

    {:ok, crls} = CrlPublisher.regenerate(crl)
    refute Map.has_key?(crls, key_id)
  end

  test "status/1 returns generation_error false and issuer_count after successful generation", %{crl: crl} do
    Process.sleep(200)
    s = CrlPublisher.status(crl)
    assert is_map(s)
    assert Map.has_key?(s, :generation_error)
    assert Map.has_key?(s, :issuer_count)
    assert s.generation_error == false
    assert s.issuer_count == 0
  end

  test "status/1 reflects issuer count after keys are present", %{crl: crl} do
    key_id = "key-status-#{System.unique_integer()}"
    key = IssuerKey.new(%{
      id: key_id, ca_instance_id: "ca-1", key_alias: "status-key",
      algorithm: "ECC_P256", status: "active", crl_strategy: "per_interval"
    })
    {:ok, _} = Repo.insert(key)
    {:ok, _} = CrlPublisher.regenerate(crl)

    s = CrlPublisher.status(crl)
    assert s.issuer_count == 1
    assert s.generation_error == false
  end

  test "signed_crl/2 returns error for non-active issuer key" do
    key_id = "key-suspended-#{System.unique_integer()}"
    key = IssuerKey.new(%{
      id: key_id, ca_instance_id: "ca-1", key_alias: "suspended-key",
      algorithm: "ECC_P256", status: "suspended", crl_strategy: "per_interval"
    })
    {:ok, _} = Repo.insert(key)

    assert {:error, :issuer_key_not_active} = CrlPublisher.signed_crl(key_id)
  end

  test "signed_crl/2 returns error for unknown issuer key" do
    assert {:error, :issuer_key_not_found} = CrlPublisher.signed_crl("nonexistent-key-id")
  end
end
