defmodule PkiValidation.CrlStrategyTest do
  use ExUnit.Case, async: false

  alias PkiMnesia.{TestHelper, Repo}
  alias PkiMnesia.Structs.{IssuerKey, PreSignedCrl}
  alias PkiValidation.CrlPublisher

  setup do
    dir = TestHelper.setup_mnesia()

    on_exit(fn ->
      TestHelper.teardown_mnesia(dir)
    end)

    :ok
  end

  describe "per_interval strategy" do
    test "returns {:error, :no_active_lease} when no active lease exists" do
      issuer_key = IssuerKey.new(%{
        ca_instance_id: "ca-1",
        algorithm: "RSA",
        key_alias: "test-key-per-interval",
        crl_strategy: "per_interval"
      })
      {:ok, _} = Repo.insert(issuer_key)

      # Start a KeyActivation server with no leases
      {:ok, ka_pid} = PkiCaEngine.KeyActivation.start_link(name: :test_ka_per_interval)

      on_exit(fn ->
        if Process.alive?(ka_pid), do: GenServer.stop(ka_pid)
      end)

      result = CrlPublisher.signed_crl(issuer_key.id,
        activation_server: :test_ka_per_interval
      )

      assert result == {:error, :no_active_lease}
    end
  end

  describe "pre_signed strategy" do
    test "returns crl_der when a valid PreSignedCrl exists for current time" do
      issuer_key = IssuerKey.new(%{
        ca_instance_id: "ca-2",
        algorithm: "RSA",
        key_alias: "test-key-pre-signed",
        crl_strategy: "pre_signed"
      })
      {:ok, _} = Repo.insert(issuer_key)

      now = DateTime.utc_now() |> DateTime.truncate(:second)
      valid_from = DateTime.add(now, -300, :second)
      valid_until = DateTime.add(now, 3600, :second)
      crl_der = :erlang.term_to_binary(%{type: "X509CRL", stub: true})

      pre_signed = PreSignedCrl.new(%{
        issuer_key_id: issuer_key.id,
        valid_from: valid_from,
        valid_until: valid_until,
        crl_der: crl_der
      })
      {:ok, _} = Repo.insert(pre_signed)

      result = CrlPublisher.signed_crl(issuer_key.id)

      assert result == {:ok, crl_der}
    end

    test "returns {:error, :no_valid_pre_signed_crl} when no valid record exists" do
      issuer_key = IssuerKey.new(%{
        ca_instance_id: "ca-3",
        algorithm: "RSA",
        key_alias: "test-key-pre-signed-empty",
        crl_strategy: "pre_signed"
      })
      {:ok, _} = Repo.insert(issuer_key)

      # Insert an expired pre-signed CRL (valid_until in the past)
      now = DateTime.utc_now() |> DateTime.truncate(:second)
      expired_from = DateTime.add(now, -7200, :second)
      expired_until = DateTime.add(now, -3600, :second)

      expired = PreSignedCrl.new(%{
        issuer_key_id: issuer_key.id,
        valid_from: expired_from,
        valid_until: expired_until,
        crl_der: <<1, 2, 3>>
      })
      {:ok, _} = Repo.insert(expired)

      result = CrlPublisher.signed_crl(issuer_key.id)

      assert result == {:error, :no_valid_pre_signed_crl}
    end
  end
end
