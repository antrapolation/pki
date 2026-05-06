defmodule PkiPlatformEngine.SystemHealthTest do
  use ExUnit.Case, async: true

  alias PkiPlatformEngine.{SystemHealth, TenantMetrics}

  describe "SystemHealth.services/0" do
    test "returns a list of service definitions" do
      services = SystemHealth.services()
      assert is_list(services)
      assert length(services) > 0
    end

    test "each service has name, port, and check fields" do
      for service <- SystemHealth.services() do
        assert Map.has_key?(service, :name)
        assert Map.has_key?(service, :port)
        assert Map.has_key?(service, :check)
      end
    end

    test "Platform Portal service uses :self check" do
      platform = Enum.find(SystemHealth.services(), &(&1.name == "Platform Portal"))
      assert platform != nil
      assert platform.check == :self
    end
  end

  describe "SystemHealth.check_service/1 — :self" do
    test "returns healthy status synchronously" do
      result = SystemHealth.check_service(%{check: :self})
      assert result.status == :healthy
      assert result.response_time_ms == 0
      assert %DateTime{} = result.checked_at
    end
  end

  # ---------------------------------------------------------------------------
  # TenantMetrics.format_bytes/1
  # ---------------------------------------------------------------------------

  describe "TenantMetrics.format_bytes/1" do
    test "formats bytes under 1 KB" do
      assert TenantMetrics.format_bytes(512) == "512 B"
      assert TenantMetrics.format_bytes(0) == "0 B"
      assert TenantMetrics.format_bytes(1023) == "1023 B"
    end

    test "formats bytes in KB range" do
      assert TenantMetrics.format_bytes(1024) == "1.0 KB"
      assert TenantMetrics.format_bytes(2048) == "2.0 KB"
    end

    test "formats bytes in MB range" do
      assert TenantMetrics.format_bytes(1_048_576) == "1.0 MB"
      assert TenantMetrics.format_bytes(5_242_880) == "5.0 MB"
    end

    test "formats bytes in GB range" do
      assert TenantMetrics.format_bytes(1_073_741_824) == "1.0 GB"
      assert TenantMetrics.format_bytes(2_147_483_648) == "2.0 GB"
    end
  end
end
