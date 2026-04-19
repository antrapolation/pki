defmodule PkiPlatformEngine.PoolConfigTest do
  @moduledoc """
  Validates that all runtime pool size configurations have sensible defaults.
  Catches regressions where pool sizes accidentally revert to undersized values.

  These tests don't need a database — they verify config/runtime.exs defaults
  by parsing the source files directly.
  """
  use ExUnit.Case

  @minimum_pools %{
    # {env_var, minimum_default} — the default value in the code must be >= minimum
    "POOL_SIZE" => 10,
    "AUDIT_POOL_SIZE" => 5,
    "PLATFORM_POOL_SIZE" => 5,
    "TENANT_POOL_SIZE" => 5,
    "VALIDATION_POOL_SIZE" => 20
  }

  @runtime_configs [
    "pki_ca_engine/config/runtime.exs",
    "pki_ra_engine/config/runtime.exs",
    "pki_tenant/config/runtime.exs",
    "pki_tenant_web/config/runtime.exs",
    "pki_platform_portal/config/runtime.exs",
    "pki_validation/config/runtime.exs"
  ]

  @src_root Path.expand("../../../", __DIR__)

  test "no runtime.exs has a hardcoded pool_size below minimum" do
    violations =
      for config_path <- @runtime_configs,
          full_path = Path.join(@src_root, config_path),
          File.exists?(full_path),
          line <- File.read!(full_path) |> String.split("\n"),
          # Match hardcoded pool_size: N (not env-var driven)
          match = Regex.run(~r/pool_size:\s*(\d+)/, line),
          match != nil do
        [_, size_str] = match
        size = String.to_integer(size_str)

        if size < 3 do
          {config_path, size, String.trim(line)}
        end
      end
      |> Enum.reject(&is_nil/1)

    assert violations == [],
           """
           Found hardcoded pool_size values below minimum (3) in runtime configs.
           These should use env vars with proper defaults:

           #{Enum.map_join(violations, "\n", fn {file, size, line} -> "  #{file}: pool_size: #{size} — #{line}" end)}
           """
  end

  test "TENANT_POOL_SIZE default in tenant_process.ex is at least #{@minimum_pools["TENANT_POOL_SIZE"]}" do
    tenant_process_path =
      Path.join(@src_root, "pki_platform_engine/lib/pki_platform_engine/tenant_process.ex")

    content = File.read!(tenant_process_path)

    case Regex.run(~r/TENANT_POOL_SIZE["\s,]+["'](\d+)["']/, content) do
      [_, default_str] ->
        default = String.to_integer(default_str)
        minimum = @minimum_pools["TENANT_POOL_SIZE"]

        assert default >= minimum,
               "TENANT_POOL_SIZE default is #{default}, expected at least #{minimum}"

      nil ->
        flunk("Could not find TENANT_POOL_SIZE default in tenant_process.ex")
    end
  end

  test "all pool_size values in runtime configs use env vars" do
    # Verify pool sizes are configurable, not hardcoded
    hardcoded =
      for config_path <- @runtime_configs,
          full_path = Path.join(@src_root, config_path),
          File.exists?(full_path) do
        content = File.read!(full_path)
        lines = String.split(content, "\n")

        for {line, line_num} <- Enum.with_index(lines, 1),
            String.contains?(line, "pool_size:"),
            # Hardcoded if it's just `pool_size: N` without System.get_env
            Regex.match?(~r/pool_size:\s*\d+\s*[,\n]?$/, String.trim(line)),
            # Ignore test/dev configs and comments
            not String.starts_with?(String.trim(line), "#") do
          {config_path, line_num, String.trim(line)}
        end
      end
      |> List.flatten()

    assert hardcoded == [],
           """
           Found hardcoded pool_size values in runtime configs.
           All pool sizes should be configurable via environment variables:

           #{Enum.map_join(hardcoded, "\n", fn {file, line, code} -> "  #{file}:#{line} — #{code}" end)}
           """
  end
end
