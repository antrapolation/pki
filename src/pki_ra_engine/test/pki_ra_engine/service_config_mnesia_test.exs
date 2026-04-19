defmodule PkiRaEngine.ServiceConfigMnesiaTest do
  @moduledoc "Mnesia-era tests for PkiRaEngine.ServiceConfig (tenant_id dropped)."
  use ExUnit.Case, async: false

  alias PkiMnesia.TestHelper
  alias PkiRaEngine.ServiceConfig, as: SvcConfig

  setup do
    dir = TestHelper.setup_mnesia()
    on_exit(fn -> TestHelper.teardown_mnesia(dir) end)
    :ok
  end

  describe "configure_service/1" do
    test "creates a new service config" do
      assert {:ok, config} =
               SvcConfig.configure_service(%{
                 service_type: "csr_web",
                 url: "https://ra.example.com",
                 port: 8080
               })

      assert config.service_type == "csr_web"
      assert config.port == 8080
      assert config.url == "https://ra.example.com"
      assert config.status == "active"
    end

    test "upserts existing service config by service_type" do
      {:ok, original} =
        SvcConfig.configure_service(%{service_type: "csr_web", url: "u", port: 8080})

      {:ok, updated} =
        SvcConfig.configure_service(%{service_type: "csr_web", url: "u", port: 9090})

      assert updated.id == original.id
      assert updated.port == 9090
    end

    test "rejects invalid service_type" do
      assert {:error, :invalid_service_type} =
               SvcConfig.configure_service(%{service_type: "ftp", url: "x", port: 1})
    end

    test "rejects missing service_type" do
      assert {:error, :service_type_required} =
               SvcConfig.configure_service(%{port: 1})
    end
  end

  describe "get_service_config/1" do
    test "returns the config" do
      {:ok, _} = SvcConfig.configure_service(%{service_type: "ocsp", url: "x", port: 8080})
      assert {:ok, config} = SvcConfig.get_service_config("ocsp")
      assert config.service_type == "ocsp"
    end

    test "not_found for unknown service_type" do
      assert {:error, :not_found} = SvcConfig.get_service_config("nope")
    end
  end

  describe "list_service_configs/0" do
    test "lists every configured service" do
      {:ok, _} = SvcConfig.configure_service(%{service_type: "csr_web", url: "a", port: 80})
      {:ok, _} = SvcConfig.configure_service(%{service_type: "crl", url: "b", port: 80})
      assert length(SvcConfig.list_service_configs()) == 2
    end

    test "empty when nothing configured" do
      assert SvcConfig.list_service_configs() == []
    end
  end

  describe "update_service_config/2" do
    test "updates by service_type" do
      {:ok, _} = SvcConfig.configure_service(%{service_type: "ocsp", url: "x", port: 8080})
      assert {:ok, updated} = SvcConfig.update_service_config("ocsp", %{port: 9999})
      assert updated.port == 9999
    end

    test "not_found for unknown service_type" do
      assert {:error, :not_found} = SvcConfig.update_service_config("nope", %{port: 1})
    end
  end

  describe "delete_service_config/1" do
    test "removes the config" do
      {:ok, _} = SvcConfig.configure_service(%{service_type: "ocsp", url: "x", port: 8080})
      assert {:ok, _id} = SvcConfig.delete_service_config("ocsp")
      assert {:error, :not_found} = SvcConfig.get_service_config("ocsp")
    end

    test "not_found for unknown service_type" do
      assert {:error, :not_found} = SvcConfig.delete_service_config("nope")
    end
  end
end
