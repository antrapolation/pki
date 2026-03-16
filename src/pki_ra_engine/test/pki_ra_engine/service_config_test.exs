defmodule PkiRaEngine.ServiceConfigTest do
  use PkiRaEngine.DataCase, async: true

  alias PkiRaEngine.ServiceConfig, as: SvcConfig

  @valid_attrs %{
    service_type: "csr_web",
    port: 8080,
    url: "https://ra.example.com",
    rate_limit: 100,
    connection_security: "tls",
    ip_whitelist: %{"ips" => ["10.0.0.0/8"]},
    ip_blacklist: %{"ips" => []}
  }

  defp create_config!(attrs \\ %{}) do
    {:ok, config} = SvcConfig.configure_service(Map.merge(@valid_attrs, attrs))
    config
  end

  describe "configure_service/1" do
    test "creates a new service config" do
      assert {:ok, config} = SvcConfig.configure_service(@valid_attrs)
      assert config.service_type == "csr_web"
      assert config.port == 8080
      assert config.url == "https://ra.example.com"
    end

    test "upserts existing service config" do
      {:ok, original} = SvcConfig.configure_service(@valid_attrs)
      {:ok, updated} = SvcConfig.configure_service(%{@valid_attrs | port: 9090})
      assert updated.id == original.id
      assert updated.port == 9090
    end

    test "fails with invalid service_type" do
      assert {:error, changeset} = SvcConfig.configure_service(%{@valid_attrs | service_type: "ftp"})
      assert errors_on(changeset)[:service_type]
    end

    test "fails without service_type" do
      assert {:error, changeset} = SvcConfig.configure_service(%{port: 8080})
      assert errors_on(changeset)[:service_type]
    end

    test "configure ldap service" do
      {:ok, config} =
        SvcConfig.configure_service(%{service_type: "ldap", port: 389, url: "ldap://localhost:389"})

      assert config.service_type == "ldap"
      assert config.port == 389
    end

    test "configure ocsp service" do
      {:ok, config} =
        SvcConfig.configure_service(%{service_type: "ocsp", port: 8080, url: "http://localhost:8080/ocsp"})

      assert config.service_type == "ocsp"
      assert config.port == 8080
    end
  end

  describe "get_service_config/1" do
    test "returns config by service_type" do
      create_config!()
      assert {:ok, config} = SvcConfig.get_service_config("csr_web")
      assert config.service_type == "csr_web"
    end

    test "returns error for non-existent service_type" do
      assert {:error, :not_found} = SvcConfig.get_service_config("nonexistent")
    end
  end

  describe "list_service_configs/0" do
    test "lists all service configs" do
      create_config!(%{service_type: "csr_web"})
      create_config!(%{service_type: "crl"})

      configs = SvcConfig.list_service_configs()
      assert length(configs) == 2
    end

    test "returns empty list when none exist" do
      assert SvcConfig.list_service_configs() == []
    end
  end

  describe "update_service_config/2" do
    test "updates config fields" do
      config = create_config!()
      assert {:ok, updated} = SvcConfig.update_service_config(config.service_type, %{port: 9999})
      assert updated.port == 9999
    end

    test "returns error for non-existent service_type" do
      assert {:error, :not_found} = SvcConfig.update_service_config("nonexistent", %{port: 1})
    end
  end

  describe "delete_service_config/1" do
    test "deletes the config" do
      create_config!()
      assert {:ok, _deleted} = SvcConfig.delete_service_config("csr_web")
      assert {:error, :not_found} = SvcConfig.get_service_config("csr_web")
    end

    test "returns error for non-existent service_type" do
      assert {:error, :not_found} = SvcConfig.delete_service_config("nonexistent")
    end
  end
end
