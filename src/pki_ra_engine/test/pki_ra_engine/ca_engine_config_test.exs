defmodule PkiRaEngine.CaEngineConfigTest do
  use ExUnit.Case, async: true

  alias PkiRaEngine.CaEngineConfig

  setup do
    # Reset state before each test
    CaEngineConfig.clear()
    :ok
  end

  describe "set/2 and get/1" do
    test "stores and retrieves a value" do
      :ok = CaEngineConfig.set(:ca_node, :"ca@localhost")
      assert {:ok, :"ca@localhost"} = CaEngineConfig.get(:ca_node)
    end

    test "returns error for missing key" do
      assert {:error, :not_found} = CaEngineConfig.get(:nonexistent)
    end

    test "overwrites existing value" do
      :ok = CaEngineConfig.set(:ca_node, :"ca@host1")
      :ok = CaEngineConfig.set(:ca_node, :"ca@host2")
      assert {:ok, :"ca@host2"} = CaEngineConfig.get(:ca_node)
    end
  end

  describe "get_all/0" do
    test "returns all stored config" do
      :ok = CaEngineConfig.set(:ca_node, :"ca@localhost")
      :ok = CaEngineConfig.set(:ca_port, 4369)
      all = CaEngineConfig.get_all()
      assert all[:ca_node] == :"ca@localhost"
      assert all[:ca_port] == 4369
    end

    test "returns empty map when no config set" do
      assert CaEngineConfig.get_all() == %{}
    end
  end

  describe "delete/1" do
    test "removes a key" do
      :ok = CaEngineConfig.set(:ca_node, :"ca@localhost")
      :ok = CaEngineConfig.delete(:ca_node)
      assert {:error, :not_found} = CaEngineConfig.get(:ca_node)
    end

    test "no-op for missing key" do
      assert :ok = CaEngineConfig.delete(:nonexistent)
    end
  end

  describe "clear/0" do
    test "removes all config" do
      :ok = CaEngineConfig.set(:ca_node, :"ca@localhost")
      :ok = CaEngineConfig.set(:ca_port, 4369)
      :ok = CaEngineConfig.clear()
      assert CaEngineConfig.get_all() == %{}
    end
  end
end
