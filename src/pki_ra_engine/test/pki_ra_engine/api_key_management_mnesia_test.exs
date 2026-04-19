defmodule PkiRaEngine.ApiKeyManagementMnesiaTest do
  use ExUnit.Case, async: false

  alias PkiMnesia.TestHelper
  alias PkiRaEngine.ApiKeyManagement

  setup do
    dir = TestHelper.setup_mnesia()
    on_exit(fn -> TestHelper.teardown_mnesia(dir) end)
    :ok
  end

  test "create_api_key returns key record and raw key" do
    {:ok, api_key, raw_key} = ApiKeyManagement.create_api_key(%{name: "Test Key"})
    assert api_key.name == "Test Key"
    assert api_key.status == "active"
    assert is_binary(raw_key)
    assert String.length(raw_key) > 0
    assert api_key.key_prefix == String.slice(raw_key, 0, 8)
  end

  test "authenticate with valid key succeeds" do
    {:ok, api_key, raw_key} = ApiKeyManagement.create_api_key(%{name: "Auth Key"})
    {:ok, found} = ApiKeyManagement.authenticate(raw_key)
    assert found.id == api_key.id
  end

  test "authenticate with invalid key fails" do
    assert {:error, :invalid_key} = ApiKeyManagement.authenticate("bogus-key-value")
  end

  test "authenticate with revoked key fails" do
    {:ok, api_key, raw_key} = ApiKeyManagement.create_api_key(%{name: "Revoke Me"})
    {:ok, _revoked} = ApiKeyManagement.revoke_api_key(api_key.id)
    assert {:error, :key_revoked} = ApiKeyManagement.authenticate(raw_key)
  end

  test "authenticate with expired key fails" do
    past = DateTime.utc_now() |> DateTime.add(-3600, :second) |> DateTime.truncate(:second)

    {:ok, _api_key, raw_key} =
      ApiKeyManagement.create_api_key(%{name: "Expired Key", expires_at: past})

    assert {:error, :key_expired} = ApiKeyManagement.authenticate(raw_key)
  end

  test "revoke_api_key sets status to revoked" do
    {:ok, api_key, _raw_key} = ApiKeyManagement.create_api_key(%{name: "To Revoke"})
    {:ok, revoked} = ApiKeyManagement.revoke_api_key(api_key.id)
    assert revoked.status == "revoked"
  end

  test "revoke_api_key returns error for non-existent id" do
    assert {:error, :not_found} = ApiKeyManagement.revoke_api_key("nonexistent")
  end

  test "list_api_keys returns all keys" do
    {:ok, _, _} = ApiKeyManagement.create_api_key(%{name: "Key A"})
    {:ok, _, _} = ApiKeyManagement.create_api_key(%{name: "Key B"})
    {:ok, keys} = ApiKeyManagement.list_api_keys()
    assert length(keys) == 2
  end

  test "list_api_keys filters by ra_instance_id" do
    {:ok, _, _} = ApiKeyManagement.create_api_key(%{name: "Key A", ra_instance_id: "ra-1"})
    {:ok, _, _} = ApiKeyManagement.create_api_key(%{name: "Key B", ra_instance_id: "ra-2"})
    {:ok, keys} = ApiKeyManagement.list_api_keys("ra-1")
    assert length(keys) == 1
    assert hd(keys).ra_instance_id == "ra-1"
  end
end
