defmodule PkiRaEngine.ApiKeyManagementTest do
  use PkiRaEngine.DataCase, async: true

  alias PkiRaEngine.ApiKeyManagement
  alias PkiRaEngine.UserManagement
  alias PkiRaEngine.Schema.RaApiKey

  defp create_user! do
    {:ok, user} =
      UserManagement.create_user(nil, %{
        display_name: "API Key User",
        role: "ra_admin"
      })

    user
  end

  describe "create_api_key/1" do
    test "creates an API key and returns raw key" do
      user = create_user!()

      assert {:ok, %{raw_key: raw_key, api_key: %RaApiKey{} = api_key}} =
               ApiKeyManagement.create_api_key(nil, %{
                 ra_user_id: user.id,
                 label: "test key"
               })

      assert is_binary(raw_key)
      assert byte_size(Base.decode64!(raw_key)) == 32
      assert api_key.status == "active"
      assert api_key.label == "test key"
      assert api_key.ra_user_id == user.id
      assert api_key.hashed_key != nil
      # The stored hash should NOT be the raw key
      assert api_key.hashed_key != raw_key
    end

    test "creates an API key with optional expiry and rate_limit" do
      user = create_user!()
      expiry = DateTime.add(DateTime.utc_now(), 3600, :second)

      assert {:ok, %{api_key: api_key}} =
               ApiKeyManagement.create_api_key(nil, %{
                 ra_user_id: user.id,
                 label: "expiring key",
                 expiry: expiry,
                 rate_limit: 100
               })

      assert api_key.rate_limit == 100
      assert api_key.expiry != nil
    end

    test "fails without ra_user_id" do
      assert {:error, _changeset} =
               ApiKeyManagement.create_api_key(nil, %{label: "orphan key"})
    end
  end

  describe "verify_key/1" do
    test "verifies a valid active key" do
      user = create_user!()

      {:ok, %{raw_key: raw_key, api_key: original}} =
        ApiKeyManagement.create_api_key(nil, %{ra_user_id: user.id, label: "verify test"})

      assert {:ok, verified} = ApiKeyManagement.verify_key(nil,raw_key)
      assert verified.id == original.id
    end

    test "returns error for unknown key" do
      fake_key = Base.encode64(:crypto.strong_rand_bytes(32))
      assert {:error, :invalid_key} = ApiKeyManagement.verify_key(nil,fake_key)
    end

    test "returns error for expired key" do
      user = create_user!()
      past = DateTime.add(DateTime.utc_now(), -3600, :second)

      {:ok, %{raw_key: raw_key}} =
        ApiKeyManagement.create_api_key(nil, %{
          ra_user_id: user.id,
          label: "expired key",
          expiry: past
        })

      assert {:error, :expired} = ApiKeyManagement.verify_key(nil,raw_key)
    end

    test "key with expiry 1 microsecond in the past returns expired" do
      user = create_user!()
      past_expiry = DateTime.add(DateTime.utc_now(), -1, :microsecond)

      {:ok, %{raw_key: raw_key}} =
        ApiKeyManagement.create_api_key(nil, %{
          ra_user_id: user.id,
          label: "boundary expired key",
          expiry: past_expiry
        })

      assert {:error, :expired} = ApiKeyManagement.verify_key(nil,raw_key)
    end

    test "returns error for revoked key" do
      user = create_user!()

      {:ok, %{raw_key: raw_key, api_key: api_key}} =
        ApiKeyManagement.create_api_key(nil, %{ra_user_id: user.id, label: "revoked key"})

      {:ok, _revoked} = ApiKeyManagement.revoke_key(nil,api_key.id)

      assert {:error, :invalid_key} = ApiKeyManagement.verify_key(nil,raw_key)
    end
  end

  describe "list_keys/1" do
    test "lists keys for a user" do
      user = create_user!()

      {:ok, _} = ApiKeyManagement.create_api_key(nil, %{ra_user_id: user.id, label: "key1"})
      {:ok, _} = ApiKeyManagement.create_api_key(nil, %{ra_user_id: user.id, label: "key2"})

      keys = ApiKeyManagement.list_keys(nil,user.id)
      assert length(keys) == 2
    end

    test "does not return keys from other users" do
      user1 = create_user!()
      user2 = create_user!()

      {:ok, _} = ApiKeyManagement.create_api_key(nil, %{ra_user_id: user1.id, label: "u1 key"})
      {:ok, _} = ApiKeyManagement.create_api_key(nil, %{ra_user_id: user2.id, label: "u2 key"})

      keys = ApiKeyManagement.list_keys(nil,user1.id)
      assert length(keys) == 1
      assert hd(keys).label == "u1 key"
    end
  end

  describe "revoke_key/1" do
    test "revokes an active key" do
      user = create_user!()

      {:ok, %{api_key: api_key}} =
        ApiKeyManagement.create_api_key(nil, %{ra_user_id: user.id, label: "to revoke"})

      assert {:ok, revoked} = ApiKeyManagement.revoke_key(nil,api_key.id)
      assert revoked.status == "revoked"
      assert revoked.revoked_at != nil
    end

    test "returns error for non-existent key" do
      assert {:error, :not_found} = ApiKeyManagement.revoke_key(nil,Uniq.UUID.uuid7())
    end
  end
end
