defmodule PkiRaEngine.CertProfileConfigMnesiaTest do
  use ExUnit.Case, async: false

  alias PkiMnesia.TestHelper
  alias PkiRaEngine.CertProfileConfig

  setup do
    dir = TestHelper.setup_mnesia()
    on_exit(fn -> TestHelper.teardown_mnesia(dir) end)
    :ok
  end

  test "create and get a profile" do
    {:ok, profile} = CertProfileConfig.create_profile(%{name: "TLS Server", validity_days: 365})
    {:ok, fetched} = CertProfileConfig.get_profile(profile.id)
    assert fetched.name == "TLS Server"
    assert fetched.validity_days == 365
  end

  test "update a profile" do
    {:ok, profile} = CertProfileConfig.create_profile(%{name: "Before", validity_days: 90})
    {:ok, updated} = CertProfileConfig.update_profile(profile.id, %{name: "After", validity_days: 180})
    assert updated.name == "After"
    assert updated.validity_days == 180
  end

  test "delete a profile" do
    {:ok, profile} = CertProfileConfig.create_profile(%{name: "Delete Me"})
    assert {:ok, returned_id} = CertProfileConfig.delete_profile(profile.id)
    assert returned_id == profile.id
    assert {:error, :not_found} = CertProfileConfig.get_profile(profile.id)
  end

  test "list_profiles returns active profiles" do
    {:ok, _} = CertProfileConfig.create_profile(%{name: "A"})
    {:ok, _} = CertProfileConfig.create_profile(%{name: "B"})
    {:ok, profiles} = CertProfileConfig.list_profiles()
    assert length(profiles) == 2
  end

  test "list_profiles excludes archived profiles" do
    {:ok, p1} = CertProfileConfig.create_profile(%{name: "Active"})
    {:ok, _p2} = CertProfileConfig.create_profile(%{name: "Archived", status: "archived"})
    {:ok, profiles} = CertProfileConfig.list_profiles()
    assert length(profiles) == 1
    assert hd(profiles).id == p1.id
  end

  test "get_profile returns error for non-existent id" do
    assert {:error, :not_found} = CertProfileConfig.get_profile("nonexistent")
  end

  test "update_profile returns error for non-existent id" do
    assert {:error, :not_found} = CertProfileConfig.update_profile("nonexistent", %{name: "X"})
  end
end
