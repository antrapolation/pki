defmodule PkiRaEngine.RaInstanceTest do
  use PkiRaEngine.DataCase, async: true

  alias PkiRaEngine.Schema.RaInstance

  @valid_attrs %{name: "JPJ Registration Authority", created_by: "admin"}

  describe "RaInstance.changeset/2" do
    test "valid changeset" do
      changeset = RaInstance.changeset(%RaInstance{}, @valid_attrs)
      assert changeset.valid?
    end

    test "defaults status to initialized" do
      changeset = RaInstance.changeset(%RaInstance{}, @valid_attrs)
      assert Ecto.Changeset.get_field(changeset, :status) == "initialized"
    end

    test "generates UUIDv7 id" do
      changeset = RaInstance.changeset(%RaInstance{}, @valid_attrs)
      assert Ecto.Changeset.get_field(changeset, :id) != nil
    end

    test "rejects missing name" do
      changeset = RaInstance.changeset(%RaInstance{}, %{created_by: "admin"})
      refute changeset.valid?
      assert errors_on(changeset)[:name]
    end

    test "rejects invalid status" do
      changeset = RaInstance.changeset(%RaInstance{}, Map.put(@valid_attrs, :status, "deleted"))
      refute changeset.valid?
      assert errors_on(changeset)[:status]
    end
  end
end
