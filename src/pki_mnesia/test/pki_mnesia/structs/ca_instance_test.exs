defmodule PkiMnesia.Structs.CaInstanceTest do
  use ExUnit.Case, async: false

  alias PkiMnesia.Structs.CaInstance

  test "new/0 creates a struct with defaults" do
    ca = CaInstance.new()
    assert ca.id != nil
    assert ca.is_root == false
    assert ca.is_offline == false
    assert ca.status == "active"
    assert ca.max_depth == 2
    assert ca.metadata == %{}
    assert %DateTime{} = ca.inserted_at
    assert %DateTime{} = ca.updated_at
  end

  test "new/1 accepts custom attributes" do
    ca = CaInstance.new(%{name: "My Root", is_root: true, max_depth: 3})
    assert ca.name == "My Root"
    assert ca.is_root == true
    assert ca.max_depth == 3
  end

  test "new/1 generates unique ids" do
    ca1 = CaInstance.new()
    ca2 = CaInstance.new()
    assert ca1.id != ca2.id
  end
end
