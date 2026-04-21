defmodule StrapCiphagileTest do
  use ExUnit.Case
  doctest StrapCiphagile

  test "returns error for invalid magic tag" do
    assert {:error, :invalid_format_or_magic_tag} = StrapCiphagile.decode(<<0x00, 0x00, 0x00>>)
  end
end
