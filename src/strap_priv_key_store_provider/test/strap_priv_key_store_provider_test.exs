defmodule StrapPrivKeyStoreProviderTest do
  use ExUnit.Case
  doctest StrapPrivKeyStoreProvider

  test "greets the world" do
    assert StrapPrivKeyStoreProvider.hello() == :world
  end
end
