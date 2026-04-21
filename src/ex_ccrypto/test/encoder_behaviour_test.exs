defmodule EncoderBehaviourTest do
  alias ExCcrypto.Cipher.CipherEngine.CipherContextEncoder
  use ExUnit.Case

  test "Test behaviour behaviour" do
    st = %{key: "key", key2: "key2"}

    # :bin is delegated to SimpleCipherModEncoder
    {:ok, stnat} = CipherContextEncoder.encode(st, :bin)
    assert(not is_nil(stnat))

    {:ok, rst} = CipherContextEncoder.decode(stnat)
    assert(rst == st)

    stnat2 = CipherContextEncoder.encode!(st, :bin)
    rst2 = CipherContextEncoder.decode!(stnat2)
    assert(rst2 == st)
  end
end
