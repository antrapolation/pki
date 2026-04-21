defmodule DecoderSafetyTest do
  alias ExCcrypto.Cipher.CipherEngine.CipherContextEncoder
  alias ExCcrypto.Asymkey.AsymkeystoreLoader
  use ExUnit.Case

  test "cipher context decode rejects invalid term binary" do
    assert {:error, :invalid_encoding} = CipherContextEncoder.decode(<<1, 2, 3>>)
  end

  test "asym keystore loader rejects invalid term binary" do
    assert {:error, :invalid_keystore_format} =
             AsymkeystoreLoader.from_keystore(<<1, 2, 3>>, %{password: "irrelevant"})
  end
end
