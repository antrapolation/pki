defmodule ExCcryptoTest do
  alias ExCcrypto.Asymkey
  alias ExCcrypto.Asymkey.Ecc.EccKeypair
  alias ExCcrypto.Asymkey.KeyEncoding
  use ExUnit.Case
  doctest ExCcrypto

  test "standard ecdh" do
    {:ok, %{private_key: sender_privkey, public_key: sender_pubkey}} =
      %EccKeypair{}
      |> Asymkey.generate()

    {:ok, %{private_key: recp_privkey, public_key: recp_pubkey}} =
      %EccKeypair{}
      |> Asymkey.generate()

    {{:ECPoint, _} = senderPub, {:namedCurve, _}} = KeyEncoding.to_native!(sender_pubkey)
    {{:ECPoint, _} = recpPub, {:namedCurve, _}} = KeyEncoding.to_native!(recp_pubkey)

    ss1 =
      :public_key.compute_key(
        recpPub,
        KeyEncoding.to_native!(sender_privkey)
      )

    IO.inspect(ss1)

    ss2 =
      :public_key.compute_key(
        senderPub,
        KeyEncoding.to_native!(recp_privkey)
      )

    IO.inspect(ss2)
    assert(ss1 == ss2)
  end
end
