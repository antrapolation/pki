defmodule KeystoreTest do
  alias ExCcrypto.Keystore
  use ExUnit.Case

  test "keystore functions" do
    eres = Keystore.to_keypairstore("keypair", "cert", ["is1", "is2"], "p@ssw0rd")
    IO.inspect(eres)
    assert {:ok, eks} = eres

    dres = Keystore.load_keystore(eks, "p@ssw0rd")
    IO.inspect(dres)
    assert {:ok, ks} = dres
    assert ks.keypair == "keypair"
    assert ks.cert == "cert"
    assert ks.cert_chain == ["is1", "is2"]

    edres = Keystore.load_keystore(eks, "wrong-pass")
    IO.inspect(edres)
    assert {:error, :password_incorrect} = edres

    eres2 = Keystore.to_raw_keypairstore("keypair", "public_key", "p@ssw0rd2")
    IO.inspect(eres2)
    assert {:ok, eks2} = eres2

    dres2 = Keystore.load_keystore(eks2, "p@ssw0rd2")
    IO.inspect(dres2)
    assert {:ok, ks2} = dres2
    assert ks2.keypair == "keypair"
    assert ks2.public_key == "public_key"

    eres3 = Keystore.to_keypairstore("keypair", "cert", ["is1", "is2"], nil)
    IO.inspect(eres3)
    assert {:ok, eks3} = eres3

    dres3 = Keystore.load_keystore(eks3)
    IO.inspect(dres3)
    assert {:ok, ks3} = dres3
    assert ks3.keypair == "keypair"
    assert ks3.cert == "cert"
    assert ks3.cert_chain == ["is1", "is2"]

    eres4 = Keystore.to_raw_keypairstore("keypair", "public_key", nil)
    IO.inspect(eres4)
    assert {:ok, eks4} = eres4

    dres4 = Keystore.load_keystore(eks4)
    IO.inspect(dres4)
    assert {:ok, ks4} = dres4
    assert ks4.keypair == "keypair"
    assert ks4.public_key == "public_key"
  end
end
