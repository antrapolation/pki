defmodule PkiValidation.Ocsp.DerResponderTest do
  use ExUnit.Case, async: false

  alias PkiMnesia.TestHelper
  alias PkiCaEngine.KeyActivation
  alias PkiValidation.Ocsp.DerResponder

  setup do
    dir = TestHelper.setup_mnesia()
    on_exit(fn -> TestHelper.teardown_mnesia(dir) end)
    :ok
  end

  describe "nonce echoing on error responses" do
    test "unauthorized response (nil issuer_key_id) echoes request nonce" do
      nonce = :crypto.strong_rand_bytes(16)
      request = %{cert_ids: [], nonce: nonce}

      {:ok, der} = DerResponder.respond(request, issuer_key_id: nil)

      assert :binary.match(der, nonce) != :nomatch,
             "Expected nonce to appear in unauthorized response DER"
    end

    test "try_later response echoes request nonce" do
      nonce = :crypto.strong_rand_bytes(16)
      key_id = "test-key-#{System.unique_integer()}"
      request = %{cert_ids: [], nonce: nonce}

      ka_name = :"test_ka_nonce_#{System.unique_integer()}"
      {:ok, ka} = KeyActivation.start_link(name: ka_name)
      on_exit(fn -> if Process.alive?(ka), do: GenServer.stop(ka) end)

      # No key registered in KeyActivation → lease_status returns %{active: false} → :try_later
      {:ok, der} =
        DerResponder.respond(request,
          issuer_key_id: key_id,
          activation_server: ka_name
        )

      assert :binary.match(der, nonce) != :nomatch,
             "Expected nonce to appear in try_later response DER"
    end
  end
end
