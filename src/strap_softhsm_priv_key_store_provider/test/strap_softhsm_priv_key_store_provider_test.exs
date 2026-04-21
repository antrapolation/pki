defmodule StrapSofthsmPrivKeyStoreProviderTest do
  alias StrapPrivKeyStoreProvider.KeyGenerator
  alias StrapPrivKeyStoreProvider.Protocol.PrivateKeyOps
  alias StrapPrivKeyStoreProvider.Protocol.ProviderInfo
  alias StrapSofthsmPrivKeyStoreProvider.TestHelper
  use ExUnit.Case

  setup do
    # Initialize SoftHSM token for testing
    slot = 0
    pin = "1234"
    label = "test-token"

    {:ok, actual_slot} =
      case TestHelper.init_test_token(slot, label, pin) do
        {:ok, id} ->
          {:ok, id}

        {:error, :softhsm_util_not_found} ->
          IO.puts("Warning: softhsm2-util not found, tests might fail if not using local config")
          {:ok, slot}

        error ->
          IO.puts("Warning: Failed to init SoftHSM token: #{inspect(error)}")
          {:ok, slot}
      end

    # Start the SoftHSM provider process
    {:ok, pid} =
      StrapSofthsmPrivKeyStoreProvider.start_link(%{
        group: :softhsm_test,
        slot: actual_slot,
        token_label: label,
        pin: pin
      })

    Process.sleep(100)

    on_exit(fn ->
      if Process.alive?(pid) do
        StrapSofthsmPrivKeyStoreProvider.stop(pid)
      end
    end)

    :ok
  end

  test "generating keys and signing data" do
    assert {:ok, ctx} =
             StrapPrivKeyStoreProvider.get_provider_context(%{
               node: node(),
               process_group_name: :softhsm_test
             })

    assert {:ok, types} =
             StrapPrivKeyStoreProvider.supported_key_types(
               ctx,
               %{
                 purpose: :sign
               }
             )

    alias StrapPrivKeyStoreProvider.Protocol.PublicKeyOps

    Enum.each(types, fn type ->
      # Generation should now succeed with our real backend
      assert {:ok, kp} = KeyGenerator.generate_key(type, %{timeout: 10_000})

      # Test separate public and private keys
      pub = StrapPrivKeyStoreProvider.Protocol.KeypairEngine.public_key(kp, %{})
      priv = StrapPrivKeyStoreProvider.Protocol.KeypairEngine.private_key(kp, %{})

      assert %StrapSofthsmPrivKeyStoreProvider.Model.SofthsmPubKey{} = pub
      assert %StrapSofthsmPrivKeyStoreProvider.Model.SofthsmPrivKey{} = priv

      assert pub.material != nil
      assert priv.key_id != nil
      assert priv.slot != nil

      # Signing and Verification
      data = "hello world"
      assert {:ok, signature} = PrivateKeyOps.sign_data(priv, data, %{})
      assert :ok = PublicKeyOps.verify_data(pub, data, signature, %{})

      # Encryption and Decryption (RSA only for now)
      if type.algo == :rsa do
        assert {:ok, ciphertext} = PublicKeyOps.encrypt_data(pub, data, %{})
        assert {:ok, plaintext} = PrivateKeyOps.decrypt_data(priv, pub, ciphertext, %{})
        assert plaintext == data
      end

      # Keystore Management and PIN Update
      new_pin = "5678"

      assert {:ok, ks} =
               StrapPrivKeyStoreProvider.Protocol.KeypairEngine.to_keystore(kp, new_pin, %{})

      assert %StrapSofthsmPrivKeyStoreProvider.Model.SofthsmKeystore{} = ks

      # Convert back to keypair (should use the new PIN in state internally)
      assert {:ok, priv2} =
               StrapPrivKeyStoreProvider.Protocol.KeystoreManagerProtocol.to_keypair(
                 ks,
                 new_pin,
                 %{}
               )

      assert priv2.key_id == priv.key_id

      # Test signing with new PIN
      assert {:ok, _sig} = PrivateKeyOps.sign_data(priv2, "test", %{})

      # Update PIN again via KeystoreManagerProtocol
      final_pin = "1111"

      assert :ok =
               StrapPrivKeyStoreProvider.Protocol.KeystoreManagerProtocol.update_auth_token(
                 ks,
                 new_pin,
                 final_pin,
                 %{}
               )

      # Verify signing still works with final PIN (internal state updated)
      assert {:ok, _sig2} = PrivateKeyOps.sign_data(priv2, "test2", %{})
    end)
  end
end
