defmodule SecretSharingTest do
  alias ExCcrypto.ContextConfig
  alias ExCcrypto.SecretSharing.SecretSharingContextBuilder
  alias ExCcrypto.SecretSharing
  use ExUnit.Case

  test "test secret sharing" do
    secret = :crypto.strong_rand_bytes(128)

    assert {:ok, splits} =
             SecretSharingContextBuilder.secret_sharing_context(:shamir)
             |> ContextConfig.set(:policy, %{total: 10, required: 2})
             |> SecretSharing.split(secret)

    IO.inspect(splits, limit: 1000)

    assert {:ok, recovered} =
             SecretSharingContextBuilder.secret_sharing_context()
             |> SecretSharing.recover_init()
             |> ContextConfig.set(:policy, %{total: 5, required: 3})
             |> SecretSharing.recover_add_share(Enum.at(splits, 0))
             |> SecretSharing.recover_add_share(Enum.at(splits, 2))
             |> SecretSharing.recover_add_share(Enum.at(splits, 4))
             |> SecretSharing.recover_final()

    assert(recovered == secret)

    assert {:ok, res} =
             SecretSharingContextBuilder.secret_sharing_context()
             |> SecretSharing.recover_init()
             |> ContextConfig.set(:policy, %{total: 5, required: 3})
             |> SecretSharing.recover_add_share(Enum.at(splits, 1))
             |> SecretSharing.recover_final()

    assert(res != secret)

    assert {:ok, res2} =
             SecretSharingContextBuilder.secret_sharing_context()
             |> SecretSharing.recover_init()
             |> ContextConfig.set(:policy, %{total: 5, required: 3})
             |> SecretSharing.recover_add_share(Enum.at(splits, 0))
             |> SecretSharing.recover_add_share(Enum.at(splits, 3))
             |> SecretSharing.recover_add_share(Enum.at(splits, 4))
             |> SecretSharing.recover_add_share(Enum.at(splits, 2))
             |> SecretSharing.recover_final()

    assert(res2 == secret)

    assert {:error, :given_share_is_nil} =
             SecretSharingContextBuilder.secret_sharing_context()
             |> SecretSharing.recover_init()
             |> ContextConfig.set(:policy, %{total: 5, required: 3})
             |> SecretSharing.recover_add_share(nil)

    assert {:error, {:runtime_error, _}} =
             SecretSharingContextBuilder.secret_sharing_context()
             |> SecretSharing.recover_init()
             |> ContextConfig.set(:policy, %{total: 10, required: 2})
             |> SecretSharing.recover_add_share(:crypto.strong_rand_bytes(64))
             |> SecretSharing.recover_add_share(:crypto.strong_rand_bytes(128))
             |> SecretSharing.recover_final()

    assert {:ok, res4} =
             SecretSharingContextBuilder.secret_sharing_context()
             |> SecretSharing.recover_init()
             |> ContextConfig.set(:policy, %{total: 10, required: 2})
             |> SecretSharing.recover_add_share(:crypto.strong_rand_bytes(128))
             |> SecretSharing.recover_add_share(:crypto.strong_rand_bytes(128))
             |> SecretSharing.recover_final()

    assert res4 != secret
  end
end
