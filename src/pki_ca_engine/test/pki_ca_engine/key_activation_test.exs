defmodule PkiCaEngine.KeyActivationTest do
  use ExUnit.Case, async: false

  alias PkiMnesia.{TestHelper, Repo}
  alias PkiMnesia.Structs.ThresholdShare
  alias PkiCaEngine.KeyActivation

  setup do
    dir = TestHelper.setup_mnesia()

    {:ok, pid} = KeyActivation.start_link(name: :test_ka, timeout_ms: 60_000)

    on_exit(fn ->
      if Process.alive?(pid), do: GenServer.stop(pid)
      TestHelper.teardown_mnesia(dir)
    end)

    %{ka: :test_ka}
  end

  test "get_active_key returns error when key not activated", %{ka: ka} do
    assert {:error, :not_active} = KeyActivation.get_active_key(ka, "some-key-id")
  end

  test "is_active? returns false for non-activated key", %{ka: ka} do
    refute KeyActivation.is_active?(ka, "some-key-id")
  end

  test "dev_activate injects a key directly", %{ka: ka} do
    Application.put_env(:pki_ca_engine, :allow_dev_activate, true)

    key_id = "test-key-1"
    priv = :crypto.strong_rand_bytes(32)

    assert {:ok, :dev_activated} = KeyActivation.dev_activate(ka, key_id, priv)
    assert KeyActivation.is_active?(ka, key_id)
    assert {:ok, ^priv} = KeyActivation.get_active_key(ka, key_id)

    Application.put_env(:pki_ca_engine, :allow_dev_activate, false)
  end

  test "deactivate removes an active key", %{ka: ka} do
    Application.put_env(:pki_ca_engine, :allow_dev_activate, true)

    key_id = "test-key-2"
    priv = :crypto.strong_rand_bytes(32)
    KeyActivation.dev_activate(ka, key_id, priv)

    assert :ok = KeyActivation.deactivate(ka, key_id)
    refute KeyActivation.is_active?(ka, key_id)

    Application.put_env(:pki_ca_engine, :allow_dev_activate, false)
  end
end
