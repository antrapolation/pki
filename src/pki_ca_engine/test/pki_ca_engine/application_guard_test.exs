defmodule PkiCaEngine.ApplicationGuardTest do
  @moduledoc """
  Tests for the boot-time guard that refuses to start a prod release
  when active software-keystore IssuerKey records are present.
  """
  use ExUnit.Case, async: false

  alias PkiCaEngine.Application, as: App
  alias PkiMnesia.{Repo, Structs.IssuerKey, TestHelper}

  # Each test needs real Mnesia so we can write IssuerKey records.
  setup do
    dir = TestHelper.setup_mnesia()
    on_exit(fn -> TestHelper.teardown_mnesia(dir) end)
    :ok
  end

  # Restore application env after each test so other tests are unaffected.
  setup do
    original_env = Application.get_env(:pki_ca_engine, :env)
    original_allow = Application.get_env(:pki_ca_engine, :allow_software_keystore_in_prod)

    on_exit(fn ->
      if original_env do
        Application.put_env(:pki_ca_engine, :env, original_env)
      else
        Application.delete_env(:pki_ca_engine, :env)
      end

      if original_allow do
        Application.put_env(:pki_ca_engine, :allow_software_keystore_in_prod, original_allow)
      else
        Application.delete_env(:pki_ca_engine, :allow_software_keystore_in_prod)
      end
    end)

    :ok
  end

  defp insert_issuer_key(attrs \\ %{}) do
    defaults = %{
      ca_instance_id: "ca-#{System.unique_integer([:positive])}",
      algorithm: "rsa",
      key_alias: "test-key-#{System.unique_integer([:positive])}",
      status: "active",
      keystore_type: :software
    }

    key = IssuerKey.new(Map.merge(defaults, attrs))
    {:ok, key} = Repo.insert(key)
    key
  end

  describe "assert_ceremony_signing_secret_set!/0" do
    setup do
      original_env = Application.get_env(:pki_ca_engine, :env)
      original_secret = Application.get_env(:pki_ca_engine, :ceremony_signing_secret)

      on_exit(fn ->
        if original_env do
          Application.put_env(:pki_ca_engine, :env, original_env)
        else
          Application.delete_env(:pki_ca_engine, :env)
        end

        if original_secret do
          Application.put_env(:pki_ca_engine, :ceremony_signing_secret, original_secret)
        else
          Application.delete_env(:pki_ca_engine, :ceremony_signing_secret)
        end
      end)

      :ok
    end

    test "raises in prod when :ceremony_signing_secret is nil (not configured)" do
      Application.put_env(:pki_ca_engine, :env, :prod)
      Application.delete_env(:pki_ca_engine, :ceremony_signing_secret)

      assert_raise RuntimeError, ~r/REFUSING TO BOOT/, fn ->
        App.assert_ceremony_signing_secret_set!()
      end
    end

    test "raises in prod when :ceremony_signing_secret is the dev default" do
      Application.put_env(:pki_ca_engine, :env, :prod)
      Application.put_env(:pki_ca_engine, :ceremony_signing_secret, "dev-only-secret")

      assert_raise RuntimeError, ~r/REFUSING TO BOOT/, fn ->
        App.assert_ceremony_signing_secret_set!()
      end
    end

    test "does not raise in prod when :ceremony_signing_secret is a real secret" do
      Application.put_env(:pki_ca_engine, :env, :prod)
      Application.put_env(:pki_ca_engine, :ceremony_signing_secret, "a-strong-random-secret-32bytes!!")

      assert :ok == App.assert_ceremony_signing_secret_set!()
    end

    test "does not raise in dev even when :ceremony_signing_secret is nil" do
      Application.put_env(:pki_ca_engine, :env, :dev)
      Application.delete_env(:pki_ca_engine, :ceremony_signing_secret)

      assert App.assert_ceremony_signing_secret_set!() |> is_nil()
    end

    test "does not raise in dev when :ceremony_signing_secret is the dev default" do
      Application.put_env(:pki_ca_engine, :env, :dev)
      Application.put_env(:pki_ca_engine, :ceremony_signing_secret, "dev-only-secret")

      assert App.assert_ceremony_signing_secret_set!() |> is_nil()
    end
  end

  describe "assert_no_software_keystore_in_prod!/0" do
    test "raises in prod when allow_software_keystore_in_prod is false (default) and active software key exists" do
      Application.put_env(:pki_ca_engine, :env, :prod)
      Application.put_env(:pki_ca_engine, :allow_software_keystore_in_prod, false)

      insert_issuer_key(%{status: "active", keystore_type: :software})

      assert_raise RuntimeError, ~r/REFUSING TO BOOT/, fn ->
        App.assert_no_software_keystore_in_prod!()
      end
    end

    test "raises in prod with default allow flag (omitted) when active software key exists" do
      Application.put_env(:pki_ca_engine, :env, :prod)
      Application.delete_env(:pki_ca_engine, :allow_software_keystore_in_prod)

      insert_issuer_key(%{status: "active", keystore_type: :software})

      assert_raise RuntimeError, ~r/REFUSING TO BOOT/, fn ->
        App.assert_no_software_keystore_in_prod!()
      end
    end

    test "does not raise in prod when allow_software_keystore_in_prod is true" do
      Application.put_env(:pki_ca_engine, :env, :prod)
      Application.put_env(:pki_ca_engine, :allow_software_keystore_in_prod, true)

      insert_issuer_key(%{status: "active", keystore_type: :software})

      # Must not raise
      assert :ok == App.assert_no_software_keystore_in_prod!()
    end

    test "does not raise in prod when no active software keys exist" do
      Application.put_env(:pki_ca_engine, :env, :prod)
      Application.put_env(:pki_ca_engine, :allow_software_keystore_in_prod, false)

      # Insert an HSM key — should not trigger the guard
      insert_issuer_key(%{status: "active", keystore_type: :local_hsm})

      assert :ok == App.assert_no_software_keystore_in_prod!()
    end

    test "does not raise in prod when software key exists but is not active" do
      Application.put_env(:pki_ca_engine, :env, :prod)
      Application.put_env(:pki_ca_engine, :allow_software_keystore_in_prod, false)

      insert_issuer_key(%{status: "pending", keystore_type: :software})

      assert :ok == App.assert_no_software_keystore_in_prod!()
    end

    test "does not raise in dev even when active software key exists and flag is false" do
      Application.put_env(:pki_ca_engine, :env, :dev)
      Application.put_env(:pki_ca_engine, :allow_software_keystore_in_prod, false)

      insert_issuer_key(%{status: "active", keystore_type: :software})

      assert :ok == App.assert_no_software_keystore_in_prod!()
    end

    test "does not raise in test even when active software key exists and flag is false" do
      Application.put_env(:pki_ca_engine, :env, :test)
      Application.put_env(:pki_ca_engine, :allow_software_keystore_in_prod, false)

      insert_issuer_key(%{status: "active", keystore_type: :software})

      assert :ok == App.assert_no_software_keystore_in_prod!()
    end

    test "error message includes the offending key alias" do
      Application.put_env(:pki_ca_engine, :env, :prod)
      Application.put_env(:pki_ca_engine, :allow_software_keystore_in_prod, false)

      insert_issuer_key(%{status: "active", keystore_type: :software, key_alias: "root-key-prod"})

      assert_raise RuntimeError, ~r/root-key-prod/, fn ->
        App.assert_no_software_keystore_in_prod!()
      end
    end
  end
end
