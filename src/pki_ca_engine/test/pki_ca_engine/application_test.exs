defmodule PkiCaEngine.ApplicationTest do
  use ExUnit.Case, async: true

  alias PkiCaEngine.Application, as: App

  describe "check_dev_activate_safe/2" do
    # Pure function — exhaustive test of the boot-time gate.

    test "allows boot when compile_env is :prod and flag is false" do
      assert :ok = App.check_dev_activate_safe(:prod, false)
    end

    test "allows boot in dev even with flag true" do
      assert :ok = App.check_dev_activate_safe(:dev, true)
    end

    test "allows boot in test even with flag true" do
      assert :ok = App.check_dev_activate_safe(:test, true)
    end

    test "refuses boot when compile_env is :prod and flag is true" do
      assert {:unsafe, msg} = App.check_dev_activate_safe(:prod, true)
      assert msg =~ "REFUSING TO BOOT"
      assert msg =~ ":allow_dev_activate"
    end
  end
end
