defmodule PkiCaEngine.KeyCeremony.PasswordPolicyTest do
  use ExUnit.Case, async: true

  alias PkiCaEngine.KeyCeremony.PasswordPolicy

  describe "validate/1" do
    test "accepts a 12+ char password that isn't in the common list" do
      assert :ok = PasswordPolicy.validate("correct horse battery staple")
      assert :ok = PasswordPolicy.validate("mypassw0rd99!")
    end

    test "rejects empty strings" do
      assert {:error, :empty} = PasswordPolicy.validate("")
    end

    test "rejects non-string input" do
      assert {:error, :empty} = PasswordPolicy.validate(nil)
      assert {:error, :empty} = PasswordPolicy.validate(123)
    end

    test "rejects passwords under minimum length" do
      assert {:error, {:too_short, 12}} = PasswordPolicy.validate("short")
      # 11-char: one below the floor
      assert {:error, {:too_short, 12}} = PasswordPolicy.validate("abcdefghijk")
    end

    test "accepts passwords at exactly the minimum length" do
      # 12-char unique password not in the common list
      assert :ok = PasswordPolicy.validate("Xq9!zY3#Lm4&")
    end

    test "rejects known common passwords even when they meet the length bar" do
      assert {:error, :common_password} = PasswordPolicy.validate("password1234")
      assert {:error, :common_password} = PasswordPolicy.validate("passwordpassword")
      assert {:error, :common_password} = PasswordPolicy.validate("changemechangeme")
    end
  end

  describe "validate_with_confirmation/2" do
    test "accepts matching, policy-compliant passwords" do
      assert :ok =
               PasswordPolicy.validate_with_confirmation(
                 "mypassw0rd99!",
                 "mypassw0rd99!"
               )
    end

    test "rejects on mismatch (even if both would pass individually)" do
      assert {:error, :mismatch} =
               PasswordPolicy.validate_with_confirmation(
                 "mypassw0rd99!",
                 "mypassw0rd99?"
               )
    end

    test "runs mismatch check before policy — avoids leaking policy via confirmation" do
      # An under-12 password that doesn't match: user should see the
      # mismatch first so they don't receive two error messages.
      assert {:error, :mismatch} =
               PasswordPolicy.validate_with_confirmation("short", "shorter")
    end

    test "rejects matched but policy-violating passwords" do
      assert {:error, :common_password} =
               PasswordPolicy.validate_with_confirmation(
                 "password1234",
                 "password1234"
               )

      assert {:error, {:too_short, 12}} =
               PasswordPolicy.validate_with_confirmation("short", "short")
    end
  end

  describe "humanize_error/1" do
    test "renders each error shape as a user-friendly message" do
      assert "Password must be at least 12 characters." =
               PasswordPolicy.humanize_error({:too_short, 12})

      assert "Password is too common. Pick something less predictable." =
               PasswordPolicy.humanize_error(:common_password)

      assert "Passwords do not match." = PasswordPolicy.humanize_error(:mismatch)
      assert "Password cannot be empty." = PasswordPolicy.humanize_error(:empty)
    end
  end
end
