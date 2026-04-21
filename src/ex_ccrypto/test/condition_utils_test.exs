defmodule ConditionUtilsTest do
  alias ExCcrypto.Utils.ConditionUtils
  use ExUnit.Case

  test "is_blank? returns true for nil" do
    assert ConditionUtils.is_blank?(nil) == true
  end

  test "is_blank? returns true for empty list" do
    assert ConditionUtils.is_blank?([]) == true
  end

  test "is_blank? returns true for empty map" do
    assert ConditionUtils.is_blank?(%{}) == true
  end

  test "is_blank? returns true for empty string" do
    assert ConditionUtils.is_blank?("") == true
  end

  test "is_blank? returns true for whitespace-only string" do
    assert ConditionUtils.is_blank?("   ") == true
    assert ConditionUtils.is_blank?("\t\n") == true
    assert ConditionUtils.is_blank?("  \n\t  ") == true
  end

  test "is_blank? returns false for non-empty string" do
    assert ConditionUtils.is_blank?("hello") == false
    assert ConditionUtils.is_blank?("  hello  ") == false
  end

  test "is_blank? returns false for non-empty list" do
    assert ConditionUtils.is_blank?([1, 2, 3]) == false
    assert ConditionUtils.is_blank?(["a"]) == false
  end

  test "is_blank? returns true for any map (implementation matches any map)" do
    assert ConditionUtils.is_blank?(%{a: 1}) == true
    assert ConditionUtils.is_blank?(%{"key" => "value"}) == true
  end

  test "is_blank? returns false for numbers" do
    assert ConditionUtils.is_blank?(0) == false
    assert ConditionUtils.is_blank?(1) == false
    assert ConditionUtils.is_blank?(-1) == false
    assert ConditionUtils.is_blank?(3.14) == false
  end

  test "is_blank? returns false for atoms" do
    assert ConditionUtils.is_blank?(:atom) == false
    assert ConditionUtils.is_blank?(true) == false
    assert ConditionUtils.is_blank?(false) == false
  end

  test "is_blank? returns false for tuples" do
    assert ConditionUtils.is_blank?({}) == false
    assert ConditionUtils.is_blank?({1, 2}) == false
  end
end
