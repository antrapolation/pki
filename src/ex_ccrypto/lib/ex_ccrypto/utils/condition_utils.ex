defmodule ExCcrypto.Utils.ConditionUtils do
  def is_blank?(nil), do: true
  def is_blank?([]), do: true
  def is_blank?(%{}), do: true

  def is_blank?(val) when is_binary(val) do
    String.trim(val) == ""
  end

  def is_blank?(_), do: false
end
