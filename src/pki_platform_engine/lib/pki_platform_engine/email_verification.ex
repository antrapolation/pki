defmodule PkiPlatformEngine.EmailVerification do
  use GenServer

  @table :email_verification_codes
  @code_length 6
  @expiry_seconds 600

  def start_link(_opts) do
    GenServer.start_link(__MODULE__, [], name: __MODULE__)
  end

  def init(_) do
    :ets.new(@table, [:named_table, :set, :public])
    {:ok, %{}}
  end

  def generate_code(email) do
    code = :crypto.strong_rand_bytes(3) |> :binary.decode_unsigned() |> rem(1_000_000) |> Integer.to_string() |> String.pad_leading(@code_length, "0")
    expires_at = System.system_time(:second) + @expiry_seconds
    :ets.insert(@table, {String.downcase(email), code, expires_at})
    code
  end

  def verify_code(email, code) do
    key = String.downcase(email)
    case :ets.lookup(@table, key) do
      [{^key, ^code, expires_at}] ->
        if System.system_time(:second) <= expires_at do
          :ets.delete(@table, key)
          :ok
        else
          :ets.delete(@table, key)
          {:error, :expired}
        end

      [{^key, _other_code, _}] ->
        {:error, :invalid_code}

      [] ->
        {:error, :no_code}
    end
  end
end
