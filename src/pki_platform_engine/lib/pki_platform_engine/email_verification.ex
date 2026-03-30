defmodule PkiPlatformEngine.EmailVerification do
  use GenServer

  @table :email_verification_codes
  @code_length 6
  @expiry_seconds 600
  @max_attempts 5

  def start_link(_opts) do
    GenServer.start_link(__MODULE__, [], name: __MODULE__)
  end

  def init(_) do
    :ets.new(@table, [:named_table, :set, :protected])
    {:ok, %{}}
  end

  def generate_code(email) do
    GenServer.call(__MODULE__, {:generate_code, email})
  end

  def verify_code(email, code) do
    GenServer.call(__MODULE__, {:verify_code, email, code})
  end

  @impl true
  def handle_call({:generate_code, email}, _from, state) do
    code = :crypto.strong_rand_bytes(4) |> :binary.decode_unsigned() |> rem(1_000_000) |> Integer.to_string() |> String.pad_leading(@code_length, "0")
    expires_at = System.system_time(:second) + @expiry_seconds
    :ets.insert(@table, {String.downcase(email), code, expires_at, 0})
    {:reply, code, state}
  end

  @impl true
  def handle_call({:verify_code, email, code}, _from, state) do
    key = String.downcase(email)
    result = case :ets.lookup(@table, key) do
      [{^key, ^code, expires_at, _attempts}] ->
        if System.system_time(:second) <= expires_at do
          :ets.delete(@table, key)
          :ok
        else
          :ets.delete(@table, key)
          {:error, :expired}
        end

      [{^key, _other_code, _expires_at, attempts}] when attempts + 1 >= @max_attempts ->
        :ets.delete(@table, key)
        {:error, :too_many_attempts}

      [{^key, stored_code, expires_at, attempts}] ->
        :ets.insert(@table, {key, stored_code, expires_at, attempts + 1})
        {:error, :invalid_code}

      [] ->
        {:error, :no_code}
    end
    {:reply, result, state}
  end
end
