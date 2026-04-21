defmodule StrapSofthsmPrivKeyStoreProvider.TestHelper do
  require Logger

  @softhsm_util "softhsm2-util"

  def init_test_token(slot_id, label, pin) do
    Logger.info("Initializing SoftHSM test token on slot #{slot_id} with label #{label}")

    case System.find_executable(@softhsm_util) do
      nil ->
        {:error, :softhsm_util_not_found}

      _path ->
        # Try to initialize on specified slot
        case init_token_on_slot(slot_id, label, pin) do
          :ok ->
            {:ok, slot_id}

          _error ->
            # If it fails, try to find a free slot or use --free if supported
            Logger.info("Failed on slot #{slot_id}, trying with --free")
            init_token_free(label, pin)
        end
    end
  end

  defp init_token_on_slot(slot_id, label, pin) do
    case System.cmd(@softhsm_util, [
           "--init-token",
           "--slot",
           to_string(slot_id),
           "--label",
           label,
           "--so-pin",
           "1234",
           "--pin",
           pin
         ]) do
      {_output, 0} -> :ok
      {output, _} -> {:error, output}
    end
  end

  defp init_token_free(label, pin) do
    case System.cmd(@softhsm_util, [
           "--init-token",
           "--free",
           "--label",
           label,
           "--so-pin",
           "1234",
           "--pin",
           pin
         ]) do
      {output, 0} ->
        # Parse slot ID from output: "The token has been initialized on slot 1"
        case Regex.run(~r/slot (\d+)/, output) do
          [_, id] -> {:ok, String.to_integer(id)}
          # Fallback to 0 if cannot parse
          _ -> {:ok, 0}
        end

      {output, _} ->
        Logger.error("Failed to init token with --free: #{output}")
        {:error, output}
    end
  end

  def delete_all_keys(_slot_id, _pin) do
    # In a real test we might want to clean up
    # However, SoftHSM tokens can be hard to "delete" without wiping the whole config
    # For now we'll just leave it or use a fresh slot if available
    :ok
  end
end
