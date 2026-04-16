defmodule PkiMnesia.TestHelper do
  @moduledoc """
  Test helper for Mnesia-based tests.
  Each test gets a unique temp directory, starts Mnesia there,
  creates tables, runs test, stops Mnesia, deletes directory.
  """

  @doc """
  Set up Mnesia for a test. Call in setup/setup_all.
  Returns the temp directory path (for teardown).
  """
  def setup_mnesia do
    # Generate unique temp dir per test
    dir = Path.join(System.tmp_dir!(), "pki_mnesia_test_#{:erlang.unique_integer([:positive])}")
    File.mkdir_p!(dir)

    # Stop Mnesia if running (from a previous crashed test)
    :mnesia.stop()

    # Point Mnesia at our temp dir
    Application.put_env(:mnesia, :dir, String.to_charlist(dir))

    # Create schema on disk for this node
    :mnesia.create_schema([node()])

    # Start Mnesia
    :ok = :mnesia.start()

    # Create all tables
    :ok = PkiMnesia.Schema.create_tables()

    # Wait for tables to be available
    table_names = :mnesia.system_info(:local_tables) -- [:schema]
    :mnesia.wait_for_tables(table_names, 5000)

    dir
  end

  @doc """
  Tear down Mnesia after a test. Pass the dir from setup_mnesia/0.
  """
  def teardown_mnesia(dir) do
    case :mnesia.stop() do
      :stopped -> :ok
      {:error, reason} -> raise "mnesia.stop() failed: #{inspect(reason)}"
    end

    # Delete the Mnesia schema so :mnesia.create_schema works next time
    case :mnesia.delete_schema([node()]) do
      :ok -> :ok
      {:error, reason} -> raise "mnesia.delete_schema/1 failed: #{inspect(reason)}"
    end

    File.rm_rf!(dir)
    :ok
  end
end
