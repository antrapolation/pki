defmodule PkiPlatformEngine.DateLogHandlerTest do
  use ExUnit.Case, async: false

  alias PkiPlatformEngine.DateLogHandler

  setup do
    dir = System.tmp_dir!() |> Path.join("pki_log_test_#{System.unique_integer([:positive])}")
    File.mkdir_p!(dir)

    {:ok, pid} =
      GenServer.start_link(DateLogHandler, [log_dir: dir, app_name: "test", retention_days: 7], [])

    on_exit(fn ->
      if Process.alive?(pid), do: GenServer.stop(pid)
      :logger.remove_handler(:pki_date_log)
      File.rm_rf!(dir)
    end)

    %{pid: pid, log_dir: dir}
  end

  test "starts without error", %{pid: pid} do
    assert Process.alive?(pid)
  end

  test "creates a log file on start", %{log_dir: log_dir} do
    log_dir_pki = Path.join(log_dir, "test")
    files = File.ls!(log_dir_pki)
    assert length(files) >= 1
    assert Enum.any?(files, &String.ends_with?(&1, ".log"))
  end

  test "write via handle_cast appends to the log file", %{pid: pid, log_dir: log_dir} do
    GenServer.cast(pid, {:write, "test log line\n"})
    Process.sleep(50)

    log_dir_pki = Path.join(log_dir, "test")
    [file | _] = File.ls!(log_dir_pki)
    content = File.read!(Path.join(log_dir_pki, file))
    assert content =~ "test log line"
  end

  test "log/2 via Erlang logger handler routes to the GenServer", %{pid: pid, log_dir: log_dir} do
    DateLogHandler.log(
      %{level: :info, msg: {:string, "hello from logger"}, meta: %{}},
      %{config: %{server: pid}}
    )
    Process.sleep(50)

    log_dir_pki = Path.join(log_dir, "test")
    [file | _] = File.ls!(log_dir_pki)
    content = File.read!(Path.join(log_dir_pki, file))
    assert content =~ "hello from logger"
  end

  test "adding_handler/1 returns ok" do
    assert {:ok, %{}} = DateLogHandler.adding_handler(%{})
  end

  test "removing_handler/1 returns ok" do
    assert :ok = DateLogHandler.removing_handler(%{})
  end

  test "changing_config/3 returns ok with new config" do
    new_cfg = %{level: :debug}
    assert {:ok, ^new_cfg} = DateLogHandler.changing_config(:set, %{}, new_cfg)
  end

  test "handle_info :rotate when date unchanged keeps the same file", %{pid: pid, log_dir: log_dir} do
    send(pid, :rotate)
    Process.sleep(50)
    assert Process.alive?(pid)
    log_dir_pki = Path.join(log_dir, "test")
    files = File.ls!(log_dir_pki)
    assert length(files) >= 1
  end
end
