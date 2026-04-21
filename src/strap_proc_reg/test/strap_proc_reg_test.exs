defmodule TestDriver do
  use GenServer

  require Logger

  def start_link() do
    Logger.debug("source module : #{inspect(self())}")

    GenServer.start_link(__MODULE__, [],
      name: {:via, StrapProcReg, %{name: :process1, group: "local", operation: :register}}
    )
  end

  def callme(pid \\ :process1), do: GenServer.call(pid, :callme)

  def init(_args) do
    {:ok, %{}}
  end

  def handle_call(:callme, _from, state) do
    {:reply, "Executing TestDriver callme() on #{inspect(:erlang.node())}", state}
  end
end

defmodule TestDriver2 do
  use GenServer

  def start_link() do
    GenServer.start_link(__MODULE__, [],
      name: {:via, StrapProcReg, %{group: "local", operation: :register}}
    )
  end

  def init(_args) do
    {:ok, %{}}
  end

  def callme(pid), do: GenServer.call(pid, :callme)

  def handle_call(:callme, _from, state) do
    {:reply, "Executing TestDriver 2 callme() on #{inspect(:erlang.node())}", state}
  end
end

defmodule StrapProcRegTest do
  use ExUnit.Case
  doctest StrapProcReg

  require Logger

  test "register via strap proc reg" do
    first = TestDriver.start_link()
    IO.inspect(first)
    assert {:ok, _} = first

    Logger.debug("source driver : #{inspect(self())}")
    first2 = TestDriver.start_link()
    IO.inspect(first2)
    assert {:error, {:already_started, _}} = first2

    second = TestDriver2.start_link()
    IO.inspect(second)
    assert {:ok, _} = second

    res =
      StrapProcReg.local_services(
        StrapProcReg.group("local")
        |> StrapProcReg.set_service_selector(:all)
      )

    IO.inspect(res)
    assert length(res) == 2

    Enum.map(res, fn r ->
      assert is_pid(r)
    end)

    res2 =
      StrapProcReg.local_services(
        StrapProcReg.group("local")
        |> StrapProcReg.set_service_selector(:all)
        |> StrapProcReg.set_return_service_info(:full)
      )

    IO.inspect(res2)
    assert length(res2) == 2

    Enum.map(res2, fn r ->
      {pid, _} = r
      assert is_pid(pid)
    end)

    res3 =
      StrapProcReg.local_services(%{
        group: "local",
        service_selector: :random,
        return_service_info: :full
      })

    IO.inspect(res3)

    {pid, _} = res3
    assert is_pid(pid)

    res4 = TestDriver.callme({:via, StrapProcReg, %{group: "local"}})
    IO.puts(res4)
  end
end
