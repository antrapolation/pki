defmodule ExJrubyPort do
  alias ExJrubyPort.JrubyService
  alias ExJrubyPort.JrubySession
  use GenServer

  def start_link(
        ctx,
        opts \\ %{
          cluster: false,
          cluster_scope: :ex_jruby_port,
          cluster_group: __MODULE__,
          process_name: nil
        }
      )

  def start_link(ctx, %{cluster: false}) do
    GenServer.start_link(__MODULE__, ctx)
  end

  def start_link(ctx, %{cluster: true} = opts) do
    GenServer.start_link(__MODULE__, ctx,
      # name: {:via, ApProcmanSyn, {opts.cluster_scope, nil, opts.cluster_group}}
      name: {:via, StrapProcReg, %{group: opts.cluster_group, operation: :register}}
    )
  end

  def run(pid, file, params \\ []) do
    GenServer.call(pid, {:run, file, params})
  catch
    :exit, {:timeout, _} -> {:ok, ""}
  end

  def start_node(pid, file, params \\ []) do
    GenServer.call(pid, {:new_node, file, params}, :infinity)
  end

  def stop(pid), do: GenServer.stop(pid)

  def init(opts) do
    # IO.puts("init ExJrubyPort opts : #{inspect(opts)}")
    {:ok, %{context: opts}}
  end

  def handle_call({:run, file, params}, _from, state) do
    {:ok, spid} = JrubySession.start_link(state.context)
    res = GenServer.call(spid, {:run, file, params})
    GenServer.stop(spid)
    {:reply, res, state}
  end

  def handle_call({:new_node, file, params}, _from, state) do
    {:ok, spid} = JrubyService.start_link(state, file, params)
    {:reply, {:ok, spid}, state}
  end

  def handle_info(msg, state) do
    IO.puts("ExJrubyPort handle_info got : #{msg}")
    {:noreply, state}
  end
end
