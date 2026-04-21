defmodule ExJrubyPort.JrubyService do
  alias ExJrubyPort.JrubyContext
  alias ExJrubyPort.JrubyJarContext
  use GenServer

  require Logger

  def start_link(sess, file, params) do
    # since the Java part shall be process per se, need to setup the environment for process

    local_node =
      case node_running_status() do
        :node_not_started ->
          local_name = generate_local_node_name()
          cookie = :crypto.strong_rand_bytes(14) |> Base.encode16()
          Node.start(local_name, :shortnames)
          Node.set_cookie(String.to_atom(cookie))
          local_name

        {:node_started, name} ->
          name
      end

    local_process_name = :crypto.strong_rand_bytes(8) |> Base.encode16() |> String.to_atom()

    port_node_name = generate_local_node_name()
    port_process_name = :crypto.strong_rand_bytes(8) |> Base.encode16() |> String.to_atom()

    {:ok, pid} =
      GenServer.start_link(
        __MODULE__,
        %{
          session: sess,
          file: file,
          params: params,
          port_node_name: port_node_name,
          port_process_name: port_process_name,
          local_node_name: local_node,
          local_process_name: local_process_name
        },
        name: local_process_name
      )

    GenServer.call(pid, :wait_for_port, :infinity)

    {:ok, pid}
  end

  def invoke(pid, cls, mtd, params, opts \\ %{})

  def invoke(pid, cls, mtd, params, opts) when not is_list(params),
    do: invoke(pid, cls, mtd, [params], opts)

  def invoke(pid, cls, mtd, params, opts) when is_list(params) do
    GenServer.call(pid, {:invoke, cls, mtd, params, opts}, :infinity)
  end

  def call(pid, req), do: GenServer.call(pid, req)

  def stop(pid) do
    GenServer.call(pid, :shutdown)
    GenServer.stop(pid)
  end

  defp node_running_status do
    case Node.self() do
      :nonode@nohost -> :node_not_started
      res -> {:node_started, res}
    end
  end

  defp generate_local_node_name() do
    prefix = :crypto.strong_rand_bytes(8) |> Base.encode16()
    # name = String.to_atom("#{prefix}@localhost")
    name = String.to_atom("#{prefix}@127.0.0.1")

    case :net_adm.ping(name) do
      :pong ->
        # exist! Damm
        generate_local_node_name()

      :pang ->
        name
    end
  end

  def init(state) do
    cmdline = build_cmdline(state)

    Logger.debug("cmdline : #{inspect(cmdline)}")

    Process.flag(:trap_exit, true)

    port =
      Port.open(
        {:spawn, cmdline},
        # "#{context.java_path} -jar #{context.jruby_jar_path} #{Path.expand(state.file)} #{state.port_node_name}/#{state.port_process_name}/#{:erlang.get_cookie()}/#{state.local_node_name}/#{state.local_process_name} #{Enum.join(state.params, " ")}"},
        # , {:packet, 4}, :nouse_stdio]
        [:binary, :exit_status]
      )

    Process.link(port)
    :erlang.monitor(:port, port)

    Process.monitor(self())

    {:ok, Map.put_new(state, :port, port)}
  end

  # def init(%{session: %{context: %JrubyContext{} = context}} = state) do
  #  port =
  #    Port.open(
  #      {:spawn,
  #       "#{context.jruby_path} #{Path.expand(state.file)} #{state.port_node_name}/#{state.port_process_name}/#{:erlang.get_cookie()}/#{state.local_node_name}/#{state.local_process_name} #{Enum.join(state.params, " ")}"},
  #      # , {:packet, 4}, :nouse_stdio]
  #      [:binary, :exit_status]
  #    )

  #  {:ok, Map.put_new(state, :port, port)}
  # end

  def handle_call(:wait_for_port, _from, state) do
    parse_port_setup_done_message(state.port, state.port_node_name, state.port_process_name)
    {:reply, :ok, state}
  end

  def handle_call(:shutdown, _from, state) do
    send({state.port_process_name, state.port_node_name}, :stop)
    read_port_response(state.port)
    {:reply, :ok, state}
  end

  def handle_call(request, _from, state) do
    send({state.port_process_name, state.port_node_name}, request)
    res = read_port_response(state.port)
    {:reply, res, state}
  end

  def handle_info(msg, state) do
    IO.puts("handle_info JruySeseion got : #{inspect(msg)}")
    {:noreply, state}
  end

  def terminate(reason, state) do
    IO.puts("terminate : #{inspect(reason)} / #{inspect(state)}")

    try do
      send({state.port_process_name, state.port_node_name}, :stop)
      Port.close(state.port)
      :ok
    rescue
      _err ->
        :ok
    end
  end

  defp build_cmdline(%{session: %{context: %JrubyContext{} = context}} = state) do
    case context.with_bundle_exec? do
      true ->
        "bundle exec #{context.jruby_path} #{Path.expand(state.file)} #{state.port_node_name}/#{state.port_process_name}/#{:erlang.get_cookie()}/#{state.local_node_name}/#{state.local_process_name} #{Enum.join(state.params, " ")}"

      false ->
        "#{context.jruby_path} #{Path.expand(state.file)} #{state.port_node_name}/#{state.port_process_name}/#{:erlang.get_cookie()}/#{state.local_node_name}/#{state.local_process_name} #{Enum.join(state.params, " ")}"
    end
  end

  defp build_cmdline(%{session: %{context: %JrubyJarContext{} = context}} = state) do
    # "#{context.java_path} -jar #{context.jruby_jar_path} #{Path.expand(state.file)} #{state.port_node_name}/#{state.port_process_name}/#{:erlang.get_cookie()}/#{state.local_node_name}/#{state.local_process_name} #{Enum.join(state.params, " ")}"
    cmdline = []
    cmdline = cmdline ++ [context.java_path]

    cmdline =
      cmdline ++
        [
          Enum.join(
            case Enum.empty?(context.java_library_path) do
              false ->
                ["-Djava.library.path="] ++ [Path.expand(Path.join(context.java_library_path))]

              true ->
                []
            end,
            ""
          )
        ]

    cmdline =
      cmdline ++
        case Enum.empty?(context.jar_path) do
          false ->
            ["-jar"] ++ context.jar_path

          true ->
            []
        end

    cmdline =
      cmdline ++
        [Path.expand(state.file)] ++
        [
          Enum.join(
            [
              state.port_node_name,
              state.port_process_name,
              :erlang.get_cookie(),
              state.local_node_name,
              state.local_process_name
            ],
            "/"
          )
        ] ++ state.params

    Enum.join(cmdline, " ")

    # "#{context.java_path} -jar #{context.jruby_jar_path} #{Path.expand(state.file)} #{state.port_node_name}/#{state.port_process_name}/#{:erlang.get_cookie()}/#{state.local_node_name}/#{state.local_process_name} #{Enum.join(state.params, " ")}"
  end

  defp read_port_response(port) do
    receive do
      {^port, {:data, data}} ->
        IO.puts("loop2 received : #{inspect(data)}")
        read_port_response(port)

      # {:ok, res} ->
      #  {:ok, res}

      # {:ok} ->
      #  :ok

      # {:error, reason} ->
      #  {:error, reason}

      {^port, {:exit_status, st}} ->
        IO.puts("Process send back exit_status #{st}")

      res ->
        case List.first(Tuple.to_list(res)) do
          :ok ->
            res

          :error ->
            res

          vres ->
            IO.puts("Loop2 received unexpected: #{inspect(vres)}")
            read_port_response(port)
        end
    end
  end

  defp parse_port_setup_done_message(port, node, pname) do
    receive do
      {:ok, {:port_setup_completed, node, pname}} ->
        IO.puts("Node #{node} with process #{pname} setup completed")

      {^port, {:data, data}} ->
        IO.puts("loop received : #{inspect(data)}")
        parse_port_setup_done_message(port, node, pname)

      res ->
        IO.puts("Loop received unexpected: #{inspect(res)}")
        parse_port_setup_done_message(port, node, pname)
    end
  end
end
