defmodule StrapProcReg do
  @moduledoc """
  Process Registry to be used in STRAP project
  However each process registry has pros and cons and 
  there should not be one-size-fit-all solution.
  Target to implement as protocol that supports 
  - Syn [https://github.com/ostinelli/syn] - Eventual consistant (Availability over Consistancy) - AP?
  - gproc [https://github.com/uwiger/gproc]
  - Horde.Registry [https://github.com/derekkraan/horde] - AP?

  From Erlang core:
  - global (Erlang core) - Consistancy over Availability - CP but no group support. Group support in pg
  - pg (Erlang core) - Eventual Consistancy - AP?
  """
  alias StrapProcReg.RegStore.EtsRegStore
  alias StrapProcReg.ServiceSelector.SeqServiceSelector
  alias StrapProcReg.ServiceSelector
  alias StrapProcReg.ServiceSelector.RandomServiceSelector
  alias StrapProcReg.RegStore.StrapProcRegStore
  alias StrapProcReg.GroupSpec
  alias StrapProcReg.DomainSpec

  use TypedStruct

  require Logger

  typedstruct do
    field(:name, any())
    field(:group, any())
    field(:group_spec, GroupSpec.t())
    field(:domain, any())
    field(:domain_spec, DomainSpec.t())
    field(:pid, any())
    field(:pid_info, any())
    # allow changing of ETS back end
    field(:reg_store, any())
    field(:heartbeat_period, any())
    # :registration or :discovery
    # to support whereis_name() function dualuse
    field(:operation, any())
  end

  @reg_store Application.compile_env(:strap_proc_reg, :reg_store_provider, EtsRegStore)

  @default_domain :proc_reg_sys

  # 5 minutes
  @default_heartbeat 300_000

  def new(spec \\ %{}) when is_map(spec) do
    Logger.debug("new params : #{inspect(spec)}")

    %StrapProcReg{
      domain: Map.get(spec, :domain, @default_domain),
      group: Map.get(spec, :group),
      name: Map.get(spec, :name),
      reg_store: apply(@reg_store, :new, []),
      heartbeat_period: Map.get(spec, :heartbeat_period, @default_heartbeat),
      operation: Map.get(spec, :operation, :discovery),
      group_spec: GroupSpec.new()
    }
    |> StrapProcReg.set_service_selector(Map.get(spec, :service_selector, :random))
    |> StrapProcReg.set_return_service_info(Map.get(spec, :return_service_info, :pid_only))
  end

  def name(name \\ nil)

  def name(nil) do
    %StrapProcReg{
      domain: @default_domain,
      reg_store: apply(@reg_store, :new, []),
      # 5 minutes
      heartbeat_period: @default_heartbeat,
      operation: :discovery,
      group_spec: GroupSpec.new()
    }
  end

  def name(name) when is_atom(name) do
    %StrapProcReg{
      name: name,
      domain: @default_domain,
      reg_store: apply(@reg_store, :new, []),
      # 5 minutes
      heartbeat_period: @default_heartbeat,
      operation: :discovery,
      group_spec: GroupSpec.new()
    }
  end

  def group(group \\ nil) do
    %StrapProcReg{
      group: group,
      domain: @default_domain,
      reg_store: apply(@reg_store, :new, []),
      # 5 minutes
      heartbeat_period: @default_heartbeat,
      operation: :discovery,
      group_spec: GroupSpec.new()
    }
  end

  def set_process_name(%StrapProcReg{} = reg, name), do: %StrapProcReg{reg | name: name}

  def set_domain(%StrapProcReg{} = reg, domain, spec \\ DomainSpec.new()),
    do: %StrapProcReg{reg | domain: domain, domain_spec: spec}

  def set_group(%StrapProcReg{} = reg, group, spec \\ GroupSpec.new()),
    do: %StrapProcReg{reg | group: group, group_spec: spec}

  def set_pid(%StrapProcReg{} = reg, pid, pid_info \\ nil),
    do: %StrapProcReg{reg | pid: pid, pid_info: pid_info}

  def get_default_heartbeat(), do: @default_heartbeat

  def set_service_selector(%StrapProcReg{} = reg, selector),
    do: %StrapProcReg{reg | group_spec: GroupSpec.set_service_selector(reg.group_spec, selector)}

  def set_return_service_info(%StrapProcReg{} = reg, info),
    do: %StrapProcReg{reg | group_spec: GroupSpec.set_return_service_info(reg.group_spec, info)}

  def set_service_selector_priority_local(%StrapProcReg{} = reg),
    do: %StrapProcReg{
      reg
      | group_spec: GroupSpec.set_service_selector_priority_local(reg.group_spec)
    }

  def set_service_selector_priority_remote(%StrapProcReg{} = reg),
    do: %StrapProcReg{
      reg
      | group_spec: GroupSpec.set_service_selector_priority_remote(reg.group_spec)
    }

  # 
  # End struct handling
  #

  use GenServer

  require Logger

  @default_process_name :strap_proc_reg

  def start_link(config) do
    GenServer.start_link(__MODULE__, config, name: @default_process_name)
  end

  def get_default_process_name(), do: @default_process_name

  def init(%StrapProcReg{} = config) do
    reg_store = to_store_context(config)

    StrapProcRegStore.create(reg_store, %{owner_pid: self()})

    case config.domain_spec do
      nil ->
        nil

      _dom_spec ->
        Logger.debug("Domain spec not empty. Inserting domain spec")
        StrapProcRegStore.save(reg_store, :domain_spec)
    end

    case config.group_spec do
      nil ->
        nil

      _gspec ->
        Logger.debug("Group spec not empty. Inserting group spec")
        StrapProcRegStore.save(reg_store, :group_spec)
    end

    :net_kernel.monitor_nodes(true)

    # setup the heartbeat
    Process.send_after(
      self(),
      :heartbeat,
      Map.get(config, :heartbeat_period, StrapProcReg.get_default_heartbeat())
    )

    {:ok, %{config: config}}
  end

  import Kernel, except: [send: 2]

  # 
  # Custom Process Registry Callback
  #
  @spec whereis_name(name :: any()) :: list() | :undefined
  def whereis_name(%StrapProcReg{operation: :register} = name) do
    Logger.debug(" whereis_name (register) : #{inspect(name)}")
    GenServer.call(@default_process_name, {:whereis, name})
  end

  def whereis_name(%StrapProcReg{operation: :discovery} = name) do
    Logger.debug(" whereis_name (discovery) : #{inspect(name)}")
    avail_services(name)
    # GenServer.call(@default_process_name, {:whereis, name})
  end

  def whereis_name(name) when is_map(name), do: whereis_name(StrapProcReg.new(name))

  @spec register_name(name :: any(), pid :: pid()) :: :yes | :no
  def register_name(%StrapProcReg{} = name, pid) do
    Logger.debug(" register_name : #{inspect(name)}")
    GenServer.call(@default_process_name, {:register, name |> StrapProcReg.set_pid(pid)})
  end

  def register_name(name, pid) when is_map(name), do: register_name(StrapProcReg.new(name), pid)
  #  Logger.debug(" register_name : #{inspect(name)}")

  #  GenServer.call(
  #    @default_process_name,
  #    {:register, StrapProcReg.new(name) |> StrapProcReg.set_pid(pid)}
  #  )
  # end

  def unregister_name(name) do
    Logger.debug(" unregister_name : #{inspect(name)}")
    GenServer.call(@default_process_name, {:unregister, name})
  end

  def send(name, msg) do
    Logger.debug(" send : #{inspect(name)}")
    GenServer.call(@default_process_name, {:send, name, msg})
  end

  # 
  # End Custom Process Registry Callback
  #

  # 
  # StrapProcReg management functions
  #
  def local_services(
        name,
        opts \\ %{}
      )

  # return locally registered PIDs
  def local_services(%StrapProcReg{} = name, opts) when is_map(opts) do
    GenServer.call(
      @default_process_name,
      {:local_services, name, opts}
    )
  end

  def local_services(%{} = name, opts), do: local_services(StrapProcReg.new(name), opts)

  # remote registered nodes
  def remote_nodes(
        %StrapProcReg{} = selector \\ StrapProcReg.new(),
        opts \\ %{}
      )
      when is_map(opts) do
    GenServer.call(@default_process_name, {:remote_nodes, selector, opts})
  end

  # returns all remotely registered services from give node
  def remote_services(node, selector, opts \\ %{})

  def remote_services(
        node,
        %StrapProcReg{} = selector,
        opts
      )
      when is_map(opts) do
    GenServer.call(
      @default_process_name,
      {:remote_services, node, selector, opts}
    )
  end

  def remote_services(
        node,
        %{} = selector,
        opts
      )
      when is_map(opts),
      do: remote_services(node, StrapProcReg.new(selector), opts)

  # avail_services()
  def avail_services(selector, opts \\ %{})

  def avail_services(
        %StrapProcReg{group_spec: %GroupSpec{service_selector_priority: :remote}} = selector,
        opts
      ) do
    selNode =
      case remote_nodes(StrapProcReg.new(), opts) do
        y when y in [nil, []] ->
          nil

        nodes when is_list(nodes) ->
          # default always random 
          Enum.random(nodes)

        node ->
          node
      end

    case selNode do
      nil ->
        local_services(selector, opts)

      node ->
        Logger.info("Looking for available service at node : #{inspect(node)}")
        remote_services(node, selector, opts)
    end
  end

  def avail_services(%StrapProcReg{} = selector, opts) do
    case local_services(selector, opts) do
      x when x in [nil, []] ->
        selNode =
          case remote_nodes(StrapProcReg.new(), opts) do
            y when y in [nil, []] ->
              nil

            nodes when is_list(nodes) ->
              # default always random 
              Enum.random(nodes)

            node ->
              node
          end

        Logger.info("Looking for available service at node : #{inspect(selNode)}")
        remote_services(selNode, selector, opts)

      res ->
        res
    end
  end

  def avail_services(%{} = selector, opts), do: avail_services(StrapProcReg.new(selector), opts)

  # 
  # broadcast
  #
  def broadcast(selector, msg, opts \\ %{})

  def broadcast(
        %StrapProcReg{group_spec: %GroupSpec{service_selector_priority: :remote}} = selector,
        msg,
        %{} = opts
      ) do
    Logger.info("broadcast with priority remote services")

    rret =
      for node <- remote_nodes(StrapProcReg.new()), reduce: [] do
        nacc ->
          Logger.debug("calling remote services on note : #{inspect(node)}")

          rres =
            for rsvr <-
                  remote_services(node, selector |> StrapProcReg.set_service_selector(:all), opts),
                reduce: [] do
              acc ->
                ret =
                  try do
                    case Map.get(opts, :method) do
                      :call ->
                        GenServer.call(rsvr, msg)

                      :cast ->
                        GenServer.cast(rsvr, msg)

                      _ ->
                        Kernel.send(rsvr, msg)
                    end
                  catch
                    kind, reason ->
                      formatted = Exception.format(kind, reason, __STACKTRACE__)
                      Logger.error("broadcast/3 failed with #{formatted}")
                  end

                acc ++ [{rsvr, node, msg, ret}]
            end

          # Logger.debug("rres : #{inspect(rres)}")
          nacc ++ rres
      end

    res =
      for svr <- local_services(selector |> StrapProcReg.set_service_selector(:all), opts),
          reduce: [] do
        acc ->
          try do
            case Map.get(opts, :method) do
              :call ->
                ret = GenServer.call(svr, msg)
                acc ++ [{svr, :erlang.node(), {msg, ret}}]

              :cast ->
                ret = GenServer.cast(svr, msg)
                acc ++ [{svr, :erlang.node(), {msg, ret}}]

              _ ->
                ret = Kernel.send(svr, msg)
                acc ++ [{svr, :erlang.node(), {msg, ret}}]
            end
          catch
            kind, reason ->
              formatted = Exception.format(kind, reason, __STACKTRACE__)
              Logger.error("broadcast/3 failed with #{formatted}")
          end
      end

    # Logger.debug("Local result : #{inspect(res)}")

    # Logger.debug("res : #{inspect(res)}")
    # Logger.debug("rret : #{inspect(rret)}")
    rret ++ res
  end

  def broadcast(%StrapProcReg{} = selector, msg, %{} = opts) do
    Logger.info("broadcast with priority local services.")

    res =
      for svr <- local_services(selector |> StrapProcReg.set_service_selector(:all), opts),
          reduce: [] do
        acc ->
          try do
            case Map.get(opts, :method) do
              :call ->
                ret = GenServer.call(svr, msg)
                acc ++ [{svr, :erlang.node(), {msg, ret}}]

              :cast ->
                ret = GenServer.cast(svr, msg)
                acc ++ [{svr, :erlang.node(), {msg, ret}}]

              _ ->
                ret = Kernel.send(svr, msg)
                acc ++ [{svr, :erlang.node(), {msg, ret}}]
            end
          catch
            kind, reason ->
              formatted = Exception.format(kind, reason, __STACKTRACE__)
              Logger.error("broadcast/3 failed with #{formatted}")
          end
      end

    Logger.debug("Local result : #{inspect(res)}")

    rret =
      for node <- remote_nodes(StrapProcReg.new()), reduce: [] do
        nacc ->
          Logger.debug("calling remote services on note : #{inspect(node)}")

          rres =
            for rsvr <-
                  remote_services(node, selector |> StrapProcReg.set_service_selector(:all), opts),
                reduce: [] do
              acc ->
                ret =
                  try do
                    case Map.get(opts, :method) do
                      :call ->
                        GenServer.call(rsvr, msg)

                      :cast ->
                        GenServer.cast(rsvr, msg)

                      _ ->
                        Kernel.send(rsvr, msg)
                    end
                  catch
                    kind, reason ->
                      formatted = Exception.format(kind, reason, __STACKTRACE__)
                      Logger.error("broadcast/3 failed with #{formatted}")
                  end

                acc ++ [{rsvr, node, msg, ret}]
            end

          # Logger.debug("rres : #{inspect(rres)}")
          nacc ++ rres
      end

    # Logger.debug("res : #{inspect(res)}")
    # Logger.debug("rret : #{inspect(rret)}")
    res ++ rret
  end

  def broadcast(%{} = selector, msg, opts), do: broadcast(StrapProcReg.new(selector), msg, opts)

  def broadcast_call(%StrapProcReg{} = selector, msg) do
    Logger.debug("call 1")
    broadcast(selector, msg, %{method: :call})
  end

  def broadcast_call(%{} = selector, msg),
    do: broadcast(StrapProcReg.new(selector), msg, %{method: :call})

  def broadcast_cast(%StrapProcReg{} = selector, msg),
    do: broadcast(selector, msg, %{method: :cast})

  def broadcast_cast(%{} = selector, msg),
    do: broadcast(StrapProcReg.new(selector), msg, %{method: :cast})

  def broadcast_info(%StrapProcReg{} = selector, msg),
    do: broadcast(selector, msg, %{method: :info})

  def broadcast_info(%{} = selector, msg),
    do: broadcast(StrapProcReg.new(selector), msg, %{method: :info})

  # 
  # GenServer Callback 
  #
  def handle_call({:register, %StrapProcReg{pid: pid} = spec}, _from, state) do
    with true <-
           StrapProcRegStore.save(to_store_context(spec), :register) do
      Logger.debug("Register_name returned yes")
      Process.monitor(pid)
      {:reply, :yes, state}
    else
      err ->
        # Logger.debug("Register_name returned no : #{inspect(err)} / #{inspect(from)}")
        Logger.debug("Register_name returned no : #{inspect(err)} ")
        {:reply, :no, state}
    end
  end

  # def handle_call({:whereis, %StrapProcReg{operation: :discovery} = name}, _from, state),
  #  do: {:reply, registered_pids(name |> StrapProcReg.set_service_selector(:random)), state}

  def handle_call({:whereis, %StrapProcReg{operation: :register}}, _from, state) do
    # Logger.debug("whereis from : #{inspect(from)}")
    # Always return not found to allow multiple registration with group.
    # However shall check during register if the PID is already in database
    # {:reply, :undefined, state}
    {:reply, :undefined, state}
  end

  def handle_call({:unregister, _name}, _from, state) do
    {:reply, :ok, state}
  end

  def handle_call({:send, name, msg}, _from, state) do
    {:reply, Kernel.send(name, msg), state}
  end

  def handle_call({:local_services, %StrapProcReg{} = name, opts}, _from, state) do
    {:reply, registered_pids(name, opts), state}
  end

  def handle_call({:remote_services, node, %StrapProcReg{} = selector, opts}, _from, state) do
    case Node.ping(node) do
      :pong ->
        res =
          GenServer.call({@default_process_name, node}, {:local_services, selector, opts})

        {:reply, res, state}

      :pang ->
        {:reply, [], state}
    end
  end

  def handle_call({:remote_nodes, selector, opts}, _from, state) do
    {:reply,
     select_service(StrapProcRegStore.find(to_store_context(selector), :remote_node), opts),
     state}
  end

  # 
  # handle_info()
  #
  # handle process down event
  def handle_info({:DOWN, _ref, :process, pid, _ops}, state) do
    Logger.debug("Removing downed PID : #{inspect(pid)}")

    StrapProcRegStore.delete(to_store_context(state.config |> StrapProcReg.set_pid(pid)))

    {:noreply, state}
  end

  # handle node up event
  def handle_info({:nodeup, node}, state) do
    #  nodeup event only triggered after Node successfully connected
    ret = check_node(node, state)
    Logger.debug("Detected valid nodeup : #{inspect(ret)}")

    {:noreply, state}
  end

  # handle node down event
  def handle_info({:nodedown, node}, state) do
    Logger.info("Remote node #{inspect(node)} with strap_proc_reg running drop from list")
    StrapProcRegStore.delete(to_store_context(StrapProcReg.new()), {:remote_node, node})
    {:noreply, state}
  end

  def handle_info({:"ETS-TRANSFER", table, pid, _data}, state) do
    Logger.debug("ETS-TRANSFER : #{inspect(table)} / #{inspect(pid)}")
    {:noreply, state}
  end

  def handle_info(:heartbeat, state) do
    nodes = StrapProcRegStore.find(to_store_context(state.config), :remote_node)

    Enum.map(nodes, fn n ->
      Logger.debug("heartbeat triggered. Probing node : #{inspect(n)}")
      check_node(n, state)
    end)

    Process.send_after(
      self(),
      :heartbeat,
      Map.get(state.config, :heartbeat_period, StrapProcReg.get_default_heartbeat())
    )

    {:noreply, state}
  end

  defp check_node(node, state) do
    ctx = to_store_context(state.config)
    remote_node_record = StrapProcRegStore.find(ctx, :remote_node)

    try do
      remote_process = :erpc.call(node, Process, :whereis, [@default_process_name])

      cond do
        remote_process == nil and Enum.member?(remote_node_record, node) ->
          Logger.debug(
            "heartbeat check remote no longer has StrapProcReg but database still have the record. Deleting node #{inspect(node)}"
          )

          StrapProcRegStore.delete(ctx, {:remote_node, node})

        remote_process != nil and not Enum.member?(remote_node_record, node) ->
          Logger.debug(
            "heartbeat check remote has StrapProcReg running but database has no record. Adding node #{inspect(node)}"
          )

          StrapProcRegStore.save(ctx, {:remote_node, node})

        true ->
          Logger.debug(
            "heartbeat check remote has StrapProcReg running and already in database. No action needed"
          )

          :ok
      end
    catch
      kind, reason ->
        Logger.debug("check_node hit error of #{inspect(kind)} : #{inspect(reason)}")
    end
  end

  # defp registered_pids(target, opts \\ nil)

  defp registered_pids(%StrapProcReg{} = target, _opts) do
    res = StrapProcRegStore.find(to_store_context(target))

    fres =
      Enum.map(res, fn r ->
        find_return(r, target)
      end)

    select_service(fres, target)
  end

  defp select_service(options, %StrapProcReg{group_spec: %GroupSpec{service_selector: :random}}) do
    ServiceSelector.get_service(RandomServiceSelector.new(), options)
  end

  defp select_service(options, %StrapProcReg{group_spec: %GroupSpec{service_selector: :sequence}}) do
    ServiceSelector.get_service(SeqServiceSelector.new(), options)
  end

  defp select_service(options, %StrapProcReg{group_spec: %GroupSpec{service_selector: nil}}),
    do: options

  defp select_service(options, %StrapProcReg{group_spec: %GroupSpec{service_selector: :all}}),
    do: options

  defp select_service(options, %StrapProcReg{group_spec: %GroupSpec{service_selector: selector}}) do
    ServiceSelector.get_service(selector, options)
  end

  defp select_service(options, _opts), do: options

  defp to_store_context(%StrapProcReg{} = reg),
    do: StrapProcRegStore.run(reg.reg_store, {:to_store_context, reg}, nil)

  defp find_return(result, %StrapProcReg{group_spec: %GroupSpec{return_service_info: :pid_only}}) do
    {pid, _info} = result
    pid
  end

  defp find_return(result, _), do: result
end
