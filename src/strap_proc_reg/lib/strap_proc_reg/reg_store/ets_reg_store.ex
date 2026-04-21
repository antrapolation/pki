defmodule StrapProcReg.RegStore.EtsRegStore do
  alias StrapProcReg.GroupSpec
  alias StrapProcReg.DomainSpec
  alias StrapProcReg.RegStore.EtsRegStore
  use TypedStruct

  use GenServer

  require Logger

  typedstruct do
    field(:domain, any())
    field(:domain_spec, any())
    field(:group, any())
    field(:group_spec, any())
    field(:process_name, any())
    field(:pid, any())
    field(:pid_info, any())
  end

  def proc_reg_to_store(%StrapProcReg{} = reg) do
    EtsRegStore.new(reg.name)
    |> EtsRegStore.set_domain(reg.domain, reg.domain_spec)
    |> EtsRegStore.set_group(reg.group, reg.group_spec)
    |> EtsRegStore.set_pid(reg.pid, reg.pid_info)
    |> EtsRegStore.apply_default_domain()
  end

  def new(pname \\ nil)

  # def new(nil), do: %EtsRegStore{} |> generate_random_process_name()

  def new(pname), do: %EtsRegStore{process_name: pname}

  def set_domain(%EtsRegStore{} = store, domain, spec \\ DomainSpec.new()),
    do: %EtsRegStore{store | domain: domain, domain_spec: spec}

  def set_group(%EtsRegStore{} = store, group, spec \\ GroupSpec.new()),
    do: %EtsRegStore{store | group: group, group_spec: spec}

  def set_pid(%EtsRegStore{} = store, pid, spec \\ nil),
    do: %EtsRegStore{store | pid: pid, pid_info: spec}

  def apply_default_domain(%EtsRegStore{domain: domain} = store) when is_nil(domain),
    do: %EtsRegStore{store | domain: :reg_store_sys}

  def apply_default_domain(%EtsRegStore{} = store), do: store

  def generate_random_process_name(%EtsRegStore{} = store),
    do: %EtsRegStore{store | process_name: :crypto.strong_rand_bytes(24) |> Base.encode16()}

  @default_name :ets_strap_proc_reg_store
  # 
  # GenServer functions
  #
  def start_link(name \\ @default_name) do
    GenServer.start_link(__MODULE__, %{}, name: name)
  end

  def create_db(store, opts \\ %{}), do: GenServer.call(@default_name, {:create, store, opts})

  def destroy_db(store, opts), do: GenServer.call(@default_name, {:destroy, store, opts})

  def save(target, ops, opts), do: GenServer.call(@default_name, {:save, target, ops, opts})

  def delete(target, opts), do: GenServer.call(@default_name, {:delete, target, opts})

  def find(target, opts), do: GenServer.call(@default_name, {:find, target, opts})

  def run(%EtsRegStore{} = _sel, {:to_store_context, %StrapProcReg{} = reg}, _opts),
    do: EtsRegStore.proc_reg_to_store(reg)

  def run(target, ops, opts), do: GenServer.call(@default_name, {:run, target, ops, opts})

  def stop(_target), do: GenServer.stop(@default_name)

  def init(_args) do
    {:ok, %{}}
  end

  def handle_call({:create, _target, %{owner_pid: nil}}, _from, state),
    do: {:reply, {:error, :owner_pid_cannot_be_nil}, state}

  def handle_call({:create, target, %{owner_pid: pid}}, _from, state) do
    Logger.debug("in create function : #{inspect(target)}")

    ret =
      case :ets.whereis(target.domain) do
        :undefined ->
          Logger.debug("Creating domain : #{inspect(target)} / #{inspect(self())}")
          :ets.new(target.domain, [:set, :public, :named_table, {:heir, self(), %{}}])
          :ets.give_away(target.domain, pid, %{})

        ets_pid ->
          Logger.debug("No creating of domain. Found existing ets pid : #{inspect(ets_pid)}")
          :ets.give_away(target.domain, pid, %{})
      end

    {:reply, ret, state}
  end

  def handle_call({:destory, target, _opts}, _from, state) do
    Logger.debug("Deleting domain : #{inspect(target)}")
    {:reply, :ets.delete(target.domain), state}
  end

  def handle_call({:save, %EtsRegStore{} = store, :domain_spec, _opts}, _from, state) do
    {:reply, :ets.insert(store.domain, {{:domain_spec, store.domain}, store.domain_spec}), state}
  end

  def handle_call({:save, %EtsRegStore{} = store, :group_spec, _opts}, _from, state) do
    {:reply, :ets.insert(store.domain, {{:group_spec, store.domain}, store.group_spec}), state}
  end

  def handle_call({:save, %EtsRegStore{} = store, {:remote_node, node}, _opts}, _from, state) do
    ret =
      case :ets.lookup(store.domain, {:remote_node, store.domain}) do
        [] ->
          :ets.insert_new(store.domain, {{:remote_node, store.domain}, [node]})

        [res] ->
          {_key, nodes} = res
          :ets.insert(store.domain, {{:remote_node, store.domain}, nodes ++ [node]})
      end

    {:reply, ret, state}
  end

  def handle_call(
        {:save, %EtsRegStore{group: group, process_name: nil, pid: pid, pid_info: pinfo} = store,
         :register, _opts},
        _from,
        state
      ) do
    Logger.debug("register process : #{inspect(store)}")

    {:reply, :ets.insert_new(store.domain, {pid, nil, group, {pid, pinfo}}), state}
  end

  def handle_call(
        {:save,
         %EtsRegStore{group: group, process_name: pname, pid: pid, pid_info: pinfo} = store,
         :register, _opts},
        _from,
        state
      ) do
    Logger.debug("register process with user given process name: #{inspect(store)}")

    # make sure process name has no conflict
    case :ets.match(store.domain, {:_, pname, :_, :_}) do
      [] ->
        Process.register(pid, pname)
        {:reply, :ets.insert_new(store.domain, {pid, pname, group, {pid, pinfo}}), state}

      _res ->
        {:reply, {:error, {:process_name_already_exist, pname}}, state}
    end
  end

  def handle_call({:delete, %EtsRegStore{pid: pid} = store, _opts}, _from, state)
      when not is_nil(pid) do
    case :ets.lookup(store.domain, pid) do
      [] ->
        :ok

      [res] ->
        {_, pname, _, _} = res

        case Process.whereis(pname) do
          nil ->
            # name not registered
            nil

          _fpid ->
            Process.unregister(pname)
        end
    end

    {:reply, :ets.delete(store.domain, pid), state}
  end

  def handle_call({:delete, %EtsRegStore{} = store, {:remote_node, node}}, _from, state) do
    retVal =
      case :ets.lookup(store.domain, {:remote_node, store.domain}) do
        [] ->
          :ok

        [res] ->
          {_key, val} = res
          :ets.insert(store.domain, {{:remote_node, store.domain}, List.delete(val, node)})
      end

    {:reply, retVal, state}
  end

  def handle_call({:find, %EtsRegStore{} = target, :remote_node}, _from, state) do
    Logger.debug(" Find remote node : #{inspect(target)} ")

    retVal =
      case :ets.lookup(target.domain, {:remote_node, target.domain}) do
        [] ->
          []

        [res] ->
          {_key, nodes} = res
          nodes
      end

    {:reply, retVal, state}
  end

  def handle_call({:find, %EtsRegStore{group: group} = target, opts}, _from, state) do
    Logger.debug(" Lookup by group : #{inspect(target)} / #{inspect(opts)}")
    res = :ets.match(target.domain, {:_, :_, group, :"$1"})

    res =
      Enum.map(res, fn r ->
        List.first(r)
      end)

    retVal =
      case opts do
        :random ->
          Enum.random(res)

        _ ->
          res
      end

    {:reply, retVal, state}
  end

  # defp find_return(result, %{return_info: :pid_only}) do
  #  {pid, _info} = result
  #  pid
  # end

  # defp find_return(result, _), do: result

  def handle_info({:"ETS-TRANSFER", table, _pid, _data}, state) do
    Logger.debug("Detected Strap Registry died. Taking back control of table #{table}")
    {:noreply, state}
  end

  # def run(%EtsRegStore{} = _sel, {:to_store_context, %StrapProcReg{} = reg}, _opts),
  #  do: EtsRegStore.proc_reg_to_store(reg)
end

defimpl StrapProcReg.RegStore.StrapProcRegStore, for: StrapProcReg.RegStore.EtsRegStore do
  alias StrapProcReg.RegStore.EtsRegStore

  require Logger

  def start_up(%EtsRegStore{} = _store, _opts) do
    EtsRegStore.start_link()
  end

  def shutdown(%EtsRegStore{} = ctx, _opts), do: EtsRegStore.stop(ctx)

  def create(%EtsRegStore{} = store, opts) do
    # Logger.debug("Creating domain : #{inspect(store)}")
    # :ets.new(store.domain, [:set, :public, :named_table])
    EtsRegStore.create_db(store, opts)
  end

  def destroy(%EtsRegStore{} = store, opts) do
    # Logger.debug("Deleting domain : #{inspect(store)}")
    # :ets.delete(store.domain)
    EtsRegStore.destroy_db(store, opts)
  end

  def save(store, ops, opts), do: EtsRegStore.save(store, ops, opts)

  # def save(
  #      %EtsRegStore{} = store,
  #      :domain_spec,
  #      _opts
  #    ) do
  #  :ets.insert(store.domain, {{:domain_spec, store.domain}, store.domain_spec})
  # end

  # def save(
  #      %EtsRegStore{} = store,
  #      :group_spec,
  #      _opts
  #    ) do
  #  :ets.insert(store.domain, {{:group_spec, store.group}, store.group_spec})
  # end

  # def save(
  #      %EtsRegStore{group: group, process_name: nil, pid: pid, pid_info: pinfo} = store,
  #      :register,
  #      _opts
  #    ) do
  #  Logger.debug("register process : #{inspect(store)}")

  #  :ets.insert_new(store.domain, {pid, nil, group, {pid, pinfo}})
  # end

  # def save(
  #      %EtsRegStore{group: group, process_name: pname, pid: pid, pid_info: pinfo} = store,
  #      :register,
  #      _opts
  #    ) do
  #  Logger.debug("register process with user given process name: #{inspect(store)}")

  #  # make sure process name has no conflict
  #  case :ets.match(store.domain, {:_, pname, :_, :_}) do
  #    [] ->
  #      Process.register(pid, pname)
  #      :ets.insert_new(store.domain, {pid, pname, group, {pid, pinfo}})

  #    _res ->
  #      {:error, {:process_name_already_exist, pname}}
  #  end
  # end

  def delete(target, opts), do: EtsRegStore.delete(target, opts)
  # def delete(%EtsRegStore{pid: pid} = store, _opts)
  #    when not is_nil(pid) do
  #  case :ets.lookup(store.domain, pid) do
  #    [] ->
  #      :ok

  #    [res] ->
  #      {_, pname, _, _} = res

  #      case Process.whereis(pname) do
  #        nil ->
  #          # name not registered
  #          nil

  #        _fpid ->
  #          Process.unregister(pname)
  #      end
  #  end

  #  :ets.delete(store.domain, pid)
  # end

  def find(target, opts), do: EtsRegStore.find(target, opts)

  def run(target, ops, opts), do: EtsRegStore.run(target, ops, opts)
  # def run(%EtsRegStore{} = _sel, {:to_store_context, %StrapProcReg{} = reg}, _opts),
  #  do: EtsRegStore.proc_reg_to_store(reg)
end
