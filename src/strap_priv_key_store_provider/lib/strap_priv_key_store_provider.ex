defmodule StrapPrivKeyStoreProvider do
  alias StrapPrivKeyStoreProvider.RemoteUtils
  alias StrapPrivKeyStoreProvider.Protocol.ProviderInfo

  # 
  # Process API
  #
  def get_provider_context(ctx, opts \\ %{})

  def get_provider_context(%{node: node, process_group_name: gname} = ctx, opts)
      when not is_nil(gname) do
    conn =
      case node do
        nil -> {:error, :landing_node_is_not_given}
        _ -> {:ok, Node.ping(node)}
      end

    case conn do
      {:ok, :pong} ->
        # connected to the cluster node
        RemoteUtils.call(gname, {:get_provider_context, Map.merge(ctx, opts)})

      #        case StrapProcReg.avail_services(%{group: gname, selector: :random}) do
      #          nil ->
      #            {:error, {:service_is_not_registered, gname}}
      #
      #          pid ->
      #            GenServer.call(pid, {:get_provider_context, Map.merge(ctx, opts)})
      #        end

      {:ok, :pang} ->
        {:error, {:failed_to_connect_to_remote_node, node}}

      err ->
        err
    end
  end

  def get_provider_context(ctx, opts), do: ProviderInfo.get_provider_context(ctx, opts)

  def supported_key_types(ctx, opts \\ %{})

  def supported_key_types(%{process_group_name: gname} = ctx, _opts) when not is_nil(gname) do
    RemoteUtils.call(gname, {:supported_key_types, ctx})
  end

  def supported_key_types(ctx, opts), do: ProviderInfo.supported_key_types(ctx, opts)
end
