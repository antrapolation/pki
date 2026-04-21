defmodule StrapPrivKeyStoreProvider.RemoteUtils do
  def call(gname, params, opts \\ %{}) do
    case StrapProcReg.avail_services(%{group: gname, selector: :random}) do
      nil ->
        {:error, {:service_is_not_registered, gname}}

      pid ->
        timeout = Map.get(opts, :timeout, 5_000)
        GenServer.call(pid, params, timeout)
    end
  end
end
