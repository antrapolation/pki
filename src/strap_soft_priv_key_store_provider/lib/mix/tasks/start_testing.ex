defmodule Mix.Tasks.StartTesting do
  use Mix.Task

  def run(_args) do
    with {:ok, _} <- Application.ensure_all_started(:strap_soft_priv_key_store_provider),
         {:ok, _pid} <-
           StrapSoftPrivKeyStoreProvider.start_link(%{group: :soft_priv_key_store_test}) do
      :ok
    end
  end
end
