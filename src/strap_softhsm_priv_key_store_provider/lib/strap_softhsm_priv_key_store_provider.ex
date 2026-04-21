defmodule StrapSofthsmPrivKeyStoreProvider do
  @moduledoc """
  SoftHSM Private Key Store Provider
  """
  alias StrapSofthsmPrivKeyStoreProvider.SofthsmPrivkeyProviderProcess
  alias StrapSofthsmPrivKeyStoreProvider.Model.SofthsmPrivKeyProvider

  #
  # Process API
  #
  defdelegate start_link(opts \\ %{}), to: SofthsmPrivkeyProviderProcess
  defdelegate stop(pid), to: SofthsmPrivkeyProviderProcess

  #
  # Embedded API
  #
  def provider_context() do
    SofthsmPrivKeyProvider.new()
  end
end
