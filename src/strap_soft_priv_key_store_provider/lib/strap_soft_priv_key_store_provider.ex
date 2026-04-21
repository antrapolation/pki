defmodule StrapSoftPrivKeyStoreProvider do
  @moduledoc """
  Software Private Key Store Provider
  This module is dual-use: As process and as library
  """
  alias StrapSoftPrivKeyStoreProvider.SoftPrivkeyProviderProcess
  alias StrapSoftPrivKeyStoreProvider.Model.SoftPrivKeyProvider

  # 
  # Process API
  #
  defdelegate start_link(opts \\ %{}), to: SoftPrivkeyProviderProcess
  defdelegate stop(pid), to: SoftPrivkeyProviderProcess

  # 
  # end Process API
  #

  # 
  # Embedded API
  #
  def provider_context() do
    SoftPrivKeyProvider.new()
  end

  # 
  # End Embedded API
  #
end
