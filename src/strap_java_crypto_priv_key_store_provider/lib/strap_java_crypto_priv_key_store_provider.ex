defmodule StrapJavaCryptoPrivKeyStoreProvider do
  @moduledoc """
  Java Crypto Private Key Store Provider
  This module is dual-use: As process and as library
  """
  alias StrapJavaCryptoPrivKeyStoreProvider.JavaCryptoProviderProcess
  alias StrapJavaCryptoPrivKeyStoreProvider.Model.JavaCryptoProvider

  #
  # Process API
  #
  defdelegate start_link(opts \\ %{}), to: JavaCryptoProviderProcess
  defdelegate stop(pid), to: JavaCryptoProviderProcess

  #
  # end Process API
  #

  #
  # Embedded API
  #
  def provider_context() do
    JavaCryptoProvider.new()
  end

  #
  # End Embedded API
  #
end
