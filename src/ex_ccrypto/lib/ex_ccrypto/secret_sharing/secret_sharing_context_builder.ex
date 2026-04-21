defmodule ExCcrypto.SecretSharing.SecretSharingContextBuilder do
  alias ExCcrypto.SecretSharing.ShamirContext
  def secret_sharing_context(algo \\ :shamir)

  def secret_sharing_context(:shamir) do
    %ShamirContext{}
  end
end
