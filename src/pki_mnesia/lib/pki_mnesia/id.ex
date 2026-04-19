defmodule PkiMnesia.Id do
  @moduledoc """
  UUIDv7 generation for Mnesia record primary keys.
  UUIDv7 is time-ordered, which gives natural chronological ordering in Mnesia.
  """

  @doc "Generate a new UUIDv7 string."
  @spec generate() :: String.t()
  def generate do
    Uniq.UUID.uuid7()
  end
end
