defmodule StrapProcReg.ServiceSelector.RandomServiceSelector do
  alias StrapProcReg.ServiceSelector.RandomServiceSelector
  use TypedStruct

  typedstruct do
    field(:start_position, any())
  end

  def new(start_position \\ :random)

  def new(nil), do: new(:random)

  def new(start_position) do
    %RandomServiceSelector{
      start_position: start_position
    }
  end
end

defimpl StrapProcReg.ServiceSelector, for: StrapProcReg.ServiceSelector.RandomServiceSelector do
  alias StrapProcReg.ServiceSelector.RandomServiceSelector

  def get_service(_sel, [], _opts), do: nil
  def get_service(_sel, nil, _opts), do: nil

  def get_service(%RandomServiceSelector{start_position: :random}, options, _opts)
      when is_list(options),
      do: Enum.random(options)
end
