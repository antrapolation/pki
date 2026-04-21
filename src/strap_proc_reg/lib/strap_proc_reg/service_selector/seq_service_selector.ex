defmodule StrapProcReg.ServiceSelector.SeqServiceSelector do
  alias StrapProcReg.ServiceSelector.SeqServiceSelector
  use TypedStruct

  typedstruct do
    field(:start_position, any())
    field(:current_position, any())
  end

  def new(opts \\ %{start_position: 0, current_position: 0})

  def new(opts) when is_map(opts) do
    %SeqServiceSelector{
      start_position: Map.get(opts, :start_position, 0),
      current_position: Map.get(opts, :current_position, 0)
    }
  end

  def inc_position(%SeqServiceSelector{} = sel),
    do: %SeqServiceSelector{sel | current_position: sel.current_position + 1}

  def get_current_position(%SeqServiceSelector{} = sel), do: sel.current_position
end

defimpl StrapProcReg.ServiceSelector, for: StrapProcReg.ServiceSelector.SeqServiceSelector do
  alias StrapProcReg.ServiceSelector.SeqServiceSelector

  def get_service(_sel, [], _opts), do: nil
  def get_service(_sel, nil, _opts), do: nil

  def get_service(%SeqServiceSelector{} = sel, options, _opts) when is_list(options) do
    sel = SeqServiceSelector.inc_position(sel)
    # modulus
    indx = rem(SeqServiceSelector.get_current_position(sel), length(options))
    {options[indx], sel}
  end
end
