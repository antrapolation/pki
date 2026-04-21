defmodule StrapProcReg.DomainSpec do
  alias StrapProcReg.DomainSpec
  use TypedStruct

  typedstruct do
    field(:blacklist, any())
  end

  def new do
    %DomainSpec{
      blacklist: []
    }
  end
end
