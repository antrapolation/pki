defmodule StrapProcReg.GroupSpec do
  alias StrapProcReg.ServiceSelector.RandomServiceSelector
  alias StrapProcReg.GroupSpec
  use TypedStruct

  typedstruct do
    # :local, :remote
    field(:service_selector_priority, any())
    # :random, :sequence, :all / nil
    field(:service_selector, any())
    field(:return_service_info, any())
  end

  def new(%{} = spec \\ %{}) do
    %GroupSpec{
      service_selector_priority: Map.get(spec, :service_selector_priority, :local),
      return_service_info: :pid_only
    }
    |> set_service_selector(Map.get(spec, :service_selector, RandomServiceSelector.new()))
  end

  def set_service_selector_priority_local(%GroupSpec{} = spec),
    do: %GroupSpec{spec | service_selector_priority: :local}

  def set_service_selector_priority_remote(%GroupSpec{} = spec),
    do: %GroupSpec{spec | service_selector_priority: :remote}

  def get_service_selector_priority(%GroupSpec{} = spec), do: spec.service_selector_priority

  def set_service_selector(%GroupSpec{} = spec, :random),
    do: %GroupSpec{spec | service_selector: RandomServiceSelector.new()}

  def set_service_selector(%GroupSpec{} = spec, val), do: %GroupSpec{spec | service_selector: val}
  def get_service_selector(%GroupSpec{} = spec), do: spec.service_selector

  def set_return_service_info(%GroupSpec{} = spec, val),
    do: %GroupSpec{spec | return_service_info: val}

  def get_return_service_info(%GroupSpec{} = spec), do: spec.return_service_info
end
