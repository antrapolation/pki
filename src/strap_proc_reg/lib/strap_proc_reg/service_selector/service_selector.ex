defprotocol StrapProcReg.ServiceSelector do
  def get_service(selector, options, opts \\ nil)
end
