defmodule ExJrubyPort.JrubyContext do
  alias ExJrubyPort.JrubyContext
  use TypedStruct

  typedstruct do
    field(:jruby_path, any(), default: System.find_executable("jruby"))
    field(:with_bundle_exec?, boolean(), default: false)
  end

  def new() do
    %JrubyContext{jruby_path: System.find_executable("jruby")}
  end

  def set_jruby_path(%JrubyContext{} = ctx, path), do: %JrubyContext{ctx | jruby_path: path}

  def run_with_bundle_exec(%JrubyContext{} = ctx),
    do: %JrubyContext{ctx | with_bundle_exec?: true}

  def run_without_bundle_exec(%JrubyContext{} = ctx),
    do: %JrubyContext{ctx | with_bundle_exec?: false}

  def is_running_with_bundle_exec?(%JrubyContext{} = ctx), do: ctx.with_bundle_exec?
end
