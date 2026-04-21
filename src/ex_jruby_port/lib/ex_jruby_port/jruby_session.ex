defmodule ExJrubyPort.JrubySession do
  alias ExJrubyPort.JrubyJarContext
  alias ExJrubyPort.JrubyContext
  alias ExJrubyPort.JrubySession
  use GenServer

  use TypedStruct

  typedstruct do
    field(:context, any())
  end

  def set_context(sess, ctx), do: %JrubySession{sess | context: ctx}

  def start_link(ctx) do
    sess =
      %JrubySession{}
      |> JrubySession.set_context(ctx)

    GenServer.start_link(__MODULE__, sess)
  end

  def init(%JrubySession{context: %JrubyContext{jruby_path: path}}) when is_nil(path),
    do: {:stop, {:error, :jruby_path_is_nil}}

  def init(%JrubySession{context: %JrubyJarContext{java_path: path}}) when is_nil(path),
    do: {:stop, {:error, :java_path_is_nil}}

  def init(%JrubySession{} = sess) do
    {:ok, sess}
  end

  def handle_call(
        {:run, file, params},
        _from,
        %JrubySession{context: %JrubyJarContext{} = context} = state
      ) do
    cmdline = [] ++ [context.java_path]

    cmdline =
      cmdline ++
        case Enum.empty?(context.jar_path) do
          false ->
            ["-jar"] ++ context.jar_path

          true ->
            []
        end

    cmdline = cmdline ++ [Path.expand(file)] ++ params

    port =
      Port.open(
        {:spawn, Enum.join(cmdline, " ")},
        # "#{context.java_path} -jar #{context.jruby_jar_path} #{Path.expand(file)} #{Enum.join(params, " ")}"},
        [
          :binary,
          :exit_status
        ]
      )

    res =
      receive do
        {^port, {:data, result}} -> result
      end

    Port.close(port)

    {:reply, {:ok, res}, state}
  end

  def handle_call(
        {:run, file, params},
        _from,
        %JrubySession{context: %JrubyContext{} = context} = state
      ) do
    port =
      Port.open(
        {:spawn, "#{context.jruby_path} #{Path.expand(file)} #{Enum.join(params, " ")}"},
        [
          :binary,
          :exit_status
        ]
      )

    res =
      receive do
        {^port, {:data, result}} -> result
      end

    Port.close(port)

    {:reply, {:ok, res}, state}
  end

  def handle_info(msg, _state) do
    IO.inspect("handle_info jruby_session: #{IO.inspect(msg)}")
    {:noreply, :ok}
  end
end
