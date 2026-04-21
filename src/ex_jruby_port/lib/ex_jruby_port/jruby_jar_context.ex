defmodule ExJrubyPort.JrubyJarContext do
  alias ExJrubyPort.JrubyJarContext
  use TypedStruct

  typedstruct do
    field(:java_path, any(), default: System.find_executable("java"))

    # field(:jruby_jar_path, any(),
    #  default: Path.expand(Path.join([__DIR__, "..", "..", "jars", "jruby-complete-9.4.7.0.jar"]))
    # )

    field(:jar_path, list(),
      default: [
        Path.expand(Path.join([__DIR__, "..", "..", "jars", "jruby-complete-9.4.7.0.jar"]))
        # Path.expand(Path.join([__DIR__, "..", "..", "jars", "jruby-complete-10.0.2.0.jar"]))
      ]
    )

    field(:java_library_path, list(), default: [])
  end

  def set_java_path(ctx, path), do: %JrubyJarContext{ctx | java_path: path}

  def add_jar_path(ctx, path) when is_list(path) do
    %JrubyJarContext{ctx | jar_path: ctx.jar_path ++ path}
  end

  def add_jar_path(ctx, path) when not is_list(path) do
    %JrubyJarContext{ctx | jar_path: ctx.jar_path ++ [path]}
  end

  # def set_jruby_jar_path(ctx, path), do: %JrubyJarContext{ctx | jruby_jar_path: path}
  def add_java_library_path(ctx, path) when not is_list(path),
    do: %JrubyJarContext{ctx | java_library_path: ctx.java_library_path ++ [path]}

  def add_java_library_path(ctx, path) when is_list(path),
    do: %JrubyJarContext{ctx | java_library_path: ctx.java_library_path ++ path}
end
