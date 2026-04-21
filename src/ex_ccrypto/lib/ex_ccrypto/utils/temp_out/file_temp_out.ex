defmodule ExCcrypto.Utils.TempOut.FileTempOut do
  alias ExCcrypto.Utils.TempOut.FileTempOut
  use TypedStruct

  @type return_mode :: :binary | :path

  typedstruct do
    field(:session, any())
    field(:output_path, binary(), default: nil)
    field(:random_path, boolean(), default: true)
    field(:return_mode, return_mode, default: :binary)
  end

  def set_temp_out_path(ctx, path) do
    %FileTempOut{ctx | random_path: false, output_path: path}
  end

  def set_return_mode(ctx, mode) do
    %FileTempOut{ctx | return_mode: mode}
  end
end

alias ExCcrypto.Utils.TempOut

defimpl TempOut, for: ExCcrypto.Utils.TempOut.FileTempOut do
  alias ExCcrypto.Utils.TempOut.FileTempOut

  def init(%FileTempOut{output_path: nil} = conf, _opts) do
    out = Path.join(System.tmp_dir!(), :crypto.strong_rand_bytes(16) |> Base.encode16())
    TempOut.init(%{conf | output_path: out})
  end

  def init(ctx, _opts) do
    %FileTempOut{output_path: name} = ctx
    fp = File.open!(name, [:write, :binary])
    %{ctx | session: fp}
  end

  def update(ctx, data) do
    :file.write(ctx.session, data)
    %{ctx | session: ctx.session}
  end

  def final(ctx) do
    :file.close(ctx.session)
    prep_for_return(ctx)
  end

  defp prep_for_return(%{return_mode: :path} = ctx), do: ctx.output_path

  defp prep_for_return(%{return_mode: :binary} = ctx) do
    cont = File.read!(ctx.output_path)
    remove_temp_path(ctx)
    cont
  end

  defp remove_temp_path(%{random_path: true, return_mode: :binary} = ctx),
    do: File.rm(ctx.output_path)

  defp remove_temp_path(ctx), do: ctx
end
