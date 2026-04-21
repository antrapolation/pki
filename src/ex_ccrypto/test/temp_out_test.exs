defmodule TempOutTest do
  alias ExCcrypto.Utils.TempOut
  alias ExCcrypto.Utils.TempOut.MemoryTempOut
  alias ExCcrypto.Utils.TempOut.FileTempOut
  use ExUnit.Case

  describe "MemoryTempOut" do
    test "init returns the context unchanged" do
      ctx = %MemoryTempOut{}
      result = TempOut.init(ctx, nil)
      assert result == ctx
    end

    test "update accumulates data in session" do
      ctx =
        %MemoryTempOut{}
        |> TempOut.init()
        |> TempOut.update("hello")

      assert ctx.session == ["hello"]
    end

    test "update multiple times accumulates in reverse order" do
      ctx =
        %MemoryTempOut{}
        |> TempOut.init()
        |> TempOut.update("hello")
        |> TempOut.update(" ")
        |> TempOut.update("world")

      assert ctx.session == ["world", " ", "hello"]
    end

    test "final returns concatenated data in correct order" do
      result =
        %MemoryTempOut{}
        |> TempOut.init()
        |> TempOut.update("hello")
        |> TempOut.update(" ")
        |> TempOut.update("world")
        |> TempOut.final()

      assert result == "hello world"
    end

    test "final returns empty string when no updates" do
      result =
        %MemoryTempOut{}
        |> TempOut.init()
        |> TempOut.final()

      assert result == ""
    end

    test "handles binary data" do
      data = <<1, 2, 3, 4, 5>>

      result =
        %MemoryTempOut{}
        |> TempOut.init()
        |> TempOut.update(data)
        |> TempOut.final()

      assert result == data
    end
  end

  describe "FileTempOut" do
    test "init creates temp file when output_path is nil" do
      ctx = %FileTempOut{}
      result = TempOut.init(ctx, nil)

      assert result.output_path != nil
      assert File.exists?(result.output_path)
      assert result.random_path == true
      assert result.return_mode == :binary

      File.rm(result.output_path)
    end

    test "init uses provided output_path" do
      temp_path = Path.join("test_artifacts", "test_temp_out_#{:rand.uniform(100_000)}")
      ctx = %FileTempOut{output_path: temp_path, random_path: false}
      result = TempOut.init(ctx, nil)

      assert result.output_path == temp_path
      assert File.exists?(temp_path)

      File.close(result.session)
      File.rm(temp_path)
    end

    test "update writes data to file" do
      result =
        %FileTempOut{}
        |> TempOut.init()
        |> TempOut.update("hello")
        |> TempOut.update(" ")
        |> TempOut.update("world")

      file_path = result.output_path
      assert File.exists?(file_path)

      content = TempOut.final(result)
      assert content == "hello world"
    end

    test "final returns binary content when return_mode is :binary" do
      ctx = %FileTempOut{return_mode: :binary}

      result =
        ctx
        |> TempOut.init()
        |> TempOut.update("test data")
        |> TempOut.final()

      assert is_binary(result)
      assert result == "test data"
    end

    test "final returns file path when return_mode is :path" do
      ctx = %FileTempOut{return_mode: :path}

      result =
        ctx
        |> TempOut.init()
        |> TempOut.update("test data")
        |> TempOut.final()

      assert is_binary(result)
      assert File.exists?(result)

      content = File.read!(result)
      assert content == "test data"

      File.rm(result)
    end

    test "set_temp_out_path sets output path and disables random_path" do
      ctx = %FileTempOut{}
      result = FileTempOut.set_temp_out_path(ctx, "/custom/path")

      assert result.output_path == "/custom/path"
      assert result.random_path == false
    end

    test "set_return_mode changes return mode" do
      ctx = %FileTempOut{return_mode: :binary}
      result = FileTempOut.set_return_mode(ctx, :path)

      assert result.return_mode == :path
    end

    test "removes temp file when random_path is true and return_mode is :binary" do
      ctx = %FileTempOut{random_path: true, return_mode: :binary}

      result =
        ctx
        |> TempOut.init()
        |> TempOut.update("test")

      file_path = result.output_path
      TempOut.final(result)

      refute File.exists?(file_path)
    end

    test "keeps temp file when random_path is false" do
      temp_path = Path.join("test_artifacts", "test_temp_out_keep_#{:rand.uniform(100_000)}")
      ctx = %FileTempOut{output_path: temp_path, random_path: false, return_mode: :binary}

      result =
        ctx
        |> TempOut.init()
        |> TempOut.update("test")

      TempOut.final(result)

      assert File.exists?(temp_path)

      File.rm(temp_path)
    end

    test "handles binary data" do
      data = <<1, 2, 3, 4, 5>>

      result =
        %FileTempOut{}
        |> TempOut.init()
        |> TempOut.update(data)
        |> TempOut.final()

      assert result == data
    end
  end
end
