defmodule ExJrubyPortTest do
  alias ExJrubyPort.JrubyJarContext
  alias ExJrubyPort.JrubyService
  alias ExJrubyPort.JrubyContext
  use ExUnit.Case

  # setup do
  #  Node.start(:exjrubyport@localhost, :shortnames)
  #  Node.set_cookie(:testing_for_ex_jruby_port)

  #  :ok
  # end

  test "Calling JRuby using jruby-complete.jar direct from Elixir" do
    {:ok, pid} = ExJrubyPort.start_link(%JrubyJarContext{})
    {:ok, res} = ExJrubyPort.run(pid, "./test/jruby/hello.rb")
    IO.inspect(res)
    # assert(res == "Hello from JRuby!\n")

    {:ok, res2} = ExJrubyPort.run(pid, "./test/jruby/hello.rb", ["world"])
    IO.inspect(res2)
    # assert(res2 == "Hello World!\n")

    {:ok, spid} =
      ExJrubyPort.start_node(pid, "./test/jruby/server_jar.rb")

    IO.inspect(spid)

    {:ok, rres} = JrubyService.invoke(spid, "RubyTest::RubyServer", "say", ["hello", "world"])
    IO.puts("Elixir side : #{inspect(rres)}")

    {:ok, rres2} = JrubyService.call(spid, {:hello, :world})
    IO.puts("Elixir side : #{inspect(rres2)}")

    # {:ok, rres2} = JRubyService.invoke(spid, "", "puts", "This is message from Elixir")
    # IO.puts("Elixir side : #{inspect(rres2)}")

    # {:error, erres} = JRubyService.invoke(spid, "", "split", "This is message from Elixir")
    # IO.inspect(erres)

    # {:ok, rres3} =
    #  JRubyService.invoke(spid, "\"This is message from Elixir to split\"", "split", " ")

    # IO.inspect(rres3)

    # {:ok, srres1} =
    #  JRubyService.invoke(spid, "RubyTest::SecondClass", "new", [], %{as_var: :jan})

    # IO.puts("Elixir side : #{inspect(srres1)}")

    # {:ok, srres2} =
    #  JRubyService.invoke(spid, "@jan", "say_some", "January is here")

    # IO.puts("Elixir side : #{inspect(srres2)}")

    JrubyService.stop(spid)
  end

  test "Calling JRuby using jruby script from Elixir" do
    {:ok, pid} = ExJrubyPort.start_link(JrubyContext.new())
    {:ok, res} = ExJrubyPort.run(pid, "./test/jruby/hello.rb")
    IO.inspect(res)
    # assert(res == "Hello from JRuby!\n")

    {:ok, res2} = ExJrubyPort.run(pid, "./test/jruby/hello.rb", ["world"])
    IO.inspect(res2)
    # assert(res2 == "Hello World!\n")

    {:ok, spid} =
      ExJrubyPort.start_node(pid, "./test/jruby/server_jruby_script.rb")

    IO.inspect(spid)

    {:ok, rres} = JrubyService.invoke(spid, "RubyTest::RubyServer", "say", ["hello", "world"])
    IO.puts("Elixir side : #{inspect(rres)}")

    {:ok, rres2} = JrubyService.call(spid, {:hello, :world})
    IO.puts("Elixir side : #{inspect(rres2)}")

    # {:ok, rres2} = JRubyService.invoke(spid, "", "puts", "This is message from Elixir")
    # IO.puts("Elixir side : #{inspect(rres2)}")

    # {:error, erres} = JRubyService.invoke(spid, "", "split", "This is message from Elixir")
    # IO.inspect(erres)

    # {:ok, rres3} =
    #  JRubyService.invoke(spid, "\"This is message from Elixir to split\"", "split", " ")

    # IO.inspect(rres3)

    # {:ok, srres1} =
    #  JRubyService.invoke(spid, "RubyTest::SecondClass", "new", [], %{as_var: :jan})

    # IO.puts("Elixir side : #{inspect(srres1)}")

    # {:ok, srres2} =
    #  JRubyService.invoke(spid, "@jan", "say_some", "January is here")

    # JrubyService.stop(spid)

    # JrubyService.stop(spid)
  end
end
