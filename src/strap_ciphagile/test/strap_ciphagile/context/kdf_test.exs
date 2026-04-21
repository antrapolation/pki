defmodule StrapCiphagile.Context.KDFTest do
  use ExUnit.Case
  alias StrapCiphagile.Context.KDF
  alias StrapCiphagile.Context.Argon2Config
  alias StrapCiphagile.Context.PBKDF2Config
  alias StrapCiphagile.Context.ScryptConfig
  alias StrapCiphagile.Context.BCryptConfig
  alias StrapCiphagile.EncoderProtocol
  alias StrapCiphagile.DecoderProtocol

  test "encode and decode Argon2Config" do
    config = %Argon2Config{
      iteration: <<3>>,
      cost: <<12>>,
      parallel: <<4>>,
      salt: "salt",
      out_length: <<32>>
    }

    kdf = %KDF{
      version: :v1_0,
      algo: :kdf,
      variant: :argon2,
      kdf_config: config,
      input: "password"
    }

    assert {:ok, encoded} = EncoderProtocol.encode(kdf)
    assert <<0x02, _::binary>> = encoded

    assert {:ok, decoded} = DecoderProtocol.decode(%KDF{}, encoded)
    assert decoded.version == :v1_0
    assert decoded.variant == :argon2
    assert decoded.kdf_config == config
    assert decoded.input == "password"
  end

  test "encode and decode PBKDF2Config" do
    config = %PBKDF2Config{
      iteration: <<1000>>,
      salt: "salt",
      out_length: <<64>>
    }

    kdf = %KDF{
      version: :v1_0,
      algo: :kdf,
      variant: :pbkdf2,
      kdf_config: config
    }

    assert {:ok, encoded} = EncoderProtocol.encode(kdf)

    assert {:ok, decoded} = DecoderProtocol.decode(%KDF{}, encoded)
    assert decoded.variant == :pbkdf2
    assert decoded.kdf_config == config
  end

  test "encode and decode BCryptConfig" do
    config = %BCryptConfig{
      cost: <<10>>,
      salt: "salt",
      out_length: <<24>>
    }

    kdf = %KDF{
      version: :v1_0,
      algo: :kdf,
      variant: :bcrypt,
      kdf_config: config
    }

    assert {:ok, encoded} = EncoderProtocol.encode(kdf)
    assert {:ok, decoded} = DecoderProtocol.decode(%KDF{}, encoded)
    assert decoded.variant == :bcrypt
    assert decoded.kdf_config == config
  end

  test "encode and decode ScryptConfig" do
    config = %ScryptConfig{
      cost: <<16384>>,
      parallel: <<8>>,
      blocksize: <<1>>,
      salt: "salt",
      out_length: <<64>>
    }

    kdf = %KDF{
      version: :v1_0,
      algo: :kdf,
      variant: :scrypt,
      kdf_config: config
    }

    assert {:ok, encoded} = EncoderProtocol.encode(kdf)
    assert {:ok, decoded} = DecoderProtocol.decode(%KDF{}, encoded)
    assert decoded.variant == :scrypt
    assert decoded.kdf_config == config
  end

  test "StrapCiphagile decode dispatch KDF" do
    config = %PBKDF2Config{
      iteration: <<5000>>,
      salt: "mysalt",
      out_length: <<32>>
    }

    kdf = %KDF{
      version: :v1_0,
      algo: :kdf,
      variant: :pbkdf2,
      kdf_config: config
    }

    {:ok, encoded} = StrapCiphagile.encode(kdf)

    assert {:ok, decoded} = StrapCiphagile.decode(encoded)
    assert decoded.variant == :pbkdf2
    assert decoded.kdf_config == config
  end

  test "decode with trailing garbage" do
    kdf = %KDF{
      version: :v1_0,
      algo: :kdf,
      variant: :pbkdf2,
      kdf_config: %PBKDF2Config{iteration: <<1>>, salt: "s", out_length: <<1>>}
    }

    {:ok, encoded} = EncoderProtocol.encode(kdf)
    garbage = <<0xDE, 0xAD>>
    full = encoded <> garbage

    assert {:ok, {decoded, rest}} = DecoderProtocol.decode(%KDF{}, full)
    assert decoded == kdf
    assert rest == garbage
  end

  test "encode with mixed integer types" do
    # iteration as integer, out_length as string
    config = %PBKDF2Config{
      iteration: 1000,
      salt: "salt",
      out_length: "64"
    }

    kdf = %KDF{
      version: :v1_0,
      algo: :kdf,
      variant: :pbkdf2,
      kdf_config: config
    }

    assert {:ok, encoded} = EncoderProtocol.encode(kdf)
    assert {:ok, decoded} = DecoderProtocol.decode(%KDF{}, encoded)

    assert decoded.kdf_config.iteration == <<0x03, 0xE8>>
    assert decoded.kdf_config.out_length == <<0x40>>
  end

  test "encode with hex string types" do
    # iteration as hex "0x3E8" (1000)
    config = %PBKDF2Config{
      iteration: "0x3E8",
      salt: "salt",
      out_length: "0x40"
    }

    kdf = %KDF{
      version: :v1_0,
      algo: :kdf,
      variant: :pbkdf2,
      kdf_config: config
    }

    assert {:ok, encoded} = EncoderProtocol.encode(kdf)
    assert {:ok, decoded} = DecoderProtocol.decode(%KDF{}, encoded)

    assert decoded.kdf_config.iteration == <<0x03, 0xE8>>
    assert decoded.kdf_config.out_length == <<0x40>>
  end

  test "encode KDF with plain map config" do
    config_map = %{
      iteration: 2000,
      salt: "mapsalt",
      out_length: 32
    }

    kdf = %KDF{
      version: :v1_0,
      algo: :kdf,
      variant: :pbkdf2,
      kdf_config: config_map
    }

    assert {:ok, encoded} = EncoderProtocol.encode(kdf)

    # Decoding always produces structs because DecoderProtocol dispatch relies on tags
    assert {:ok, decoded} = DecoderProtocol.decode(%KDF{}, encoded)
    assert decoded.variant == :pbkdf2
    assert is_struct(decoded.kdf_config, PBKDF2Config)

    # 2000 = 0x07D0
    assert decoded.kdf_config.iteration == <<0x07, 0xD0>>
    assert decoded.kdf_config.salt == "mapsalt"
  end

  test "encode generic KDF with new/1 functionality" do
    # Argon2
    kdf_argon =
      KDF.new(
        version: :v1_0,
        algo: :kdf,
        variant: :argon2,
        kdf_config: %{
          iteration: 2,
          cost: 10,
          parallel: 2,
          salt: "s",
          out_length: 16
        }
      )

    assert {:ok, encoded} = EncoderProtocol.encode(kdf_argon)
    assert {:ok, decoded} = DecoderProtocol.decode(%KDF{}, encoded)
    assert is_struct(decoded.kdf_config, Argon2Config)
    assert decoded.kdf_config.iteration == <<2>>
  end

  test "use KDF helper functions to set config" do
    kdf =
      KDF.new()
      |> KDF.set_config(:pbkdf2, %{iteration: 1000, salt: "helper", out_length: 32})

    assert kdf.variant == :pbkdf2
    assert is_struct(kdf.kdf_config, PBKDF2Config)

    assert {:ok, encoded} = EncoderProtocol.encode(kdf)
    assert {:ok, decoded} = DecoderProtocol.decode(%KDF{}, encoded)
    assert decoded.variant == :pbkdf2
    assert decoded.kdf_config.salt == "helper"

    # Test chainability or switching
    kdf_argon =
      kdf
      |> KDF.set_config(:argon2,
        iteration: 2,
        cost: 10,
        parallel: 4,
        salt: "argon",
        out_length: 64
      )

    assert kdf_argon.variant == :argon2
    assert is_struct(kdf_argon.kdf_config, Argon2Config)
    assert {:ok, _} = EncoderProtocol.encode(kdf_argon)
  end
end
