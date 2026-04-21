defmodule KdfTest do
  alias ExCcrypto.KDF.KDFContextBuilder
  alias ExCcrypto.ContextConfig
  alias ExCcrypto.KDF
  use ExUnit.Case

  test "derive with Argon2 algo" do
    {:ok, res} =
      KDFContextBuilder.kdf_context(:argon2)
      |> ContextConfig.set(:out_length, 64)
      |> ContextConfig.set(:salt, :random)
      |> KDF.derive("p@ssw0rd")

    assert(byte_size(ContextConfig.get(res, :salt)) > 0)
    assert(byte_size(ContextConfig.get(res, :derived_value)) == 64)

    res2 =
      KDFContextBuilder.kdf_context(ContextConfig.get(res, :derivation_context))
      |> KDF.derive!("p@ssw0rd")

    assert(ContextConfig.get(res2, :derived_value) == ContextConfig.get(res, :derived_value))
  end

  test "predictive output with Argon2 algo" do
    {:ok, res} =
      KDFContextBuilder.kdf_context(:argon2)
      |> ContextConfig.set(:out_length, 32)
      |> ContextConfig.set(
        :salt,
        <<190, 129, 60, 155, 204, 171, 255, 214, 62, 255, 137, 227, 207, 145, 184, 226>>
      )
      |> ContextConfig.set(:out_format, :hex)
      |> KDF.derive("p@ssw0rd")

    assert(
      ContextConfig.get(res, :derived_value) ==
        "c92cd47e6c9da11d6a79199803429258dc7942cfe2e144d6c51d5c0d74c70644"
    )

    {:ok, bres} =
      KDFContextBuilder.kdf_context(ContextConfig.get(res, :derivation_context))
      |> ContextConfig.set(:out_format, :bin)
      |> KDF.derive("p@ssw0rd")

    assert(
      ContextConfig.get(bres, :derived_value) ==
        <<201, 44, 212, 126, 108, 157, 161, 29, 106, 121, 25, 152, 3, 66, 146, 88, 220, 121, 66,
          207, 226, 225, 68, 214, 197, 29, 92, 13, 116, 199, 6, 68>>
    )

    {:ok, b64res} =
      KDFContextBuilder.kdf_context(ContextConfig.get(res, :derivation_context))
      |> ContextConfig.set(:out_format, :b64)
      |> KDF.derive("p@ssw0rd")

    assert(
      ContextConfig.get(b64res, :derived_value) == "ySzUfmydoR1qeRmYA0KSWNx5Qs/i4UTWxR1cDXTHBkQ="
    )
  end
end
