defmodule StrapCiphagile.Context.Asymkey.Encodings do
  alias StrapCiphagile.VarLengthData

  def encode_version(:v1_0), do: {:ok, 0x01}
  def encode_version(_), do: {:error, :unsupported_version}

  def encode_asymkey_format(:pem), do: {:ok, 0x01}
  def encode_asymkey_format(:der), do: {:ok, 0x02}
  def encode_asymkey_format(:pkcs12), do: {:ok, 0x03}
  def encode_asymkey_format(:pkcs8), do: {:ok, 0x04}
  def encode_asymkey_format(:symkey_cipher), do: {:ok, 0x05}
  def encode_asymkey_format(:asymkey_cipher), do: {:ok, 0x06}
  def encode_asymkey_format(nil), do: {:ok, 0x00}
  def encode_asymkey_format(_), do: {:error, :unknown_format}

  def encode_signature_format(:raw), do: {:ok, 0x01}
  def encode_signature_format(:pkcs7), do: {:ok, 0x02}
  def encode_signature_format(:cms), do: {:ok, 0x02}
  def encode_signature_format(nil), do: {:ok, 0x00}
  def encode_signature_format(_), do: {:error, :unknown_format}

  def encode_algo(:kaz_sign), do: {:ok, 0x01}
  def encode_algo(:ml_dsa), do: {:ok, 0x02}
  def encode_algo(:slh_dsa), do: {:ok, 0x03}
  def encode_algo(:falcon), do: {:ok, 0x04}
  def encode_algo(:kaz_kem), do: {:ok, 0x10}
  def encode_algo(:ml_kem), do: {:ok, 0x11}
  def encode_algo(:kaz_ka), do: {:ok, 0x20}
  def encode_algo(:rsa), do: {:ok, 0x40}
  def encode_algo(:ecc), do: {:ok, 0x41}
  def encode_algo(_), do: {:error, :unknown_algo}

  def encode_variant(:kaz_sign, :kaz_sign_128_v1_6_4), do: {:ok, 0x01}
  def encode_variant(:kaz_sign, :kaz_sign_192_v1_6_4), do: {:ok, 0x02}
  def encode_variant(:kaz_sign, :kaz_sign_256_v1_6_4), do: {:ok, 0x03}
  def encode_variant(:kaz_sign, :kaz_sign_128_v2_0), do: {:ok, 0x05}
  def encode_variant(:kaz_sign, :kaz_sign_192_v2_0), do: {:ok, 0x06}
  def encode_variant(:kaz_sign, :kaz_sign_256_v2_0), do: {:ok, 0x07}
  def encode_variant(:kaz_sign, :kaz_sign_128_v2_1), do: {:ok, 0x09}
  def encode_variant(:kaz_sign, :kaz_sign_192_v2_1), do: {:ok, 0x0A}
  def encode_variant(:kaz_sign, :kaz_sign_256_v2_1), do: {:ok, 0x0B}

  def encode_variant(:ml_dsa, :ml_dsa_44), do: {:ok, 0x01}
  def encode_variant(:ml_dsa, :ml_dsa_65), do: {:ok, 0x02}
  def encode_variant(:ml_dsa, :ml_dsa_87), do: {:ok, 0x03}

  def encode_variant(:slh_dsa, :sha_128_s), do: {:ok, 0x01}
  def encode_variant(:slh_dsa, :sha_128_f), do: {:ok, 0x02}
  def encode_variant(:slh_dsa, :sha_192_s), do: {:ok, 0x04}
  def encode_variant(:slh_dsa, :sha_192_f), do: {:ok, 0x05}
  def encode_variant(:slh_dsa, :sha_256_s), do: {:ok, 0x07}
  def encode_variant(:slh_dsa, :sha_256_f), do: {:ok, 0x08}
  def encode_variant(:slh_dsa, :shake_128_s), do: {:ok, 0x10}
  def encode_variant(:slh_dsa, :shake_128_f), do: {:ok, 0x11}
  def encode_variant(:slh_dsa, :shake_192_s), do: {:ok, 0x13}
  def encode_variant(:slh_dsa, :shake_192_f), do: {:ok, 0x14}
  def encode_variant(:slh_dsa, :shake_256_s), do: {:ok, 0x16}
  def encode_variant(:slh_dsa, :shake_256_f), do: {:ok, 0x17}

  def encode_variant(:falcon, 512), do: {:ok, 0x01}
  def encode_variant(:falcon, 768), do: {:ok, 0x02}
  def encode_variant(:falcon, 1024), do: {:ok, 0x03}

  def encode_variant(:kaz_kem, :kaz_kem_128_v1_0), do: {:ok, 0x01}
  def encode_variant(:kaz_kem, :kaz_kem_192_v1_0), do: {:ok, 0x02}
  def encode_variant(:kaz_kem, :kaz_kem_256_v1_0), do: {:ok, 0x03}
  def encode_variant(:kaz_kem, :kaz_kem_128_v1_1), do: {:ok, 0x05}
  def encode_variant(:kaz_kem, :kaz_kem_192_v1_1), do: {:ok, 0x06}
  def encode_variant(:kaz_kem, :kaz_kem_256_v1_1), do: {:ok, 0x07}

  def encode_variant(:ml_kem, :ml_kem_512), do: {:ok, 0x01}
  def encode_variant(:ml_kem, :ml_kem_768), do: {:ok, 0x03}
  def encode_variant(:ml_kem, :ml_kem_1024), do: {:ok, 0x02}

  def encode_variant(:kaz_ka, :kaz_ka_128_v1_0), do: {:ok, 0x01}
  def encode_variant(:kaz_ka, :kaz_ka_192_v1_0), do: {:ok, 0x02}
  def encode_variant(:kaz_ka, :kaz_ka_256_v1_0), do: {:ok, 0x03}
  def encode_variant(:kaz_ka, :kaz_ka_128_v1_1), do: {:ok, 0x05}
  def encode_variant(:kaz_ka, :kaz_ka_192_v1_1), do: {:ok, 0x06}
  def encode_variant(:kaz_ka, :kaz_ka_256_v1_1), do: {:ok, 0x07}

  def encode_variant(:rsa, :rsa_1024), do: {:ok, 0x01}
  def encode_variant(:rsa, :rsa_2048), do: {:ok, 0x02}
  def encode_variant(:rsa, :rsa_3072), do: {:ok, 0x03}
  def encode_variant(:rsa, :rsa_4096), do: {:ok, 0x04}
  def encode_variant(:rsa, :rsa_8192), do: {:ok, 0x05}

  def encode_variant(:ecc, :secp112r1), do: {:ok, 0x01}
  def encode_variant(:ecc, :secp112r2), do: {:ok, 0x02}
  def encode_variant(:ecc, :secp128r1), do: {:ok, 0x03}
  def encode_variant(:ecc, :secp128r2), do: {:ok, 0x04}
  def encode_variant(:ecc, :secp160k1), do: {:ok, 0x05}
  def encode_variant(:ecc, :secp160r1), do: {:ok, 0x06}
  def encode_variant(:ecc, :secp160r2), do: {:ok, 0x07}
  def encode_variant(:ecc, :secp192k1), do: {:ok, 0x08}
  def encode_variant(:ecc, :secp192r1), do: {:ok, 0x09}
  def encode_variant(:ecc, :secp224k1), do: {:ok, 0x0A}
  def encode_variant(:ecc, :secp224r1), do: {:ok, 0x0B}
  def encode_variant(:ecc, :secp256k1), do: {:ok, 0x0C}
  def encode_variant(:ecc, :secp256r1), do: {:ok, 0x0D}
  def encode_variant(:ecc, :secp384r1), do: {:ok, 0x0E}
  def encode_variant(:ecc, :secp521r1), do: {:ok, 0x0F}
  def encode_variant(:ecc, :prime192v1), do: {:ok, 0x10}
  def encode_variant(:ecc, :prime192v2), do: {:ok, 0x11}
  def encode_variant(:ecc, :prime192v3), do: {:ok, 0x12}
  def encode_variant(:ecc, :prime239v1), do: {:ok, 0x13}
  def encode_variant(:ecc, :prime239v2), do: {:ok, 0x14}
  def encode_variant(:ecc, :prime239v3), do: {:ok, 0x15}
  def encode_variant(:ecc, :prime256v1), do: {:ok, 0x16}
  def encode_variant(:ecc, :sect113r1), do: {:ok, 0x17}
  def encode_variant(:ecc, :sect113r2), do: {:ok, 0x18}
  def encode_variant(:ecc, :sect131r1), do: {:ok, 0x19}
  def encode_variant(:ecc, :sect131r2), do: {:ok, 0x1A}
  def encode_variant(:ecc, :sect163k1), do: {:ok, 0x1B}
  def encode_variant(:ecc, :sect163r1), do: {:ok, 0x1C}
  def encode_variant(:ecc, :sect163r2), do: {:ok, 0x1D}
  def encode_variant(:ecc, :sect193r1), do: {:ok, 0x1E}
  def encode_variant(:ecc, :sect193r2), do: {:ok, 0x1F}
  def encode_variant(:ecc, :sect233k1), do: {:ok, 0x20}
  def encode_variant(:ecc, :sect233r1), do: {:ok, 0x21}
  def encode_variant(:ecc, :sect239k1), do: {:ok, 0x22}
  def encode_variant(:ecc, :sect283k1), do: {:ok, 0x23}
  def encode_variant(:ecc, :sect283r1), do: {:ok, 0x24}
  def encode_variant(:ecc, :sect409k1), do: {:ok, 0x25}
  def encode_variant(:ecc, :sect409r1), do: {:ok, 0x26}
  def encode_variant(:ecc, :sect571k1), do: {:ok, 0x27}
  def encode_variant(:ecc, :sect571r1), do: {:ok, 0x28}
  def encode_variant(:ecc, :brainpoolp160r1), do: {:ok, 0x30}
  def encode_variant(:ecc, :brainpoolp160t1), do: {:ok, 0x31}
  def encode_variant(:ecc, :brainpoolp192r1), do: {:ok, 0x32}
  def encode_variant(:ecc, :brainpoolp192t1), do: {:ok, 0x33}
  def encode_variant(:ecc, :brainpoolp224r1), do: {:ok, 0x34}
  def encode_variant(:ecc, :brainpoolp224t1), do: {:ok, 0x35}
  def encode_variant(:ecc, :brainpoolp256r1), do: {:ok, 0x36}
  def encode_variant(:ecc, :brainpoolp256t1), do: {:ok, 0x37}
  def encode_variant(:ecc, :brainpoolp320r1), do: {:ok, 0x38}
  def encode_variant(:ecc, :brainpoolp320t1), do: {:ok, 0x39}
  def encode_variant(:ecc, :brainpoolp384r1), do: {:ok, 0x3A}
  def encode_variant(:ecc, :brainpoolp384t1), do: {:ok, 0x3B}
  def encode_variant(:ecc, :brainpoolp512r1), do: {:ok, 0x3C}
  def encode_variant(:ecc, :brainpoolp512t1), do: {:ok, 0x3D}

  # Allow integers explicitly
  def encode_variant(_, val) when is_integer(val), do: {:ok, val}
  def encode_variant(_, _), do: {:error, :unknown_variant}

  def encode_tlv(_tag, nil), do: {:ok, <<>>}
  def encode_tlv(_tag, ""), do: {:ok, <<>>}

  def encode_tlv(tag, val) when is_binary(val) do
    with {:ok, encoded} <- VarLengthData.encode(val) do
      {:ok, <<tag>> <> encoded}
    else
      err -> err
    end
  end

  def encode_tlv(_, _), do: {:error, :invalid_tlv_value}

  def decode_version(0x01), do: {:ok, :v1_0}
  def decode_version(_), do: {:error, :unknown_version}

  def decode_asymkey_format(0x01), do: {:ok, :pem}
  def decode_asymkey_format(0x02), do: {:ok, :der}
  def decode_asymkey_format(0x03), do: {:ok, :pkcs12}
  def decode_asymkey_format(0x04), do: {:ok, :pkcs8}
  def decode_asymkey_format(0x05), do: {:ok, :symkey_cipher}
  def decode_asymkey_format(0x06), do: {:ok, :asymkey_cipher}
  def decode_asymkey_format(0x00), do: {:ok, nil}
  def decode_asymkey_format(_), do: {:error, :unknown_format}

  def decode_signature_format(0x01), do: {:ok, :raw}
  def decode_signature_format(0x02), do: {:ok, :pkcs7}
  def decode_signature_format(0x00), do: {:ok, nil}
  def decode_signature_format(_), do: {:error, :unknown_format}

  def decode_algo(0x01), do: {:ok, :kaz_sign}
  def decode_algo(0x02), do: {:ok, :ml_dsa}
  def decode_algo(0x03), do: {:ok, :slh_dsa}
  def decode_algo(0x04), do: {:ok, :falcon}
  def decode_algo(0x10), do: {:ok, :kaz_kem}
  def decode_algo(0x11), do: {:ok, :ml_kem}
  def decode_algo(0x20), do: {:ok, :kaz_ka}
  def decode_algo(0x40), do: {:ok, :rsa}
  def decode_algo(0x41), do: {:ok, :ecc}
  def decode_algo(_), do: {:error, :unknown_algo}

  def decode_variant(:kaz_sign, 0x01), do: {:ok, :kaz_sign_128_v1_6_4}
  def decode_variant(:kaz_sign, 0x02), do: {:ok, :kaz_sign_192_v1_6_4}
  def decode_variant(:kaz_sign, 0x03), do: {:ok, :kaz_sign_256_v1_6_4}
  def decode_variant(:kaz_sign, 0x05), do: {:ok, :kaz_sign_128_v2_0}
  def decode_variant(:kaz_sign, 0x06), do: {:ok, :kaz_sign_192_v2_0}
  def decode_variant(:kaz_sign, 0x07), do: {:ok, :kaz_sign_256_v2_0}
  def decode_variant(:kaz_sign, 0x09), do: {:ok, :kaz_sign_128_v2_1}
  def decode_variant(:kaz_sign, 0x0A), do: {:ok, :kaz_sign_192_v2_1}
  def decode_variant(:kaz_sign, 0x0B), do: {:ok, :kaz_sign_256_v2_1}

  def decode_variant(:ml_dsa, 0x01), do: {:ok, :ml_dsa_44}
  def decode_variant(:ml_dsa, 0x02), do: {:ok, :ml_dsa_65}
  def decode_variant(:ml_dsa, 0x03), do: {:ok, :ml_dsa_87}

  def decode_variant(:slh_dsa, 0x01), do: {:ok, :sha_128_s}
  def decode_variant(:slh_dsa, 0x02), do: {:ok, :sha_128_f}
  def decode_variant(:slh_dsa, 0x04), do: {:ok, :sha_192_s}
  def decode_variant(:slh_dsa, 0x05), do: {:ok, :sha_192_f}
  def decode_variant(:slh_dsa, 0x07), do: {:ok, :sha_256_s}
  def decode_variant(:slh_dsa, 0x08), do: {:ok, :sha_256_f}
  def decode_variant(:slh_dsa, 0x10), do: {:ok, :shake_128_s}
  def decode_variant(:slh_dsa, 0x11), do: {:ok, :shake_128_f}
  def decode_variant(:slh_dsa, 0x13), do: {:ok, :shake_192_s}
  def decode_variant(:slh_dsa, 0x14), do: {:ok, :shake_192_f}
  def decode_variant(:slh_dsa, 0x16), do: {:ok, :shake_256_s}
  def decode_variant(:slh_dsa, 0x17), do: {:ok, :shake_256_f}

  def decode_variant(:falcon, 0x01), do: {:ok, 512}
  def decode_variant(:falcon, 0x02), do: {:ok, 768}
  def decode_variant(:falcon, 0x03), do: {:ok, 1024}

  def decode_variant(:kaz_kem, 0x01), do: {:ok, :kaz_kem_128_v1_0}
  def decode_variant(:kaz_kem, 0x02), do: {:ok, :kaz_kem_192_v1_0}
  def decode_variant(:kaz_kem, 0x03), do: {:ok, :kaz_kem_256_v1_0}
  def decode_variant(:kaz_kem, 0x05), do: {:ok, :kaz_kem_128_v1_1}
  def decode_variant(:kaz_kem, 0x06), do: {:ok, :kaz_kem_192_v1_1}
  def decode_variant(:kaz_kem, 0x07), do: {:ok, :kaz_kem_256_v1_1}

  def decode_variant(:ml_kem, 0x01), do: {:ok, :ml_kem_512}
  def decode_variant(:ml_kem, 0x03), do: {:ok, :ml_kem_768}
  def decode_variant(:ml_kem, 0x02), do: {:ok, :ml_kem_1024}

  def decode_variant(:kaz_ka, 0x01), do: {:ok, :kaz_ka_128_v1_0}
  def decode_variant(:kaz_ka, 0x02), do: {:ok, :kaz_ka_192_v1_0}
  def decode_variant(:kaz_ka, 0x03), do: {:ok, :kaz_ka_256_v1_0}
  def decode_variant(:kaz_ka, 0x05), do: {:ok, :kaz_ka_128_v1_1}
  def decode_variant(:kaz_ka, 0x06), do: {:ok, :kaz_ka_192_v1_1}
  def decode_variant(:kaz_ka, 0x07), do: {:ok, :kaz_ka_256_v1_1}

  def decode_variant(:rsa, 0x01), do: {:ok, :rsa_1024}
  def decode_variant(:rsa, 0x02), do: {:ok, :rsa_2048}
  def decode_variant(:rsa, 0x03), do: {:ok, :rsa_3072}
  def decode_variant(:rsa, 0x04), do: {:ok, :rsa_4096}
  def decode_variant(:rsa, 0x05), do: {:ok, :rsa_8192}

  def decode_variant(:ecc, 0x01), do: {:ok, :secp112r1}
  def decode_variant(:ecc, 0x02), do: {:ok, :secp112r2}
  def decode_variant(:ecc, 0x03), do: {:ok, :secp128r1}
  def decode_variant(:ecc, 0x04), do: {:ok, :secp128r2}
  def decode_variant(:ecc, 0x05), do: {:ok, :secp160k1}
  def decode_variant(:ecc, 0x06), do: {:ok, :secp160r1}
  def decode_variant(:ecc, 0x07), do: {:ok, :secp160r2}
  def decode_variant(:ecc, 0x08), do: {:ok, :secp192k1}
  def decode_variant(:ecc, 0x09), do: {:ok, :secp192r1}
  def decode_variant(:ecc, 0x0A), do: {:ok, :secp224k1}
  def decode_variant(:ecc, 0x0B), do: {:ok, :secp224r1}
  def decode_variant(:ecc, 0x0C), do: {:ok, :secp256k1}
  def decode_variant(:ecc, 0x0D), do: {:ok, :secp256r1}
  def decode_variant(:ecc, 0x0E), do: {:ok, :secp384r1}
  def decode_variant(:ecc, 0x0F), do: {:ok, :secp521r1}
  def decode_variant(:ecc, 0x10), do: {:ok, :prime192v1}
  def decode_variant(:ecc, 0x11), do: {:ok, :prime192v2}
  def decode_variant(:ecc, 0x12), do: {:ok, :prime192v3}
  def decode_variant(:ecc, 0x13), do: {:ok, :prime239v1}
  def decode_variant(:ecc, 0x14), do: {:ok, :prime239v2}
  def decode_variant(:ecc, 0x15), do: {:ok, :prime239v3}
  def decode_variant(:ecc, 0x16), do: {:ok, :prime256v1}
  def decode_variant(:ecc, 0x17), do: {:ok, :sect113r1}
  def decode_variant(:ecc, 0x18), do: {:ok, :sect113r2}
  def decode_variant(:ecc, 0x19), do: {:ok, :sect131r1}
  def decode_variant(:ecc, 0x1A), do: {:ok, :sect131r2}
  def decode_variant(:ecc, 0x1B), do: {:ok, :sect163k1}
  def decode_variant(:ecc, 0x1C), do: {:ok, :sect163r1}
  def decode_variant(:ecc, 0x1D), do: {:ok, :sect163r2}
  def decode_variant(:ecc, 0x1E), do: {:ok, :sect193r1}
  def decode_variant(:ecc, 0x1F), do: {:ok, :sect193r2}
  def decode_variant(:ecc, 0x20), do: {:ok, :sect233k1}
  def decode_variant(:ecc, 0x21), do: {:ok, :sect233r1}
  def decode_variant(:ecc, 0x22), do: {:ok, :sect239k1}
  def decode_variant(:ecc, 0x23), do: {:ok, :sect283k1}
  def decode_variant(:ecc, 0x24), do: {:ok, :sect283r1}
  def decode_variant(:ecc, 0x25), do: {:ok, :sect409k1}
  def decode_variant(:ecc, 0x26), do: {:ok, :sect409r1}
  def decode_variant(:ecc, 0x27), do: {:ok, :sect571k1}
  def decode_variant(:ecc, 0x28), do: {:ok, :sect571r1}
  def decode_variant(:ecc, 0x30), do: {:ok, :brainpoolp160r1}
  def decode_variant(:ecc, 0x31), do: {:ok, :brainpoolp160t1}
  def decode_variant(:ecc, 0x32), do: {:ok, :brainpoolp192r1}
  def decode_variant(:ecc, 0x33), do: {:ok, :brainpoolp192t1}
  def decode_variant(:ecc, 0x34), do: {:ok, :brainpoolp224r1}
  def decode_variant(:ecc, 0x35), do: {:ok, :brainpoolp224t1}
  def decode_variant(:ecc, 0x36), do: {:ok, :brainpoolp256r1}
  def decode_variant(:ecc, 0x37), do: {:ok, :brainpoolp256t1}
  def decode_variant(:ecc, 0x38), do: {:ok, :brainpoolp320r1}
  def decode_variant(:ecc, 0x39), do: {:ok, :brainpoolp320t1}
  def decode_variant(:ecc, 0x3A), do: {:ok, :brainpoolp384r1}
  def decode_variant(:ecc, 0x3B), do: {:ok, :brainpoolp384t1}
  def decode_variant(:ecc, 0x3C), do: {:ok, :brainpoolp512r1}
  def decode_variant(:ecc, 0x3D), do: {:ok, :brainpoolp512t1}

  # Fallback
  def decode_variant(_, val), do: {:ok, val}
end
