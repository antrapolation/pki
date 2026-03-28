defmodule PkiCrypto.AlgorithmSharedTest do
  @moduledoc """
  Shared test suite that every PkiCrypto.Algorithm implementation must pass.
  Use in each algorithm's test module: `use PkiCrypto.AlgorithmSharedTest, algorithm: %MyAlgo{}`
  """

  defmacro __using__(opts) do
    algorithm = Keyword.fetch!(opts, :algorithm)

    quote do
      alias PkiCrypto.Algorithm

      describe "#{inspect(unquote(algorithm))} protocol compliance" do
        test "identifier returns a non-empty string" do
          algo = unquote(algorithm)
          id = Algorithm.identifier(algo)
          assert is_binary(id)
          assert byte_size(id) > 0
        end

        test "algorithm_type returns :signing, :kem, or :dual" do
          algo = unquote(algorithm)
          assert Algorithm.algorithm_type(algo) in [:signing, :kem, :dual]
        end

        test "generate_keypair returns {:ok, %{public_key, private_key}}" do
          algo = unquote(algorithm)
          assert {:ok, %{public_key: pub, private_key: priv}} = Algorithm.generate_keypair(algo)
          assert is_binary(pub)
          assert is_binary(priv)
          assert byte_size(pub) > 0
          assert byte_size(priv) > 0
        end

        test "generate_keypair produces different keys each time" do
          algo = unquote(algorithm)
          {:ok, kp1} = Algorithm.generate_keypair(algo)
          {:ok, kp2} = Algorithm.generate_keypair(algo)
          assert kp1.private_key != kp2.private_key
        end
      end

      if Algorithm.algorithm_type(unquote(algorithm)) in [:signing, :dual] do
        describe "#{inspect(unquote(algorithm))} signing" do
          test "sign then verify round-trip" do
            algo = unquote(algorithm)
            {:ok, %{public_key: pub, private_key: priv}} = Algorithm.generate_keypair(algo)
            data = :crypto.strong_rand_bytes(64)
            {:ok, sig} = Algorithm.sign(algo, priv, data)
            assert is_binary(sig)
            assert :ok = Algorithm.verify(algo, pub, sig, data)
          end

          test "verify rejects wrong data" do
            algo = unquote(algorithm)
            {:ok, %{public_key: pub, private_key: priv}} = Algorithm.generate_keypair(algo)
            data = :crypto.strong_rand_bytes(64)
            wrong_data = :crypto.strong_rand_bytes(64)
            {:ok, sig} = Algorithm.sign(algo, priv, data)
            assert {:error, :invalid_signature} = Algorithm.verify(algo, pub, sig, wrong_data)
          end

          test "verify rejects wrong key" do
            algo = unquote(algorithm)
            {:ok, %{public_key: _pub1, private_key: priv}} = Algorithm.generate_keypair(algo)
            {:ok, %{public_key: pub2, private_key: _priv2}} = Algorithm.generate_keypair(algo)
            data = :crypto.strong_rand_bytes(64)
            {:ok, sig} = Algorithm.sign(algo, priv, data)
            assert {:error, :invalid_signature} = Algorithm.verify(algo, pub2, sig, data)
          end
        end
      end

      if Algorithm.algorithm_type(unquote(algorithm)) in [:kem, :dual] do
        describe "#{inspect(unquote(algorithm))} KEM" do
          test "encapsulate then decapsulate round-trip" do
            algo = unquote(algorithm)
            {:ok, %{public_key: pub, private_key: priv}} = Algorithm.generate_keypair(algo)
            {:ok, {shared_secret_enc, ciphertext}} = Algorithm.kem_encapsulate(algo, pub)
            {:ok, shared_secret_dec} = Algorithm.kem_decapsulate(algo, priv, ciphertext)
            assert shared_secret_enc == shared_secret_dec
            assert byte_size(shared_secret_enc) >= 16
          end

          test "decapsulate with wrong key produces different secret" do
            algo = unquote(algorithm)
            {:ok, %{public_key: pub, private_key: _priv1}} = Algorithm.generate_keypair(algo)
            {:ok, %{public_key: _pub2, private_key: priv2}} = Algorithm.generate_keypair(algo)
            {:ok, {ss1, ciphertext}} = Algorithm.kem_encapsulate(algo, pub)
            case Algorithm.kem_decapsulate(algo, priv2, ciphertext) do
              {:error, _} -> :ok
              {:ok, ss2} -> assert ss1 != ss2
            end
          end
        end
      end
    end
  end
end
