defmodule PkiCrypto.Signing.KazSign128 do
  @moduledoc "KAZ-SIGN-128 — Malaysia PQC Level 1 digital signature via NIF."
  defstruct []
end

defmodule PkiCrypto.Signing.KazSign192 do
  @moduledoc "KAZ-SIGN-192 — Malaysia PQC Level 3 digital signature via NIF."
  defstruct []
end

defmodule PkiCrypto.Signing.KazSign256 do
  @moduledoc "KAZ-SIGN-256 — Malaysia PQC Level 5 digital signature via NIF."
  defstruct []
end

defimpl PkiCrypto.Algorithm, for: PkiCrypto.Signing.KazSign128 do
  def generate_keypair(_) do
    with :ok <- KazSign.init(128),
         {:ok, kp} <- KazSign.keypair(128) do
      {:ok, %{public_key: kp.public_key, private_key: kp.private_key}}
    end
  end
  def sign(_, private_key, data), do: KazSign.sign(128, private_key, data)
  def verify(_, public_key, signature, data), do: KazSign.verify(128, public_key, signature, data)
  def kem_encapsulate(_, _), do: {:error, :not_supported}
  def kem_decapsulate(_, _, _), do: {:error, :not_supported}
  def identifier(_), do: "KAZ-SIGN-128"
  def algorithm_type(_), do: :signing
end

defimpl PkiCrypto.Algorithm, for: PkiCrypto.Signing.KazSign192 do
  def generate_keypair(_) do
    with :ok <- KazSign.init(192),
         {:ok, kp} <- KazSign.keypair(192) do
      {:ok, %{public_key: kp.public_key, private_key: kp.private_key}}
    end
  end
  def sign(_, private_key, data), do: KazSign.sign(192, private_key, data)
  def verify(_, public_key, signature, data), do: KazSign.verify(192, public_key, signature, data)
  def kem_encapsulate(_, _), do: {:error, :not_supported}
  def kem_decapsulate(_, _, _), do: {:error, :not_supported}
  def identifier(_), do: "KAZ-SIGN-192"
  def algorithm_type(_), do: :signing
end

defimpl PkiCrypto.Algorithm, for: PkiCrypto.Signing.KazSign256 do
  def generate_keypair(_) do
    with :ok <- KazSign.init(256),
         {:ok, kp} <- KazSign.keypair(256) do
      {:ok, %{public_key: kp.public_key, private_key: kp.private_key}}
    end
  end
  def sign(_, private_key, data), do: KazSign.sign(256, private_key, data)
  def verify(_, public_key, signature, data), do: KazSign.verify(256, public_key, signature, data)
  def kem_encapsulate(_, _), do: {:error, :not_supported}
  def kem_decapsulate(_, _, _), do: {:error, :not_supported}
  def identifier(_), do: "KAZ-SIGN-256"
  def algorithm_type(_), do: :signing
end
