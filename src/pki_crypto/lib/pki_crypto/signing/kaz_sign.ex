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

  def sign(_, private_key, data) do
    case KazSign.sign_detached(128, data, private_key) do
      {:ok, sig} -> {:ok, sig}
      {:error, _} = err -> err
    end
  end

  def verify(_, public_key, signature, data) do
    case KazSign.verify_detached(128, data, signature, public_key) do
      {:ok, true} -> :ok
      {:ok, false} -> {:error, :invalid_signature}
      {:error, _} -> {:error, :invalid_signature}
    end
  end

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

  def sign(_, private_key, data) do
    case KazSign.sign_detached(192, data, private_key) do
      {:ok, sig} -> {:ok, sig}
      {:error, _} = err -> err
    end
  end

  def verify(_, public_key, signature, data) do
    case KazSign.verify_detached(192, data, signature, public_key) do
      {:ok, true} -> :ok
      {:ok, false} -> {:error, :invalid_signature}
      {:error, _} -> {:error, :invalid_signature}
    end
  end

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

  def sign(_, private_key, data) do
    case KazSign.sign_detached(256, data, private_key) do
      {:ok, sig} -> {:ok, sig}
      {:error, _} = err -> err
    end
  end

  def verify(_, public_key, signature, data) do
    case KazSign.verify_detached(256, data, signature, public_key) do
      {:ok, true} -> :ok
      {:ok, false} -> {:error, :invalid_signature}
      {:error, _} -> {:error, :invalid_signature}
    end
  end

  def kem_encapsulate(_, _), do: {:error, :not_supported}
  def kem_decapsulate(_, _, _), do: {:error, :not_supported}
  def identifier(_), do: "KAZ-SIGN-256"
  def algorithm_type(_), do: :signing
end
