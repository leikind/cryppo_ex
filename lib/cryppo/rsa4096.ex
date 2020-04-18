defmodule Cryppo.Rsa4096 do
  @moduledoc """
    Encryption Strategy RSA 4096.
    Key length 4096
    Exponents: 65537
    Padding: rsa_pkcs1_oaep_padding
  """

  alias Cryppo.{EncryptionKey, EncryptedData}

  # 4096 is the key size in ruby Cryppo
  @size 4_096
  # 65537 is the default in OpenSSL, and hence in ruby Cryppo
  @exponent 65_537

  # rsa_pkcs1_oaep_padding is the padding in Cryppo
  @padding :rsa_pkcs1_oaep_padding

  @spec generate_key :: EncryptionKey.t()
  def generate_key do
    {:rsa, @size, @exponent}
    |> :public_key.generate_key()
    |> EncryptionKey.new()
  end

  @spec strategy_name :: binary
  def strategy_name, do: "Rsa4096"

  @spec encrypt(binary, EncryptionKey.t()) :: EncryptedData.t()
  def encrypt(data, %EncryptionKey{key: private_key})
      when is_binary(data) and elem(private_key, 0) == :RSAPrivateKey do
    public_modulus = private_key |> elem(2)
    public_exponent = private_key |> elem(3)

    public_key = {:RSAPublicKey, public_modulus, public_exponent}

    encrypted = data |> :public_key.encrypt_public(public_key, rsa_padding: @padding)

    EncryptedData.new(__MODULE__, encrypted)
  end

  def encrypt(_, _), do: :encryption_error

  @spec decrypt(EncryptedData.t(), EncryptionKey.t()) :: {:ok, binary}
  def decrypt(
        %EncryptedData{
          encryption_strategy_module: __MODULE__,
          encrypted_data: encrypted_data
        },
        %EncryptionKey{key: private_key}
      )
      when is_binary(encrypted_data) do
    try do
      decrypted = :public_key.decrypt_private(encrypted_data, private_key, rsa_padding: @padding)
      {:ok, decrypted}
    rescue
      ErlangError -> :decryption_error
    end
  end

  def decrypt(_, _), do: :decryption_error
end
