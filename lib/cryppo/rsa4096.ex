defmodule Cryppo.Rsa4096 do
  @moduledoc """
    Encryption Strategy RSA 4096.
    Key length 4096
    Exponents: 65537
    Padding: rsa_pkcs1_oaep_padding
  """

  use Cryppo.EncryptionStrategy, strategy_name: "Aes256Gcm"

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
    |> EncryptionKey.new(__MODULE__)
  end

  @spec encrypt(binary, EncryptionKey.binary_key()) :: :encryption_error | {:ok, binary, list}
  defp encrypt(data, private_key)
       when is_binary(data) and elem(private_key, 0) == :RSAPrivateKey do
    public_modulus = private_key |> elem(2)
    public_exponent = private_key |> elem(3)

    public_key = {:RSAPublicKey, public_modulus, public_exponent}

    encrypted = data |> :public_key.encrypt_public(public_key, rsa_padding: @padding)

    {:ok, encrypted, []}
  end

  defp encrypt(_, _), do: :encryption_error

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
