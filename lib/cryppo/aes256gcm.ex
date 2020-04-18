defmodule Cryppo.Aes256gcm do
  @moduledoc """
    Encryption Strategy AES 256 GCM (Galois/Counter Mode).
    Key length: 32 bytes.
    IV length: 12 bytes.
    Auth tag length: 16 bytes.
    AAD: "none"
  """

  alias Cryppo.{EncryptionKey, EncryptedData}

  @erlang_crypto_cypher :aes_256_gcm

  @key_length 32

  # OpenSSL::Cipher::AES.new(256, :GCM).iv_len return 12 in Ruby
  @iv_byte_size 12

  # like in ruby Cryppo
  @additional_authenticated_data "none"
  # like in ruby Cryppo
  @auth_tag_length 16

  @spec strategy_name :: binary
  def strategy_name, do: "Aes256Gcm"

  @spec generate_key :: EncryptionKey.t()
  def generate_key do
    @key_length |> :crypto.strong_rand_bytes() |> EncryptionKey.new()
  end

  @spec encrypt(binary, EncryptionKey.t()) :: EncryptedData.t() | :encryption_error
  def encrypt(data, %EncryptionKey{} = key),
    do: encrypt(data, key, @additional_authenticated_data)

  @spec encrypt(binary, EncryptionKey.t(), binary) :: EncryptedData.t()
  def encrypt(data, %EncryptionKey{key: key}, auth_data)
      when is_binary(data) and is_binary(auth_data) and is_binary(key) do
    iv = :crypto.strong_rand_bytes(@iv_byte_size)

    {encrypted, auth_tag} =
      :crypto.crypto_one_time_aead(
        @erlang_crypto_cypher,
        key,
        iv,
        data,
        auth_data,
        @auth_tag_length,
        true
      )

    EncryptedData.new(
      __MODULE__,
      encrypted,
      iv: iv,
      auth_tag: auth_tag,
      auth_data: auth_data
    )
  end

  def encrypt(_, _, _), do: :encryption_error

  @spec decrypt(EncryptedData.t(), EncryptionKey.t()) ::
          {:ok, binary} | {:error, binary | {binary, binary}}
  def decrypt(
        %EncryptedData{
          encryption_strategy_module: __MODULE__,
          encrypted_data: encrypted_data,
          encryption_artefacts: %{iv: iv, auth_tag: auth_tag, auth_data: auth_data}
        },
        %EncryptionKey{key: key}
      )
      when is_binary(encrypted_data) and is_binary(key) and
             byte_size(auth_tag) == @auth_tag_length do
    decrypted =
      :crypto.crypto_one_time_aead(
        @erlang_crypto_cypher,
        key,
        iv,
        encrypted_data,
        auth_data,
        auth_tag,
        false
      )

    case decrypted do
      :error -> :decryption_error
      decrypted_data when is_binary(decrypted_data) -> {:ok, decrypted_data}
      {ch1, ch2} -> {:decryption_error, {ch1, ch2}}
    end
  end

  def decrypt(_, _), do: :decryption_error
end
