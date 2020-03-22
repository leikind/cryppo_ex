defmodule Cryppo.Aes256gcm do
  alias Cryppo.{EncryptionKey, EncryptedData}

  # same is the cipher in Erlang crypto
  @strategy_name :aes_256_gcm

  @key_length 32

  # OpenSSL::Cipher::AES.new(256, :GCM).iv_len return 12 in Ruby
  @iv_byte_size 12

  # like in ruby Cryppo
  @additional_authenticated_data "none"
  # like in ruby Cryppo
  @auth_tag_length 16

  @spec generate_key :: Cryppo.EncryptionKey.t()
  def generate_key do
    @key_length |> :crypto.strong_rand_bytes() |> EncryptionKey.new()
  end

  @spec encrypt(binary, Cryppo.EncryptionKey.t()) :: Cryppo.EncryptedData.t()
  def encrypt(data, %EncryptionKey{} = key),
    do: encrypt(data, key, @additional_authenticated_data)

  def encrypt(data, %EncryptionKey{key: key}, auth_data)
      when is_binary(data) and is_binary(auth_data) do
    iv = :crypto.strong_rand_bytes(@iv_byte_size)

    {encrypted, auth_tag} =
      :crypto.crypto_one_time_aead(
        @strategy_name,
        key,
        iv,
        data,
        auth_data,
        @auth_tag_length,
        true
      )

    EncryptedData.new(
      @strategy_name,
      encrypted,
      iv: iv,
      auth_tag: auth_tag,
      auth_data: auth_data
    )
  end

  @spec decrypt(EncryptedData.t(), EncryptionKey.t()) ::
          {:ok, binary} | {:error, binary | {binary, binary}}
  def decrypt(
        %EncryptedData{encryption_artefacts: %{auth_tag: auth_tag}},
        %EncryptionKey{}
      )
      when byte_size(auth_tag) != @auth_tag_length,
      do: {:error, "auth_tag is not 16 bytes in length"}

  def decrypt(
        %EncryptedData{
          encryption_strategy: @strategy_name,
          encrypted_data: encrypted_data,
          encryption_artefacts: %{iv: iv, auth_tag: auth_tag, auth_data: auth_data}
        },
        %EncryptionKey{key: key}
      ) do
    decrypted =
      :crypto.crypto_one_time_aead(
        @strategy_name,
        key,
        iv,
        encrypted_data,
        auth_data,
        auth_tag,
        false
      )

    case decrypted do
      :error -> {:error, "decryption error"}
      decrypted_data when is_binary(decrypted_data) -> {:ok, decrypted_data}
      {ch1, ch2} -> {:error, {ch1, ch2}}
    end
  end
end
