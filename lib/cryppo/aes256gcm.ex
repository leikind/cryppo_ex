defmodule Cryppo.Aes256gcm do
  @moduledoc false

  # Encryption Strategy AES 256 GCM (Galois/Counter Mode).

  # Key length: 32 bytes.
  # IV length: 12 bytes.
  # Auth tag length: 16 bytes.
  # AAD: "none"

  use Cryppo.EncryptionStrategy,
    strategy_name: "Aes256Gcm",
    key_length: 32,
    key_derivation_possible: true

  alias Cryppo.Aes

  @erlang_crypto_cypher :aes_256_gcm

  # OpenSSL::Cipher::AES.new(256, :GCM).iv_len return 12 in Ruby
  @iv_byte_size 12

  # like in ruby Cryppo
  @additional_authenticated_data "none"
  # like in ruby Cryppo
  @auth_tag_length 16

  @spec generate_key :: EncryptionKey.t()
  @impl EncryptionStrategy
  def generate_key, do: key_length() |> Aes.generate_key(__MODULE__)

  @spec encrypt(binary, EncryptionKey.t()) ::
          {:ok, binary, EncryptionArtefacts.t()} | :encryption_error
  @impl EncryptionStrategy
  def encrypt(data, %EncryptionKey{key: key}) when is_binary(data) and is_binary(key) do
    iv = :crypto.strong_rand_bytes(@iv_byte_size)

    {encrypted, auth_tag} =
      :crypto.crypto_one_time_aead(
        @erlang_crypto_cypher,
        key,
        iv,
        data,
        @additional_authenticated_data,
        @auth_tag_length,
        true
      )

    artefacts = %EncryptionArtefacts{
      initialization_vector: iv,
      authentication_tag: auth_tag,
      additional_authenticated_data: @additional_authenticated_data
    }

    {:ok, encrypted, artefacts}
  end

  def encrypt(_, _), do: :encryption_error

  @spec decrypt(EncryptedData.t(), EncryptionKey.t()) ::
          {:ok, binary} | :decryption_error | {:decryption_error, {any, any}}
  @impl EncryptionStrategy
  def decrypt(
        %EncryptedData{
          encrypted_data: encrypted_data,
          encryption_artefacts: %EncryptionArtefacts{
            initialization_vector: iv,
            authentication_tag: auth_tag,
            additional_authenticated_data: auth_data
          }
        },
        %EncryptionKey{key: key}
      )
      when is_binary(encrypted_data) and is_binary(key) and
             byte_size(auth_tag) == @auth_tag_length do
    decrypted = crypto_one_time_aead(key, iv, encrypted_data, auth_data, auth_tag)

    case decrypted do
      :error -> :decryption_error
      :decryption_error -> :decryption_error
      decrypted_data when is_binary(decrypted_data) -> {:ok, decrypted_data}
      {ch1, ch2} -> {:decryption_error, {ch1, ch2}}
    end
  end

  def decrypt(_, _), do: :decryption_error

  defp crypto_one_time_aead(key, iv, encrypted_data, auth_data, auth_tag) do
    :crypto.crypto_one_time_aead(
      @erlang_crypto_cypher,
      key,
      iv,
      encrypted_data,
      auth_data,
      auth_tag,
      false
    )
  rescue
    ErlangError -> :decryption_error
  end

  @impl EncryptionStrategy
  @spec build_encryption_key(binary) ::
          {:ok, EncryptionKey.t()} | {:error, :invalid_encryption_key}
  def build_encryption_key(raw_key), do: Aes.build_encryption_key(raw_key, __MODULE__)
end
