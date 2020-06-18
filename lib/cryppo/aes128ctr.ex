defmodule Cryppo.Aes128ctr do
  @moduledoc false

  # Encryption Strategy AES 128 CTR (The Counter Mode or CTR
  # is a simple counter based block cipher implementation)

  # Key length: 16 bytes.
  # IV length: 16 bytes.

  use Cryppo.EncryptionStrategy,
    strategy_name: "Aes128Ctr",
    key_derivation_possible: false

  alias Cryppo.Aes

  @erlang_crypto_cypher :aes_128_ctr

  @key_length 16
  @iv_byte_size 16

  @spec generate_key :: EncryptionKey.t()
  @impl EncryptionStrategy
  def generate_key, do: Aes.generate_key(@key_length, __MODULE__)

  @spec encrypt(binary, EncryptionKey.t()) ::
          {:ok, binary, EncryptionArtefacts.t()} | :encryption_error
  @impl EncryptionStrategy
  def encrypt(data, %EncryptionKey{key: key}) when is_binary(data) and is_binary(key) do
    iv = :crypto.strong_rand_bytes(@iv_byte_size)

    encrypted =
      @erlang_crypto_cypher
      |> :crypto.crypto_init(key, iv, true)
      |> :crypto.crypto_update(data)

    {:ok, encrypted, %EncryptionArtefacts{initialization_vector: iv}}
  end

  def encrypt(_, _), do: :encryption_error

  @spec decrypt(EncryptedData.t(), EncryptionKey.t()) ::
          {:ok, binary} | :decryption_error | {:decryption_error, {any, any}}
  @impl EncryptionStrategy
  def decrypt(
        %EncryptedData{
          encrypted_data: encrypted_data,
          encryption_artefacts: %EncryptionArtefacts{initialization_vector: iv}
        },
        %EncryptionKey{key: key}
      )
      when is_binary(encrypted_data) and is_binary(key) do
    decrypted =
      @erlang_crypto_cypher
      |> :crypto.crypto_init(key, iv, false)
      |> :crypto.crypto_update(encrypted_data)

    {:ok, decrypted}
  end

  def decrypt(_, _), do: :decryption_error

  @impl EncryptionStrategy
  @spec build_encryption_key(binary) ::
          {:ok, EncryptionKey.t()} | {:error, :invalid_encryption_key}
  def build_encryption_key(raw_key), do: Aes.build_encryption_key(raw_key, __MODULE__)
end
