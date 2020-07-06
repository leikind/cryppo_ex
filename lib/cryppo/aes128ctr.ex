defmodule Cryppo.Aes128ctr do
  @moduledoc false

  # Encryption Strategy AES 128 CTR (The Counter Mode or CTR
  # is a simple counter based block cipher implementation)

  # Key length: 16 bytes.
  # IV length: 16 bytes.

  use Cryppo.EncryptionStrategy,
    strategy_name: "Aes128Ctr",
    key_length: 16,
    key_derivation_possible: true

  alias Cryppo.Aes

  @erlang_crypto_cypher :aes_128_ctr
  @iv_byte_size 16

  @spec generate_key :: EncryptionKey.t()
  @impl EncryptionStrategy
  def generate_key, do: key_length() |> Aes.generate_key(__MODULE__)

  @spec encrypt(binary, EncryptionKey.t()) ::
          {:ok, binary, EncryptionArtefacts.t()} | :encryption_error
  @impl EncryptionStrategy
  def encrypt(data, %EncryptionKey{key: key}) when is_binary(data) and is_binary(key) do
    iv = :crypto.strong_rand_bytes(@iv_byte_size)

    encrypted =
      @erlang_crypto_cypher
      |> :crypto.crypto_init(key, iv, true)
      |> :crypto.crypto_update(data)

    # present from OTP 23. What do we do with it?
    # :crypto.crypto_final

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

    # present from OTP 23. What do we do with it?
    # :crypto.crypto_final

    {:ok, decrypted}
  end

  def decrypt(_, _), do: :decryption_error

  @impl EncryptionStrategy
  @spec build_encryption_key(binary) ::
          {:ok, EncryptionKey.t()} | {:error, :invalid_encryption_key}
  def build_encryption_key(raw_key), do: Aes.build_encryption_key(raw_key, __MODULE__)
end
