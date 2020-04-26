defmodule Cryppo do
  @moduledoc """
    Main public API of Cryppo.
  """

  alias Cryppo.{
    DerivedKey,
    EncryptedData,
    EncryptedDataWithDerivedKey,
    EncryptionKey,
    Loader,
    Rsa4096,
    RsaSignature,
    Serialization,
    Strategies
  }

  import Strategies, only: [find_strategy: 1, find_key_derivation_strategy: 1]

  @type encryption_strategy() :: String.t()
  @type encryption_strategy_module() :: atom

  @spec encryption_strategies :: [encryption_strategy()]
  def encryption_strategies, do: Strategies.encryption_strategies()

  @spec derivation_strategies :: [encryption_strategy()]
  def derivation_strategies, do: Strategies.derivation_strategies()

  @spec generate_encryption_key(encryption_strategy) ::
          EncryptionKey.t() | {:unsupported_encryption_strategy, binary}
  def generate_encryption_key(encryption_strategy) when is_binary(encryption_strategy) do
    with {:ok, mod} <- find_strategy(encryption_strategy) do
      %EncryptionKey{} = apply(mod, :generate_key, [])
    end
  end

  @spec encrypt(binary, encryption_strategy, EncryptionKey.t()) ::
          EncryptedData.t()
          | {:unsupported_encryption_strategy, atom}
          | :encryption_error
          | {:incompatible_key, submitted_key_strategy: atom, encryption_strategy: atom}
  def encrypt(data, encryption_strategy, %EncryptionKey{} = key)
      when is_binary(encryption_strategy) and is_binary(data) do
    with {:ok, mod} <- find_strategy(encryption_strategy) do
      apply(mod, :run_encryption, [data, key])
    end
  end

  @spec decrypt(EncryptedData.t(), EncryptionKey.t()) ::
          {:ok, binary}
          | :decryption_error
          | {:decryption_error, {any, any}}
          | {:incompatible_key, submitted_key_strategy: atom, encryption_strategy: atom}
  def decrypt(
        %EncryptedData{encryption_strategy_module: mod} = encrypted_data,
        %EncryptionKey{} = key
      ) do
    apply(mod, :run_decryption, [encrypted_data, key])
  end

  @spec encrypt_with_derived_key(binary, encryption_strategy(), encryption_strategy(), String.t()) ::
          EncryptedDataWithDerivedKey.t()
          | {:unsupported_encryption_strategy, encryption_strategy}
          | {:unsupported_key_derivation_strategy, encryption_strategy}
  def encrypt_with_derived_key(
        data,
        encryption_strategy,
        key_derivation_strategy,
        passphrase
      )
      when is_binary(encryption_strategy) and is_binary(key_derivation_strategy) and
             is_binary(passphrase) and is_binary(data) do
    with {:ok, key_derivation_mod} <- find_key_derivation_strategy(key_derivation_strategy),
         {:ok, encryption_strategy_mod} <- find_strategy(encryption_strategy) do
      %DerivedKey{encryption_key: key} =
        derived_key = apply(key_derivation_mod, :generate_derived_key, [passphrase])

      key_with_encryption_strategy = %{key | encryption_strategy_module: encryption_strategy_mod}

      %EncryptedData{} =
        encrypted_data =
        apply(encryption_strategy_mod, :run_encryption, [data, key_with_encryption_strategy])

      %EncryptedDataWithDerivedKey{encrypted_data: encrypted_data, derived_key: derived_key}
    end
  end

  @spec decrypt_with_derived_key(binary, Cryppo.EncryptedDataWithDerivedKey.t()) ::
          {:ok, binary, DerivedKey.t()}
          | :decryption_error
          | {:decryption_error, {any, any}}
          | {:incompatible_key, submitted_key_strategy: atom, encryption_strategy: atom}
  def decrypt_with_derived_key(
        passphrase,
        %EncryptedDataWithDerivedKey{
          derived_key:
            %DerivedKey{
              key_derivation_strategy: key_derivation_mod
            } = derived_key,
          encrypted_data:
            %EncryptedData{
              encryption_strategy_module: encryption_strategy_mod
            } = encrypted_data
        }
      )
      when is_binary(passphrase) do
    derived_key =
      %DerivedKey{encryption_key: key} =
      apply(key_derivation_mod, :build_derived_key, [passphrase, derived_key])

    key_with_encryption_strategy = %{key | encryption_strategy_module: encryption_strategy_mod}

    with {:ok, decrypted} <-
           apply(encryption_strategy_mod, :run_decryption, [
             encrypted_data,
             key_with_encryption_strategy
           ]) do
      {:ok, decrypted, derived_key}
    end
  end

  @spec sign_with_private_key(binary, EncryptionKey.t()) :: RsaSignature.t()
  def sign_with_private_key(data, private_key), do: Rsa4096.sign(data, private_key)

  @spec verify_rsa_signature(RsaSignature.t(), Rsa4096.rsa_public_key()) :: boolean()
  def verify_rsa_signature(rsa_signature, public_key),
    do: Rsa4096.verify(rsa_signature, public_key)

  @spec private_key_to_public_key(Rsa4096.rsa_private_key() | EncryptionKey.t()) ::
          Rsa4096.rsa_public_key()
  def private_key_to_public_key(rsa_key), do: Rsa4096.private_key_to_public_key(rsa_key)

  @spec serialize(EncryptedData.t() | EncryptedDataWithDerivedKey.t() | RsaSignature.t()) ::
          binary
  def serialize(%EncryptedData{} = s), do: Serialization.serialize(s)
  def serialize(%EncryptedDataWithDerivedKey{} = s), do: Serialization.serialize(s)
  def serialize(%RsaSignature{} = s), do: Serialization.serialize(s)

  @spec load(binary) ::
          EncryptedDataWithDerivedKey.t()
          | EncryptedData.t()
          | RsaSignature.t()
          | {:error, :invalid_base64}
          | {:error, :invalid_derivation_artefacts}
          | {:unsupported_encryption_strategy, binary}
          | {:unsupported_key_derivation_strategy, binary}
  def load(serialized), do: Loader.load(serialized)
end
