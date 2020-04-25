defmodule Cryppo do
  @moduledoc """
    Main public API of Cryppo.
  """

  alias Cryppo.{
    Aes256gcm,
    DerivedKey,
    EncryptedData,
    EncryptedDataWithDerivedKey,
    EncryptionKey,
    Pbkdf2hmac,
    Rsa4096,
    RsaSignature,
    Serialization,
    Yaml
  }

  @type encryption_strategy() :: String.t()
  @type encryption_strategy_module() :: atom

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

  # probably code it with a macro
  # Aes256Gcm
  # Rsa4096
  # these 2 below are same is the cipher in Erlang crypto
  # :aes_256_gcm -> {:ok, Aes256gcm}
  # :rsa_4096 -> {:ok, Rsa4096}
  @spec find_strategy(encryption_strategy) ::
          {:ok, atom} | {:unsupported_encryption_strategy, encryption_strategy}
  defp find_strategy(encryption_strategy) do
    case encryption_strategy do
      "Aes256Gcm" -> {:ok, Aes256gcm}
      "Rsa4096" -> {:ok, Rsa4096}
      _ -> {:unsupported_encryption_strategy, encryption_strategy}
    end
  end

  @spec find_key_derivation_strategy(encryption_strategy) ::
          {:ok, atom} | {:unsupported_key_derivation_strategy, encryption_strategy}
  defp find_key_derivation_strategy(key_derivation_strategy) do
    case key_derivation_strategy do
      "Pbkdf2Hmac" -> {:ok, Pbkdf2hmac}
      _ -> {:unsupported_key_derivation_strategy, key_derivation_strategy}
    end
  end

  @spec load(binary) ::
          EncryptedDataWithDerivedKey.t()
          | EncryptedData.t()
          | {:unsupported_encryption_strategy, binary}
          | {:error, :invalid_serialization_value}
  def load(serialized) when is_binary(serialized) do
    case String.split(serialized, ".") do
      [
        strategy_name,
        encrypted_data_base64,
        encryption_artefacts_base64,
        key_derivation_strategy,
        derivation_artefacts_base64
      ] ->
        with {:ok, key_derivation_mod} <- find_key_derivation_strategy(key_derivation_strategy),
             {:ok, derivation_artefacts_yaml} = Base.url_decode64(derivation_artefacts_base64),
             derivation_artefacts = Yaml.decode(derivation_artefacts_yaml),
             {:ok, %{"iv" => salt, "i" => iterations, "l" => length}} <-
               parse_derivation_artefacts(derivation_artefacts) do
          encrypted_data =
            to_encrypted_data(strategy_name, encrypted_data_base64, encryption_artefacts_base64)

          hash = apply(key_derivation_mod, :hash_function, [])

          derived_key = %DerivedKey{
            encryption_key: nil,
            key_derivation_strategy: key_derivation_mod,
            salt: salt,
            iter: iterations,
            length: length,
            hash: hash
          }

          %EncryptedDataWithDerivedKey{encrypted_data: encrypted_data, derived_key: derived_key}
        end

      [
        strategy_name,
        encrypted_data_base64,
        encryption_artefacts_base64
      ] ->
        to_encrypted_data(strategy_name, encrypted_data_base64, encryption_artefacts_base64)

      _ ->
        {:error, :invalid_serialization_value}
    end
  end

  @spec parse_derivation_artefacts(any) :: {:error, :invalid_derivation_artefacts} | {:ok, map}
  defp parse_derivation_artefacts(%{"iv" => _, "i" => _, "l" => _} = da), do: {:ok, da}
  defp parse_derivation_artefacts(_), do: {:error, :invalid_derivation_artefacts}

  @spec to_encrypted_data(encryption_strategy(), binary, binary) ::
          {:unsupported_encryption_strategy, binary} | EncryptedData.t()
  defp to_encrypted_data(strategy_name, encrypted_data_base64, encryption_artefacts_base64) do
    case find_strategy(strategy_name) do
      {:ok, encryption_strategy_mod} ->
        {:ok, encrypted_data} = Base.url_decode64(encrypted_data_base64)
        {:ok, encryption_artefacts_base64} = Base.url_decode64(encryption_artefacts_base64)

        encryption_artefacts = Yaml.decode(encryption_artefacts_base64)

        EncryptedData.new(encryption_strategy_mod, encrypted_data, encryption_artefacts)

      err ->
        err
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

  @spec serialize(EncryptedData.t() | EncryptedDataWithDerivedKey.t()) :: binary
  def serialize(%EncryptedData{} = ed), do: Serialization.serialize(ed)
  def serialize(%EncryptedDataWithDerivedKey{} = edwdk), do: Serialization.serialize(edwdk)
end
