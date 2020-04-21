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

  @spec encrypt(encryption_strategy, EncryptionKey.t(), binary) ::
          EncryptedData.t()
          | {:unsupported_encryption_strategy, atom}
          | :encryption_error
          | {:incompatible_key, submitted_key_strategy: atom, encryption_strategy: atom}
  def encrypt(encryption_strategy, %EncryptionKey{} = key, data)
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

  @spec encrypt_with_derived_key(encryption_strategy(), encryption_strategy(), String.t(), binary) ::
          EncryptedDataWithDerivedKey.t()
          | {:unsupported_encryption_strategy, encryption_strategy}
          | {:unsupported_key_derivation_strategy, encryption_strategy}
  def encrypt_with_derived_key(
        encryption_strategy,
        key_derivation_strategy,
        passphrase,
        data
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
             # TODO deal with invalid derivation_artefacts
             %{"iv" => salt, "i" => iterations, "l" => length} <- derivation_artefacts do
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

  # TODO protocol serializable and move to structs
  @spec serialize(EncryptedData.t() | EncryptedDataWithDerivedKey.t()) :: binary
  def serialize(%EncryptedData{
        encryption_strategy_module: mod,
        encrypted_data: encrypted_data,
        encryption_artefacts: encryption_artefacts
      }) do
    strategy_name = apply(mod, :strategy_name, [])
    encrypted_data_base64 = encrypted_data |> Base.url_encode64(padding: true)

    encryption_artefacts_base64 =
      encryption_artefacts |> Yaml.encode() |> Base.url_encode64(padding: true)

    [strategy_name, encrypted_data_base64, encryption_artefacts_base64] |> Enum.join(".")
  end

  def serialize(%EncryptedDataWithDerivedKey{
        derived_key: %DerivedKey{} = derived_key,
        encrypted_data: %EncryptedData{} = encrypted_data
      }) do
    [serialize(encrypted_data), serialize_derived_key(derived_key)] |> Enum.join(".")
  end

  @spec serialize_derived_key(DerivedKey.t()) :: binary
  defp serialize_derived_key(%DerivedKey{
         key_derivation_strategy: key_derivation_mod,
         salt: salt,
         iter: iterations,
         length: length
       }) do
    key_derivation_mod = apply(key_derivation_mod, :strategy_name, [])

    derivation_artefacts =
      %{"iv" => salt, "i" => iterations, "l" => length}
      |> Yaml.encode()
      |> Base.url_encode64(padding: true)

    [key_derivation_mod, derivation_artefacts] |> Enum.join(".")
  end
end
