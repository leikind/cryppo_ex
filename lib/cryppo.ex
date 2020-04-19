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
    %DerivedKey{encryption_key: key} =
      apply(key_derivation_mod, :build_derived_key, [passphrase, derived_key])

    key_with_encryption_strategy = %{key | encryption_strategy_module: encryption_strategy_mod}

    # maybe this could return the derived key, too
    apply(encryption_strategy_mod, :run_decryption, [encrypted_data, key_with_encryption_strategy])
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

  def load(serialized) when is_binary(serialized) do
    case String.split(serialized, ".") do
      [
        _strategy_name,
        _encrypted_data_base64,
        _encryption_artefacts_base64,
        _key_derivation_strategy_name,
        _derivation_artefacts_base64
      ] ->
        # TODO
        {:key_derivation_case}

      [
        strategy_name,
        encrypted_data_base64,
        encryption_artefacts_base64
      ] ->
        case find_strategy(strategy_name) do
          {:ok, encryption_strategy_mod} ->
            {:ok, encrypted_data} = Base.url_decode64(encrypted_data_base64)
            {:ok, encryption_artefacts_base64} = Base.url_decode64(encryption_artefacts_base64)

            encryption_artefacts = Yaml.decode(encryption_artefacts_base64)

            EncryptedData.new(encryption_strategy_mod, encrypted_data, encryption_artefacts)

          err ->
            err
        end

      _ ->
        {:error, :invalid_serialization_value}
    end
  end

  @spec serialize(EncryptedData.t()) :: binary
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
end
