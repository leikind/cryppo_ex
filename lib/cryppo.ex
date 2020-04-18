defmodule Cryppo do
  @moduledoc """
    Main public API of Cryppo.
  """

  alias Cryppo.{Aes256gcm, Rsa4096, EncryptionKey, EncryptedData, Yaml}

  @type encryption_strategy() :: binary
  @type encryption_strategy_module() :: atom
  @type strategy_not_found() :: tuple

  @spec generate_encryption_key(encryption_strategy) :: EncryptionKey.t() | strategy_not_found
  def generate_encryption_key(encryption_strategy) when is_binary(encryption_strategy) do
    with {:ok, mod} <- find_strategy(encryption_strategy) do
      %EncryptionKey{} = apply(mod, :generate_key, [])
    end
  end

  @spec encrypt(encryption_strategy, EncryptionKey.t(), binary) ::
          :ok | {:unsupported_encryption_strategy, atom}
  def encrypt(encryption_strategy, %EncryptionKey{} = key, data)
      when is_binary(encryption_strategy) and is_binary(data) do
    with {:ok, mod} <- find_strategy(encryption_strategy) do
      apply(mod, :run_encryption, [data, key])
    end
  end

  @spec decrypt(EncryptedData.t(), EncryptionKey.t()) ::
          {:ok, binary} | {:error, binary | {binary, binary}}
  def decrypt(
        %EncryptedData{encryption_strategy_module: mod} = encrypted_data,
        %EncryptionKey{} = key
      ) do
    apply(mod, :decrypt, [encrypted_data, key])
  end

  def encrypt_with_derived_key(
        _encryption_strategy_name,
        _key_derivation_strategy_name,
        _key,
        _data
      ) do
    :todo
  end

  # code it with a macro
  # Aes256Gcm
  # Rsa4096
  # these 2 below are same is the cipher in Erlang crypto
  # :aes_256_gcm -> {:ok, Aes256gcm}
  # :rsa_4096 -> {:ok, Rsa4096}
  @spec find_strategy(encryption_strategy) :: {:ok, atom} | strategy_not_found
  defp find_strategy(encryption_strategy) do
    case encryption_strategy do
      "Aes256Gcm" -> {:ok, Aes256gcm}
      "Rsa4096" -> {:ok, Rsa4096}
      _ -> {:unsupported_encryption_strategy, encryption_strategy}
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
            # catch this error too
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

    # use IO lists, Luke!!
    # iolist_to_binary/1
    [strategy_name, encrypted_data_base64, encryption_artefacts_base64] |> Enum.join(".")
  end
end
