defmodule Cryppo.Loader do
  @moduledoc false

  alias Cryppo.{DerivedKey, EncryptedData, EncryptedDataWithDerivedKey, RsaSignature, Yaml}

  import Cryppo.Strategies, only: [find_strategy: 1, find_key_derivation_strategy: 1]

  @spec load(binary) ::
          EncryptedDataWithDerivedKey.t()
          | EncryptedData.t()
          | RsaSignature.t()
          | {:error, :invalid_base64}
          | {:error, :invalid_derivation_artefacts}
          | {:unsupported_encryption_strategy, binary}
          | {:unsupported_key_derivation_strategy, binary}
  def load(serialized) when is_binary(serialized) do
    case String.split(serialized, ".") do
      ["Sign", "Rsa4096", signature, data] ->
        to_rsa_signature(signature, data)

      [strategy_name, encrypted_data, encryption_artefacts] ->
        to_encrypted_data(strategy_name, encrypted_data, encryption_artefacts)

      [
        strategy,
        encrypted_data,
        encryption_artefacts,
        key_derivation_strategy,
        derivation_artefacts
      ] ->
        to_encrypted_data_with_derived_key(
          strategy,
          encrypted_data,
          encryption_artefacts,
          key_derivation_strategy,
          derivation_artefacts
        )

      _ ->
        {:error, :invalid_serialization_value}
    end
  end

  @spec to_rsa_signature(binary, binary) :: RsaSignature.t() | {:error, :invalid_base64}
  defp to_rsa_signature(signature, data) do
    with {:ok, signature} <- decode_base64(signature),
         {:ok, data} <- decode_base64(data) do
      %RsaSignature{signature: signature, data: data}
    end
  end

  @spec to_encrypted_data(binary, any, any) ::
          EncryptedData.t()
          | {:error, :invalid_base64}
          | {:unsupported_encryption_strategy, binary}
  defp to_encrypted_data(strategy_name, encrypted_data_base64, encryption_artefacts_base64) do
    case find_strategy(strategy_name) do
      {:ok, encryption_strategy_mod} ->
        with {:ok, encrypted_data} <- decode_base64(encrypted_data_base64),
             {:ok, encryption_artefacts_base64} <- decode_base64(encryption_artefacts_base64),
             encryption_artefacts <- Yaml.decode(encryption_artefacts_base64) do
          EncryptedData.new(encryption_strategy_mod, encrypted_data, encryption_artefacts)
        end

      err ->
        err
    end
  end

  @spec to_encrypted_data_with_derived_key(binary, binary, binary, binary, binary) ::
          EncryptedDataWithDerivedKey.t()
          | {:error, :invalid_base64}
          | {:error, :invalid_derivation_artefacts}
          | {:unsupported_encryption_strategy, binary}
          | {:unsupported_key_derivation_strategy, binary}
  defp to_encrypted_data_with_derived_key(
         strategy_name,
         encrypted_data_base64,
         encryption_artefacts_base64,
         key_derivation_strategy,
         derivation_artefacts_base64
       ) do
    with {:ok, key_derivation_mod} <-
           find_key_derivation_strategy(key_derivation_strategy),
         {:ok, derivation_artefacts_yaml} <- decode_base64(derivation_artefacts_base64),
         derivation_artefacts <- Yaml.decode(derivation_artefacts_yaml),
         {:ok, salt, iterations, length} <- parse_derivation_artefacts(derivation_artefacts),
         %EncryptedData{} = encrypted_data <-
           to_encrypted_data(strategy_name, encrypted_data_base64, encryption_artefacts_base64) do
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
  end

  @spec parse_derivation_artefacts(any) ::
          {:error, :invalid_derivation_artefacts} | {:ok, binary, binary, binary}
  defp parse_derivation_artefacts(%{"iv" => iv, "i" => i, "l" => l}), do: {:ok, iv, i, l}
  defp parse_derivation_artefacts(_), do: {:error, :invalid_derivation_artefacts}

  @spec decode_base64(binary) :: {:error, :invalid_base64} | {:ok, binary}
  defp decode_base64(base64) do
    case Base.url_decode64(base64) do
      :error -> {:error, :invalid_base64}
      {:ok, decoded} -> {:ok, decoded}
    end
  end
end
