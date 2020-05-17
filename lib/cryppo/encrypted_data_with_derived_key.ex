defmodule Cryppo.EncryptedDataWithDerivedKey do
  @moduledoc """
  A struct for a derived key and data encrypted with this derived key
  """

  alias Cryppo.{
    DerivedKey,
    EncryptedData,
    EncryptedDataWithDerivedKey,
    Serialization,
    Yaml
  }

  import Cryppo.Base64
  import Cryppo.Strategies, only: [find_key_derivation_strategy: 1]

  @typedoc """
  Struct `Cryppo.EncryptedData`

  A `Cryppo.EncryptedData` struct contains

  * `encrypted_data`: a `Cryppo.EncryptedData` struct
  * `derived_key`: a `Cryppo.DerivedKey` struct
  """

  @type t :: %__MODULE__{
          encrypted_data: EncryptedData.t(),
          derived_key: DerivedKey.t()
        }

  @enforce_keys [:encrypted_data, :derived_key]
  defstruct [:encrypted_data, :derived_key]

  @doc false
  @spec load(any, any, any, binary, any) ::
          {:ok, t()}
          | {:error, :invalid_base64 | :invalid_derivation_artefacts | :invalid_yaml}
          | {:unsupported_encryption_strategy, binary}
          | {:unsupported_key_derivation_strategy, binary}
  def load(
        strategy_name,
        encrypted_data_base64,
        encryption_artefacts_base64,
        key_derivation_strategy,
        derivation_artefacts_base64
      ) do
    with {:ok, key_derivation_mod} <-
           find_key_derivation_strategy(key_derivation_strategy),
         {:ok, derivation_artefacts_yaml} <- decode_base64(derivation_artefacts_base64),
         {:ok, derivation_artefacts} <- Yaml.decode(derivation_artefacts_yaml),
         {:ok, salt, iterations, length} <- parse_derivation_artefacts(derivation_artefacts),
         {:ok, encrypted_data} <-
           EncryptedData.load(strategy_name, encrypted_data_base64, encryption_artefacts_base64) do
      hash = apply(key_derivation_mod, :hash_function, [])

      derived_key = %DerivedKey{
        encryption_key: nil,
        key_derivation_strategy: key_derivation_mod,
        salt: salt,
        iter: iterations,
        length: length,
        hash: hash
      }

      key = %__MODULE__{encrypted_data: encrypted_data, derived_key: derived_key}
      {:ok, key}
    end
  end

  @spec parse_derivation_artefacts(any) ::
          {:error, :invalid_derivation_artefacts} | {:ok, binary, integer, integer}
  defp parse_derivation_artefacts(%{"iv" => iv, "i" => i, "l" => l}), do: {:ok, iv, i, l}
  defp parse_derivation_artefacts(_), do: {:error, :invalid_derivation_artefacts}

  defimpl Serialization do
    @spec serialize(EncryptedDataWithDerivedKey.t()) :: binary
    def serialize(%EncryptedDataWithDerivedKey{
          derived_key: %DerivedKey{} = derived_key,
          encrypted_data: %EncryptedData{} = encrypted_data
        }) do
      [encrypted_data, derived_key]
      |> Enum.map(&Serialization.serialize(&1))
      |> Enum.join(".")
    end
  end
end
