defmodule Cryppo.EncryptedDataWithDerivedKey do
  @moduledoc """
  A struct for a derived key and data encrypted with this derived key
  """

  import Cryppo.Base64
  import Cryppo.Strategies, only: [find_key_derivation_strategy: 1]
  alias Cryppo.{DerivedKey, EncryptedData, EncryptedDataWithDerivedKey, Serialization}

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
  @spec load(String.t(), String.t(), String.t(), String.t(), String.t()) ::
          {:ok, t()}
          | {:error,
             :invalid_base64 | :invalid_derivation_artefacts | :invalid_yaml | :invalid_bson}
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
         {:ok, salt, iterations, length} <- DerivedKey.load_artefacts(derivation_artefacts_yaml),
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

  defimpl Serialization do
    @spec serialize(EncryptedDataWithDerivedKey.t(), Keyword.t()) :: binary
    def serialize(
          %EncryptedDataWithDerivedKey{
            derived_key: %DerivedKey{} = derived_key,
            encrypted_data: %EncryptedData{} = encrypted_data
          },
          opts \\ []
        ) do
      [encrypted_data, derived_key]
      |> Enum.map(fn v -> Serialization.serialize(v, opts) end)
      |> Enum.join(".")
    end
  end
end
