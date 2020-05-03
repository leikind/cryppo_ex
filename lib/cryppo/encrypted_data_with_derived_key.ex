defmodule Cryppo.EncryptedDataWithDerivedKey do
  @moduledoc """
  A struct for a derived key and data encrypted with this derived key
  """

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
