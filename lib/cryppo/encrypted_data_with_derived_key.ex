defmodule Cryppo.EncryptedDataWithDerivedKey do
  @moduledoc """
  A struct to hold a derived key struct and an encrypted data struct
  """

  alias Cryppo.{DerivedKey, EncryptedData, Serialization}

  @type t :: %__MODULE__{
          encrypted_data: EncryptedData.t(),
          derived_key: DerivedKey.t()
        }

  @enforce_keys [:encrypted_data, :derived_key]
  defstruct [:encrypted_data, :derived_key]
end

defimpl Cryppo.Serialization, for: Cryppo.EncryptedDataWithDerivedKey do
  alias Cryppo.{
    DerivedKey,
    EncryptedData,
    EncryptedDataWithDerivedKey,
    Serialization
  }

  @spec serialize(EncryptedDataWithDerivedKey.t()) :: binary
  def serialize(%EncryptedDataWithDerivedKey{
        derived_key: %DerivedKey{} = derived_key,
        encrypted_data: %EncryptedData{} = encrypted_data
      }) do
    [Serialization.serialize(encrypted_data), Serialization.serialize(derived_key)]
    |> Enum.join(".")
  end
end
