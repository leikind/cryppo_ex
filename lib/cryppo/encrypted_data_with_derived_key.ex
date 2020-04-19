defmodule Cryppo.EncryptedDataWithDerivedKey do
  @moduledoc """
  A struct to hold a derived key struct and an encrypted data struct
  """

  alias Cryppo.{DerivedKey, EncryptedData}

  @type t :: %__MODULE__{
          encrypted_data: EncryptedData.t(),
          derived_key: DerivedKey.t()
        }

  @enforce_keys [:encrypted_data, :derived_key]
  defstruct [:encrypted_data, :derived_key]
end
