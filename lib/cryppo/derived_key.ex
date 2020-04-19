defmodule Cryppo.DerivedKey do
  @moduledoc """
  A struct to hold a derived encryption key and all derivation artefacts
  """

  alias Cryppo.EncryptionKey

  @type t :: %__MODULE__{
          encryption_key: EncryptionKey.t(),
          key_derivation_strategy: Cryppo.encryption_strategy(),
          salt: binary,
          iter: integer,
          length: integer,
          hash: String.t()
        }

  @enforce_keys [:encryption_key, :key_derivation_strategy, :salt, :iter, :length, :hash]
  defstruct [:encryption_key, :key_derivation_strategy, :salt, :iter, :length, :hash]
end
