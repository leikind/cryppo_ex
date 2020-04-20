defmodule Cryppo.DerivedKey do
  @moduledoc """
  A struct to hold a derived encryption key and all derivation artefacts
  """

  alias Cryppo.EncryptionKey

  @type t :: %__MODULE__{
          encryption_key: EncryptionKey.t(),
          key_derivation_strategy: Cryppo.encryption_strategy_module(),
          salt: binary,
          iter: integer,
          length: integer,
          hash: String.t()
        }

  # DerivedKey comes in 2 flavors:
  # (1) with a derived encryption_key
  # (2) and without encryption_key , but ready to derive it
  @enforce_keys [:key_derivation_strategy, :salt, :iter, :length, :hash]
  defstruct [:encryption_key, :key_derivation_strategy, :salt, :iter, :length, :hash]
end
