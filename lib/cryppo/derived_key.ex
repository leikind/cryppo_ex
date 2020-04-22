defmodule Cryppo.DerivedKey do
  @moduledoc """
  A struct to hold a derived encryption key and all derivation artefacts
  """

  alias Cryppo.{EncryptionKey, Yaml}

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

defimpl Cryppo.Serialization, for: Cryppo.DerivedKey do
  alias Cryppo.{DerivedKey, Yaml}

  @spec serialize(DerivedKey.t()) :: binary
  def serialize(%DerivedKey{
        key_derivation_strategy: key_derivation_mod,
        salt: salt,
        iter: iterations,
        length: length
      }) do
    key_derivation_mod = apply(key_derivation_mod, :strategy_name, [])

    derivation_artefacts =
      %{"iv" => salt, "i" => iterations, "l" => length}
      |> Yaml.encode()
      |> Base.url_encode64(padding: true)

    [key_derivation_mod, derivation_artefacts] |> Enum.join(".")
  end
end
