defmodule Cryppo.DerivedKey do
  @moduledoc """
  A struct for a derived encryption key and its derivation artefacts

  A `Cryppo.EncryptedData` struct may be marked as belonging to a certain key derivation strategy
  using field `key_derivation_strategy` containing the module of the key derivation.

  A `Cryppo.DerivedKey` comes in 2 flavors:

  * With a derived encryption key. When used for encryption or decryption this key will be used
  * Without an encryption key. Encrypting or decrypting with this struct requires a passphrase to derive the key
  """

  alias Cryppo.{DerivedKey, EncryptionKey, Serialization, Yaml}

  @typedoc """
  Struct `Cryppo.DerivedKey`

  A `Cryppo.DerivedKey` struct contains

  * `encryption_key` - `nil` or a `Cryppo.EncryptionKey`
  * `key_derivation_strategy` - module of the key derivation strategy
  * `salt` - salt used for key derivation
  * `iter` - number of iterations for key derivation
  * `length` - key length
  * `hash` - hash function for key derivation
  """

  @type t :: %__MODULE__{
          encryption_key: EncryptionKey.t(),
          key_derivation_strategy: Cryppo.encryption_strategy_module(),
          salt: binary,
          iter: integer,
          length: integer,
          hash: String.t()
        }

  @enforce_keys [:key_derivation_strategy, :salt, :iter, :length, :hash]
  defstruct [:encryption_key, :key_derivation_strategy, :salt, :iter, :length, :hash]

  defimpl Serialization do
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
end
