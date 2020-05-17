defmodule Cryppo.EncryptedData do
  @moduledoc """
  A struct for encrypted data and encryption artefacts

  An `Cryppo.EncryptedData` struct may be marked as belonging to a certain encryption strategy
  using field `encryption_strategy_module` containing the module of the encryption strategy.

  Can also contain encryption artefacts if they are part of the  encryption strategy.
  """

  alias Cryppo.{EncryptedData, EncryptionArtefacts, Serialization}

  @typedoc """
  Struct `Cryppo.EncryptedData`

  A `Cryppo.EncryptedData` struct contains

  * `encrypted_data`: encrypted data
  * `encryption_strategy_module`: module of the encryption strategy to which the key belongs
  * `encryption_artefacts`: a map with encryption artefacts
  """

  @type t :: %__MODULE__{
          encryption_strategy_module: Cryppo.encryption_strategy_module(),
          encrypted_data: binary,
          encryption_artefacts: EncryptionArtefacts.t()
        }

  @enforce_keys [:encryption_strategy_module, :encrypted_data, :encryption_artefacts]
  defstruct [:encryption_strategy_module, :encrypted_data, :encryption_artefacts]

  @doc """
  Initialize a struct with the module of an encryption strategy, a
  binary with encrypted data, and encryption_artefacts.
  """
  @spec new(Cryppo.encryption_strategy_module(), binary, EncryptionArtefacts.t()) :: t()
  def new(mod, encrypted_data, %EncryptionArtefacts{} = encryption_artefacts)
      when is_atom(mod) and is_binary(encrypted_data) do
    %__MODULE__{
      encryption_strategy_module: mod,
      encrypted_data: encrypted_data,
      encryption_artefacts: encryption_artefacts
    }
  end

  defimpl Serialization do
    @spec serialize(EncryptedData.t()) :: binary
    def serialize(%EncryptedData{
          encryption_strategy_module: mod,
          encrypted_data: encrypted_data,
          encryption_artefacts: encryption_artefacts
        }) do
      strategy_name = apply(mod, :strategy_name, [])

      [
        strategy_name,
        Base.url_encode64(encrypted_data, padding: true),
        Serialization.serialize(encryption_artefacts)
      ]
      |> Enum.join(".")
    end
  end
end
