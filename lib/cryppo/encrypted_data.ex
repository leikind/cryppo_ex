defmodule Cryppo.EncryptedData do
  @moduledoc """
  A struct for encrypted data and encryption artefacts

  An `Cryppo.EncryptedData` struct may be marked as belonging to a certain encryption strategy
  using field `encryption_strategy_module` containing the module of the encryption strategy.

  Can also contain encryption artefacts if they are part of the  encryption strategy.
  """

  import Cryppo.Base64
  import Cryppo.Strategies, only: [find_strategy: 1]
  alias Cryppo.{EncryptedData, EncryptionArtefacts, Serialization}

  @typedoc """
  Struct `Cryppo.EncryptedData`

  A `Cryppo.EncryptedData` struct contains

  * `encrypted_data`: encrypted data
  * `encryption_strategy_module`: module of the encryption strategy to which the key belongs
  * `encryption_artefacts`: a map with encryption artefacts
  """

  @type t :: %__MODULE__{
          encryption_strategy_module: Cryppo.encryption_strategy_module() | nil,
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

  @doc false
  @spec load(String.t(), String.t(), String.t()) ::
          {:ok, t()}
          | {:error, :invalid_yaml, :invalid_bson, :invalid_base64}
          | {:unsupported_encryption_strategy, binary}
  def load(strategy_name, encrypted_data_base64, encryption_artefacts_base64) do
    case find_strategy(strategy_name) do
      {:ok, encryption_strategy_mod} ->
        with {:ok, encrypted_data} <- decode_base64(encrypted_data_base64),
             {:ok, encryption_artefacts} <- EncryptionArtefacts.load(encryption_artefacts_base64) do
          {:ok, new(encryption_strategy_mod, encrypted_data, encryption_artefacts)}
        end

      err ->
        err
    end
  end

  defimpl Serialization do
    @spec serialize(EncryptedData.t(), Keyword.t()) :: binary
    def serialize(
          %EncryptedData{
            encryption_strategy_module: mod,
            encrypted_data: encrypted_data,
            encryption_artefacts: encryption_artefacts
          },
          opts \\ []
        ) do
      strategy_name = apply(mod, :strategy_name, [])

      [
        strategy_name,
        Base.url_encode64(encrypted_data, padding: true),
        Serialization.serialize(encryption_artefacts, opts)
      ]
      |> Enum.join(".")
    end
  end
end
