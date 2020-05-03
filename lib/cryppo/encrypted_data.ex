defmodule Cryppo.EncryptedData do
  @moduledoc """
  A struct for encrypted data and encryption artefacts

  An `Cryppo.EncryptedData` struct may be marked as belonging to a certain encryption strategy
  using field `encryption_strategy_module` containing the module of the encryption strategy.

  Can also contain encryption artefacts if they are part of the  encryption strategy.
  """

  alias Cryppo.{EncryptedData, Serialization, Yaml}

  @typedoc """
  A map with encryption artefacts
  """

  @type encryption_artefacts :: map() | Keyword.t()

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
          encryption_artefacts: encryption_artefacts
        }

  @enforce_keys [:encryption_strategy_module, :encrypted_data, :encryption_artefacts]
  defstruct [:encryption_strategy_module, :encrypted_data, :encryption_artefacts]

  @doc """
  Initialize a struct with the module of an encryption strategy and a
  binary with encrypted data.
  """
  @spec new(Cryppo.encryption_strategy_module(), binary) :: t()
  def new(mod, encrypted_data), do: new(mod, encrypted_data, %{})

  @doc """
  Initialize a struct with the module of an encryption strategy, a
  binary with encrypted data, and encryption_artefacts.
  """
  @spec new(Cryppo.encryption_strategy_module(), binary, encryption_artefacts()) :: t()
  def new(mod, encrypted_data, encryption_artefacts) when is_list(encryption_artefacts),
    do: new(mod, encrypted_data, encryption_artefacts |> Enum.into(%{}))

  def new(mod, encrypted_data, %{} = encryption_artefacts)
      when is_atom(mod) and is_binary(encrypted_data) do
    %__MODULE__{
      encryption_strategy_module: mod,
      encrypted_data: encrypted_data,
      encryption_artefacts: atomize_keys(encryption_artefacts)
    }
  end

  defp atomize_keys(nil), do: nil

  defp atomize_keys(%{} = map) do
    map
    |> Enum.map(fn
      {k, v} when is_binary(k) -> {String.to_atom(k), atomize_keys(v)}
      {k, v} -> {k, atomize_keys(v)}
    end)
    |> Enum.into(%{})
  end

  defp atomize_keys([head | rest]) do
    [atomize_keys(head) | atomize_keys(rest)]
  end

  defp atomize_keys(not_a_map), do: not_a_map

  defimpl Serialization do
    @spec serialize(EncryptedData.t()) :: binary
    def serialize(%EncryptedData{
          encryption_strategy_module: mod,
          encrypted_data: encrypted_data,
          encryption_artefacts: encryption_artefacts
        }) do
      strategy_name = apply(mod, :strategy_name, [])
      encrypted_data_base64 = encrypted_data |> Base.url_encode64(padding: true)

      encryption_artefacts_base64 =
        encryption_artefacts |> Yaml.encode() |> Base.url_encode64(padding: true)

      [strategy_name, encrypted_data_base64, encryption_artefacts_base64] |> Enum.join(".")
    end
  end
end
