defmodule Cryppo.EncryptedData do
  @moduledoc """
  A struct to hold encrypted tagged with the encryption strategy.
  Can also contain encryption artefacts if they are part of the  encryption strategy.
  """

  alias Cryppo.Yaml

  @type encryption_artefacts :: map() | Keyword.t()
  @type t :: %__MODULE__{
          encryption_strategy_module: Cryppo.encryption_strategy_module(),
          encrypted_data: binary,
          encryption_artefacts: encryption_artefacts
        }

  @enforce_keys [:encryption_strategy_module, :encrypted_data, :encryption_artefacts]
  defstruct [:encryption_strategy_module, :encrypted_data, :encryption_artefacts]

  @spec new(Cryppo.encryption_strategy_module(), binary) :: t()
  def new(mod, encrypted_data), do: new(mod, encrypted_data, %{})

  @spec new(Cryppo.encryption_strategy_module(), binary, map() | Keyword.t()) :: t()

  def new(mod, encrypted_data, encryption_artefacts) when is_list(encryption_artefacts) do
    new(mod, encrypted_data, encryption_artefacts |> Enum.into(%{}))
  end

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
end

defimpl Cryppo.Serialization, for: Cryppo.EncryptedData do
  alias Cryppo.{EncryptedData, Yaml}

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
