defmodule Cryppo.EncryptedData do
  @type t :: %__MODULE__{
          encryption_strategy_module: Cryppo.encryption_strategy_module(),
          encrypted_data: binary,
          encryption_artefacts: map() | Keyword.t()
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
