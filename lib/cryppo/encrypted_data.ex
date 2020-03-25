defmodule Cryppo.EncryptedData do
  @type t :: %__MODULE__{
          encryption_strategy_module: Cryppo.encryption_strategy_module(),
          encrypted_data: binary,
          encryption_artefacts: map() | Keyword.t()
        }

  @enforce_keys [:encryption_strategy_module, :encrypted_data, :encryption_artefacts]
  defstruct [:encryption_strategy_module, :encrypted_data, :encryption_artefacts]

  @spec new(Cryppo.encryption_strategy_module(), binary, map() | Keyword.t()) :: t()
  def new(mod, encrypted_data, encryption_artefacts \\ %{})
      when is_atom(mod) and is_binary(encrypted_data) do
    %__MODULE__{
      encryption_strategy_module: mod,
      encrypted_data: encrypted_data,
      encryption_artefacts: encryption_artefacts |> Enum.into(%{})
    }
  end
end
