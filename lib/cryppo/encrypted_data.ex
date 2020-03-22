defmodule Cryppo.EncryptedData do
  @type t :: %__MODULE__{
          encryption_strategy: Cryppo.encryption_strategy_name(),
          encrypted_data: binary,
          encryption_artefacts: map() | Keyword.t()
        }

  @enforce_keys [:encryption_strategy, :encrypted_data, :encryption_artefacts]
  defstruct [:encryption_strategy, :encrypted_data, :encryption_artefacts]

  @spec new(Cryppo.encryption_strategy_name(), binary, map() | Keyword.t()) :: t()
  def new(encryption_strategy, encrypted_data, encryption_artefacts)
      when is_atom(encryption_strategy) and is_binary(encrypted_data) do
    %__MODULE__{
      encryption_strategy: encryption_strategy,
      encrypted_data: encrypted_data,
      encryption_artefacts: encryption_artefacts |> Enum.into(%{})
    }
  end
end
