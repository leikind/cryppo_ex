defmodule Cryppo.EncryptionKey do
  @moduledoc """
  A struct to hold encryption keys of various encryption strategies
  """

  @type binary_key() :: binary()
  @type rsa_key_tuple() :: tuple()
  @type internal_key() :: binary_key() | rsa_key_tuple()
  @type t :: %__MODULE__{
          encryption_strategy_module: Cryppo.encryption_strategy_module(),
          key: internal_key()
        }

  @enforce_keys [:key]
  defstruct [:encryption_strategy_module, :key]

  @spec new(binary_key() | rsa_key_tuple(), Cryppo.encryption_strategy_module()) ::
          Cryppo.EncryptionKey.t()
  def new(key, mod), do: %__MODULE__{key: key, encryption_strategy_module: mod}

  @spec new(binary_key() | rsa_key_tuple()) :: Cryppo.EncryptionKey.t()
  def new(key), do: %__MODULE__{key: key}

  defimpl Inspect do
    @spec inspect(Inspect.t(), Inspect.Opts.t()) :: Inspect.Algebra.t()
    def inspect(_data, _opts), do: "%Cryppo.EncryptionKey{ HIDDEN }"
  end
end
