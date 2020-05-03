defmodule Cryppo.EncryptionKey do
  @moduledoc """
  A struct to wrap an encryption key

  An `EncryptionKey` struct may be marked as belonging to a certain encryption strategy
  using field `encryption_strategy_module` containing the module of the encryption strategy.

  Depending on the encryption strategy the key can be a binary or a tuple.

  Keys must be guarded and protected, that is why the `Inspect` protocol has been
  overridden for this struct to disable pretty-printing.

  Should you need to access the key, access it via field `key`.
  """

  @typedoc "A binary key"
  @type binary_key() :: binary()

  @typedoc """
  Encryption key

  An encryption key may me a tuple or a binary depending on the encryption strategy
  """
  @type internal_key() :: binary_key() | tuple

  @typedoc """
  Struct EncryptionKey

  A `Cryppo.EncryptionKey` struct contains

  * `key`: the key itself
  * `encryption_strategy_module`: module of the encryption strategy to which the key belongs
  """
  @type t :: %__MODULE__{
          encryption_strategy_module: Cryppo.encryption_strategy_module(),
          key: internal_key()
        }

  @enforce_keys [:key]
  defstruct [:encryption_strategy_module, :key]

  @doc """
  Initialize a struct with  an encryption key and the module of an encryption strategy
  """
  @spec new(internal_key(), Cryppo.encryption_strategy_module()) :: t()
  def new(key, mod), do: %__MODULE__{key: key, encryption_strategy_module: mod}

  @doc """
  Initialize a struct with an encryption key
  """
  @spec new(internal_key()) :: t()
  def new(key), do: %__MODULE__{key: key}

  defimpl Inspect do
    @spec inspect(Inspect.t(), Inspect.Opts.t()) :: Inspect.Algebra.t()
    def inspect(_data, _opts), do: "%Cryppo.EncryptionKey{ HIDDEN }"
  end
end
