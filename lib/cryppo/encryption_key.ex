defmodule Cryppo.EncryptionKey do
  @type binary_key() :: binary()
  @type rsa_key_tuple() :: tuple()
  @type t :: %__MODULE__{key: binary_key() | rsa_key_tuple()}

  @enforce_keys [:key]
  defstruct [:key]

  @spec new(binary_key() | rsa_key_tuple()) :: Cryppo.EncryptionKey.t()
  def new(key), do: %__MODULE__{key: key}

  @spec unwrap(Cryppo.EncryptionKey.t()) :: binary_key() | rsa_key_tuple()
  def unwrap(%__MODULE__{key: key}), do: key

  defimpl Inspect do
    @spec inspect(Inspect.t(), Inspect.Opts.t()) :: Inspect.Algebra.t()
    def inspect(_data, _opts), do: "%Cryppo.EncryptionKey{ HIDDEN }"
  end
end
