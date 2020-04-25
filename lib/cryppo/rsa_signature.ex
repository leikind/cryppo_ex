defmodule Cryppo.RsaSignature do
  @moduledoc """
  A struct to hold an RSA singature and the signed data
  """

  @type t :: %__MODULE__{signature: binary, data: binary}

  @enforce_keys [:signature, :data]
  defstruct [:signature, :data]
end
