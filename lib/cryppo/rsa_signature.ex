defmodule Cryppo.RsaSignature do
  @moduledoc """
  A struct to hold an RSA singature and the signed data
  """

  @type t :: %__MODULE__{signature: binary, data: binary}

  @enforce_keys [:signature, :data]
  defstruct [:signature, :data]
end

defimpl Cryppo.Serialization, for: Cryppo.RsaSignature do
  alias Cryppo.RsaSignature

  @spec serialize(RsaSignature.t()) :: binary
  def serialize(%RsaSignature{signature: signature, data: data}) do
    [
      "Sign.Rsa4096",
      Base.url_encode64(signature, padding: true),
      Base.url_encode64(data, padding: true)
    ]
    |> Enum.join(".")
  end
end
