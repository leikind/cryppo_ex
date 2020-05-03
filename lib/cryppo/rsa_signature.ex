defmodule Cryppo.RsaSignature do
  @moduledoc """
  A struct for an RSA singature and the signed data
  """

  alias Cryppo.{RsaSignature, Serialization}

  @typedoc """
  Struct `Cryppo.RsaSignature`

  A `Cryppo.RsaSignature` struct contains

  * `signature`: RSA signature
  * `data`: signed data
  """

  @type t :: %__MODULE__{signature: binary, data: binary}

  @enforce_keys [:signature, :data]
  defstruct [:signature, :data]

  defimpl Serialization do
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
end
