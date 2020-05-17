defmodule Cryppo.RsaSignature do
  @moduledoc """
  A struct for an RSA singature and the signed data
  """

  alias Cryppo.{RsaSignature, Serialization}
  import Cryppo.Base64

  @typedoc """
  Struct `Cryppo.RsaSignature`

  A `Cryppo.RsaSignature` struct contains

  * `signature`: RSA signature
  * `data`: signed data
  """

  @type t :: %__MODULE__{signature: binary, data: binary}

  @enforce_keys [:signature, :data]
  defstruct [:signature, :data]

  @doc false
  @spec load(binary, binary) :: t() | {:error, :invalid_base64}
  def load(signature, data) do
    with {:ok, signature} <- decode_base64(signature),
         {:ok, data} <- decode_base64(data) do
      %__MODULE__{signature: signature, data: data}
    end
  end

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
