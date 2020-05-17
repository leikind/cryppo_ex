defmodule Cryppo.EncryptionArtefacts do
  @moduledoc """
  A struct for encryption artefacts

  Each encryption strategy can use `Cryppo.EncryptionArtefacts` if it
  makes sense for the underlying cipher.
  """

  alias Cryppo.Yaml
  import Cryppo.Base64

  @typedoc "Struct `Cryppo.EncryptionArtefacts`"

  @type t :: %__MODULE__{
          initialization_vector: binary | nil,
          authentication_tag: binary | nil,
          additional_authenticated_data: binary | nil
        }

  alias Cryppo.{EncryptionArtefacts, Serialization, Yaml}

  defstruct [:initialization_vector, :authentication_tag, :additional_authenticated_data]

  @doc false
  @spec load(String.t()) :: {:ok, t()} | {:error, :invalid_base64 | :invalid_yaml}
  def load(s) when is_binary(s) do
    with {:ok, encryption_artefacts_base64} <- decode_base64(s),
         {:ok, %{} = artefacts_map} <- Yaml.decode(encryption_artefacts_base64) do
      {:ok,
       %__MODULE__{
         initialization_vector: artefacts_map["iv"],
         authentication_tag: artefacts_map["at"],
         additional_authenticated_data: artefacts_map["ad"]
       }}
    end
  end

  defimpl Serialization do
    @spec serialize(EncryptionArtefacts.t()) :: binary
    def serialize(%EncryptionArtefacts{
          initialization_vector: iv,
          authentication_tag: at,
          additional_authenticated_data: ad
        }) do
      %{iv: iv, at: at, ad: ad}
      |> Yaml.encode()
      |> Base.url_encode64(padding: true)
    end
  end
end
