defmodule Cryppo.EncryptionArtefacts do
  @moduledoc """
  A struct for encryption artefacts

  Each encryption strategy can use `Cryppo.EncryptionArtefacts` if it
  makes sense for the underlying cipher.
  """

  @typedoc "Struct `Cryppo.EncryptionArtefacts`"

  @type t :: %__MODULE__{
          initialization_vector: binary | nil,
          authentication_tag: binary | nil,
          additional_authenticated_data: binary | nil
        }

  alias Cryppo.{EncryptionArtefacts, Serialization, Yaml}

  defstruct [:initialization_vector, :authentication_tag, :additional_authenticated_data]

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
