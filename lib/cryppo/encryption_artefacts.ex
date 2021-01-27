defmodule Cryppo.EncryptionArtefacts do
  @moduledoc """
  A struct for encryption artefacts

  Each encryption strategy can use `Cryppo.EncryptionArtefacts` if it
  makes sense for the underlying cipher.
  """

  import Cryppo.Base64
  alias Cryppo.{EncryptionArtefacts, Serialization}

  @typedoc "Struct `Cryppo.EncryptionArtefacts`"

  @type t :: %__MODULE__{
          initialization_vector: binary | nil,
          authentication_tag: binary | nil,
          additional_authenticated_data: binary | nil
        }

  defstruct [:initialization_vector, :authentication_tag, :additional_authenticated_data]

  # 65 is the version byte for encryption artefacts encoded with BSON
  @current_version "A"

  @spec current_version :: <<_::8>>
  def current_version, do: @current_version

  @doc false
  @spec load(String.t()) ::
          {:ok, t()}
          | {:error, :invalid_base64 | :invalid_bson | :invalid_encryption_artefacts, String.t()}
  def load(s) when is_binary(s) do
    with {:ok, encryption_artefacts_base64} <- decode_base64(s) do
      load_artefacts(encryption_artefacts_base64)
    end
  end

  defp load_artefacts(<<@current_version::binary, bin::binary>>) do
    with {:ok, map} <- Cyanide.decode(bin) do
      {:ok,
       %__MODULE__{
         initialization_vector: unwrap_bin(map["iv"]),
         authentication_tag: unwrap_bin(map["at"]),
         additional_authenticated_data: map["ad"]
       }}
    end
  end

  defp load_artefacts(_), do: {:error, :invalid_encryption_artefacts}

  defp unwrap_bin(nil), do: nil
  defp unwrap_bin({0x0, ""}), do: nil
  defp unwrap_bin({0x0, bin}), do: bin

  defimpl Serialization do
    @spec serialize(EncryptionArtefacts.t()) :: String.t() | {:error, :cannot_bson_encode}
    def serialize(%EncryptionArtefacts{
          initialization_vector: iv,
          authentication_tag: at,
          additional_authenticated_data: ad
        }) do
      with {:ok, bytes} <- serialize_for_version(iv, at, ad) do
        Base.url_encode64(bytes, padding: true)
      end
    end

    @spec serialize_for_version(any, any, any) :: {:error, :cannot_bson_encode} | {:ok, binary}
    defp serialize_for_version(iv, at, ad) do
      with_wrapped_binaries =
        if non_empty_string?(ad),
          do: %{"ad" => ad},
          else: %{}

      with_wrapped_binaries =
        [{"iv", iv}, {"at", at}]
        |> Enum.filter(fn {_k, v} -> non_empty_string?(v) end)
        |> Enum.map(fn {k, v} -> {k, wrap_bin(v)} end)
        |> Enum.into(with_wrapped_binaries)

      with {:ok, bin} <- Cyanide.encode(with_wrapped_binaries) do
        with_version_prefix = <<EncryptionArtefacts.current_version()::binary, bin::binary>>
        {:ok, with_version_prefix}
      end
    end

    defp non_empty_string?(s), do: is_binary(s) && s != ""

    # 0x0 is a marker for generic binary subtype in BSON
    # see http://bsonspec.org/spec.html
    defp wrap_bin(nil), do: {0x0, ""}
    defp wrap_bin(bin), do: {0x0, bin}
  end
end
