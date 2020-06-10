defmodule Cryppo.EncryptionArtefacts do
  @moduledoc """
  A struct for encryption artefacts

  Each encryption strategy can use `Cryppo.EncryptionArtefacts` if it
  makes sense for the underlying cipher.
  """

  alias Cryppo.{EncryptionArtefacts, Serialization, Yaml}
  import Cryppo.Base64

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
  @spec load(String.t()) :: {:ok, t()} | {:error, :invalid_base64 | :invalid_yaml | :invalid_bson}
  def load(s) when is_binary(s) do
    with {:ok, encryption_artefacts_base64} <- decode_base64(s) do
      load_artefacts(encryption_artefacts_base64)
    end
  end

  @spec load_artefacts(binary) ::
          {:error, :invalid_bson | :invalid_yaml}
          | {:ok, EncryptionArtefacts.t()}
  defp load_artefacts(<<"---", _::binary>> = bin) do
    with {:ok, %{} = artefacts_map} <- Yaml.decode(bin) do
      {:ok,
       %__MODULE__{
         initialization_vector: to_nil(artefacts_map["iv"]),
         authentication_tag: to_nil(artefacts_map["at"]),
         additional_authenticated_data: to_nil(artefacts_map["ad"])
       }}
    end
  end

  defp load_artefacts(<<@current_version::binary, bin::binary>>) do
    with {:ok, %{"iv" => {0x0, iv}, "at" => {0x0, at}, "ad" => ad}} <- Cyanide.decode(bin) do
      {:ok,
       %__MODULE__{
         initialization_vector: to_nil(iv),
         authentication_tag: to_nil(at),
         additional_authenticated_data: to_nil(ad)
       }}
    end
  end

  defp to_nil(""), do: nil
  defp to_nil(v), do: v

  defimpl Serialization do
    @spec serialize(EncryptionArtefacts.t(), Keyword.t()) ::
            String.t() | {:error, :cannot_bson_encode | :unrecognized_format}
    def serialize(
          %EncryptionArtefacts{
            initialization_vector: iv,
            authentication_tag: at,
            additional_authenticated_data: ad
          },
          opts \\ []
        ) do
      version = Keyword.get(opts, :version, :latest_version)

      with {:ok, bytes} <- serialize_for_version({version, {iv, at, ad}}) do
        Base.url_encode64(bytes, padding: true)
      end
    end

    @spec serialize_for_version({atom, {any, any, any}}) ::
            {:error, :cannot_bson_encode | :unrecognized_format} | {:ok, binary}
    defp serialize_for_version({:legacy, {iv, at, ad}}) do
      {:ok, Yaml.encode(%{"iv" => iv, "at" => at, "ad" => ad})}
    end

    defp serialize_for_version({:latest_version, {iv, at, ad}}) do
      with_wrapped_binaries = %{"iv" => wrap_bin(iv), "at" => wrap_bin(at), "ad" => ad}

      with {:ok, bin} <- Cyanide.encode(with_wrapped_binaries) do
        with_version_prefix = <<EncryptionArtefacts.current_version()::binary, bin::binary>>
        {:ok, with_version_prefix}
      end
    end

    defp serialize_for_version({_, {_, _, _}}), do: {:error, :unrecognized_format}

    # 0x0 is a marker for generic binary subtype in BSON
    # see http://bsonspec.org/spec.html
    defp wrap_bin(nil), do: {0x0, ""}
    defp wrap_bin(bin), do: {0x0, bin}
  end
end
