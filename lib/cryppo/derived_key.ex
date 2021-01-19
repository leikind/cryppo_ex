defmodule Cryppo.DerivedKey do
  @moduledoc """
  A struct for a derived encryption key and its derivation artefacts

  A `Cryppo.EncryptedData` struct may be marked as belonging to a certain key derivation strategy
  using field `key_derivation_strategy` containing the module of the key derivation.

  A `Cryppo.DerivedKey` comes in 2 flavors:

  * With a derived encryption key. When used for encryption or decryption this key will be used
  * Without an encryption key. Encrypting or decrypting with this struct requires a passphrase to derive the key
  """

  alias Cryppo.{DerivedKey, EncryptionKey, Serialization, Yaml}

  @typedoc """
  Struct `Cryppo.DerivedKey`

  A `Cryppo.DerivedKey` struct contains

  * `encryption_key` - `nil` or a `Cryppo.EncryptionKey`
  * `key_derivation_strategy` - module of the key derivation strategy
  * `salt` - salt used for key derivation
  * `iter` - number of iterations for key derivation
  * `length` - key length
  * `hash` - hash function for key derivation
  """

  @type t :: %__MODULE__{
          encryption_key: EncryptionKey.t() | nil,
          key_derivation_strategy: Cryppo.encryption_strategy_module(),
          salt: binary,
          iter: integer,
          length: integer,
          hash: String.t()
        }

  @enforce_keys [:key_derivation_strategy, :salt, :iter, :length, :hash]
  defstruct [:encryption_key, :key_derivation_strategy, :salt, :iter, :length, :hash]

  # 75 is the version byte for derivation artefacts encoded with BSON
  @current_version "K"

  @spec current_version :: <<_::8>>
  def current_version, do: @current_version

  @spec load_artefacts(binary) ::
          {:error, :invalid_bson | :invalid_derivation_artefacts | :invalid_yaml | String.t()}
          | {:ok, binary, integer, integer}
  def load_artefacts(<<"---", _::binary>> = bin) do
    with {:ok, derivation_artefacts} <- Yaml.decode(bin) do
      parse_derivation_artefacts(derivation_artefacts)
    end
  end

  def load_artefacts(<<@current_version::binary, bin::binary>>) do
    with {:ok, %{"iv" => {0x0, iv}, "i" => i, "l" => l}} <- Cyanide.decode(bin) do
      %{"iv" => iv, "i" => i, "l" => l} |> parse_derivation_artefacts()
    end
  end

  @spec parse_derivation_artefacts(any) ::
          {:error, :invalid_derivation_artefacts} | {:ok, binary, integer, integer}
  defp parse_derivation_artefacts(%{"iv" => iv, "i" => i, "l" => l}), do: {:ok, iv, i, l}
  defp parse_derivation_artefacts(_), do: {:error, :invalid_derivation_artefacts}

  defimpl Serialization do
    @spec serialize(DerivedKey.t(), Keyword.t()) ::
            String.t() | {:error, :cannot_bson_encode | :unrecognized_format}
    def serialize(
          %DerivedKey{
            key_derivation_strategy: key_derivation_mod,
            salt: salt,
            iter: iterations,
            length: length
          },
          opts \\ []
        ) do
      version = Keyword.get(opts, :version, :latest_version)
      key_derivation_mod = apply(key_derivation_mod, :strategy_name, [])

      with {:ok, bytes} <- serialize_for_version({version, {salt, iterations, length}}) do
        derivation_artefacts = Base.url_encode64(bytes, padding: true)
        [key_derivation_mod, derivation_artefacts] |> Enum.join(".")
      end
    end

    @spec serialize_for_version({atom, {any, any, any}}) ::
            {:error, :cannot_bson_encode | :unrecognized_format} | {:ok, binary}
    def serialize_for_version({:legacy, {salt, iterations, length}}) do
      {:ok, Yaml.encode(%{"iv" => salt, "i" => iterations, "l" => length})}
    end

    def serialize_for_version({:latest_version, {salt, iterations, length}}) do
      # 0x0 is a marker for generic binary subtype in BSON
      # see http://bsonspec.org/spec.html
      with_wrapped_binaries = %{"iv" => {0x0, salt}, "i" => iterations, "l" => length}

      with {:ok, bin} <- Cyanide.encode(with_wrapped_binaries) do
        with_version_prefix = <<DerivedKey.current_version()::binary, bin::binary>>

        {:ok, with_version_prefix}
      end
    end

    def serialize_for_version({_, {_, _, _}}), do: {:error, :unrecognized_format}
  end
end
