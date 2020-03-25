defmodule Cryppo do
  @moduledoc """
  to do
  """

  alias Cryppo.{Aes256gcm, Rsa4096, EncryptionKey, EncryptedData}

  @type encryption_strategy() :: binary
  @type encryption_strategy_module() :: atom
  @type strategy_not_found() :: tuple

  @spec generate_encryption_key(encryption_strategy) :: EncryptionKey.t() | strategy_not_found
  def generate_encryption_key(encryption_strategy) when is_binary(encryption_strategy) do
    with {:ok, mod} <- find_strategy(encryption_strategy) do
      %EncryptionKey{} = apply(mod, :generate_key, [])
    end
  end

  @spec encrypt(encryption_strategy, EncryptionKey.t(), binary) ::
          :ok | {:strategy_not_found, atom}
  def encrypt(encryption_strategy, %EncryptionKey{} = key, data)
      when is_binary(encryption_strategy) and is_binary(data) do
    with {:ok, mod} <- find_strategy(encryption_strategy) do
      apply(mod, :encrypt, [data, key])
    end
  end

  @spec decrypt(EncryptedData.t(), EncryptionKey.t()) ::
          {:ok, binary} | {:error, binary | {binary, binary}}
  def decrypt(
        %EncryptedData{encryption_strategy_module: mod} = encrypted_data,
        %EncryptionKey{} = key
      ) do
    apply(mod, :decrypt, [encrypted_data, key])
  end

  # code it with a macro
  # Aes256Gcm
  # Rsa4096
  # these 2 below are same is the cipher in Erlang crypto
  # :aes_256_gcm -> {:ok, Aes256gcm}
  # :rsa_4096 -> {:ok, Rsa4096}
  @spec find_strategy(encryption_strategy) :: {:ok, atom} | strategy_not_found
  defp find_strategy(encryption_strategy) do
    case encryption_strategy do
      "Aes256Gcm" -> {:ok, Aes256gcm}
      "Rsa4096" -> {:ok, Rsa4096}
      _ -> {:strategy_not_found, encryption_strategy}
    end
  end

  @spec serialize(EncryptedData.t()) :: binary
  def serialize(%EncryptedData{
        encryption_strategy_module: mod,
        encrypted_data: encrypted_data,
        encryption_artefacts: encryption_artefacts
      }) do
    strategy_name = apply(mod, :strategy_name, [])
    encrypted_data_base64 = encrypted_data |> Base.url_encode64(padding: true)

    encryption_artefacts_base64 =
      encryption_artefacts |> to_yaml() |> Base.url_encode64(padding: true)

    # use IO lists, Luke!!
    # iolist_to_binary/1
    [strategy_name, encrypted_data_base64, encryption_artefacts_base64] |> Enum.join(".")
  end

  defp to_yaml(%{} = map) do
    if map == %{} do
      "--- {}\n"
    else
      "---\n" <> to_yaml(map, "") <> "\n"
    end
  end

  defp to_yaml(%{} = map, indentation) do
    map
    |> Enum.map(fn {key, value} ->
      next_indentation = "#{indentation}  "

      cond do
        is_bitstring(value) ->
          if String.valid?(value) do
            "#{indentation}#{key}: #{value}"
          else
            value_base64 = value |> Base.encode64()
            # refactor this mess
            "#{indentation}#{key}: !binary |-\n#{next_indentation}#{value_base64}"
          end

        is_number(value) ->
          "#{indentation}#{key}: #{value}"

        is_map(value) ->
          # refactor this mess
          "#{indentation}#{key}:\n#{to_yaml(value, next_indentation)}"
      end
    end)
    |> Enum.join("\n")
  end
end
