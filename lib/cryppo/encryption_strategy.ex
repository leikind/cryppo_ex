defmodule Cryppo.EncryptionStrategy do
  @moduledoc """
  EncryptionStrategy behavior and macros to inject functions
  common to all EncryptionStrategy modules
  """

  alias Cryppo.{EncryptedData, EncryptionKey}

  @callback strategy_name :: binary
  @callback generate_key :: EncryptionKey.t()
  @callback encrypt(binary, EncryptionKey.t()) ::
              {:ok, binary, EncryptedData.encryption_artefacts()} | :encryption_error
  @callback decrypt(EncryptedData.t(), EncryptionKey.t()) ::
              {:ok, binary} | :decryption_error | {:decryption_error, {any, any}}

  @spec __using__([{:strategy_name, binary}]) :: any
  defmacro __using__(strategy_name: strategy_name) when is_binary(strategy_name) do
    [
      quote do
        alias Cryppo.{EncryptedData, EncryptionKey, EncryptionStrategy}
        @behaviour EncryptionStrategy
      end,
      inject_strategy_name(strategy_name),
      inject_run_encryption(),
      inject_run_decryption()
    ]
  end

  defp inject_strategy_name(strategy_name) do
    quote do
      @impl EncryptionStrategy
      def strategy_name, do: unquote(strategy_name)
    end
  end

  defp inject_run_encryption do
    quote do
      def run_encryption(data, %EncryptionKey{encryption_strategy_module: __MODULE__} = key) do
        case encrypt(data, key) do
          {:ok, encrypted, enc_artefacts} ->
            EncryptedData.new(__MODULE__, encrypted, enc_artefacts)

          any ->
            any
        end
      end

      def run_encryption(_data, %EncryptionKey{key: key, encryption_strategy_module: mod}) do
        {:incompatible_key, submitted_key_strategy: mod, encryption_strategy: __MODULE__}
      end
    end
  end

  defp inject_run_decryption do
    quote do
      def run_decryption(
            %EncryptedData{encryption_strategy_module: __MODULE__} = encrypted_data,
            %EncryptionKey{encryption_strategy_module: __MODULE__} = encryption_key
          ) do
        decrypt(encrypted_data, encryption_key)
      end

      def run_decryption(%EncryptedData{encryption_strategy_module: __MODULE__}, %EncryptionKey{
            encryption_strategy_module: mod
          }) do
        {:incompatible_key, submitted_key_strategy: mod, encryption_strategy: __MODULE__}
      end
    end
  end
end
