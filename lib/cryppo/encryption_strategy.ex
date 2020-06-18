defmodule Cryppo.EncryptionStrategy do
  @moduledoc false

  # EncryptionStrategy behavior and macros to inject functions common to all EncryptionStrategy modules

  alias Cryppo.{EncryptedData, EncryptionArtefacts, EncryptionKey}

  @callback strategy_name :: binary

  @callback generate_key :: EncryptionKey.t()

  @callback build_encryption_key(any) ::
              {:ok, EncryptionKey.t()} | {:error, :invalid_encryption_key}

  @callback encrypt(binary, EncryptionKey.t()) ::
              {:ok, binary, EncryptionArtefacts.t()} | :encryption_error

  @callback decrypt(EncryptedData.t(), EncryptionKey.t()) ::
              {:ok, binary} | :decryption_error | {:decryption_error, {any, any}}

  @callback key_derivation_possible :: boolean()

  defmacro __using__(
             strategy_name: strategy_name,
             key_derivation_possible: key_derivation_possible
           )
           when is_binary(strategy_name) do
    [
      quote do
        alias Cryppo.{EncryptedData, EncryptionArtefacts, EncryptionKey, EncryptionStrategy}
        @behaviour EncryptionStrategy
      end,
      inject_strategy_name(strategy_name),
      inject_key_derivation_possible(key_derivation_possible),
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

  defp inject_key_derivation_possible(true) do
    quote do
      @impl EncryptionStrategy
      def key_derivation_possible, do: true
    end
  end

  defp inject_key_derivation_possible(false) do
    quote do
      @impl EncryptionStrategy
      def key_derivation_possible, do: false
    end
  end

  defp inject_run_encryption do
    quote do
      @doc false
      def run_encryption(data, %EncryptionKey{encryption_strategy_module: __MODULE__} = key) do
        case encrypt(data, key) do
          {:ok, encrypted, artefacts} -> EncryptedData.new(__MODULE__, encrypted, artefacts)
          any -> any
        end
      end

      def run_encryption(_data, %EncryptionKey{key: key, encryption_strategy_module: mod}) do
        {:incompatible_key, submitted_key_strategy: mod, encryption_strategy: __MODULE__}
      end

      def run_encryption(data, raw_key) do
        with {:ok, key} <- build_encryption_key(raw_key) do
          run_encryption(data, key)
        end
      end
    end
  end

  defp inject_run_decryption do
    quote do
      @doc false
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

      def run_decryption(data, raw_key) do
        with {:ok, key} <- build_encryption_key(raw_key) do
          run_decryption(data, key)
        end
      end
    end
  end
end
