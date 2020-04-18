defmodule Cryppo.EncryptionStrategy do
  @moduledoc """
  TODO
  """

  defmacro __using__(strategy_name: strategy_name) when is_binary(strategy_name) do
    quote do
      alias Cryppo.{EncryptionKey, EncryptedData}

      @spec strategy_name :: binary
      def strategy_name, do: unquote(strategy_name)

      def run_encryption(data, %EncryptionKey{key: key, encryption_strategy_module: __MODULE__}) do
        case encrypt(data, key) do
          {:ok, encrypted, enc_artefacts} ->
            EncryptedData.new(__MODULE__, encrypted, enc_artefacts)

          any ->
            any
        end
      end

      def run_encryption(_data, %EncryptionKey{key: key, encryption_strategy_module: mod}),
        do: {:incompatible_key, submitted_key_strategy: mod, encryption_strategy: __MODULE__}
    end
  end
end
