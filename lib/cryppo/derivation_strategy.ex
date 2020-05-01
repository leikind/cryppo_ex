defmodule Cryppo.DerivationStrategy do
  @moduledoc """
  DerivationStrategy behavior and macros to inject functions
  common to all DerivationStrategy modules
  """

  alias Cryppo.DerivedKey

  @callback strategy_name :: binary
  @callback generate_derived_key(String.t()) :: DerivedKey.t()
  @callback build_derived_key(String.t(), DerivedKey.t()) :: DerivedKey.t()

  @spec __using__([{:strategy_name, binary}]) :: any
  defmacro __using__(strategy_name: strategy_name) when is_binary(strategy_name) do
    [
      quote do
        alias Cryppo.{DerivationStrategy, DerivedKey, EncryptionKey}
        @behaviour DerivationStrategy

        @impl DerivationStrategy
        def strategy_name, do: unquote(strategy_name)
      end
    ]
  end
end
