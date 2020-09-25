defmodule Cryppo.InitializationWorker do
  @moduledoc false

  # for now the only point of this genserver is to seed
  # Erlang random generator. Then it exits.

  use GenServer

  @spec start_link :: :ignore
  def start_link do
    :crypto.rand_seed()
    :ignore
  end

  @impl true
  def init(init_arg), do: {:ok, init_arg}
end
