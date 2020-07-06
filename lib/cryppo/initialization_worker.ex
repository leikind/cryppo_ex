defmodule Cryppo.InitializationWorker do
  @moduledoc false

  # for now the only point of this genserver is to seed
  # Erlang random generator. Then it exits.

  use GenServer

  @spec start_link :: :ignore | {:error, any} | {:ok, pid}
  def start_link do
    GenServer.start_link(__MODULE__, nil, name: __MODULE__)
  end

  @impl true
  def init(_) do
    {:ok, nil, {:continue, nil}}
  end

  @impl true
  def handle_continue(_continue, _) do
    # https://erlang.org/doc/man/crypto.html#rand_seed-0
    :crypto.rand_seed()

    {:stop, :normal, nil}
  end
end
