defmodule Cryppo.CryppoApp do
  @moduledoc false

  use Application

  alias Cryppo.InitializationWorker

  def start(_type, _args) do
    [
      %{
        id: InitializationWorker,
        start: {InitializationWorker, :start_link, []},
        type: :worker,
        restart: :transient
      }
    ]
    |> Supervisor.start_link(strategy: :one_for_one)
  end
end
