defmodule Cryppo.CryppoApp do
  @moduledoc false

  use Application

  alias Cryppo.InitializationWorker

  @spec start(any, any) :: {:error, any} | {:ok, pid}
  def start(_type, _args) do
    [
      %{
        id: InitializationWorker,
        start: {InitializationWorker, :start_link, []},
        type: :worker
      }
    ]
    |> Supervisor.start_link(strategy: :one_for_one)
  end
end
