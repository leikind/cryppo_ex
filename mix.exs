defmodule Cryppo.MixProject do
  use Mix.Project

  def project do
    [
      app: :cryppo_ex,
      version: "0.1.0",
      elixir: "~> 1.10",
      deps: deps()
      # name: "CryppoEx",
      # description: description(),
      # package: package(),
      # docs: [extras: ["README.md"]]
    ]
  end

  def application do
    [
      extra_applications: [:logger, :crypto, :public_key]
    ]
  end

  defp deps do
    [
      {:credo, "~> 1.1.0", only: :dev},
      {:pbkdf2, "~> 2.0"},
      {:yamerl, git: "https://github.com/leikind/yamerl"},
      {:dialyxir, "~> 1.0", only: [:dev], runtime: false}
    ]
  end
end
