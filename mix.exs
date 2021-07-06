defmodule Cryppo.MixProject do
  use Mix.Project

  def project do
    [
      app: :cryppo_ex,
      version: "0.2.1",
      elixir: ">= 1.10.0",
      erlc_paths: ["lib"],
      deps: deps(),
      name: "CryppoEx",
      description: "Encryption library for the Meeco platform",
      escript: escript(),
      package: package(),
      homepage_url: "https://github.com/leikind/cryppo_ex",
      source_url: "https://github.com/leikind/cryppo_ex",
      docs: [
        main: "readme",
        extras: ["README.md"]
      ]
    ]
  end

  def application do
    [
      mod: {Cryppo.CryppoApp, []},
      extra_applications: [:logger, :crypto, :public_key]
    ]
  end

  defp deps do
    [
      {:cyanide, ">= 1.0.0"},
      {:credo, ">= 1.1.0", only: :dev},
      {:ex_cli, ">= 0.1.0"},
      {:ex_doc, ">= 0.21.0", only: :dev, runtime: false},
      {:dialyxir, ">= 1.0.0", only: :dev, runtime: false},
      {:faker, ">= 0.13.0", only: :test},
      {:jason, ">= 1.0.0", only: [:test, :dev]}
    ]
  end

  defp escript do
    [
      main_module: Cryppo.Cli,
      name: "cryppo"
    ]
  end

  defp package do
    [
      maintainers: ["Yuri Leikind"],
      licenses: ["Apache-2.0"],
      links: %{
        "Github" => "https://github.com/leikind/cryppo_ex"
      }
    ]
  end
end
