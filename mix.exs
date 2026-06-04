defmodule Cryppo.MixProject do
  use Mix.Project

  def project do
    [
      app: :cryppo_ex,
      version: "0.2.4",
      elixir: ">= 1.16.0",
      erlc_paths: ["lib"],
      deps: deps(),
      name: "CryppoEx",
      aliases: aliases(),
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
      {:cyanide, "~> 2.0.0"},
      {:ex_cli, "~> 0.1.0"},
      {:credo, ">= 1.7.0", only: :dev},
      {:ex_doc, ">= 0.40.0", only: :dev, runtime: false},
      {:dialyxir, ">= 1.4.0", only: :dev, runtime: false},
      {:jason, ">= 1.4.0", only: [:test, :dev]}
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

  defp aliases do
    [
      d: ["dialyzer"],
      c: ["credo --strict"],
      outdated: ["hex.outdated --all"],
      remove_unused_deps: ["deps.clean --unused --unlock"]
    ]
  end
end
