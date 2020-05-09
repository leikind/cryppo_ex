defmodule Cryppo.MixProject do
  use Mix.Project

  def project do
    [
      app: :cryppo_ex,
      version: "0.1.0",
      elixir: ">= 1.5.0",
      deps: deps(),
      name: "CryppoEx",
      description: "Encryption library for the Meeco platform",
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
      extra_applications: [:logger, :crypto, :public_key]
    ]
  end

  defp deps do
    [
      {:pbkdf2, "~> 2.0"},
      {:yamerl, "~> 0.8"},
      {:credo, "~> 1.1.0", only: :dev},
      {:ex_doc, "~> 0.21", only: :dev, runtime: false},
      {:dialyxir, "~> 1.0", only: [:dev], runtime: false}
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
