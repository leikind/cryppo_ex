defmodule YamlTest do
  use ExUnit.Case

  alias Cryppo.Yaml

  test "YAML decode and encode" do
    [
      %{
        "abc" => 12,
        "hello" => "world"
      },
      %{"c34" => 42.2},
      %{
        "bb" => "ff",
        "ggg" => %{
          "abc" => 12,
          "hello" => "world"
        }
      }
    ]
    |> Enum.each(fn input ->
      out = input |> Yaml.encode() |> Yaml.decode()
      assert input == out
    end)
  end

  test "keys are numbers" do
    input = %{"123" => 12}
    out = input |> Yaml.encode() |> Yaml.decode()
    assert out == %{"123" => 12}

    input = %{"123" => 12}
    out = input |> Yaml.encode() |> Yaml.decode()
    assert out == %{"123" => 12}

    input = %{"123.2" => 12.3}
    out = input |> Yaml.encode() |> Yaml.decode()
    assert out == %{"123.2" => 12.3}

    input = %{123.2 => 12.3}
    out = input |> Yaml.encode() |> Yaml.decode()
    assert out == %{123.2 => 12.3}
  end

  test "YAML atoms" do
    input = %{foo: 12, bar: :boo}

    out = input |> Yaml.encode() |> Yaml.decode()
    assert out == %{"foo" => 12, "bar" => "boo"}
  end

  test "YAML with binaries" do
    bin1 = <<154, 2, 219, 38, 97, 228>>
    bin2 = <<247, 141, 43>>
    bin3 = <<180, 208, 147, 105, 242, 220, 62>>

    input = %{
      "foo" => "bar",
      "gggg" => %{"qwe11" => "ytre", "qwe2" => bin2},
      "bin1" => bin1,
      "bin2" => bin3
    }

    output = input |> Yaml.encode() |> Yaml.decode()

    assert input == output
  end
end
