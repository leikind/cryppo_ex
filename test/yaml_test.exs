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
      {:ok, out} = input |> Yaml.encode() |> Yaml.decode()
      assert input == out
    end)
  end

  test "why lists of numbers used as strings in classic Erlang is a bad bad bad idea" do
    input = %{"123" => [97, 98, 99]}

    {:ok, out} = input |> Yaml.encode() |> Yaml.decode()

    assert out == %{"123" => "abc"}
  end

  test "keys are numbers" do
    input = %{"123" => 12}
    {:ok, out} = input |> Yaml.encode() |> Yaml.decode()
    assert out == %{"123" => 12}

    input = %{"123" => 12}
    {:ok, out} = input |> Yaml.encode() |> Yaml.decode()
    assert out == %{"123" => 12}

    input = %{"123.2" => 12.3}
    {:ok, out} = input |> Yaml.encode() |> Yaml.decode()
    assert out == %{"123.2" => 12.3}

    input = %{123.2 => 12.3}
    {:ok, out} = input |> Yaml.encode() |> Yaml.decode()
    assert out == %{123.2 => 12.3}
  end

  test "YAML atoms" do
    input = %{foo: 12, bar: :boo}

    {:ok, out} = input |> Yaml.encode() |> Yaml.decode()
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

    {:ok, output} = input |> Yaml.encode() |> Yaml.decode()

    assert input == output
  end

  test "yaml with binary generated with Ruby YAML" do
    yaml = "---\nfoo: !binary |-\n  lpl7XzUwhUZflw==\nbar: !binary |-\n  iKSs266T9yGKqw==\n"

    {:ok, output} = Yaml.decode(yaml)

    assert output == %{
             "bar" => <<136, 164, 172, 219, 174, 147, 247, 33, 138, 171>>,
             "foo" => <<150, 153, 123, 95, 53, 48, 133, 70, 95, 151>>
           }
  end

  test "invalid YAML" do
    assert Yaml.decode("foobar") == {:error, :invalid_yaml}
  end
end
