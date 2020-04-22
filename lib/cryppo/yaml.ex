defmodule Cryppo.Yaml do
  @moduledoc """
    * Poor man's to_yaml good enough for our purposes
    * Wrapper around a fork of yamerl to decode YAML
  """

  @spec decode(binary) :: map
  def decode(yaml) when is_binary(yaml) do
    [yaml_doc | _] =
      yaml
      # hack for yamerl
      |> String.replace(": !binary |-", ": !!binary |-", global: true)
      |> :yamerl.decode()

    yaml_doc |> list_of_tuples() |> to_map
  end

  defp to_map(list) when is_list(list) do
    list
    |> Enum.into(%{}, fn
      {k, v} when is_list(v) -> {k, to_map(v)}
      tuple -> tuple
    end)
  end

  @spec key_value({maybe_improper_list | number, any}) :: {binary | number, any}
  defp key_value({k, v}) when is_list(k), do: {to_string(k), value(v)}
  defp key_value({k, v}) when is_number(k), do: {k, value(v)}

  defp value([{_, _} | _] = v), do: list_of_tuples(v)
  defp value(v) when is_list(v), do: to_string(v)
  defp value(v), do: v

  defp list_of_tuples(v), do: v |> Enum.map(&key_value/1)

  # Encode

  @spec encode(map) :: binary
  def encode(%{} = map) do
    if map == %{} do
      "--- {}\n"
    else
      ["---\n", to_yaml(map, ""), "\n"] |> :erlang.iolist_to_binary()
    end
  end

  @indentation_step "  "

  defp next_indentation(indentation), do: [indentation, @indentation_step]

  defp to_yaml(%{} = map, indentation) do
    map
    |> Enum.map(fn {key, value} ->
      to_key_value(key, value, indentation)
    end)
    |> Enum.intersperse("\n")
  end

  defp to_key_value(key, value, indentation) do
    [to_key(key, indentation), to_value(value, indentation)]
  end

  defp to_value(v, _indentation) when is_number(v), do: [" ", to_string(v)]
  defp to_value(v, _indentation) when is_atom(v), do: [" '", to_string(v), "'"]

  defp to_value(v, indentation) when is_map(v) do
    indentation = next_indentation(indentation)
    ["\n", to_yaml(v, indentation)]
  end

  defp to_value(list, indentation) when is_list(list) do
    indentation = next_indentation(indentation)

    [
      "\n",
      list |> Enum.map(fn v -> ["-", to_value(v, indentation), "\n"] end)
    ]
  end

  defp to_value(v, indentation) when is_bitstring(v) do
    indentation = next_indentation(indentation)

    if String.valid?(v) do
      [" ", v]
    else
      [" !!binary |-\n", indentation, Base.encode64(v)]
    end
  end

  defp to_key(key, indentation), do: [indentation, to_key(key), ":"]

  defp to_key(key) when is_binary(key), do: ["'", key, "'"]
  defp to_key(key) when is_atom(key) or is_number(key), do: to_string(key)
end
