# CryppoEx

**TODO: Add a tutorial**

## Installation

If [available in Hex](https://hex.pm/docs/publish), the package can be installed
by adding `cryppo_ex` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:cryppo_ex, "~> 0.1.0"}
  ]
end
```

Documentation can be generated with [ExDoc](https://github.com/elixir-lang/ex_doc)
and published on [HexDocs](https://hexdocs.pm). Once published, the docs can
be found at [https://hexdocs.pm/cryppo_ex](https://hexdocs.pm/cryppo_ex).


## TODO

* RSA signatures
* Command line interface like for Cryppo.js
* Add functions which list (1) available encryption strategies (2) available key derivation strategies
* check the compatibility with yaml with binaries from ruby, there can be a problem with the tag
* behaviour for key derivation strategies just like for encryption strategies
* proper readme
* Maybe: implement Cryppo.encrypt/2 which would also generate the key like in the typescript port
