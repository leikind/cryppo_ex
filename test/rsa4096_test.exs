defmodule Rsa4096Test do
  use ExUnit.Case

  alias Cryppo.Rsa4096

  test "to_pem and back from_pem" do
    key = Cryppo.generate_encryption_key("Rsa4096")

    {:ok, pem} = Rsa4096.to_pem(key)
    {:ok, restored_key} = Rsa4096.from_pem(pem)

    assert restored_key.encryption_strategy_module == key.encryption_strategy_module
    assert restored_key.key == key.key
  end

  test "to_pem using the erlang tuple and back from_pem" do
    key = Cryppo.generate_encryption_key("Rsa4096")
    erlang_private_key_tuple = key.key

    {:ok, pem} = Rsa4096.to_pem(erlang_private_key_tuple)
    {:ok, restored_key} = Rsa4096.from_pem(pem)

    assert restored_key.encryption_strategy_module == key.encryption_strategy_module
    assert restored_key.key == key.key
  end
end
