defmodule CompatTest do
  use ExUnit.Case

  alias Cryppo.EncryptionKey

  test "can decrypt a serialized encrypted value encrypted with Aes256Gcm by Ruby Cryppo" do
    {:ok, key} = Base.url_decode64("S5-0MiMs1jkg52bB9nzl1IoNYzxfSyxuoIx6Tvj2vCk=")

    serialized =
      "Aes256Gcm.29dTcNFcPs-0SOnA.LS0tCml2OiAhYmluYXJ5IHwtCiAgUU1oRnpWZWU3bzE5Qy9XcwphdDogIWJpbmFyeSB8LQogIGFKQjVhYU0wWGZnTjZCYm42U0FzUnc9PQphZDogbm9uZQo="

    restored_encrypted_data = Cryppo.load(serialized)

    key = %EncryptionKey{
      key: key,
      encryption_strategy_module: Cryppo.Aes256gcm
    }

    assert Cryppo.decrypt(restored_encrypted_data, key) == {:ok, "this is love"}
  end
end
