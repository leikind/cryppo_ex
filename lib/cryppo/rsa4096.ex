defmodule Cryppo.Rsa4096 do
  alias Cryppo.EncryptionKey

  # 65537 is the default in OpenSSL, and hence in ruby Cryppo
  # 4096 is the key size in ruby Cryppo
  @size 4_096
  @exponent 65_537

  @spec generate_key :: Cryppo.EncryptionKey.t()
  def generate_key do
    {:rsa, @size, @exponent}
    |> :public_key.generate_key()
    |> EncryptionKey.new()
  end
end
