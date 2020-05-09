# CryppoEx

CryppoEx is a cryptographic library that enables you to encrypt and decrypt data.
CryppoEx combines very different ciphers under one simplified API and a set of serialization formats.

CryppoEx is an Elixir port of [Cryppo in Ruby](https://github.com/Meeco/cryppo)
and [Cryppo-js](https://github.com/Meeco/cryppo-js).

CryppoEx uses Erlang modules [crypto](https://erlang.org/doc/man/crypto.html)
and [public_key](https://erlang.org/doc/man/public_key.html) under the hood.

## Installation

TODO

Not released on [hex.pm](https://hex.pm) yet.

## Encrypt and decrypt data using a derived key

When encrypting data with a user-generated passphrase or password, use function `Cryppo.encrypt_with_derived_key/4`.

The data will be encrypted with a cryptographically secure key that is derived from the passphrase:

```elixir
encryption_strategy = "Aes256Gcm"
key_derivation_strategy = "Pbkdf2Hmac"
passphrase = "MyPassword!!"
data = "some data to encrypt"

encrypted_data = Cryppo.encrypt_with_derived_key(data, encryption_strategy, key_derivation_strategy, passphrase)
```

You can list all available encryption strategies with `Cryppo.encryption_strategies/0`,
and all key derivation strategies with `Cryppo.derivation_strategies/0`.

The encryption process will return a `Cryppo.EncryptedDataWithDerivedKey` struct that contains all the encryption
artefacts necessary to decrypt the encrypted data.
This structure can be serialized as a string using function `Cryppo.serialize/1`.
The serialized payload can be stored directly in a data store.

```elixir
serialized = Cryppo.serialize(encrypted_data)
```

The serialized payload can later be loaded by using `Cryppo.load/1` and decrypted with
`Cryppo.decrypt_with_derived_key/2` and the passphrase:

```elixir
{:ok, decrypted, _encryption_key} = serialized
|> Cryppo.load()
|> Cryppo.decrypt_with_derived_key(passphrase)

IO.inspect(decrypted) #=> "some data to encrypt"
```

### Encrypt and decrypt data using a generated cryptographic key

You can also encrypt using your own generated key using functions
the `Cryppo.generate_encryption_key/1` and `Cryppo.encrypt/3`:

```elixir
encryption_strategy = "Aes256Gcm"
data = "some data to encrypt"

encryption_key = Cryppo.generate_encryption_key(encryption_strategy)
encrypted = Cryppo.encrypt(data, encryption_strategy, encryption_key)
```

The encryption process will return an `Cryppo.EncryptedData` struct that contains all the encryption
artefacts necessary to decrypt the encrypted data.

It is also possible to generate a key and encrypt data in one go with `Cryppo.encrypt/2`:

```elixir
{encrypted_data, encryption_key} = Cryppo.encrypt(data, encryption_strategy)
```

`Cryppo.EncryptedData` structs can be serialized as a string using function `Cryppo.serialize/1`.
The serialized payload can be stored directly in a data store.

```elixir
serialized = Cryppo.serialize(encrypted_data)
```

The serialized payload can later be loaded by using `Cryppo.load/1` and decrypted with
`Cryppo.decrypt/2` and the passphrase:

```elixir
{:ok, decrypted} = serialized |> Cryppo.load() |> Cryppo.decrypt(encryption_key)

Cryppo.inspect(decrypted) #=> "some data to encrypt"
```

### Signing and verification

For authentication purposes, a sender can sign a message with their private key,
and a recipient can verify this signature using the sender's public key.

```elixir
private_key = Cryppo.generate_encryption_key("Rsa4096")

rsa_signature = Cryppo.Rsa4096.sign("data to verify", private_key)
serialized = Cryppo.serialize(rsa_signature)

serialized
|> Cryppo.load()
|> Cryppo.Rsa4096.verify(Cryppo.Rsa4096.private_key_to_public_key(private_key)) # => true
```

## Encryption Strategies

### Aes256Gcm

Aes256Gcm was chosen because it provides authenticated encryption.
An error will be raised if an incorrect value, such as the encryption key, were used during decryption.
This means you can always be sure that the decrypted data is the same as the data that was originally encrypted.

## Key Derivation Strategies

### Pbkdf2Hmac

Pbkdf2Hmac generates cryptographically secure keys from potentially insecure sources such as user-generated passwords.

The derived key is cryptographically secure such that brute force attacks directly on the encrypted data is infeasible.
The amount of computational effort required to complete the operation can be tweaked.
This ensures that brute force attacks on the password encrypted data.


## TODO

* Command line interface like in Cryppo.js
* New better serialization format for encryption/derivation artefacts
