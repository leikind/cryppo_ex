# CryppoEx

CryppoEx is a cryptographic library that enables you to encrypt and decrypt data.
CryppoEx combines very different ciphers under one simplified API, and a set of serialization formats.

CryppoEx is an Elixir port of [Cryppo in Ruby](https://github.com/Meeco/cryppo)
and [Cryppo-js](https://github.com/Meeco/cryppo-js) used for [the Meeco platform](https://dev.meeco.me/).

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
{:ok, encrypted} = Cryppo.load(serialized)
{:ok, decrypted, _encryption_key} = Cryppo.decrypt_with_derived_key(encrypted, passphrase)

IO.inspect(decrypted) #=> "some data to encrypt"
```

## Encrypt and decrypt data using a generated cryptographic key

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
{:ok, encrypted} = Cryppo.load(serialized)
{:ok, decrypted} = Cryppo.decrypt(encrypted, encryption_key)

Cryppo.inspect(decrypted) #=> "some data to encrypt"
```

## Signing and verification

For authentication purposes, a sender can sign a message with their private key,
and a recipient can verify this signature using the sender's public key.

```elixir
private_key = Cryppo.generate_encryption_key("Rsa4096")

rsa_signature = Cryppo.Rsa4096.sign("data to verify", private_key)
serialized = Cryppo.serialize(rsa_signature)

{:ok, signature} = Cryppo.load(serialized)
Cryppo.Rsa4096.verify(signature, Cryppo.Rsa4096.private_key_to_public_key(private_key)) # => true
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


## Command Line Interface

CryppoEx exposes its functionality via a command line interface.

In order to use the CryppoEx CLI, you need to build an
[escript](https://hexdocs.pm/mix/master/Mix.Tasks.Escript.Build.html) executable with the following command:

```sh
MIX_ENV=prod mix escript.build
```

The generated executable can run on any machine that has Erlang installed and does not require Elixir to be installed.


### `cryppo genkey`

Generate a new (random) encryption key - printed as base64 encoded

```
USAGE
  cryppo genkey -s [ENCRYPTION_STRATEGY]

OPTIONS
  -s, --strategy=strategy  encryption strategy (defaults to Aes256Gcm)

EXAMPLES
  cryppo genkey
  cryppo genkey --strategy=Aes256Gcm
```

### `cryppo genkeypair`

Generate a new RSA key pair, writing the private and public keys to files.

```
USAGE
  cryppo genkeypair -p [PRIVATE_KEY_FILE] -P [PUBLIC_KEY_FILE]

OPTIONS
  -p, --privateKeyOut=privateKeyOut  (required) Private key output path
  -P, --publicKeyOut=publicKeyOut    (required) Public key output path

EXAMPLE
  cryppo genkeypair -p private.pem -P public.pem
```

### `cryppo encrypt`

Encrypt data with a generated key

```
USAGE
  cryppo encrypt -v [DATA] -k [KEY] -s [ENCRYPTION_STRATEGY]
  cryppo encrypt -v [DATA] -P [PUBLIC_KEY_FILE]

OPTIONS
  -v, --value=value                  (required) value to encrypt
  -s, --strategy=strategy            encryption strategy (defaults to Aes256Gcm)
  -k, --key=key                      base64 encoded data encryption key
  -P, --publicKeyFile=publicKeyFile  public key file (if encrypting with RSA)

EXAMPLES
  encrypt -v "hello world" -k vm8CjugMda2zdjsI9W25nH-CY-84DDYoBxTFLwfKLDk= -s Aes256Gcm
  encrypt -v "hello world" -P public.pem
```

### `cryppo decrypt`

Decrypt a serialized encrypted value

```
USAGE
  cryppo decrypt -e [ENCRYPTED_DATA] -k [KEY] -s [ENCRYPTION_STRATEGY]
  cryppo decrypt -e [ENCRYPTED_DATA] -p [PRIVATE_KEY_FILE]

OPTIONS
  -e, --encrypted=encrypted            (required) serialized encrypted value
  -s, --strategy=strategy              encryption strategy (defaults to Aes256Gcm)
  -k, --key=key                        base64 encoded data encryption key
  -p, --privateKeyFile=privateKeyFile  private key file (if encrypting with RSA)

EXAMPLES
  cryppo decrypt -e
  "Aes256Gcm.gSAByGMq4edzM0U=.LS0tCml2OiAhYmluYXJ5IHwtCiAgaW1QL09qMWZ6eWw0cmwwSgphdDogIWJpbmFyeSB8LQogIE5SbjZUQXJ2bitNS1
  Z5M0FpZEpmWlE9PQphZDogbm9uZQo=" -k vm8CjugMda2zdjsI9W25nH-CY-84DDYoBxTFLwfKLDk=

  cryppo decrypt -e "Rsa4096.bJjV2g_RBZKeyqBr-dSjPAc3qtkTgd0=.LS0tCnt9Cg==" -p private.pem
```

### `cryppo encrypt-der`

Encrypt data with a derived key

```
USAGE
cryppo encrypt-der -v [DATA] -w [PASSWORD] -s [ENCRYPTION_STRATEGY] -d [DERIVATION_STRATEGY]

OPTIONS
  -v, --value=value                  (required) value to encrypt
  -w, --password=password            (required) password for key derivation
  -s, --strategy=strategy            encryption strategy (defaults to Aes256Gcm)
  -d, --derivation-strategy=strategy derivation strategy (defaults to Pbkdf2Hmac)

EXAMPLES
  cryppo encrypt-der -v "hello world" -w "secret phrase" -s Aes256Gcm -d Pbkdf2Hmac

  cryppo encrypt-der -v "hello world" -w "secret phrase"
```

### `cryppo decrypt-der`

Decrypt a serialized encrypted value with a derived key

```
USAGE
  cryppo decrypt-der -e [ENCRYPTED_DATA] -p [PASSPHRASE]

OPTIONS
  -e, --encrypted=encrypted          (required) serialized encrypted value
  -p, --passphrase=passphrase        (required) passphrase for key derivation

EXAMPLES
  cryppo decrypt-der -p "secret phrase"  \
  -e "Aes256Gcm.e-IJT9E8ew3wlz8=.LS0tCmFkOiBub25lCmF0OiAhIWJpbmFyeSB8LQogIHpTRzQzbVhlSFBsR3ZQQVZoNTVJQUE9PQppdjogISFiaW5hcnkgfC0KICBMU2NDNmVCZ2wrUCtuUkpaCg==.Pbkdf2Hmac.LS0tCidpJzogMjEzMjIKJ2l2JzogISFiaW5hcnkgfC0KICBzTmlGT21xWEg5b1piNzRNVElCcGxvNHlHV2M9CidsJzogMzIK"
```

### `cryppo sign FILE DESTINATION`

Sign a file with an RSA private key and write the signed contents to a new file

```
USAGE
  cryppo sign -p [PRIVATE_KEY_FILE] FILE DESTINATION

ARGUMENTS
  FILE         File to sign
  DESTINATION  file to write the resulting signed content to

OPTIONS
  -p, --privateKeyFile=privateKeyFile  (required) path to the private key file

EXAMPLE
  cryppo sign -p private.pem my_file.txt my_file.signed.txt
```

### `cryppo verify FILE DESTINATION`

Verify an RSA signed file and write the contents to another file.

```
USAGE
  cryppo verify -P [PUBLIC_KEY_FILE] FILE DESTINATION

ARGUMENTS
  FILE         Signed file contents to verify
  DESTINATION  File to write the resulting verified content to

OPTIONS
  -P, --publicKeyFile=publicKeyFile  (required) path to the public key file

EXAMPLE
  cryppo verify -P public.pem my_file.signed.txt my_file.txt
```
