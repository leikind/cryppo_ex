# Changelog

## v0.1.7 29.11.2020

- Handle a error when too much data is given to RSA encryption

## v0.1.6 25.09.2020

- A more correct way to run :crypto.rand_seed() when initializing
- Better tests for serialization

## v0.1.5 01.09.2020

- Stricter Credo rules

## v0.1.4 24.08.2020

- An error in type specs is fixed

## v0.1.3 06.07.2020

- Do not use crypto:crypto_final because it is present in OTP 23, and not in OTP 22

## v0.1.2 06.07.2020

- Seeding the Erlang random generator happens in one transient worker which then exits

## v0.1.1 06.07.2020

- Fixed an error in README

## v0.1.0 05.07.2020

- First version compatible with Ruby Cryppo and Cryppo.js
