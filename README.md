# SHA-2

A simple implementation of the SHA-2 family of cryptographic hash functions in
Python 3 for educational purposes. This implementation should not be trusted in
production, but it seems to produce correct values for all hash functions. The
code is written to be as short and readable as possible, with many references
to the FIPS spec.

Read the
[FIPS 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf)
specification for more details on the algorithms.

## Usage

Program:
```
from sha2 import sha256
print(sha256('Hello\n'.encode('utf-8')).hex())
```

Output:
```
66a045b452102c59d840ec097d59d9467e13a3f34f6494e539ffd32c1bb35f18
```

This matches the value from `printf "Hello\n" | sha256sum`.

## Available Functions

* `sha224(message)`
* `sha256(message)`
* `sha384(message)`
* `sha512(message)`
* `sha512_t(truncation, message)`
  * SHA-512/224 can be invoked by `sha512_t(224, message)`
  * SHA-512/256 can be invoked by `sha512_t(256, message)`
  * Any other valid SHA-512/t truncation is also supported.

Each function expects `message` to be an array of bytes. Each function returns
the SHA digest as an array of bytes.
