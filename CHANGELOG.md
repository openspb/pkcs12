# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [0.1.1] - 2026-10-23

### Fixed

- The interop tests skip a Python `cryptography` older than 36, which has no
  `load_pkcs12`, instead of failing.

### Documentation

- `decode/3`: `nil` is the same as the empty password, and what that means
  for a password read from an environment variable that is not set.
- `decode/3` and the README: the key derivation is paid on every call, so a
  file is best decoded once and the result kept.

## [0.1.0] - 2026-10-23

### Added

- `PKCS12.decode/3` and `PKCS12.decode!/3`: read a PKCS#12 file and return the
  private key, its certificate, the other certificates, every bag with its
  attributes, and the algorithms the file uses.
- Encryption: PBES2 with AES-CBC, 3DES or DES, and the PKCS#12 ciphers (3DES,
  2-key 3DES, RC2-40, RC2-128, RC4). RC2 is implemented by the library.
- Integrity: the classic MAC with SHA-1 to SHA-512, and PBMAC1 (RFC 9879).
- BER input, and the password encodings of tools that differ from RFC 7292.
- Limits on the key derivation work (`:max_iterations`,
  `:max_total_iterations`) and `verify_mac: false`.
- `PKCS12.encode/3` and `PKCS12.encode!/3`: write a PKCS#12 file from a key
  (PrivateKeyInfo in DER, or a key record of `:public_key`), its certificate
  and other certificates. The `:modern` profile (default) uses AES-256-CBC
  with PBKDF2-HMAC-SHA-256 and a SHA-256 MAC, with 100,000 iterations; the
  `:legacy` profile, 3DES and RC2-40 with a SHA-1 MAC. Options choose each
  algorithm, PBMAC1, the iteration count, `friendlyName` and `localKeyId`.

[0.1.1]: https://github.com/openspb/pkcs12/releases/tag/v0.1.1
[0.1.0]: https://github.com/openspb/pkcs12/releases/tag/v0.1.0
