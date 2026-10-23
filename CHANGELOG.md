# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

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

[Unreleased]: https://github.com/openspb/pkcs12/commits/main
