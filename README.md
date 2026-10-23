# PKCS12

Reads PKCS#12 files (`.pfx`, `.p12`) in pure Elixir: the private key, its
certificate and the rest of the chain, ready for `:ssl` and `:public_key`.

* **No NIF and no `openssl` binary.** Everything runs on top of `:crypto` and
  `:public_key`, which come with OTP.
* **Old and new files.** The PBES2/AES files of OpenSSL 3, Java and other
  recent tools, and the "legacy" RC2 + 3DES files that many tools still
  write. RC2 is built in, so legacy files open even where OpenSSL 3 has no
  "legacy" provider.
* **Safe with untrusted input.** Bounded parsing, limits on the key
  derivation work, the MAC checked before anything is decrypted, and no key
  or password in `inspect/1` or in error messages.

> **Status: v0.1.** The API is small and expected to stay, but may still
> change before 1.0. The library reads PKCS#12; it does not write it.

## Installation

```elixir
def deps do
  [{:pkcs12, "~> 0.1"}]
end
```

Elixir 1.16 or later, OTP 26 or later. No other dependencies.

## Usage

```elixir
{:ok, p12} = PKCS12.decode(File.read!("me.pfx"), "password")

p12.private_key      # PrivateKeyInfo (PKCS#8), in DER
p12.certificate      # the certificate of that key, in DER
p12.ca_certificates  # the other certificates, in DER, in file order
p12.info             # the algorithms the file uses
```

Errors come as `{:error, %PKCS12.Error{reason: reason}}`, and `decode!/3`
raises them:

```elixir
case PKCS12.decode(bin, password) do
  {:ok, p12} -> p12
  {:error, %PKCS12.Error{reason: :invalid_password}} -> ...
  {:error, %PKCS12.Error{reason: :malformed}} -> ...
  {:error, error} -> raise error
end
```

### With `:ssl`

```elixir
:ssl.connect(~c"example.com", 443,
  certs_keys: [%{cert: [p12.certificate | p12.ca_certificates],
                 key: {:PrivateKeyInfo, p12.private_key}}],
  verify: :verify_peer,
  cacerts: :public_key.cacerts_get()
)
```

The same `certs_keys` works in `:ssl.listen/2`, and in the TLS options of
HTTP clients built on `:ssl`, such as Mint, Finch and Req.

### With `:public_key`

```elixir
key = :public_key.der_decode(:PrivateKeyInfo, p12.private_key)
signature = :public_key.sign(message, :sha256, key)

# PEM, for tools that want it
pem = :public_key.pem_encode([{:PrivateKeyInfo, p12.private_key, :not_encrypted}])
```

### Files from untrusted sources

A PKCS#12 file sets its own iteration counts, so a hostile file can ask for a
lot of CPU. The defaults accept every common file and cap the work at about a
second. For uploads, bound the size of the file, lower the limits and put a
timeout around the call:

```elixir
PKCS12.decode(bin, password, max_iterations: 200_000, max_total_iterations: 600_000)
```

`p12.info` tells what the file uses, so an application can refuse weak
algorithms:

```elixir
weak? = Enum.any?(p12.info.encryption, &(&1.cipher in [:rc2_40_cbc, :rc4_40, :rc4_128]))
```

See [SECURITY.md](SECURITY.md) for the threat model.

## What it reads

| | |
|---|---|
| Encryption | PBES2 (PBKDF2 with HMAC-SHA-1/224/256/384/512) with AES-128/192/256-CBC, 3DES or DES; the PKCS#12 ciphers: 3DES, 2-key 3DES, RC2-40, RC2-128, and RC4-40/128 when `:crypto` has RC4 |
| Integrity | the classic MAC (HMAC-SHA-1/224/256/384/512) and PBMAC1 (RFC 9879); files without a MAC are accepted, and `info.mac` is `nil` |
| Content | keys (encrypted or not), X.509 certificates, nested SafeContents; other bags (secrets, CRLs) are passed on in `p12.bags` |
| Encoding | DER and BER (indefinite lengths, segmented strings), which some tools write |
| Passwords | UTF-8, as RFC 7292 says, and the forms some tools use instead (bytes as characters for non-ASCII passwords, the empty password as no bytes); the MAC decides which one is right |

Not supported: files signed with, or encrypted to, a public key instead of a
password (both are very rare), and writing PKCS#12.

The test suite reads files written by OpenSSL 3, OpenSSL 1.1.1, LibreSSL,
Python's `cryptography` and Java's `keytool`, in their default and legacy
modes, and the test vectors of RFC 9879. CI runs it on OTP 26 to 29, and on
an OpenSSL 3 without the legacy provider.

## Performance

The time is almost all key derivation, so it follows the iteration counts in
the file. On an Apple M-series laptop, OTP 27 with OpenSSL 3.6
(`mix run bench/decode.exs`):

| File | Time |
|---|---|
| OpenSSL 3 default (PBES2 AES-256, 2,048 iterations) | 0.9 ms |
| OpenSSL legacy (RC2-40 + 3DES, 2,048) | 2.7 ms |
| Java default (PBES2 AES-256, 10,000) | 4.1 ms |
| Java legacy (MAC 100,000, 50,000) | 60 ms |
| Wrong password (2,048) | 0.35 ms |

PBKDF2 runs inside OpenSSL on a dirty scheduler. The PKCS#12 key derivation of
the legacy files is an Elixir loop over `:crypto.hash/2`, which the BEAM
preempts like any other code.

## Development

```
mix test
mix precommit   # format, warnings, Credo and tests, before a commit
mix dialyzer
```

The files in `test/fixtures` are made by the project, with
`test/support/gen_fixtures.sh` (OpenSSL 3 and 1.1.1, LibreSSL, Python and a
JDK) and `test/support/extract_rfc9879.exs` (the RFC 9879 vectors). They are
committed because CI does not have every generator.

## References

* [RFC 7292](https://www.rfc-editor.org/rfc/rfc7292), PKCS #12 v1.1
* [RFC 8018](https://www.rfc-editor.org/rfc/rfc8018), PKCS #5 v2.1 (PBES2, PBKDF2)
* [RFC 9879](https://www.rfc-editor.org/rfc/rfc9879), PBMAC1 in PKCS #12
* [RFC 2268](https://www.rfc-editor.org/rfc/rfc2268), RC2
* [RFC 5958](https://www.rfc-editor.org/rfc/rfc5958), Asymmetric Key Packages (PKCS #8)

## License

Apache-2.0: see the `LICENSE` and `NOTICE` files.
