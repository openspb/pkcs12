# PKCS12

[![Hex.pm](https://img.shields.io/hexpm/v/pkcs12.svg)](https://hex.pm/packages/pkcs12)
[![Docs](https://img.shields.io/badge/hex-docs-blue.svg)](https://hexdocs.pm/pkcs12)
[![CI](https://github.com/openspb/pkcs12/actions/workflows/ci.yml/badge.svg)](https://github.com/openspb/pkcs12/actions/workflows/ci.yml)

Reads and writes PKCS#12 files (`.pfx`, `.p12`) in pure Elixir: the private
key, its certificate and the rest of the chain, ready for `:ssl` and
`:public_key`.

* **No NIF and no `openssl` binary.** Everything runs on top of `:crypto` and
  `:public_key`, which come with OTP.
* **Old and new files.** The PBES2/AES files of OpenSSL 3, Java and other
  recent tools, and the "legacy" RC2 + 3DES files that many tools still
  write. RC2 is built in, so legacy files open even where OpenSSL 3 has no
  "legacy" provider.
* **Writes them too.** AES-256 and SHA-256 by default, the legacy format for
  old importers, PBMAC1 on request. The test suite checks that OpenSSL,
  LibreSSL, Python and Java read what it writes.
* **Safe with untrusted input.** Bounded parsing, limits on the key
  derivation work, the MAC checked before anything is decrypted, and no key
  or password in `inspect/1` or in error messages.

> **Status: v0.1.** The API is small and expected to stay, but may still
> change before 1.0.

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

The time goes to the key derivation that the file asks for, from under a
millisecond to tens of milliseconds ([Performance](#performance)), and it is
paid again on every call: decode a file once, for example at startup, and
keep the result. For files from untrusted sources, see
[the limits](#files-from-untrusted-sources).

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

### Writing

`PKCS12.encode/3` takes the same fields that `decode/3` returns, so PEM files
become a `.pfx` for the systems and tools that import one:

```elixir
[key] = :public_key.pem_decode(File.read!("key.pem"))
[cert | chain] = for {:Certificate, der, _} <- :public_key.pem_decode(File.read!("chain.pem")), do: der

{:ok, pfx} =
  PKCS12.encode(
    %{private_key: :public_key.pem_entry_decode(key), certificate: cert, ca_certificates: chain},
    "password",
    friendly_name: "My key"
  )
```

The key can be a PrivateKeyInfo in DER or a key record of `:public_key`. A
file in an old format can be read and written again in the modern one:

```elixir
pfx |> PKCS12.decode!(password) |> PKCS12.encode!(password)
```

For importers that know nothing newer, `profile: :legacy` writes the format
of OpenSSL 1.x. The options set each algorithm and the iteration count on
their own; see `PKCS12.encode/3`.

## What it reads

| | |
|---|---|
| Encryption | PBES2 (PBKDF2 with HMAC-SHA-1/224/256/384/512) with AES-128/192/256-CBC, 3DES or DES; the PKCS#12 ciphers: 3DES, 2-key 3DES, RC2-40, RC2-128, and RC4-40/128 when `:crypto` has RC4 |
| Integrity | the classic MAC (HMAC-SHA-1/224/256/384/512) and PBMAC1 (RFC 9879); files without a MAC are accepted, and `info.mac` is `nil` |
| Content | keys (encrypted or not), X.509 certificates, nested SafeContents; other bags (secrets, CRLs) are passed on in `p12.bags` |
| Encoding | DER and BER (indefinite lengths, segmented strings), which some tools write |
| Passwords | UTF-8, as RFC 7292 says, and the forms some tools use instead (bytes as characters for non-ASCII passwords, the empty password as no bytes); the MAC decides which one is right |

Not supported: files signed with, or encrypted to, a public key instead of a
password (both are very rare).

The test suite reads files written by OpenSSL 3, OpenSSL 1.1.1, LibreSSL,
Python's `cryptography` and Java's `keytool`, in their default and legacy
modes, and the test vectors of RFC 9879. CI runs it on OTP 26 to 29, and on
an OpenSSL 3 without the legacy provider.

## What it writes

| | Key | Certificates | MAC | Iterations |
|---|---|---|---|---|
| `:modern` (default) | PBES2 AES-256-CBC, PBKDF2-HMAC-SHA-256 | the same | HMAC-SHA-256 | 100,000 |
| `:legacy` | pbeWithSHAAnd3-KeyTripleDES-CBC | pbeWithSHAAnd40BitRC2-CBC | HMAC-SHA-1 | 2,048 |

The modern profile is the format that OpenSSL 3 and Java write by default,
with a higher iteration count than either: the count is what slows down
guessing the password of a stolen file. Options choose AES-128/192, 3DES or
no encryption for each part, any of the MACs above, PBMAC1 or no MAC, the
iteration count, the `friendlyName` and the `localKeyId`. The output is DER,
with random salts and IVs.

The test suite has OpenSSL 3 and 1.1.1, LibreSSL, Python's `cryptography` and
Java's `keytool` read the files it writes, with each profile and the main
options. What they do not read:

* PBMAC1: OpenSSL before 3.4, LibreSSL and Java 23.
* A key that is not encrypted: Java skips it. Certificates without a key:
  Java skips them too, unless they carry an attribute of its own, which the
  library does not write.
* Non-ASCII passwords: LibreSSL encodes them byte by byte, so it does not
  open files from other tools that use one.
* No MAC: OpenSSL 1.1.1 and LibreSSL open such files only with `-nomacver`.

## Performance

The time is almost all key derivation, so it follows the iteration counts in
the file. On an Apple M-series laptop, OTP 27 with OpenSSL 3.6
(`mix run bench/decode.exs` and `bench/encode.exs`).

Reading:

| File | Time |
|---|---|
| OpenSSL 3 default (PBES2 AES-256, 2,048 iterations) | 0.9 ms |
| OpenSSL legacy (RC2-40 + 3DES, 2,048) | 2.7 ms |
| Java default (PBES2 AES-256, 10,000) | 4.1 ms |
| Java legacy (MAC 100,000, 50,000) | 60 ms |
| Wrong password (2,048) | 0.35 ms |

Writing a key, its certificate and a CA certificate:

| Options | Time |
|---|---|
| Default (modern, 100,000 iterations) | 39 ms |
| Modern with 2,048 iterations, as OpenSSL 3 | 0.9 ms |
| Modern with PBMAC1 (100,000) | 35 ms |
| Legacy (2,048) | 2.6 ms |

Reading a file of the default profile takes about as long as writing it.

PBKDF2 runs inside OpenSSL on a dirty scheduler. The PKCS#12 key derivation,
of the legacy ciphers and of the classic MAC, is an Elixir loop over
`:crypto.hash/2`, which the BEAM preempts like any other code.

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

The interop tests (`mix test --only interop`) run the readers they find on
the system and skip the others, as well as a Python `cryptography` older
than 36; `test/support/interop.ex` lists the variables that point to them. CI runs them with OpenSSL 3, Python and a JDK.

## References

* [RFC 7292](https://www.rfc-editor.org/rfc/rfc7292), PKCS #12 v1.1
* [RFC 8018](https://www.rfc-editor.org/rfc/rfc8018), PKCS #5 v2.1 (PBES2, PBKDF2)
* [RFC 9879](https://www.rfc-editor.org/rfc/rfc9879), PBMAC1 in PKCS #12
* [RFC 2268](https://www.rfc-editor.org/rfc/rfc2268), RC2
* [RFC 5958](https://www.rfc-editor.org/rfc/rfc5958), Asymmetric Key Packages (PKCS #8)

## License

Apache-2.0: see the `LICENSE` and `NOTICE` files.
