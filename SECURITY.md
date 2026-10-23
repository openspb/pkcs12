# Security

## Reporting a vulnerability

Please do not open a public issue. Use GitHub's
[private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
on this repository ("Security" tab, "Report a vulnerability"). You should get
an answer within a week. Fixes are released for the latest minor version.

## Threat model

The library is meant to read files from anyone: a certificate uploaded by a
user, a file from a partner, a key store found on disk. It assumes the file
may be hostile and the password may be wrong. When it writes, the input comes
from the application and is trusted; the section on writing below covers
what the written file protects.

### Malformed input

* `PKCS12.decode/3` returns `{:error, %PKCS12.Error{}}` for any input it cannot
  read. It does not raise on malformed input; the test suite feeds it damaged
  and random files to check that.
* The parser limits nesting (32 levels of ASN.1, 4 levels of nested
  SafeContents) and length fields (4 bytes), and checks every length against
  the input before it reads.
* Nothing from the file becomes an atom. Unknown algorithms and bag types are
  reported by their OID, as a string.
* The memory used is a small multiple of the input size. Bound the size of
  the files you accept; the library does not.

### CPU

A PKCS#12 file sets its own iteration counts. Without limits, one small file
could ask for minutes of CPU. Two options cap the work:

* `:max_iterations` (default 1,000,000) is checked for every key derivation
  while the file is parsed, before any of them runs.
* `:max_total_iterations` (default 4,000,000) caps the work of all
  derivations together, counted in iterations of the hash: the MAC checks,
  one per form of the password tried, and every decryption. A file with
  many encrypted parts, or a wrong password tried in several forms, stops
  at this limit.

At the defaults the worst case is about a second of one core. The work runs
in the calling process: PBKDF2 inside OpenSSL on a dirty scheduler, the
PKCS#12 key derivation as an Elixir loop that the BEAM preempts. For files
from untrusted sources, lower both limits and put a timeout around the call
(for example, with `Task.async/1` and `Task.yield/2`).

### Integrity and the password

* When the file has a MAC, it is checked first, in constant time
  (`:crypto.hash_equals/2`), and nothing is decrypted before it matches. A
  wrong password gives `:invalid_password` after the MAC check alone.
* Some tools encode the password in other ways than RFC 7292 says. The
  library tries those forms (at most two for any password), and the MAC
  decides which is right. Each try counts towards `:max_total_iterations`.
* A file without a MAC has no integrity protection: anyone can change its
  unencrypted parts, or replace a certificate. `info.mac` is `nil` for such
  files; refuse them if you need integrity. Without a MAC, a wrong password
  is detected by the padding and the structure of what it decrypts.
* `verify_mac: false` reads a file without checking its MAC. Use it only to
  recover a file you trust.

### Weak algorithms

Files in the wild still use RC2-40 and RC4-40 for certificates, 3DES and
SHA-1 for keys and MACs, and low iteration counts. The library reads them,
because refusing would make it useless for many real files. They protect the
file at rest poorly. `p12.info` reports the algorithms and iteration counts
of each file, so that an application can warn about them or refuse them.

The library implements RC2 and the PKCS#12 key derivation itself, on top of
the SHA-1 of `:crypto`. They therefore work even where the OpenSSL that OTP
uses refuses legacy algorithms, such as under a FIPS policy. If your policy
forbids reading such files, check `p12.info`.

### Secrets in memory

* `inspect/1` of `PKCS12` and `PKCS12.Bag` leaves the private key out, and no
  error, exception message or argument check includes the password or key
  material.
* The decrypted key is a binary like any other. The BEAM copies binaries
  and frees them when the garbage collector decides; there is no way to wipe
  them. Keep the key in as few processes as possible, and do not log the
  result of `PKCS12.decode/3` with tools that bypass `inspect/1`.
* The returned key and certificates are binaries of their own, not
  references into the input or the decrypted buffers.

### Side channels

The MAC comparison is constant-time. RC2 and the PKCS#12 key derivation are
written in Elixir and are not hardened against timing or cache attacks. In
the files that use RC2, it protects the certificates, which are public. The
library is meant for reading a file once, such as at startup or after an
upload, not for an oracle that answers many queries with the same key.

### What the library does not check

It does not validate certificates: not the chain, the dates, the key usage
or revocation. `p12.certificate` is the certificate that belongs to the key
by `localKeyId` or by public key, and `p12.ca_certificates` is everything
else, in file order. Validate them as your application requires, for
example with `:public_key.pkix_path_validation/3`.

### Writing

* The salts (16 bytes) and the IVs come from `:crypto.strong_rand_bytes/1`,
  the random generator of OpenSSL.
* The password is all that protects a written file. Anyone who gets the file
  can try passwords offline, as fast as the key derivation allows. Every
  derivation in a file uses the same iteration count, because the cheapest
  one would set the pace. The default is 100,000; use a long random password
  for files that leave your systems, and a higher count for files that live
  long.
* The `:legacy` profile is weak. Its key derivation is SHA-1 with 2,048
  iterations, so guessing is cheap, and the 40-bit key of RC2-40 can be found
  without the password, which exposes the certificates (public anyway). Use
  it only for importers that need it, and keep such files short-lived.
* `key_encryption: :none` leaves the key readable by anyone with the file,
  and `mac: :none` leaves the file without integrity protection. They are
  meant for trust stores and for files protected by other means.
* The library checks the shape of the key and of the certificates it writes,
  not that the certificate belongs to the key, nor that it is valid.
* As when reading, the key and the password are binaries in the memory of
  the calling process, which the BEAM cannot wipe.
