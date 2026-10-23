defmodule PKCS12 do
  @moduledoc """
  Reads PKCS#12 files (`.pfx`, `.p12`): the private key, its certificate and
  the rest of the chain.

      {:ok, p12} = PKCS12.decode(File.read!("me.pfx"), "password")

      p12.private_key      # PrivateKeyInfo (PKCS#8), in DER
      p12.certificate      # the certificate of that key, in DER
      p12.ca_certificates  # the other certificates, in DER, in file order

  Everything is done in Elixir on top of `:crypto` and `:public_key`, with no
  NIF of its own and no call to the `openssl` binary. RC2, which the legacy
  files use for their certificates, is implemented by the library, because
  OpenSSL 3 only has it in its "legacy" provider, often missing.

  ## Using the result

  The key and the certificates are DER binaries, the form that the rest of
  OTP takes:

      # TLS client authentication (mTLS)
      :ssl.connect(host, 443,
        certs_keys: [%{cert: [p12.certificate | p12.ca_certificates],
                       key: {:PrivateKeyInfo, p12.private_key}}],
        verify: :verify_peer,
        cacerts: :public_key.cacerts_get()
      )

      # Signing
      key = :public_key.der_decode(:PrivateKeyInfo, p12.private_key)
      signature = :public_key.sign(message, :sha256, key)

      # PEM files, for tools that want them
      pem = :public_key.pem_encode([{:PrivateKeyInfo, p12.private_key, :not_encrypted}])

  ## Algorithms

  Encryption:

    * PBES2 (PBKDF2 with HMAC-SHA-1/224/256/384/512) with AES-128/192/256-CBC,
      3DES-CBC or DES-CBC, the default of OpenSSL 3, Java and other recent
      tools;
    * pbeWithSHAAnd3-KeyTripleDES-CBC and pbeWithSHAAnd40BitRC2-CBC, the
      "legacy" combination of OpenSSL 1.x and of many older tools, still
      common;
    * the other PKCS#12 ciphers: 2-key 3DES, RC2-128, and RC4-40/128 when
      `:crypto` has RC4.

  Integrity: the classic MAC with SHA-1/224/256/384/512, and PBMAC1
  (RFC 9879). Files without a MAC are accepted; `:info` tells.

  Not supported: files signed with, or encrypted to, a public key instead of
  a password (both are very rare), and writing PKCS#12.

  ## Passwords

  The password is a UTF-8 binary, or `nil` for none. Some generators encode
  passwords in other ways: with each byte as a character (non-ASCII
  passwords in older OpenSSL versions and LibreSSL), or the empty password
  as no bytes at all. The library tries those forms too, and the MAC decides
  which is right; `:info` tells which one matched.
  """

  alias PKCS12.{Bag, Decoder, Error}

  @derive {Inspect, except: [:private_key]}
  defstruct private_key: nil, certificate: nil, ca_certificates: [], bags: [], info: %{}

  @typedoc """
  A decoded PKCS#12 file.

    * `:private_key` - the first private key of the file, as a
      PrivateKeyInfo (PKCS#8) in DER, or `nil` if the file has none.
      `inspect/1` leaves it out.
    * `:certificate` - the certificate of that key, in DER: the one with the
      same `localKeyId`, or else the one with the same public key. `nil` if
      there is no key, or no certificate matches.
    * `:ca_certificates` - every other certificate, in DER, in file order.
      In files with a key, that is usually the chain; the library does not
      reorder or validate it.
    * `:bags` - every bag of the file, as `t:PKCS12.Bag.t/0`, in file order,
      with their attributes. Files with more than one key list them all
      here.
    * `:info` - what the file uses, to warn about or refuse weak algorithms
      (see `t:info/0`).
  """
  @type t :: %__MODULE__{
          private_key: binary() | nil,
          certificate: binary() | nil,
          ca_certificates: [binary()],
          bags: [Bag.t()],
          info: info()
        }

  @typedoc """
  What the file uses.

    * `:mac` - `nil` if the file has no MAC, otherwise a map with `:scheme`
      (`:hmac`, the classic MAC, or `:pbmac1`), `:digest` (the HMAC hash),
      `:prf` (the PBKDF2 hash of PBMAC1, `nil` for `:hmac`), `:iterations`
      and `:verified` (`false` with `verify_mac: false`).
    * `:encryption` - one map per distinct algorithm, with `:scheme`
      (`:pbes2` or `:pkcs12_pbe`), `:cipher` (such as `:aes_256_cbc`,
      `:des_ede3_cbc` or `:rc2_40_cbc`), `:digest` (the hash of the key
      derivation) and `:iterations`: first those of the encrypted parts of
      the file, then those of the encrypted keys. Empty if nothing is
      encrypted.
    * `:password_encoding` - which form of the password matched: `:unicode`
      (the standard one), `:latin1` or `:null`. `nil` if the password was
      not needed.

  More keys may be added in later versions.
  """
  @type info :: %{
          mac:
            nil
            | %{
                scheme: :hmac | :pbmac1,
                digest: hash(),
                prf: hash() | nil,
                iterations: pos_integer(),
                verified: boolean()
              },
          encryption: [
            %{
              scheme: :pbes2 | :pkcs12_pbe,
              cipher: atom(),
              digest: hash(),
              iterations: pos_integer()
            }
          ],
          password_encoding: :unicode | :latin1 | :null | nil
        }

  @typedoc "A hash algorithm, named as in `:crypto`."
  @type hash :: :sha | :sha224 | :sha256 | :sha384 | :sha512

  @type option ::
          {:max_iterations, pos_integer()}
          | {:max_total_iterations, pos_integer()}
          | {:verify_mac, boolean()}

  @default_max_iterations 1_000_000

  @doc """
  Decodes a PKCS#12 file.

  `password` is a binary (UTF-8 text, as typed by the user) or `nil`.

  ## Options

    * `:max_iterations` - the largest iteration count accepted for any one
      key derivation. Default: `#{@default_max_iterations}`. Common tools
      write from 2,048 to 100,000 (the MAC of the Java legacy format); a
      much larger count in a file from an untrusted source is a way to make
      the server spend CPU.
    * `:max_total_iterations` - the limit for the work of all derivations
      together: the MAC checks (one per form of the password tried) and
      every decryption. Each counts its iteration count times the output
      blocks of the hash it needs, so a legacy 3DES decryption of 2,048
      iterations counts 6,144: two blocks for the key and one for the IV.
      Default: 4 times `:max_iterations`.
    * `:verify_mac` - whether to check the MAC. Default: `true`. With
      `false`, a file with a damaged MAC can still be read, but nothing tells
      whether it was changed; use it only to recover a file you trust.

  The work is CPU-bound: a few milliseconds for common files, up to about a
  second at the default limits. It runs in the calling process, which the
  BEAM preempts as usual. To read files from untrusted sources, bound their
  size, lower the limits and consider a timeout around the call.

  ## Errors

  Returns `{:error, %PKCS12.Error{}}`; see `PKCS12.Error` for the reasons.
  A wrong password gives `:invalid_password`.
  """
  @spec decode(binary(), String.t() | nil, [option()]) :: {:ok, t()} | {:error, Error.t()}
  def decode(pfx, password, opts \\ []) do
    # The arguments are checked here, with no guard in the function head, so
    # that a FunctionClauseError never prints the password.
    check!(is_binary(pfx), "expected the PKCS#12 file as a binary")
    check!(is_binary(password) or is_nil(password), "expected the password as a binary or nil")

    case Decoder.decode(pfx, password || "", options(opts)) do
      {:ok, p12} -> {:ok, p12}
      {:error, reason} -> {:error, %Error{reason: reason}}
    end
  end

  @doc """
  Like `decode/3`, but returns the result or raises `PKCS12.Error`.
  """
  @spec decode!(binary(), String.t() | nil, [option()]) :: t()
  def decode!(pfx, password, opts \\ []) do
    case decode(pfx, password, opts) do
      {:ok, p12} -> p12
      {:error, error} -> raise error
    end
  end

  defp options(opts) do
    opts =
      Keyword.validate!(opts,
        max_iterations: @default_max_iterations,
        max_total_iterations: nil,
        verify_mac: true
      )

    max = opts[:max_iterations]
    check!(pos_integer?(max), ":max_iterations must be a positive integer, got: #{inspect(max)}")

    total = opts[:max_total_iterations] || 4 * max

    check!(
      pos_integer?(total),
      ":max_total_iterations must be a positive integer, got: #{inspect(total)}"
    )

    verify_mac = opts[:verify_mac]
    check!(is_boolean(verify_mac), ":verify_mac must be a boolean, got: #{inspect(verify_mac)}")

    %{max_iterations: max, max_total_iterations: total, verify_mac: verify_mac}
  end

  defp pos_integer?(value), do: is_integer(value) and value > 0

  defp check!(true, _message), do: :ok
  defp check!(false, message), do: raise(ArgumentError, message)
end
