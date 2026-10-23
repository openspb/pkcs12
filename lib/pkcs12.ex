defmodule PKCS12 do
  @moduledoc """
  Reads and writes PKCS#12 files (`.pfx`, `.p12`): the private key, its
  certificate and the rest of the chain.

      {:ok, p12} = PKCS12.decode(File.read!("me.pfx"), "password")

      p12.private_key      # PrivateKeyInfo (PKCS#8), in DER
      p12.certificate      # the certificate of that key, in DER
      p12.ca_certificates  # the other certificates, in DER, in file order

      {:ok, pfx} = PKCS12.encode(p12, "new password")

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

  ## Writing

  `encode/3` takes the same fields, so PEM files become a `.pfx` for the
  systems and tools that import one:

      [key] = :public_key.pem_decode(File.read!("key.pem"))
      [cert | chain] = for {:Certificate, der, _} <- :public_key.pem_decode(File.read!("chain.pem")), do: der

      {:ok, pfx} =
        PKCS12.encode(
          %{private_key: :public_key.pem_entry_decode(key), certificate: cert, ca_certificates: chain},
          "password",
          friendly_name: "My key"
        )

  A file in an old format can be read and written again in the modern one:

      pfx |> PKCS12.decode!(password) |> PKCS12.encode!(password)

  ## Algorithms

  Reading, encryption:

    * PBES2 (PBKDF2 with HMAC-SHA-1/224/256/384/512) with AES-128/192/256-CBC,
      3DES-CBC or DES-CBC, the default of OpenSSL 3, Java and other recent
      tools;
    * pbeWithSHAAnd3-KeyTripleDES-CBC and pbeWithSHAAnd40BitRC2-CBC, the
      "legacy" combination of OpenSSL 1.x and of many older tools, still
      common;
    * the other PKCS#12 ciphers: 2-key 3DES, RC2-128, and RC4-40/128 when
      `:crypto` has RC4.

  Reading, integrity: the classic MAC with SHA-1/224/256/384/512, and PBMAC1
  (RFC 9879). Files without a MAC are accepted; `:info` tells.

  Writing: PBES2 with AES and PBKDF2-HMAC-SHA-256 by default, the legacy
  combination when asked, and any of the MACs above. See `encode/3`.

  Not supported: files signed with, or encrypted to, a public key instead of
  a password (both are very rare).

  ## Passwords

  The password is a UTF-8 binary, or `nil`, which is the same as `""`. Some
  generators encode passwords in other ways: with each byte as a character
  (non-ASCII passwords in older OpenSSL versions and LibreSSL), or the empty
  password as no bytes at all. When reading, the library tries those forms
  too, and the MAC decides which is right; `:info` tells which one matched.
  When writing, it uses the standard forms only.
  """

  alias PKCS12.{Bag, Decoder, Encoder, Error, Password}

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

  @type decode_option ::
          {:max_iterations, pos_integer()}
          | {:max_total_iterations, pos_integer()}
          | {:verify_mac, boolean()}

  @typedoc """
  What `encode/3` writes: a `t:t/0`, or a map with any of its first three
  keys. See `encode/3`.
  """
  @type input ::
          t()
          | %{
              optional(:private_key) => binary() | tuple() | nil,
              optional(:certificate) => binary() | nil,
              optional(:ca_certificates) => [binary()] | nil
            }

  @typedoc "A cipher that `encode/3` writes."
  @type cipher :: :aes_256_cbc | :aes_192_cbc | :aes_128_cbc | :des_ede3_cbc | :rc2_40_cbc

  @type encode_option ::
          {:profile, :modern | :legacy}
          | {:key_encryption, cipher() | :none}
          | {:certificate_encryption, cipher() | :none}
          | {:mac, hash() | :pbmac1 | :none}
          | {:iterations, pos_integer()}
          | {:friendly_name, String.t()}
          | {:local_key_id, binary()}

  @default_max_iterations 1_000_000

  @profiles %{
    modern: %{
      key_encryption: :aes_256_cbc,
      certificate_encryption: :aes_256_cbc,
      mac: :sha256,
      iterations: 100_000
    },
    legacy: %{
      key_encryption: :des_ede3_cbc,
      certificate_encryption: :rc2_40_cbc,
      mac: :sha,
      iterations: 2048
    }
  }

  @key_ciphers [:aes_256_cbc, :aes_192_cbc, :aes_128_cbc, :des_ede3_cbc, :none]
  @certificate_ciphers @key_ciphers ++ [:rc2_40_cbc]
  @macs [:sha256, :sha384, :sha512, :sha224, :sha, :pbmac1, :none]

  @doc """
  Decodes a PKCS#12 file.

  `password` is a binary (UTF-8 text, as typed by the user) or `nil`, which
  is the same as `""`. A password read with `System.get_env/1` is `nil` when
  the variable is not set, and a file with a password then fails with
  `:invalid_password`; `System.fetch_env!/1` raises first, with the name of
  the variable.

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
  second at the default limits, paid again on every call. Decode a file
  once, for example at startup, and keep the result. The work runs in the
  calling process, which the BEAM preempts as usual. To read files from untrusted sources, bound their
  size, lower the limits and consider a timeout around the call.

  ## Errors

  Returns `{:error, %PKCS12.Error{}}`; see `PKCS12.Error` for the reasons.
  A wrong password gives `:invalid_password`.
  """
  @spec decode(binary(), String.t() | nil, [decode_option()]) :: {:ok, t()} | {:error, Error.t()}
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
  @spec decode!(binary(), String.t() | nil, [decode_option()]) :: t()
  def decode!(pfx, password, opts \\ []) do
    case decode(pfx, password, opts) do
      {:ok, p12} -> p12
      {:error, error} -> raise error
    end
  end

  @doc """
  Encodes a PKCS#12 file, in DER.

  `p12` is a `t:t/0`, such as one that `decode/3` returns, or a map with
  some of the same keys:

    * `:private_key` - a PrivateKeyInfo (PKCS#8) in DER, or a key record of
      `:public_key`, such as `{:RSAPrivateKey, ...}` or `{:ECPrivateKey, ...}`.
    * `:certificate` - the certificate of that key, in DER.
    * `:ca_certificates` - other certificates, in DER, usually the rest of
      the chain. They are written in this order, after `:certificate`.

  Any of them can be missing: a file of certificates alone, for example, is
  a trust store. Other keys, such as `:bags` and `:info`, are ignored, so
  only the first key of a decoded file and its certificates are written
  again. The library checks the shape of the key and of the certificates,
  not that the certificate belongs to the key.

  `password` is a UTF-8 binary, or `nil`, which is the same as `""`.

  The salts and IVs come from `:crypto.strong_rand_bytes/1`, so no two
  results are the same.

  ## Options

    * `:profile` - the values of the options below when they are not given:
      * `:modern` (default) - AES-256-CBC with PBKDF2-HMAC-SHA-256 for the
        key and for the certificates, and a SHA-256 MAC, all with 100,000
        iterations. It is the format that OpenSSL 3 and Java write by
        default, with a higher count than either.
      * `:legacy` - pbeWithSHAAnd3-KeyTripleDES-CBC for the key,
        pbeWithSHAAnd40BitRC2-CBC for the certificates and a SHA-1 MAC, all
        with 2,048 iterations: the format of OpenSSL 1.x, for importers
        that know nothing newer. It is weak; see the
        [security notes](SECURITY.md).
    * `:key_encryption` - `:aes_256_cbc`, `:aes_192_cbc` or `:aes_128_cbc`
      (PBES2 with PBKDF2-HMAC-SHA-256), `:des_ede3_cbc`
      (pbeWithSHAAnd3-KeyTripleDES-CBC), or `:none`.
    * `:certificate_encryption` - the same choices, and `:rc2_40_cbc`
      (pbeWithSHAAnd40BitRC2-CBC). With `:none`, anyone can read the
      certificates, as they could anyway from the certificates themselves.
    * `:mac` - `:sha256`, `:sha384`, `:sha512`, `:sha224` or `:sha` (the
      classic MAC with that hash), `:pbmac1` (RFC 9879, with
      PBKDF2-HMAC-SHA-256 and HMAC-SHA-256, which OpenSSL reads from 3.4 on),
      or `:none`.
    * `:iterations` - the iteration count of every key derivation. A
      password is as hard to guess as the cheapest derivation that checks
      it, so they all take the same. The cost grows with the count when
      writing and when reading; `decode/3` reads up to 1,000,000 by
      default, and other readers have limits of their own.
    * `:friendly_name` - a name for the key and its certificate, which
      importers show; Java uses it as the alias.
    * `:local_key_id` - the localKeyId of the key and its certificate, which
      readers use to pair them. Default: the SHA-1 hash of the certificate,
      when there are both.

  An option given as `nil` takes the value of the profile.

  ## Errors

  Returns `{:error, %PKCS12.Error{}}` with `{:invalid_input, field}` when a
  field of `p12` is not what it should be, or `{:not_available, cipher}`
  when `:crypto` refuses a cipher, as a FIPS provider may do with
  `:des_ede3_cbc`. Raises `ArgumentError` for invalid options, or for a
  password that is not UTF-8.
  """
  @spec encode(input(), String.t() | nil, [encode_option()]) ::
          {:ok, binary()} | {:error, Error.t()}
  def encode(p12, password, opts \\ []) do
    # As in decode/3, checked here so that no error prints the password.
    check!(is_map(p12), "expected a %PKCS12{} or a map with its fields")
    check!(is_binary(password) or is_nil(password), "expected the password as a binary or nil")

    password =
      case Password.standard(password || "") do
        {:ok, password} -> password
        :error -> raise ArgumentError, "expected the password as UTF-8"
      end

    case Encoder.encode(p12, password, encode_options(opts)) do
      {:ok, pfx} -> {:ok, pfx}
      {:error, reason} -> {:error, %Error{reason: reason}}
    end
  end

  @doc """
  Like `encode/3`, but returns the file or raises `PKCS12.Error`.
  """
  @spec encode!(input(), String.t() | nil, [encode_option()]) :: binary()
  def encode!(p12, password, opts \\ []) do
    case encode(p12, password, opts) do
      {:ok, pfx} -> pfx
      {:error, error} -> raise error
    end
  end

  defp encode_options(opts) do
    opts =
      Keyword.validate!(opts,
        profile: :modern,
        key_encryption: nil,
        certificate_encryption: nil,
        mac: nil,
        iterations: nil,
        friendly_name: nil,
        local_key_id: nil
      )

    profile = opts[:profile]

    check!(
      is_map_key(@profiles, profile),
      ":profile must be :modern or :legacy, got: #{inspect(profile)}"
    )

    defaults = Map.fetch!(@profiles, profile)
    iterations = default(opts[:iterations], defaults.iterations)

    check!(
      pos_integer?(iterations),
      ":iterations must be a positive integer, got: #{inspect(iterations)}"
    )

    name = opts[:friendly_name]

    check!(
      is_nil(name) or (is_binary(name) and String.valid?(name)),
      ":friendly_name must be a UTF-8 string, got: #{inspect(name)}"
    )

    id = opts[:local_key_id]

    check!(
      is_nil(id) or (is_binary(id) and id != ""),
      ":local_key_id must be a non-empty binary, got: #{inspect(id)}"
    )

    %{
      key_encryption: choice!(opts, :key_encryption, defaults, @key_ciphers),
      certificate_encryption:
        choice!(opts, :certificate_encryption, defaults, @certificate_ciphers),
      mac: choice!(opts, :mac, defaults, @macs),
      iterations: iterations,
      friendly_name: name,
      local_key_id: id
    }
  end

  defp choice!(opts, name, defaults, choices) do
    value = default(opts[name], Map.fetch!(defaults, name))

    check!(
      value in choices,
      ":#{name} must be one of #{inspect(choices)}, got: #{inspect(value)}"
    )

    value
  end

  defp default(nil, default), do: default
  defp default(value, _default), do: value

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
