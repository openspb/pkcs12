defmodule PKCS12.PBE do
  @moduledoc false
  # Password-based encryption: the PKCS#12 ciphers (RFC 7292, appendix C)
  # and PBES2 (RFC 8018). Reading the parameters and decrypting are separate
  # steps, so the decoder can check the iteration counts and its budget
  # before it does any expensive work.

  alias PKCS12.{DER, KDF, OID, Password, RC2}

  @pbes2 OID.encode("1.2.840.113549.1.5.13")
  @pbkdf2 OID.encode("1.2.840.113549.1.5.12")

  # pbeWithSHAAnd...: {name, implementation, key size, IV size}
  @pkcs12 %{
    OID.encode("1.2.840.113549.1.12.1.1") => {:rc4_128, :rc4, 16, 0},
    OID.encode("1.2.840.113549.1.12.1.2") => {:rc4_40, :rc4, 5, 0},
    OID.encode("1.2.840.113549.1.12.1.3") => {:des_ede3_cbc, :des_ede3_cbc, 24, 8},
    OID.encode("1.2.840.113549.1.12.1.4") => {:des_ede_cbc, :des_ede_cbc, 16, 8},
    OID.encode("1.2.840.113549.1.12.1.5") => {:rc2_128_cbc, :rc2, 16, 8},
    OID.encode("1.2.840.113549.1.12.1.6") => {:rc2_40_cbc, :rc2, 5, 8}
  }

  # Encryption schemes of PBES2: {name, key size, block size}
  @pbes2_ciphers %{
    OID.encode("2.16.840.1.101.3.4.1.2") => {:aes_128_cbc, 16, 16},
    OID.encode("2.16.840.1.101.3.4.1.22") => {:aes_192_cbc, 24, 16},
    OID.encode("2.16.840.1.101.3.4.1.42") => {:aes_256_cbc, 32, 16},
    OID.encode("1.2.840.113549.3.7") => {:des_ede3_cbc, 24, 8},
    OID.encode("1.3.14.3.2.7") => {:des_cbc, 8, 8}
  }

  @prfs %{
    OID.encode("1.2.840.113549.2.7") => :sha,
    OID.encode("1.2.840.113549.2.8") => :sha224,
    OID.encode("1.2.840.113549.2.9") => :sha256,
    OID.encode("1.2.840.113549.2.10") => :sha384,
    OID.encode("1.2.840.113549.2.11") => :sha512
  }

  @type cipher ::
          :rc4_128
          | :rc4_40
          | :des_ede3_cbc
          | :des_ede_cbc
          | :rc2_128_cbc
          | :rc2_40_cbc
          | :aes_128_cbc
          | :aes_192_cbc
          | :aes_256_cbc
          | :des_cbc

  @type t :: %{
          scheme: :pkcs12_pbe | :pbes2,
          cipher: cipher(),
          digest: KDF.hash(),
          iterations: pos_integer(),
          salt: binary(),
          key_size: pos_integer(),
          iv: binary() | {:derive, non_neg_integer()},
          impl: atom()
        }

  @type error ::
          :malformed
          | {:unsupported_algorithm, String.t()}
          | {:too_many_iterations, pos_integer()}

  @doc """
  Reads an AlgorithmIdentifier of a password-based cipher.
  """
  @spec parse(DER.element(), pos_integer()) :: {:ok, t()} | {:error, error()}
  def parse({0x30, [{0x06, oid} | params]}, max_iterations) do
    case @pkcs12 do
      %{^oid => cipher} -> pkcs12(cipher, params, max_iterations)
      %{} when oid == @pbes2 -> pbes2(params, max_iterations)
      %{} -> unsupported(oid)
    end
  end

  def parse(_element, _max_iterations), do: {:error, :malformed}

  # pkcs-12PbeParams ::= SEQUENCE { salt OCTET STRING, iterations INTEGER }
  defp pkcs12({name, impl, key_size, iv_size}, [{0x30, [salt, iterations]}], max) do
    with {:ok, salt} <- DER.octets(salt, 0x04),
         {:ok, iterations} <- iterations(iterations, max) do
      {:ok,
       %{
         scheme: :pkcs12_pbe,
         cipher: name,
         digest: :sha,
         iterations: iterations,
         salt: salt,
         key_size: key_size,
         iv: {:derive, iv_size},
         impl: impl
       }}
    end
  end

  defp pkcs12(_cipher, _params, _max), do: {:error, :malformed}

  # PBES2-params ::= SEQUENCE { keyDerivationFunc, encryptionScheme }
  defp pbes2(
         [{0x30, [{0x30, [{0x06, @pbkdf2}, kdf_params]}, {0x30, [{0x06, enc} | enc_params]}]}],
         max
       ) do
    with {:ok, {name, key_size, block}} <- fetch(@pbes2_ciphers, enc),
         {:ok, iv} <- iv(enc_params, block),
         {:ok, pbkdf2} <- pbkdf2(kdf_params, max),
         :ok <- key_size(pbkdf2.key_size, key_size) do
      {:ok,
       %{
         scheme: :pbes2,
         cipher: name,
         digest: pbkdf2.prf,
         iterations: pbkdf2.iterations,
         salt: pbkdf2.salt,
         key_size: key_size,
         iv: iv,
         impl: name
       }}
    end
  end

  defp pbes2([{0x30, [{0x30, [{0x06, kdf} | _]}, _]}], _max) when kdf != @pbkdf2,
    do: unsupported(kdf)

  defp pbes2(_params, _max), do: {:error, :malformed}

  # The keyLength of PBKDF2, when present, must match the cipher.
  defp key_size(nil, _expected), do: :ok
  defp key_size(expected, expected), do: :ok
  defp key_size(_other, _expected), do: {:error, :malformed}

  defp iv([{0x04, iv}], block) when byte_size(iv) == block, do: {:ok, iv}
  defp iv(_params, _block), do: {:error, :malformed}

  @doc """
  Reads PBKDF2-params. `key_size` is `nil` when the field is absent.
  """
  @spec pbkdf2(DER.element(), pos_integer()) ::
          {:ok,
           %{
             salt: binary(),
             iterations: pos_integer(),
             key_size: pos_integer() | nil,
             prf: KDF.hash()
           }}
          | {:error, error()}
  def pbkdf2({0x30, [salt, iterations | rest]}, max) do
    {key_size, prf} =
      case rest do
        [{0x02, _} = key_size | prf] -> {key_size, prf}
        prf -> {nil, prf}
      end

    with {:ok, salt} <- DER.octets(salt, 0x04),
         {:ok, iterations} <- iterations(iterations, max),
         {:ok, key_size} <- optional_uint(key_size),
         {:ok, prf} <- prf(prf) do
      {:ok, %{salt: salt, iterations: iterations, key_size: key_size, prf: prf}}
    end
  end

  def pbkdf2(_params, _max), do: {:error, :malformed}

  defp optional_uint(nil), do: {:ok, nil}
  defp optional_uint(element), do: DER.uint(element)

  # prf AlgorithmIdentifier DEFAULT algid-hmacWithSHA1
  defp prf([]), do: {:ok, :sha}
  defp prf([{0x30, [{0x06, oid} | _params]}]), do: hmac(oid)
  defp prf(_), do: {:error, :malformed}

  @doc """
  Hash of an hmacWithSHA* OID.
  """
  @spec hmac(binary()) :: {:ok, KDF.hash()} | {:error, error()}
  def hmac(oid), do: fetch(@prfs, oid)

  @doc """
  Reads an iteration count and checks it against the limit.
  """
  @spec iterations(DER.element(), pos_integer()) :: {:ok, pos_integer()} | {:error, error()}
  def iterations(element, max) do
    case DER.uint(element) do
      {:ok, n} when n in 1..max//1 -> {:ok, n}
      {:ok, n} when n > max -> {:error, {:too_many_iterations, n}}
      _ -> {:error, :malformed}
    end
  end

  @doc """
  The work of the key derivation, in iterations of the hash: the iteration
  count times the output blocks needed, for the IV too when it is derived.
  """
  @spec cost(t()) :: pos_integer()
  def cost(%{scheme: :pkcs12_pbe, iterations: n, key_size: key_size, iv: {:derive, iv_size}})
      when is_integer(n) do
    iv_blocks = if iv_size > 0, do: KDF.blocks(:sha, iv_size), else: 0
    n * (KDF.blocks(:sha, key_size) + iv_blocks)
  end

  def cost(%{scheme: :pbes2, iterations: n, digest: prf, key_size: key_size}) when is_integer(n),
    do: n * KDF.blocks(prf, key_size)

  @doc """
  The parameters that tell what a file uses, without salt or IV.
  """
  @spec describe(t()) :: map()
  def describe(params), do: Map.take(params, [:scheme, :cipher, :digest, :iterations])

  @doc """
  Derives the key and decrypts. A bad padding gives `:bad_decrypt`, which
  usually means a wrong password.
  """
  @spec decrypt(t(), Password.t(), binary()) ::
          {:ok, binary()} | {:error, :bad_decrypt | :malformed | {:not_available, atom()}}
  def decrypt(params, password, data) do
    with :ok <- available(params),
         {:ok, key, iv} <- derive(params, password) do
      case run(params.impl, key, iv, data) do
        # Named as in `:info`, not as in `:crypto`.
        {:error, {:not_available, _}} -> {:error, {:not_available, params.cipher}}
        result -> result
      end
    end
  end

  defp available(%{impl: :rc2}), do: :ok
  defp available(%{impl: :des_ede_cbc}), do: supported(:des_ede3_cbc, :des_ede_cbc)
  defp available(%{impl: impl, cipher: cipher}), do: supported(impl, cipher)

  defp supported(impl, name) do
    if impl in :crypto.supports(:ciphers), do: :ok, else: {:error, {:not_available, name}}
  end

  defp derive(%{scheme: :pkcs12_pbe, iv: {:derive, iv_size}} = params, password) do
    bmp = Password.bmp(password)
    %{salt: salt, iterations: iterations, key_size: key_size} = params
    key = KDF.derive(:sha, bmp, salt, iterations, :key, key_size)
    iv = if iv_size > 0, do: KDF.derive(:sha, bmp, salt, iterations, :iv, iv_size), else: <<>>
    {:ok, key, iv}
  end

  defp derive(%{scheme: :pbes2} = params, password) do
    %{digest: prf, salt: salt, iterations: iterations, key_size: key_size, iv: iv} = params
    {:ok, :crypto.pbkdf2_hmac(prf, Password.raw(password), salt, iterations, key_size), iv}
  rescue
    # A FIPS provider may refuse some parameters, such as a short password.
    ErlangError -> {:error, {:not_available, :pbkdf2}}
  end

  defp run(:rc2, key, iv, data) when data != <<>> and rem(byte_size(data), 8) == 0,
    do: unpad(RC2.decrypt_cbc(key, byte_size(key) * 8, iv, data), 8)

  defp run(:rc4, key, _iv, data), do: crypto(:rc4, key, nil, data)

  # Two-key triple DES is three-key with K3 = K1.
  defp run(:des_ede_cbc, <<k1::binary-size(8), k2::binary-size(8)>>, iv, data),
    do: run(:des_ede3_cbc, k1 <> k2 <> k1, iv, data)

  defp run(cipher, key, iv, data) when cipher != :rc2 and data != <<>> do
    block = byte_size(iv)

    if rem(byte_size(data), block) == 0 do
      with {:ok, plain} <- crypto(cipher, key, iv, data), do: unpad(plain, block)
    else
      {:error, :malformed}
    end
  end

  defp run(_cipher, _key, _iv, _data), do: {:error, :malformed}

  defp crypto(cipher, key, iv, data) do
    plain =
      if iv,
        do: :crypto.crypto_one_time(cipher, key, iv, data, false),
        else: :crypto.crypto_one_time(cipher, key, data, false)

    {:ok, plain}
  rescue
    ErlangError -> {:error, {:not_available, cipher}}
  end

  # PKCS#5 padding. When it is wrong, the key most likely was.
  defp unpad(plain, block) do
    size = byte_size(plain)
    n = :binary.last(plain)

    if n in 1..block and binary_part(plain, size - n, n) == :binary.copy(<<n>>, n),
      do: {:ok, binary_part(plain, 0, size - n)},
      else: {:error, :bad_decrypt}
  end

  defp fetch(map, oid) do
    case map do
      %{^oid => value} -> {:ok, value}
      %{} -> unsupported(oid)
    end
  end

  @doc false
  @spec unsupported(binary()) :: {:error, error()}
  def unsupported(oid) do
    case OID.decode(oid) do
      {:ok, dotted} -> {:error, {:unsupported_algorithm, dotted}}
      :error -> {:error, :malformed}
    end
  end
end
