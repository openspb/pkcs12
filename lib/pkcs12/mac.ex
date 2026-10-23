defmodule PKCS12.MAC do
  @moduledoc false
  # The integrity check (MacData): the classic MAC of PKCS#12, an HMAC keyed
  # by the KDF of appendix B with ID 3, and PBMAC1 (RFC 9879), an HMAC keyed
  # by PBKDF2.

  alias PKCS12.{DER, KDF, OID, Password, PBE}

  @pbmac1 OID.encode("1.2.840.113549.1.5.14")
  @pbkdf2 OID.encode("1.2.840.113549.1.5.12")

  @digests %{
    OID.encode("1.3.14.3.2.26") => :sha,
    OID.encode("2.16.840.1.101.3.4.2.4") => :sha224,
    OID.encode("2.16.840.1.101.3.4.2.1") => :sha256,
    OID.encode("2.16.840.1.101.3.4.2.2") => :sha384,
    OID.encode("2.16.840.1.101.3.4.2.3") => :sha512
  }

  # PBMAC1 keys shorter than this are too weak to mean anything, and longer
  # ones only cost more PBKDF2 blocks.
  @pbmac1_key_sizes 20..64

  @type t :: %{
          scheme: :hmac | :pbmac1,
          digest: KDF.hash(),
          prf: KDF.hash() | nil,
          iterations: pos_integer(),
          salt: binary(),
          key_size: pos_integer(),
          expected: binary()
        }

  @doc """
  Reads the MacData.

      MacData ::= SEQUENCE {
        mac        DigestInfo,
        macSalt    OCTET STRING,
        iterations INTEGER DEFAULT 1 }
  """
  @spec parse(DER.element(), pos_integer()) :: {:ok, t()} | {:error, term()}
  def parse({0x30, [{0x30, [{0x30, [{0x06, oid} | params]}, digest]}, salt | rest]}, max) do
    with {:ok, expected} <- DER.octets(digest, 0x04),
         {:ok, salt} <- DER.octets(salt, 0x04) do
      if oid == @pbmac1,
        do: pbmac1(params, expected, max),
        else: classic(oid, salt, rest, expected, max)
    end
  end

  def parse(_element, _max), do: {:error, :malformed}

  defp classic(oid, salt, rest, expected, max) do
    with {:ok, digest} <- digest(oid),
         {:ok, iterations} <- classic_iterations(rest, max) do
      {:ok,
       %{
         scheme: :hmac,
         digest: digest,
         prf: nil,
         iterations: iterations,
         salt: salt,
         key_size: KDF.hash_size(digest),
         expected: expected
       }}
    end
  end

  defp classic_iterations([], _max), do: {:ok, 1}
  defp classic_iterations([iterations], max), do: PBE.iterations(iterations, max)
  defp classic_iterations(_rest, _max), do: {:error, :malformed}

  defp digest(oid) do
    case @digests do
      %{^oid => digest} -> {:ok, digest}
      %{} -> PBE.unsupported(oid)
    end
  end

  # PBMAC1-params ::= SEQUENCE { keyDerivationFunc, messageAuthScheme }
  #
  # The salt and iteration count of MacData do not apply to PBMAC1; its own
  # PBKDF2-params carry them, and keyLength is required there.
  defp pbmac1(
         [{0x30, [{0x30, [{0x06, @pbkdf2}, kdf]}, {0x30, [{0x06, hmac} | _]}]}],
         expected,
         max
       ) do
    with {:ok, pbkdf2} <- PBE.pbkdf2(kdf, max),
         {:ok, key_size} <- pbmac1_key_size(pbkdf2.key_size),
         {:ok, digest} <- PBE.hmac(hmac) do
      {:ok,
       %{
         scheme: :pbmac1,
         digest: digest,
         prf: pbkdf2.prf,
         iterations: pbkdf2.iterations,
         salt: pbkdf2.salt,
         key_size: key_size,
         expected: expected
       }}
    end
  end

  defp pbmac1([{0x30, [{0x30, [{0x06, kdf} | _]}, _]}], _expected, _max) when kdf != @pbkdf2,
    do: PBE.unsupported(kdf)

  defp pbmac1(_params, _expected, _max), do: {:error, :malformed}

  defp pbmac1_key_size(nil), do: {:error, :malformed}
  defp pbmac1_key_size(n) when n in @pbmac1_key_sizes, do: {:ok, n}
  defp pbmac1_key_size(n), do: {:error, {:unsupported_mac_key_size, n}}

  @doc """
  The work of one check, in iterations of the hash (see `PKCS12.PBE.cost/1`).
  """
  @spec cost(t()) :: pos_integer()
  def cost(%{scheme: :hmac, iterations: n, digest: digest, key_size: key_size})
      when is_integer(n),
      do: n * KDF.blocks(digest, key_size)

  def cost(%{scheme: :pbmac1, iterations: n, prf: prf, key_size: key_size}) when is_integer(n),
    do: n * KDF.blocks(prf, key_size)

  @doc """
  Which form of the password the MAC key is derived from.
  """
  @spec password_form(t()) :: :bmp | :raw
  def password_form(%{scheme: :hmac}), do: :bmp
  def password_form(%{scheme: :pbmac1}), do: :raw

  @doc """
  Checks the MAC of `data`. The comparison takes constant time.
  """
  @spec verify(t(), Password.t(), binary()) ::
          :ok | :mismatch | {:error, {:not_available, :pbkdf2}}
  def verify(%{expected: expected} = mac, password, data) do
    with {:ok, actual} <- compute(mac, password, data) do
      if byte_size(actual) == byte_size(expected) and :crypto.hash_equals(actual, expected),
        do: :ok,
        else: :mismatch
    end
  end

  defp compute(%{scheme: :hmac, digest: digest} = mac, password, data) do
    key = KDF.derive(digest, Password.bmp(password), mac.salt, mac.iterations, :mac, mac.key_size)
    {:ok, :crypto.mac(:hmac, digest, key, data)}
  end

  # RFC 9879, which replaces RFC 9579, passes the password to PBKDF2 as is,
  # like PBES2 does.
  defp compute(%{scheme: :pbmac1, digest: digest} = mac, password, data) do
    key =
      :crypto.pbkdf2_hmac(mac.prf, Password.raw(password), mac.salt, mac.iterations, mac.key_size)

    {:ok, :crypto.mac(:hmac, digest, key, data)}
  rescue
    # A FIPS provider may refuse some parameters, such as a short password.
    ErlangError -> {:error, {:not_available, :pbkdf2}}
  end

  @doc """
  The parameters that tell what a file uses.
  """
  @spec describe(t(), boolean()) :: map()
  def describe(mac, verified?) do
    mac
    |> Map.take([:scheme, :digest, :prf, :iterations])
    |> Map.put(:verified, verified?)
  end
end
