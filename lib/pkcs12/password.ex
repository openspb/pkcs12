defmodule PKCS12.Password do
  @moduledoc false
  # The forms in which a password reaches the key derivations.
  #
  # The PKCS#12 KDF (legacy ciphers and the classic MAC) takes the password as
  # a BMPString: UTF-16BE with a two-byte terminator. PBKDF2 (PBES2 and
  # PBMAC1) takes the raw bytes. Generators do not all agree on the BMPString,
  # so the decoder tries the candidates below in order, and the MAC, when
  # there is one, decides which is right:
  #
  #   * `:unicode` - UTF-8 converted to UTF-16, as RFC 7292 says.
  #   * `:latin1`  - one character per byte, which is what older OpenSSL
  #     versions and LibreSSL do with non-ASCII passwords.
  #   * `:null`    - for the empty password only: no bytes at all, not even
  #     the terminator, as some generators write "no password".
  #
  # The bytes are kept inside closures, so that an inspected or logged
  # candidate shows no secret, whatever formats it.

  @enforce_keys [:encoding, :bmp, :raw]
  defstruct @enforce_keys

  @type encoding :: :unicode | :latin1 | :null
  @type t :: %__MODULE__{encoding: encoding(), bmp: (-> binary()), raw: (-> binary())}

  @spec candidates(binary()) :: [t(), ...]
  def candidates(password) do
    raw = fn -> password end

    case :unicode.characters_to_binary(password, :utf8, {:utf16, :big}) do
      utf16 when is_binary(utf16) ->
        unicode = new(:unicode, utf16 <> <<0, 0>>, raw)

        cond do
          password == "" -> [unicode, new(:null, <<>>, raw)]
          ascii?(password) -> [unicode]
          true -> [unicode, new(:latin1, latin1(password), raw)]
        end

      _not_utf8 ->
        [new(:latin1, latin1(password), raw)]
    end
  end

  @spec bmp(t()) :: binary()
  def bmp(%__MODULE__{bmp: bmp}), do: bmp.()

  @spec raw(t()) :: binary()
  def raw(%__MODULE__{raw: raw}), do: raw.()

  defp new(encoding, bmp, raw), do: %__MODULE__{encoding: encoding, bmp: fn -> bmp end, raw: raw}

  defp ascii?(password), do: :binary.bin_to_list(password) |> Enum.all?(&(&1 < 0x80))

  defp latin1(password), do: IO.iodata_to_binary([for(<<b <- password>>, do: [0, b]), 0, 0])
end
