defmodule PKCS12.Error do
  @moduledoc """
  Why a PKCS#12 file could not be read or written.

  `PKCS12.decode/3` and `PKCS12.encode/3` return it as
  `{:error, %PKCS12.Error{}}`, and `PKCS12.decode!/3` and `PKCS12.encode!/3`
  raise it. Match on `:reason`:

    * `:malformed` - not a valid PKCS#12 structure.
    * `:invalid_password` - the MAC does not match, or, in a file without a
      MAC, the content does not decrypt.
    * `{:unsupported_version, version}` - the PFX version is not 3.
    * `{:unsupported_algorithm, oid}` - an algorithm the library does not
      implement, with its OID in dotted form.
    * `{:unsupported, :public_key_integrity | :public_key_privacy}` - the
      file is signed with, or encrypted to, a public key instead of a
      password. Such files are very rare.
    * `{:not_available, algorithm}` - the library knows the algorithm, but
      the `:crypto` application of this system (its OpenSSL) refuses it. For
      example, RC4 when the OpenSSL "legacy" provider is missing, or
      parameters that a FIPS provider rejects.
    * `{:too_many_iterations, count}` - one key derivation asks for more
      iterations than the `:max_iterations` option allows.
    * `{:too_many_total_iterations, count}` - the work of all derivations
      together goes beyond the `:max_total_iterations` option; `count` is
      the work done or due when the limit was reached.
    * `{:unsupported_mac_key_size, bytes}` - a PBMAC1 key size outside
      20..64 bytes.
    * `{:invalid_input, field}` - when writing, `field` (`:private_key`,
      `:certificate` or `:ca_certificates`) is not a key or certificates in
      a form that `PKCS12.encode/3` takes.

  The error never carries the password or any key material.
  """

  @type reason ::
          :malformed
          | :invalid_password
          | {:unsupported_version, non_neg_integer()}
          | {:unsupported_algorithm, String.t()}
          | {:unsupported, :public_key_integrity | :public_key_privacy}
          | {:not_available, atom()}
          | {:too_many_iterations, pos_integer()}
          | {:too_many_total_iterations, pos_integer()}
          | {:unsupported_mac_key_size, non_neg_integer()}
          | {:invalid_input, :private_key | :certificate | :ca_certificates}

  @type t :: %__MODULE__{reason: reason()}

  defexception [:reason]

  @impl true
  def message(%__MODULE__{reason: reason}), do: describe(reason)

  defp describe(:malformed), do: "not a valid PKCS#12 file"
  defp describe(:invalid_password), do: "wrong password"
  defp describe({:unsupported_version, v}), do: "unsupported PFX version #{v} (expected 3)"
  defp describe({:unsupported_algorithm, oid}), do: "unsupported algorithm #{oid}"

  defp describe({:unsupported, :public_key_integrity}),
    do: "the file is signed with a public key, which is not supported"

  defp describe({:unsupported, :public_key_privacy}),
    do: "part of the file is encrypted to a public key, which is not supported"

  defp describe({:not_available, algorithm}),
    do: "#{algorithm} is not available in the :crypto application of this system"

  defp describe({:too_many_iterations, n}),
    do: "a key derivation asks for #{n} iterations, more than the :max_iterations option allows"

  defp describe({:too_many_total_iterations, n}),
    do:
      "reading the file takes at least #{n} iterations in total, " <>
        "more than the :max_total_iterations option allows"

  defp describe({:unsupported_mac_key_size, n}), do: "unsupported PBMAC1 key size: #{n} bytes"

  defp describe({:invalid_input, :private_key}),
    do: "the private key is neither a PrivateKeyInfo (PKCS#8) in DER nor a key record"

  defp describe({:invalid_input, :certificate}), do: "the certificate is not a certificate in DER"

  defp describe({:invalid_input, :ca_certificates}),
    do: "the CA certificates are not a list of certificates in DER"

  defp describe(other), do: "PKCS#12 error: #{inspect(other)}"
end
