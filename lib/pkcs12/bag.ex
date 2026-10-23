defmodule PKCS12.Bag do
  @moduledoc """
  One SafeBag of a PKCS#12 file: a private key, a certificate or something
  else, with its attributes.

  `PKCS12.decode/3` lists every bag of the file in `t:PKCS12.t/0`, in file
  order. Most programs only need the `:private_key`, `:certificate` and
  `:ca_certificates` fields there; the bags are for files with more than one
  key, for the friendly names and for attributes the library does not
  interpret.

  Fields:

    * `:type` - `:private_key`, `:certificate` or `:other`.
    * `:value` - for `:private_key`, the PrivateKeyInfo (PKCS#8) in DER,
      already decrypted; for `:certificate`, the X.509 certificate in DER;
      for `:other`, the DER of the bag value as it is in the file.
    * `:oid` - the bag type (`bagId`), in dotted form.
    * `:friendly_name` - the `friendlyName` attribute, or `nil`.
    * `:local_key_id` - the `localKeyId` attribute, or `nil`. A key and its
      certificate usually share it.
    * `:attributes` - the other attributes, as `{oid, values}` with each
      value in DER, in file order.

  `inspect/1` leaves `:value` out, so that a private key does not end up in
  a log by accident.
  """

  @derive {Inspect, except: [:value]}
  @enforce_keys [:type, :value, :oid]
  defstruct [:type, :value, :oid, friendly_name: nil, local_key_id: nil, attributes: []]

  @type type :: :private_key | :certificate | :other

  @type t :: %__MODULE__{
          type: type(),
          value: binary(),
          oid: String.t(),
          friendly_name: String.t() | nil,
          local_key_id: binary() | nil,
          attributes: [{String.t(), [binary()]}]
        }
end
