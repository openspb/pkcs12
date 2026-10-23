defmodule PKCS12.InteropTest do
  # Other implementations read what encode/3 writes. The readers are tools
  # found on this system; see test/support/interop.ex.
  use ExUnit.Case, async: true

  import PKCS12.Fixtures

  alias PKCS12.Interop

  @moduletag :interop
  @moduletag :tmp_dir

  # ASCII, as keytool and LibreSSL want, and long enough for keytool.
  @pw "interop-pw"
  @pwu "Senha-ção ✓"
  @fast [iterations: 2048]

  # {name, material, options, password, readers that do not take it}
  @variants [
    {"modern, by default", "rsa", [], @pw, []},
    {"legacy", "rsa", [profile: :legacy] ++ @fast, @pw, []},
    # OpenSSL 1.1, LibreSSL and Java 23 do not know PBMAC1; OpenSSL reads
    # it from 3.4 on.
    {"PBMAC1", "rsa", [mac: :pbmac1] ++ @fast, @pw, [:openssl11, :libressl, :keytool]},
    {"AES-128 and SHA-512", "rsa",
     [key_encryption: :aes_128_cbc, certificate_encryption: :aes_128_cbc, mac: :sha512] ++ @fast,
     @pw, []},
    {"PKCS#12 3DES and SHA-1", "rsa",
     [key_encryption: :des_ede3_cbc, certificate_encryption: :des_ede3_cbc, mac: :sha] ++ @fast,
     @pw, []},
    {"EC key", "ec", @fast, @pw, []},
    {"no MAC", "rsa", [mac: :none] ++ @fast, @pw, []},
    # Java reads keys only from pkcs8ShroudedKeyBag.
    {"nothing encrypted", "rsa", [key_encryption: :none, certificate_encryption: :none] ++ @fast,
     @pw, [:keytool]},
    # LibreSSL encodes non-ASCII passwords byte by byte; keytool refuses them.
    {"non-ASCII password", "rsa", @fast, @pwu, [:libressl, :keytool]},
    {"empty password", "rsa", @fast, "", []},
    {"friendly name", "rsa", [friendly_name: "interop"] ++ @fast, @pw, []},
    # Java takes certificates without a key only with an attribute of its own.
    {"certificates only", :certificates, @fast, @pw, [:keytool]}
  ]

  for reader <- Interop.readers() do
    tool = Interop.find(reader)

    describe "#{reader}" do
      cond do
        tool ->
          for {name, material, opts, password, excluded} <- @variants,
              reader not in excluded,
              opts[:mac] != :pbmac1 or Interop.pbmac1?(elem(tool, 1)) do
            test name, %{tmp_dir: dir} do
              check(
                unquote(reader),
                unquote(Macro.escape(tool)),
                unquote(material),
                unquote(opts),
                unquote(password),
                dir
              )
            end
          end

        Interop.required?(reader) ->
          test "is found" do
            flunk("#{unquote(reader)} was not found; see test/support/interop.ex")
          end

        true ->
          @tag skip: "#{reader} was not found"
          test "is found", do: :ok
      end
    end
  end

  defp check(reader, tool, material, opts, password, dir) do
    {input, key} = input(material)
    file = Path.join(dir, "ours.p12")
    File.write!(file, PKCS12.encode!(input, password, opts))

    result = read(reader, tool, file, password, opts, dir)
    assert result.key == key
    certs = for cert <- [input[:certificate] | input.ca_certificates], cert, do: cert
    assert Enum.sort(result.certs) == Enum.sort(certs)
    if name = opts[:friendly_name], do: assert(name in result.names)
  end

  defp input(:certificates),
    do: {%{ca_certificates: [cert_der("rsa"), cert_der("ca")]}, nil}

  defp input(material) do
    key = key(material)

    input = %{
      private_key: :public_key.der_encode(:PrivateKeyInfo, key),
      certificate: cert_der(material),
      ca_certificates: [cert_der("ca")]
    }

    {input, key}
  end

  ## Readers

  @python_reader """
  import base64, os, sys
  from cryptography.hazmat.primitives import serialization as s
  from cryptography.hazmat.primitives.serialization import pkcs12

  password = os.environb.get(b"PKCS12_PW", b"")
  p12 = pkcs12.load_pkcs12(open(sys.argv[1], "rb").read(), password)
  b64 = lambda data: base64.b64encode(data).decode()
  if p12.key:
      print("key", b64(p12.key.private_bytes(s.Encoding.DER, s.PrivateFormat.PKCS8, s.NoEncryption())))
  for cert in ([p12.cert] if p12.cert else []) + p12.additional_certs:
      print("cert", b64(cert.certificate.public_bytes(s.Encoding.DER)))
      if cert.friendly_name:
          print("name", b64(cert.friendly_name))
  """

  defp read(:python, {python, _}, file, password, _opts, _dir) do
    out = run!(python, ["-I", "-c", @python_reader, file], password)

    lines =
      for line <- String.split(out, "\n", trim: true),
          [kind, value] <- [String.split(line, " ")],
          kind in ~w(key cert name),
          do: {kind, Base.decode64!(value)}

    %{
      key:
        Enum.find_value(lines, fn
          {"key", der} -> :public_key.der_decode(:PrivateKeyInfo, der)
          _ -> nil
        end),
      certs: for({"cert", der} <- lines, do: der),
      names: for({"name", name} <- lines, do: name)
    }
  end

  # keytool imports our file into a keystore of its own, which this library
  # then reads: Java has seen the key and the chain.
  defp read(:keytool, {keytool, _}, file, password, _opts, dir) do
    out_file = Path.join(dir, "java.p12")

    source =
      if password == "", do: ["-srcstorepass", ""], else: ["-srcstorepass:env", "PKCS12_PW"]

    args =
      ~w(-importkeystore -noprompt -srcstoretype PKCS12 -deststoretype PKCS12) ++
        ["-srckeystore", file | source] ++
        ["-destkeystore", out_file, "-deststorepass:env", "PKCS12_PW"]

    # keytool wants a destination password of 6 characters at least.
    destination = if password == "", do: @pw, else: password
    run!(keytool, args, destination)
    p12 = PKCS12.decode!(File.read!(out_file), destination)

    %{
      key: p12.private_key && :public_key.der_decode(:PrivateKeyInfo, p12.private_key),
      certs: for(cert <- [p12.certificate | p12.ca_certificates], cert, do: cert),
      names: Enum.map(p12.bags, & &1.friendly_name)
    }
  end

  # The openssl command of OpenSSL 3, OpenSSL 1.1 and LibreSSL.
  defp read(reader, {openssl, _}, file, password, opts, _dir) do
    passin = if password == "", do: "pass:", else: "env:PKCS12_PW"

    args =
      ["pkcs12", "-in", file, "-passin", passin, "-nodes"] ++
        if(opts[:mac] == :none, do: ["-nomacver"], else: []) ++
        if(reader == :openssl and opts[:profile] == :legacy, do: ["-legacy"], else: [])

    out = run!(openssl, args, password)
    entries = :public_key.pem_decode(out)

    %{
      key:
        Enum.find_value(entries, fn
          {:Certificate, _, _} -> nil
          entry -> :public_key.pem_entry_decode(entry)
        end),
      certs: for({:Certificate, der, _} <- entries, do: der),
      names: for([_, name] <- Regex.scan(~r/friendlyName: (.*)/, out), do: String.trim(name))
    }
  end

  # An empty value would unset the variable, so empty passwords go in the
  # arguments instead.
  defp run!(command, args, password) do
    {out, status} =
      System.cmd(command, args, env: [{"PKCS12_PW", password}], stderr_to_stdout: true)

    assert status == 0, "#{Path.basename(command)} #{hd(args)} failed:\n#{out}"
    out
  end
end
