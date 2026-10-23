defmodule PKCS12.IntegrationTest do
  # The result of decode/3 works as is with the rest of OTP.
  use ExUnit.Case, async: true

  import PKCS12.Fixtures

  @pw "test-password"

  test "signs with :public_key, and the certificate verifies it" do
    for file <- ["o3_legacy.p12", "o3_ec.p12", "java_legacy.p12", "rfc9879_a1.p12"] do
      password = if file =~ "rfc9879", do: "1234", else: @pw
      {:ok, p12} = PKCS12.decode(read!(file), password)
      key = :public_key.der_decode(:PrivateKeyInfo, p12.private_key)
      signature = :public_key.sign("message", :sha256, key)

      if p12.certificate do
        assert :public_key.verify("message", :sha256, signature, public_key(p12.certificate)),
               file
      end
    end
  end

  test "PEM for other tools" do
    {:ok, p12} = PKCS12.decode(read!("o3_default.p12"), @pw)
    pem = :public_key.pem_encode([{:PrivateKeyInfo, p12.private_key, :not_encrypted}])
    assert pem =~ "-----BEGIN PRIVATE KEY-----"
    assert [{:PrivateKeyInfo, der, :not_encrypted}] = :public_key.pem_decode(pem)
    assert der == p12.private_key
  end

  test "mTLS with :ssl: a legacy RSA server and an EC client" do
    {:ok, server} = PKCS12.decode(read!("o3_legacy.p12"), @pw)
    {:ok, client} = PKCS12.decode(read!("o3_ec.p12"), @pw)

    common = [
      verify: :verify_peer,
      versions: [:"tlsv1.3", :"tlsv1.2"],
      active: false
    ]

    {:ok, listen} =
      :ssl.listen(
        0,
        [
          certs_keys: [certs_keys(server)],
          cacerts: server.ca_certificates,
          fail_if_no_peer_cert: true
        ] ++ common
      )

    {:ok, {_, port}} = :ssl.sockname(listen)
    parent = self()

    spawn_link(fn ->
      {:ok, socket} = :ssl.transport_accept(listen)
      {:ok, socket} = :ssl.handshake(socket)
      {:ok, peer} = :ssl.peercert(socket)
      send(parent, {:server_saw, peer})
      :ok = :ssl.send(socket, "ok")
      receive do: (:done -> :ok)
    end)

    {:ok, socket} =
      :ssl.connect(
        ~c"localhost",
        port,
        [
          certs_keys: [certs_keys(client)],
          cacerts: client.ca_certificates,
          server_name_indication: :disable
        ] ++ common
      )

    assert {:ok, ~c"ok"} = :ssl.recv(socket, 0, 5_000)
    assert_receive {:server_saw, peer}
    assert peer == client.certificate
    :ssl.close(socket)
    :ssl.close(listen)
  end

  defp certs_keys(p12) do
    %{cert: [p12.certificate | p12.ca_certificates], key: {:PrivateKeyInfo, p12.private_key}}
  end

  defp public_key(cert_der) do
    {:OTPCertificate, tbs, _, _} = :public_key.pkix_decode_cert(cert_der, :otp)

    case elem(tbs, 7) do
      {:OTPSubjectPublicKeyInfo, {_, _, params}, {:ECPoint, _} = point} -> {point, params}
      {:OTPSubjectPublicKeyInfo, _, key} -> key
    end
  end
end
