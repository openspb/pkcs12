defmodule PKCS12.Interop do
  @moduledoc false
  # The readers of the interop tests, found on this system:
  #
  #   PKCS12_OPENSSL    an OpenSSL binary, 3.0 or later
  #   PKCS12_OPENSSL11  an OpenSSL 1.1.1 binary
  #   PKCS12_LIBRESSL   a LibreSSL binary (the openssl of macOS)
  #   PKCS12_PYTHON     a Python 3 with the "cryptography" package
  #   PKCS12_KEYTOOL    the keytool of a JDK
  #
  # Without the variable, a few usual places are tried. A reader that is not
  # found is skipped, unless PKCS12_REQUIRE_INTEROP names it, as in
  # "openssl,python", or is "all": then its tests fail.

  @readers [:openssl, :openssl11, :libressl, :python, :keytool]

  @python_probe """
  import cryptography
  from cryptography.hazmat.primitives.serialization import pkcs12
  from cryptography.hazmat.backends.openssl.backend import backend
  print("cryptography", cryptography.__version__, "with", backend.openssl_version_text())
  """

  def readers, do: @readers

  @doc "`{path, version text}` of a reader, or `nil`."
  def find(:openssl),
    do:
      openssl(
        "PKCS12_OPENSSL",
        ["/opt/homebrew/opt/openssl@3/bin/openssl", "openssl"],
        ~r/^OpenSSL [3-9]\./
      )

  def find(:openssl11),
    do:
      openssl(
        "PKCS12_OPENSSL11",
        ["/opt/homebrew/opt/openssl@1.1/bin/openssl", "openssl"],
        ~r/^OpenSSL 1\.1\./
      )

  def find(:libressl),
    do: openssl("PKCS12_LIBRESSL", ["/usr/bin/openssl", "openssl"], ~r/^LibreSSL /)

  def find(:python) do
    first_found("PKCS12_PYTHON", ["python3"], fn path ->
      case System.cmd(path, ["-I", "-c", @python_probe], stderr_to_stdout: true) do
        {version, 0} -> String.trim(version)
        _ -> nil
      end
    end)
  end

  def find(:keytool) do
    java_home = System.get_env("JAVA_HOME")
    candidates = ["/opt/homebrew/opt/openjdk/bin/keytool", "keytool"]

    candidates =
      if java_home, do: [Path.join([java_home, "bin", "keytool"]) | candidates], else: candidates

    first_found("PKCS12_KEYTOOL", candidates, fn path ->
      case System.cmd(path, ["-version"], stderr_to_stdout: true) do
        {"keytool " <> _ = version, 0} -> String.trim(version)
        _ -> nil
      end
    end)
  end

  def required?(reader) do
    names = System.get_env("PKCS12_REQUIRE_INTEROP", "") |> String.split(",", trim: true)
    "all" in names or Atom.to_string(reader) in names
  end

  @doc "Whether the OpenSSL in a version text reads PBMAC1, which came in 3.4."
  def pbmac1?(version) do
    case Regex.run(~r/OpenSSL (\d+)\.(\d+)/, version) do
      [_, major, minor] -> {String.to_integer(major), String.to_integer(minor)} >= {3, 4}
      nil -> false
    end
  end

  defp openssl(variable, candidates, pattern) do
    first_found(variable, candidates, fn path ->
      with {version, 0} <- System.cmd(path, ["version"], stderr_to_stdout: true),
           true <- version =~ pattern do
        String.trim(version)
      else
        _ -> nil
      end
    end)
  end

  # With the variable set, only its value is tried.
  defp first_found(variable, candidates, probe) do
    candidates =
      case System.get_env(variable) do
        nil -> candidates
        path -> [path]
      end

    Enum.find_value(candidates, fn candidate ->
      with path when is_binary(path) <- System.find_executable(candidate),
           version when is_binary(version) <- probe.(path) do
        {path, version}
      end
    end)
  end
end
