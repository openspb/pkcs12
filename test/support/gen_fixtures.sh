#!/usr/bin/env bash
# Generates the test material in test/fixtures: a CA, two leaf certificates
# (RSA and EC) and PKCS#12 files written by several generators. Nothing comes
# from elsewhere, except the RFC 9879 vectors (see extract_rfc9879.exs).
#
# The generated files are versioned, because the generators (OpenSSL 1.1,
# LibreSSL, ...) are not all available in CI. Run again only to change the
# set; every key changes with it.
#
# Tools, all overridable:
#   O3       OpenSSL 3.x
#   O11      OpenSSL 1.1.1
#   LRE      LibreSSL (the openssl of macOS)
#   PY       Python 3 with the "cryptography" package
#   KEYTOOL  keytool of a JDK, 17 or later
set -euo pipefail

O3=${O3:-/opt/homebrew/opt/openssl@3/bin/openssl}
O11=${O11:-/opt/homebrew/opt/openssl@1.1/bin/openssl}
LRE=${LRE:-/usr/bin/openssl}
PY=${PY:-python3}
KEYTOOL=${KEYTOOL:-/opt/homebrew/opt/openjdk/bin/keytool}

cd "$(dirname "$0")/../fixtures"
rm -f ./o3_*.p12 ./o11_*.p12 ./lre_*.p12 ./py_*.p12 ./java_*.p12 ./*.key ./*.crt INFO.txt

export PW='test-password'
export PWU='Senha-ção'
export PWE=''

# A CA and two leaves (RSA and EC) signed by it.
$O3 req -x509 -newkey rsa:2048 -noenc -keyout ca.key -out ca.crt -days 7300 \
  -subj "/CN=PKCS12 Test CA" \
  -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign 2>/dev/null
for k in rsa ec; do
  if [ $k = rsa ]; then alg=(-newkey rsa:2048); else alg=(-newkey ec -pkeyopt ec_paramgen_curve:P-256); fi
  $O3 req "${alg[@]}" -noenc -keyout $k.key -out $k.csr -subj "/CN=PKCS12 Test $k" 2>/dev/null
  $O3 x509 -req -in $k.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out $k.crt -days 7300 2>/dev/null
done
# The CA key is only needed to sign the leaves.
rm -f ./*.csr ./*.srl ca.key

o3() { local out=$1; shift; $O3 pkcs12 -export -in rsa.crt -inkey rsa.key -certfile ca.crt -out "$out.p12" "$@"; }

# OpenSSL 3
o3 o3_default -passout env:PW
o3 o3_legacy -passout env:PW -legacy
o3 o3_3des -passout env:PW -keypbe PBE-SHA1-3DES -certpbe PBE-SHA1-3DES -macalg sha1
o3 o3_pbmac1 -passout env:PW -pbmac1_pbkdf2
o3 o3_pbmac1_sha512 -passout env:PW -pbmac1_pbkdf2 -pbmac1_pbkdf2_md sha512 -macalg sha512
o3 o3_nomac -passout env:PW -nomac
o3 o3_noenc -passout env:PW -keypbe NONE -certpbe NONE
o3 o3_noenc_nomac -passout env:PW -keypbe NONE -certpbe NONE -nomac
o3 o3_aes128_sha512 -passout env:PW -keypbe AES-128-CBC -certpbe AES-128-CBC -macalg sha512
o3 o3_aes192_sha384 -passout env:PW -keypbe AES-192-CBC -certpbe AES-192-CBC -macalg sha384
o3 o3_pbes2_3des -passout env:PW -keypbe DES-EDE3-CBC -certpbe DES-EDE3-CBC
o3 o3_rc2_128 -passout env:PW -legacy -keypbe PBE-SHA1-2DES -certpbe PBE-SHA1-RC2-128
o3 o3_rc4 -passout env:PW -legacy -keypbe PBE-SHA1-RC4-128 -certpbe PBE-SHA1-RC4-40
o3 o3_iter100k -passout env:PW -iter 100000
o3 o3_noiter -passout env:PW -legacy -noiter -nomaciter
o3 o3_utf8 -passout env:PWU
o3 o3_utf8_legacy -passout env:PWU -legacy
o3 o3_empty -passout env:PWE
o3 o3_empty_legacy -passout env:PWE -legacy
o3 o3_names -passout env:PW -name 'Chave de teste ção' -caname 'AC de teste'
o3 o3_bigiter -passout env:PW -iter 3000000
o3 o3_legacy_100k -passout env:PW -legacy -iter 100000
$O3 pkcs12 -export -in ec.crt -inkey ec.key -certfile ca.crt -out o3_ec.p12 -passout env:PW
$O3 pkcs12 -export -in ec.crt -inkey ec.key -certfile ca.crt -out o3_ec_legacy.p12 -passout env:PW -legacy
$O3 pkcs12 -export -nokeys -in rsa.crt -certfile ca.crt -out o3_certs_only.p12 -passout env:PW

# OpenSSL 1.1.1
o11() { local out=$1; shift; $O11 pkcs12 -export -in rsa.crt -inkey rsa.key -certfile ca.crt -out "$out.p12" "$@"; }
o11 o11_default -passout env:PW
o11 o11_utf8 -passout env:PWU
o11 o11_empty -passout env:PWE
o11 o11_aes -passout env:PW -keypbe AES-256-CBC -certpbe AES-256-CBC -macalg sha256

# LibreSSL
lre() { local out=$1; shift; $LRE pkcs12 -export -in rsa.crt -inkey rsa.key -certfile ca.crt -out "$out.p12" "$@"; }
lre lre_default -passout env:PW
lre lre_utf8 -passout env:PWU
lre lre_empty -passout env:PWE

# Python cryptography
$PY - <<'PYEOF'
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs12

key = serialization.load_pem_private_key(open("rsa.key", "rb").read(), None)
cert = x509.load_pem_x509_certificate(open("rsa.crt", "rb").read())
ca = x509.load_pem_x509_certificate(open("ca.crt", "rb").read())
pw = b"test-password"
fmt = serialization.PrivateFormat.PKCS12

cases = {
    "py_best": serialization.BestAvailableEncryption(pw),
    "py_3des_sha1": fmt.encryption_builder().kdf_rounds(2000)
        .key_cert_algorithm(pkcs12.PBES.PBESv1SHA1And3KeyTripleDESCBC)
        .hmac_hash(hashes.SHA1()).build(pw),
    "py_aes_sha256": fmt.encryption_builder().kdf_rounds(10000)
        .key_cert_algorithm(pkcs12.PBES.PBESv2SHA256AndAES256CBC)
        .hmac_hash(hashes.SHA256()).build(pw),
    "py_noenc": serialization.NoEncryption(),
    "py_utf8": serialization.BestAvailableEncryption("Senha-ção".encode()),
}
for name, enc in cases.items():
    data = pkcs12.serialize_key_and_certificates(b"py", key, cert, [ca], enc)
    open(name + ".p12", "wb").write(data)
PYEOF

# Java keytool, which re-encrypts what it imports with its own algorithms.
# The legacy mode is the format of Java 8 and earlier. keytool refuses
# non-ASCII passwords for PKCS#12, so there is no such case here.
kt() { $KEYTOOL "$@" 2>/dev/null >/dev/null; }
import() {
  local src=$1 dest=$2 alias=$3; shift 3
  kt -importkeystore -noprompt -srckeystore "$src" -srcstoretype PKCS12 -srcstorepass:env PW \
    -srcalias 1 -destalias "$alias" -destkeystore "$dest" -deststoretype PKCS12 \
    -deststorepass:env PW "$@"
}
import o3_default.p12 java_default.p12 rsa
import o3_default.p12 java_legacy.p12 rsa -J-Dkeystore.pkcs12.legacy
import o3_default.p12 java_two_keys.p12 rsa
import o3_ec.p12 java_two_keys.p12 ec
kt -importcert -noprompt -alias ca -file ca.crt -keystore java_truststore.p12 -storetype PKCS12 \
  -storepass:env PW -J-Dkeystore.pkcs12.certProtectionAlgorithm=NONE -J-Dkeystore.pkcs12.macAlgorithm=NONE
kt -genseckey -alias aes -keyalg AES -keysize 128 -keystore java_secret.p12 -storetype PKCS12 -storepass:env PW

# What each file uses, as OpenSSL reports it.
for f in ./*.p12; do
  case $f in
    *utf8*) pass=env:PWU ;;
    *empty*) pass=env:PWE ;;
    *rfc9879*) continue ;;
    *) pass=env:PW ;;
  esac
  echo "== $f"
  $O3 pkcs12 -in "$f" -passin "$pass" -info -noout -legacy 2>&1 |
    grep -v -E '^(Bag Attributes|    |subject|issuer|-----|[A-Za-z0-9+/=]{20,}$)' || true
done > INFO.txt 2>&1

ls -1 ./*.p12 | wc -l
