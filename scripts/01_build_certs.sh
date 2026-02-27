#!/usr/bin/env bash
set -euo pipefail

export SRCDIR=$(dirname $(cd ${0%/*} 2>>/dev/null ; echo `pwd`/${0##*/}))
ROOT_DIR="${SRCDIR}/.."
CERT_DIR="$ROOT_DIR/example/certs"

mkdir -p "$CERT_DIR"

generate_set() {
  local name="$1"
  local ca_cn="$2"
  local server_cn="$3"
  local server_san="$4"
  local client_cn="$5"
  local server_key_type="${6:-ec}"
  local server_key_pkcs8="${7:-yes}"
  local dir="$CERT_DIR/$name"

  mkdir -p "$dir"

  rm -f \
    "$dir/ca.key" \
    "$dir/ca.crt" \
    "$dir/ca.srl" \
    "$dir/server.key" \
    "$dir/server.csr" \
    "$dir/server.crt" \
    "$dir/client.key" \
    "$dir/client.csr" \
    "$dir/client.crt"

  # CA
  openssl genrsa -out "$dir/ca.key" 2048
  openssl req -x509 -new -nodes -key "$dir/ca.key" -sha256 -days 365 \
    -subj "/CN=$ca_cn" -out "$dir/ca.crt"

  # Server cert
  if [ "$server_key_type" = "rsa" ]; then
    openssl genrsa -out "$dir/server.key" 2048
  else
    openssl ecparam -name prime256v1 -genkey -noout -out "$dir/server.key"
  fi
  if [ "$server_key_pkcs8" = "yes" ]; then
    # Convert to PKCS#8 for Botan compatibility
    openssl pkcs8 -topk8 -nocrypt -in "$dir/server.key" -out "$dir/server.key.tmp"
    mv "$dir/server.key.tmp" "$dir/server.key"
  else
    # Ensure traditional PKCS#1 format for OpenSSL compatibility.
    openssl rsa -in "$dir/server.key" -traditional -out "$dir/server.key.tmp" 2>/dev/null
    mv "$dir/server.key.tmp" "$dir/server.key"
  fi
  openssl req -new -key "$dir/server.key" -subj "/CN=$server_cn" -out "$dir/server.csr"
  local extfile
  extfile=$(mktemp)
  {
    printf "subjectAltName=%s\n" "$server_san"
    printf "basicConstraints=CA:FALSE\n"
    printf "keyUsage=digitalSignature,keyEncipherment\n"
    printf "extendedKeyUsage=serverAuth\n"
  } > "$extfile"
  openssl x509 -req -in "$dir/server.csr" -CA "$dir/ca.crt" -CAkey "$dir/ca.key" \
    -CAcreateserial -out "$dir/server.crt" -days 365 -sha256 -extfile "$extfile"
  rm -f "$extfile"

  # Client cert (RSA for broader mTLS compatibility)
  openssl genrsa -out "$dir/client.key" 2048
  # Convert to PKCS#8 for Botan compatibility
  openssl pkcs8 -topk8 -nocrypt -in "$dir/client.key" -out "$dir/client.key.tmp"
  mv "$dir/client.key.tmp" "$dir/client.key"
  openssl req -new -key "$dir/client.key" -subj "/CN=$client_cn" -out "$dir/client.csr"
  extfile=$(mktemp)
  {
    printf "basicConstraints=CA:FALSE\n"
    printf "keyUsage=digitalSignature\n"
    printf "extendedKeyUsage=clientAuth\n"
  } > "$extfile"
  openssl x509 -req -in "$dir/client.csr" -CA "$dir/ca.crt" -CAkey "$dir/ca.key" \
    -CAcreateserial -out "$dir/client.crt" -days 365 -sha256 -extfile "$extfile"
  rm -f "$extfile"
}

generate_set "server1" "Server1 CA" "localhost" "DNS:localhost,IP:127.0.0.1,DNS:server1.local" "server1-client" "rsa" "no"
generate_set "server2" "Server2 CA" "localhost" "DNS:localhost,IP:127.0.0.1,DNS:server2.local" "server2-client" "rsa" "yes"
generate_set "internal" "Internal CA" "internal.local" "DNS:internal.local" "internal-client" "rsa" "yes"

echo "Certificates written to:"
echo "  $CERT_DIR/server1"
echo "  $CERT_DIR/server2"
echo "  $CERT_DIR/internal"
