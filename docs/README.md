# Setup

This demo runs two separate TLS servers:

- Old server (OpenSSL, C++98)
- New server (Botan, C++20)

Both servers require:

1. mTLS (client certificate signed by your CA)
2. Username/password authentication (HTTP Basic or `X-Auth-User` / `X-Auth-Pass`)

## Build

## Prereqs

Ubuntu 22.04:

```bash
sudo apt update
sudo apt install -y build-essential cmake pkg-config libsqlite3-dev libssl-dev ninja-build
```

Botan 3 is built from source on Linux using the vendored source in `thirdparty/botan-3.10.0/`.
The top-level build will automatically build and install Botan into `build/botan-install`.
The first Linux build will take longer because Botan is compiled from source.

Ninja is recommended for faster builds and progress counts.

macOS (Homebrew):

```bash
brew install cmake botan openssl@3 pkg-config
```

If CMake cannot find OpenSSL on macOS:

```bash
cmake -S . -B build -DOPENSSL_ROOT_DIR="$(brew --prefix openssl@3)"
```

Optional (faster builds with progress counts):

```bash
brew install ninja
```

## Build

```bash
cmake -S . -B build -G Ninja
cmake --build build
```

If you prefer Makefiles:

```bash
cmake -S . -B build
cmake --build build
```

## Generate Certificates

Use the provided script to generate three independent cert sets:

```bash
./scripts/01_build_certs.sh
```

This creates:

- `example/certs/server1` (OpenSSL)
- `example/certs/server2` (Botan)
- `example/certs/internal` (inter-server mTLS)

Key formats:

- `server1` keys are PKCS#1 (`BEGIN RSA PRIVATE KEY`) for OpenSSL compatibility.
- `server2` and `internal` keys are PKCS#8 (`BEGIN PRIVATE KEY`) for Botan.

## Run

CLI args for both servers:

```
<port> <server_cert> <server_key> <local_ca_cert> <user_file> <db_path> <remote_host> <remote_port> <remote_ca_cert> <remote_client_cert> <remote_client_key> <remote_server_ca>
```

Defaults are baked in; you can run with just the port or pass all args explicitly.
The server trusts both the local CA and the internal CA so it can accept user mTLS
and inter-server mTLS. The sync client uses `remote_server_ca` to validate the
peer server certificate.

Start both servers (using the config files in `example/`):

```bash
./scripts/03_start_newserver.sh
./scripts/02_start_oldserver.sh
```

The example configs include:

- `REMOTE_CA` (internal CA for mTLS client certs)
- `REMOTE_SERVER_CA` (peer server CA for sync client verification)

## Test

Quick tests:

```bash
curl --cacert example/certs/server1/ca.crt \
  --cert example/certs/server1/client.crt --key example/certs/server1/client.key \
  -u demo:demo https://localhost:8444/oldapi/getuser

curl --cacert example/certs/server1/ca.crt \
  --cert example/certs/server1/client.crt --key example/certs/server1/client.key \
  -u demo:demo https://localhost:8444/

curl --cacert example/certs/server2/ca.crt \
  --cert example/certs/server2/client.crt --key example/certs/server2/client.key \
  -u demo:demo https://localhost:8443/newapi/getuser

curl --cacert example/certs/server2/ca.crt \
  --cert example/certs/server2/client.crt --key example/certs/server2/client.key \
  -u demo:demo https://localhost:8443/
```

Cross-server (tunneling via the local server):

```bash
curl --cacert example/certs/server1/ca.crt \
  --cert example/certs/server1/client.crt --key example/certs/server1/client.key \
  -u demo:demo https://localhost:8444/newapi/getuser

curl --cacert example/certs/server2/ca.crt \
  --cert example/certs/server2/client.crt --key example/certs/server2/client.key \
  -u demo:demo https://localhost:8443/oldapi/getuser
```

## API Examples

Old server (`/oldapi/*`):

```bash
curl --cacert example/certs/server1/ca.crt \
  --cert example/certs/server1/client.crt --key example/certs/server1/client.key \
  -u demo:demo \
  -H "Content-Type: application/json" \
  -d '{"nickname":"alice","age":30}' \
  https://localhost:8444/oldapi/setuser

curl --cacert example/certs/server1/ca.crt \
  --cert example/certs/server1/client.crt --key example/certs/server1/client.key \
  -u demo:demo \
  -H "Content-Type: application/json" \
  -d '{"assets":"100","colour":"blue"}' \
  https://localhost:8444/oldapi/setdata

curl --cacert example/certs/server1/ca.crt \
  --cert example/certs/server1/client.crt --key example/certs/server1/client.key \
  -u demo:demo https://localhost:8444/oldapi/getuser
```

New server (`/newapi/*`):

```bash
curl --cacert example/certs/server2/ca.crt \
  --cert example/certs/server2/client.crt --key example/certs/server2/client.key \
  -u demo:demo \
  -H "Content-Type: application/json" \
  -d '{"nickname":"alice","age":30}' \
  https://localhost:8443/newapi/setuser

curl --cacert example/certs/server2/ca.crt \
  --cert example/certs/server2/client.crt --key example/certs/server2/client.key \
  -u demo:demo \
  -H "Content-Type: application/json" \
  -d '{"portfolio":"100","flavour":"vanilla"}' \
  https://localhost:8443/newapi/setdata

curl --cacert example/certs/server2/ca.crt \
  --cert example/certs/server2/client.crt --key example/certs/server2/client.key \
  -u demo:demo https://localhost:8443/newapi/getuser
```

If the remote server is down or the user does not exist on the remote, the response is:

```
remote server not running
```
