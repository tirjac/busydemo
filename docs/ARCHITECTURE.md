# Architecture

This project is intentionally split into small, readable modules so it can be used as a learning reference.

## High-Level Structure

Two independent servers run on different ports:

- **Old server** (`oldserver`): OpenSSL-based, C++98.
- **New server** (`newserver`): Botan-based, C++20.

Each server has its **own local SQLite database** and **never writes directly** to the other server’s DB. Cross-server synchronization happens **only via HTTP API calls**.

## Module Map

### Old server (OpenSSL, C++98)

- `src/oldserver/oldserver.cpp`
  - Network accept loop, HTTP parsing, auth, routing.
  - Calls local DB and sync functions.

- `src/oldserver/oldserver_db.{h,cpp}`
  - SQLite database access for the old server.
  - Table: `olddata` (id, nickname, age, assets, colour).

- `src/oldserver/oldserver_sync.{h,cpp}`
  - OpenSSL-based HTTPS client used to call the new server.
  - Used for `/api/v2/*` proxying and sync of shared fields.

### New server (Botan, C++20)

- `src/newserver/newserver.cpp`
  - Network accept loop, HTTP parsing, auth, routing.
  - Calls local DB and sync functions.

- `src/newserver/newserver_db.{h,cpp}`
  - SQLite database access for the new server.
  - Table: `newdata` (id, nickname, age, portfolio, flavour).

- `src/newserver/newserver_sync.{h,cpp}`
  - Botan-based HTTPS client used to call the old server.
  - Used for `/api/v1/*` proxying and sync of shared fields.

- `src/newserver/newserver_tls.{h,cpp}`
  - Botan TLS helpers (policy, credentials, callbacks).

## Data Rules

- **`id`** is the authenticated username (primary key).
- **`nickname`** is local-only.
- **`age`** is synchronized to both servers.
- **`assets`** on old server syncs to **`portfolio`** on new server.
- **`colour`** exists only on old server.
- **`flavour`** exists only on new server.

## API Behavior

- `oldserver` owns `/oldapi/*` endpoints locally.
- `newserver` owns `/newapi/*` endpoints locally.
- Each server proxies the *other* API namespace via HTTPS when requested.
- All sync happens via API calls only, never through shared DB access.

## Learning Goals

- Show a minimal TLS server in two different stacks.
- Demonstrate mTLS + Basic auth with a simple user file.
- Keep HTTP parsing minimal but readable.
- Separate IO (TLS), DB, and sync logic into small modules.
