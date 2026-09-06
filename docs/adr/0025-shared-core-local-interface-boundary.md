# ADR-0025 — Shared Core Local Interface Boundary

**Status:** Accepted — Architecture Authority approved 2026-09-06

## Context

ADR-0006 requires Atlas interfaces to consume one shared offline core rather than reimplement search, pack trust, canonical validation, or rollback semantics independently. ADR-0024 selected Go as the production Shared Core implementation family, but deliberately left the Desktop integration boundary open.

The Windows Desktop MVP must call the Shared Core without coupling the UI stack to Go internals, without exposing a local network service by default, and without creating a fragile cross-language ABI that would be difficult to version safely across Desktop, CLI, and later adapters.

The boundary must preserve the already-accepted Atlas security properties:

- offline operation with no hidden network fallback;
- canonical and deterministic search semantics remain inside the Shared Core;
- pack/TUF verification and durable activation state remain inside the Shared Core;
- no arbitrary command execution;
- bounded typed inputs and fail-closed parsing;
- Desktop UI technology remains replaceable.

## Decision

Atlas will expose the production Shared Core to Desktop-style clients through a **local child-process stdio protocol**, implemented by the `atlas-core` executable.

The v1 transport is:

```text
trusted first-party host process
        |
        | spawn atlas-core --serve-stdio
        v
+------------------------------------+
| stdin:  framed requests            |
| stdout: framed responses only      |
| stderr: diagnostic logs only       |
+------------------------------------+
```

The process does **not** listen on TCP, UDP, Unix sockets, named pipes, HTTP, WebSocket, or another network-capable endpoint by default.

### Framing

Each protocol frame is:

```text
4-byte unsigned big-endian payload length
+
UTF-8 JSON payload bytes
```

The length prefix is not included in the payload length.

Bounds for protocol v1:

- maximum request payload: **1 MiB**;
- maximum response payload: **8 MiB**;
- frames above the relevant bound are rejected before JSON allocation/decoding;
- zero-length frames are invalid;
- truncated frames are fatal to the session;
- invalid UTF-8 is rejected;
- JSON BOMs are rejected;
- trailing non-whitespace bytes after the single JSON value are rejected;
- duplicate JSON object member names are rejected;
- envelope unknown fields are rejected;
- protocol JSON nesting depth is bounded to **32**.

The payload bounds are interface bounds, not permission to weaken lower-level query/filter/graph/archive limits. Existing lower limits remain authoritative.

### Session handshake

The first request in every new process session must be a handshake. No operational method is accepted before it.

Client request:

```json
{
  "id": "1",
  "method": "core.handshake",
  "params": {
    "protocol": "atlas-core",
    "version": "1.0.0",
    "client_name": "atlas-desktop",
    "client_version": "0.1.0",
    "session_nonce": "<opaque client-generated value>"
  }
}
```

The successful response echoes the protocol/version/session nonce and reports the core build/version plus declared capabilities.

Protocol v1 requires an exact supported protocol version. Unsupported versions fail closed; there is no silent downgrade.

The nonce is a session-correlation value, not an authentication credential. Trust derives from the parent/child process relationship and inherited anonymous pipes.

### Request/response envelope

After the handshake, requests use:

```json
{
  "id": "opaque-request-id",
  "method": "allowlisted.method",
  "params": {}
}
```

Responses use exactly one of:

```json
{
  "id": "opaque-request-id",
  "ok": true,
  "result": {}
}
```

or:

```json
{
  "id": "opaque-request-id",
  "ok": false,
  "error": {
    "code": "ATLAS_STABLE_ERROR_CODE",
    "message": "bounded non-sensitive diagnostic",
    "retryable": false
  }
}
```

Request IDs are opaque strings with a maximum length of 128 Unicode scalar values. They are correlation identifiers only and must never be interpreted as commands, paths, SQL, FTS syntax, or canonical identifiers.

Protocol v1 processes **one request at a time per child process**. A second request is not read for dispatch until the previous request has produced its terminal response. This intentionally keeps v1 deterministic and reduces concurrency/state complexity. A future multiplexed protocol requires a new compatible protocol revision and evidence.

### Method surface

Only explicitly compiled and versioned methods may be dispatched. User-controlled strings cannot dynamically name Go functions, subprocesses, SQL fragments, filesystem operations, or plugins.

The initial method families are:

- `core.handshake`
- `core.status`
- `search.query`
- `record.get`
- `catalog.list`
- `graph.expand`
- `pack.status`

Pack mutation methods such as installation or activation are **not implicitly enabled by the generic dispatcher**. They may be added only as explicit typed methods after the production pack/state port proves the same Phase 5.5.1/5.5.2 security envelope. Any filesystem path accepted by a future pack-management method must be constrained to a core-owned or explicitly configured import root and canonicalized before use.

### Parser and method-contract rules

- The envelope and every method parameter object are typed contracts.
- Unknown required state fails closed.
- No method accepts an arbitrary backend query language or shell command.
- `search.query` still enforces the accepted 512-Unicode-scalar and 32-term limits and never exposes raw input directly to SQLite FTS syntax.
- `graph.expand` keeps the accepted bounded graph-depth contract.
- response record bodies remain canonical/read-model data; the protocol does not create a new canonical record family.
- internal errors must not leak secrets, raw stack traces, environment contents, signing material, or arbitrary filesystem paths to the client.

### Process and logging rules

- `stdout` is protocol-only after startup; human logs must never be written there.
- diagnostics go to `stderr` using bounded structured/plain logging.
- secrets must not be passed through command-line arguments.
- the Desktop host should launch the child with a minimal inherited environment.
- child termination or malformed/fatal protocol input cannot leave a partially committed pack activation; accepted durable-state/atomic-replacement semantics remain authoritative.
- the client may restart the child after process failure; state recovery occurs inside the Shared Core, not in the UI.

## Why a local stdio process boundary

A child-process boundary provides stronger isolation and versioning than embedding a foreign-language ABI while avoiding the attack surface and deployment complexity of an always-listening local HTTP/TCP service.

It also keeps the Desktop stack open: Tauri, Electron, .NET, native Windows, React, or another UI may all spawn the same executable and consume the same versioned protocol.

The boundary is reusable for test harnesses and later adapters without making the IPC protocol the public remote API.

## Alternatives considered

### Direct Go FFI / C ABI

Rejected for the v1 Desktop boundary. It couples process lifetime, memory ownership, crash behavior, toolchains, ABI compatibility, and language bindings. It can be revisited only if executable evidence demonstrates a material advantage that outweighs those risks.

### Local HTTP/TCP service

Rejected as the default. It introduces a listening socket, port ownership, local-origin/authentication questions, firewall/endpoint interactions, and an unnecessary network-shaped attack surface for the offline Desktop use case.

### NDJSON / newline-delimited JSON

Not selected for v1 framing. Length-prefixed JSON makes payload boundaries independent of newline representation, supports bounded allocation before decode, and avoids accidental protocol/log interleaving semantics.

### Protobuf/gRPC

Deferred. It provides strong schemas but adds code-generation/runtime/tooling complexity before the local interface surface is mature. A future version may adopt it only through a compatibility ADR and migration evidence.

## Consequences

Positive:

- UI implementation remains independent from Go internals;
- no default listening network endpoint;
- deterministic bounded framing and strict parser behavior;
- Shared Core remains the single implementation of security/search/pack semantics;
- child crash is isolated from the UI process;
- the same executable boundary can be tested on Linux and Windows.

Costs:

- process startup and serialization overhead exist;
- protocol schemas and compatibility become release artifacts that require tests;
- large responses must remain bounded and may require pagination rather than increasing frame limits;
- Desktop packaging must include and locate the `atlas-core` executable safely.

## Compatibility and versioning

`atlas-core` protocol versioning is independent from Go package/module versions and canonical schema versions.

For v1:

- protocol identifier: `atlas-core`;
- protocol version: `1.0.0`;
- unsupported versions fail closed;
- field/method semantic changes that break an existing client require a protocol major-version change;
- additive changes require explicit compatibility tests and capability negotiation rather than silent assumptions.

## Security invariants

The protocol must never:

- permit arbitrary command/process execution;
- expose raw SQLite/FTS/backend query syntax;
- accept unbounded frames or recursive data;
- enable network access as a hidden fallback;
- bypass TUF/pack verification or durable activation rules;
- treat client-provided data as canonical truth;
- load executable code from Atlas content packs;
- send signing/private-key material across the interface.

## Revisit triggers

Reopen this ADR if:

- the Desktop spike proves child-process startup/packaging materially infeasible;
- required high-throughput workloads cannot meet product targets with bounded process IPC;
- a future public local API needs multi-client authentication/authorization rather than parent-child trust;
- multiplexing becomes necessary and cannot be added compatibly;
- sandboxing requirements demand a different OS-native transport;
- a demonstrated FFI or schema protocol materially improves security/operability without coupling the UI stack.

## Architecture Authority acceptance

Accepted by Architecture Authority on 2026-09-06 under the standing project authorization. The Phase 5.5.4 production implementation must implement and test this boundary before Windows Desktop work consumes the Shared Core.
