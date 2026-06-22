# bridge-monitor

A [Proton Mail Bridge](https://proton.me/mail/bridge) sidecar that runs alongside
the bridge in the `proton-bridge` Kubernetes Deployment. It talks **directly to
the bridge's gRPC API** (the same API the desktop GUI uses) to:

- export Prometheus metrics about account state, and
- serve a small web form to re-authenticate the account from any browser
  (phone included) without `kubectl exec` or the interactive `--cli` flow.

It replaces the old "kill the bridge process and drive `protonmail-bridge --cli`
with pexpect" approach: nothing is killed, no supervisor coordination
(`/tmp/.bridge-reauth`) is involved — it drives the live bridge over gRPC.

> Deployment manifests, the `gateway-private` HTTPRoute, DNS and network policy
> live in the **homelab** repo, not here. This repo only produces the image
> (`ghcr.io/sometimeskind/bridge-monitor`). Context: homelab issues #935 / this
> repo's #1.

## Usage

`bridge-monitor` is a single long-running process: metrics on `:9100` and the
re-auth web UI on `:8080`. Run `bridge-monitor -h` for flags. All paths and
ports default to the homelab layout and are overridable:

| Flag | Default |
|------|---------|
| `--grpc-config` | `$XDG_CONFIG_HOME/protonmail/bridge-v3/grpcServerConfig.json` |
| `--email-file` | `/secrets/bridge-login-credentials/email` |
| `--imap-password-file` | `/secrets/bridge-imap-password/password` |
| `--metrics-addr` | `:9100` |
| `--web-addr` | `:8080` |
| `--poll-interval` | `30s` |

**No login credentials are stored in the cluster.** The operator supplies the
password and the 2FA code in the form — both autofilled by 1Password (the 2FA
field uses `autocomplete="one-time-code"`). Only the email (pre-filled hint) and
the sealed IMAP password (for change detection) are mounted.

## Metrics

| Metric | Meaning |
|--------|---------|
| `bridge_account_state{user,email}` | 0 = SIGNED_OUT, 1 = LOCKED, 2 = CONNECTED |
| `bridge_account_connected` | 1 if any user is CONNECTED |
| `bridge_grpc_up` | 1 if the last `GetUserList` poll succeeded |

## IMAP password changes

After a successful re-auth the new IMAP password is compared against the sealed
`bridge-imap-password`. If it changed, the UI surfaces the new value with a
note to **re-seal it manually in the homelab repo** (`kubeseal`). There is no
auto-PR.

## How re-auth works (gRPC)

1. `GetUserList` → if the account is logged in, `LogoutUser` (keeps the local
   cache; `Login` then reconnects without a resync).
2. Subscribe to `RunEventStream` **before** `Login` (so the 2FA prompt isn't
   missed).
3. `Login(username, base64(password))`. The bytes password field carries the
   **std-base64** encoding of the secret — the bridge base64-decodes it.
4. On the `tfaRequested` event → `Login2FA(username, base64(TOTP))`.
5. On `finished` / `alreadyLoggedIn` → read the user's IMAP password.

Connection: gRPC over **TLS over the bridge's unix socket**. The socket path,
self-signed cert, and `server-token` come from `grpcServerConfig.json`, which the
bridge regenerates on every restart — so we read it fresh and connect per
operation. TLS uses `ServerName: 127.0.0.1` (the cert's CN/SAN); the token is
sent as `server-token` metadata on every call.

## Development

Requires Go (see `go.mod`). Regenerate gRPC stubs after editing `proto/`:

```sh
go install github.com/bufbuild/buf/cmd/buf@latest
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
buf generate
```

Test (no real bridge needed — the login/connection tests run against an
in-process fake bridge gRPC server over a real TLS unix socket):

```sh
go test ./...
```

The bridge gRPC behaviour here (the `server-token` metadata key, the
base64-encoded password field, the `ServerName: 127.0.0.1` cert, the
event-driven login flow) was reverse-engineered from
[`ProtonMail/proton-bridge`](https://github.com/ProtonMail/proton-bridge)
`@ master` (`internal/frontend/grpc`). It can drift if the bridge changes; see
`proto/NOTICE.md`.

## License

[GPL-3.0](LICENSE). This project vendors `bridge.proto` and generates Go stubs
from [`ProtonMail/proton-bridge`](https://github.com/ProtonMail/proton-bridge),
which is GPLv3; this repository matches that license. See `proto/NOTICE.md`.
