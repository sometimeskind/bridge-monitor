# IMAP login health probe — design

Issue: [#3](https://github.com/sometimeskind/bridge-monitor/issues/3) — reauth reports
false success; metrics blind to de-authed (`Code=10013`) session.

## Problem

`bridge-monitor` infers session health purely from gRPC RPC results
(`GetUserList` state, the login event stream). When the Bridge↔Proton refresh
token is invalidated, the bridge daemon does not transition the user out of
`CONNECTED` locally, so:

- `bridge_account_connected` stays `1` while mail is fully down.
- Reauth declares `reauth succeeded` as soon as the login event stream emits
  `finished`/`alreadyLoggedIn` — which only confirms the password/2FA were
  accepted, not that the session actually works afterward.

The only signal that distinguishes the dead state is an authenticated IMAP
`LOGIN` against the bridge's local listener (it returns `no such user` when
de-authed). This design adds that probe as the source of truth for both the
periodic health metric and reauth's success criterion.

## Components

### `internal/bridge/imap.go` (new)

```go
func (c *Client) MailServerSettings(ctx context.Context) (port int, useSSL bool, err error)
func ProbeIMAPLogin(ctx context.Context, port int, useSSL bool, username string, password []byte) error
```

- `MailServerSettings` wraps the existing `MailServerSettings` gRPC RPC
  (`proto/bridge.proto:84`, `ImapSmtpSettings{imapPort, useSSLForImap, ...}`).
  No new flag or config is needed — the port is read live from the running
  bridge on every call.
- `ProbeIMAPLogin` dials `127.0.0.1:<port>`:
  - TLS with `InsecureSkipVerify: true` if `useSSL`. Trust in the bridge is
    already established via the token-authenticated gRPC call that handed us
    the port; TLS here is transport only, not identity. A loopback MITM would
    require local code execution, which is already a stronger compromise than
    this probe defends against.
  - Reads the IMAP greeting, sends a tagged `LOGIN "<user>" "<pass>"` with
    `\` and `"` escaped in both fields (quoted-string syntax — sufficient
    since secrets are read as single trimmed lines, never containing CR/LF),
    reads until the tagged response, checks for `OK`.
  - Sends a tagged `LOGOUT`, reads the tagged response, closes. **Never**
    issues `SELECT`/`FETCH` — those would trigger a real mailbox sync against
    Proton, which is exactly what this probe must avoid.
  - Respects the caller's `ctx` deadline for dial/read/write; returns a plain
    error on any failure (bad credentials, connection refused, timeout) — the
    caller doesn't need to distinguish failure modes, only success vs. not.

### Metrics (`internal/serve/metrics.go`)

- New gauge `bridge_imap_login_ok` — "1 if an authenticated IMAP LOGIN against
  the local bridge listener succeeded on the last poll, else 0."
- `poll()` gains `emailFile, imapPasswordFile string` parameters (forwarded
  from `Options.EmailFile` / `Options.IMAPPasswordFile`, which already exist
  as flags for the web UI — no new flag).
- After a successful `GetUsers` call, reuse the already-open `Client` to call
  `MailServerSettings`, read the email and sealed IMAP password via
  `secrets.Read`, and call `ProbeIMAPLogin`. Any failure in that chain
  (settings RPC, secret read, or the probe itself) sets the gauge to 0;
  success sets it to 1.
- `markDown()` (called when `Connect`/`GetUserList` fails) also zeroes this
  gauge — if we can't even reach gRPC, IMAP health is unknown/bad.
- `runPoller` signature gains the two file paths; `serve.Run` passes
  `opts.EmailFile` / `opts.IMAPPasswordFile` through.

### Reauth (`internal/reauth/reauth.go`)

After `c.Login` succeeds and `res.IMAPPassword` is in hand, and before
`reauth.Run` returns success:

1. Call `c.MailServerSettings(ctx)` on the same still-open client.
2. Probe up to **3 times, 2 seconds apart**, using the *freshly returned*
   `res.IMAPPassword` (not the old sealed value — it may have just changed)
   and the login email as credentials.
3. If every attempt fails, `Run` returns `nil, fmt.Errorf("post-login IMAP
   verification failed: %w", lastErr)` instead of an `*Outcome`.

This budget adds at most ~4-6s on top of the existing login flow, well inside
the 60s `loginTimeout` in `web.go`. **No changes needed in `web.go`** — its
existing `if err != nil` branch already logs failure and shows it to the
operator instead of a false "succeeded", because the failure now surfaces
through `reauth.Run`'s error return.

## Testing

### `internal/bridgetest` (new, extracted from `internal/bridge/fake_test.go`)

The existing fake gRPC bridge (cert generation, fake `Login`/`GetUserList`/
event stream, `startFakeBridge` helper) is moved from `bridge_test` (unexported)
into an exported `internal/bridgetest` package, unchanged in behavior. This is
required because the reauth test (below) needs both a fake gRPC bridge *and* a
fake IMAP server running together, and the fake bridge currently isn't
reachable outside `internal/bridge`'s own tests.

### `internal/bridge/imap_test.go` (new)

A minimal fake IMAP server (plain TCP, greeting + `LOGIN`/`LOGOUT` handling)
covering:

- Healthy login → `ProbeIMAPLogin` returns nil.
- Wrong credentials (server replies `NO`, simulating "no such user") →
  returns an error.
- Connection refused (dial a closed port, no listener) → returns an error.
- One TLS variant (reusing the existing cert-gen helper, now in
  `bridgetest`) to exercise the `useSSL` path.

### `internal/serve/metrics_test.go` (extended)

- Existing `TestPollMarksDownOnBadConfig` gains an assertion that
  `bridge_imap_login_ok == 0`.
- New test: fake gRPC bridge (`bridgetest`) + fake IMAP server, healthy poll →
  `bridge_imap_login_ok == 1`.

### `internal/reauth/reauth_test.go` (new)

Using `bridgetest` + a fake IMAP server:

- Probe succeeds → `Run` returns a populated `*Outcome`, no error.
- Probe never recovers within the retry budget → `Run` returns an error
  (and the fake IMAP server can assert it was hit 3 times).

## Documentation

- `README.md`: one new row in the metrics table for `bridge_imap_login_ok`.
- No new flags to document — `MailServerSettings` is fetched live, and the
  email/IMAP-password file flags already exist.

## Out of scope

- The matching `PrometheusRule` (`bridge_imap_login_ok == 0`) alerting rule
  lands in the homelab repo (tracking issue #1060), not here.
- No CLI login entrypoint exists in this repo today (despite a stale doc
  comment in `reauth.go` referencing one) — `web.go`'s `POST /auth` is the
  only caller of `reauth.Run`.
