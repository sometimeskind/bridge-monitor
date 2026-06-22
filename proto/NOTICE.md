# Vendored proto — provenance and licence

`bridge.proto` is copied verbatim from:

- Repo: https://github.com/ProtonMail/proton-bridge
- Path: `internal/frontend/grpc/bridge.proto`
- Ref: `master` (vendored 2026-06-22)

**Proton Mail Bridge is licensed under the GNU GPL v3.** This `.proto` file and
the Go stubs generated from it (`internal/pb/`) derive from that GPLv3 source.
Distributing this project — including the published container image — therefore
has GPLv3 implications. Confirm the licensing posture for this repository before
publishing.

The generated stubs are redirected into this module's package via buf managed
mode (`buf.gen.yaml`), so the vendored `bridge.proto` itself is left unmodified
(its original `go_package` option still points at ProtonMail's internal path).

To refresh the vendored copy:

```sh
curl -sL https://raw.githubusercontent.com/ProtonMail/proton-bridge/master/internal/frontend/grpc/bridge.proto -o proto/bridge.proto
buf generate
```
