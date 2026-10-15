# Third-party notices

## CLIProxyAPI

- Upstream: <https://github.com/router-for-me/CLIProxyAPI>
- Historical deployment template: v7.2.155.
- License: MIT, reproduced verbatim in `licenses/CLIProxyAPI-MIT.txt`.
- Copyright: Luis Pater and Router-For.ME, as written in the upstream license.

The upstream project supplies OAuth login/refresh, upstream inference forwarding,
Responses API compatibility and usage events. This repository supplies the
surrounding access-management, client-routing, recovery and reporting code.
The installer downloads a separately versioned upstream binary; it does not
represent that binary as code written by this repository's contributors.

## Other dependencies

OpenSSH, systemd, SQLite, Python, PyYAML and bcrypt retain their respective
licenses. Codex App / CLI are external clients and are not distributed here.
Dependencies installed separately are not relicensed by this repository's MIT
license. No private keys, member credentials, upstream login tokens or client
executables are bundled.
