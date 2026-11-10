# Changelog

All notable changes to [NAS-Sentinel](https://github.com/9-Security/NAS-Sentinel) are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows semantic versioning once tagged releases begin.

## [Unreleased]

### Fixed

- Setup wizard no longer dead-ends without a reachable NAS: added **Skip / offline SOC** (`POST /api/setup/skip-offline` + UI button) that sets `is_configured=true` with `offline_mode=true`, dismisses the modal, and pauses SSH poller/inotify until a real Save & Launch succeeds.
- Offline skip **no longer rewrites** `nas_host` / `nas_user` / `nas_port` / `ssh_key_path` (flags only). Removed dangerous SSH/`probe` fallback to `127.0.0.1` when host is blank. Added **僅儲存連線參數** (`persist_without_connect`) so host/key can be repaired without a successful SSH probe; blank key field keeps the existing key.

### Security

Security hardening from the internal code review, shipped across [#1](https://github.com/9-Security/NAS-Sentinel/pull/1) and [#2](https://github.com/9-Security/NAS-Sentinel/pull/2).

#### [#1](https://github.com/9-Security/NAS-Sentinel/pull/1) — API auth, Docker defaults, secrets & trust pinning

- **C1** — Required `Authorization: Bearer <API_TOKEN>` on all `/api/*` routes (deny by default). `/api/auth/status` remains the only public API. Auto-generated tokens are written to `nas-sentinel/data/api_token.txt` when unset.
- **C2** — Bound Docker Compose / Dockerfile defaults to `127.0.0.1` (not `0.0.0.0`); stopped mounting the entire host `~/.ssh`; documented that network exposure without auth is unsupported.
- **H1** — Stripped raw Cloudflare API tokens from API responses; returned masked / presence flags only.
- **H2** — Stopped empty-passphrase `ssh-keygen` (`-N ""`); required a passphrase (min 8) or refused auto-generate with docs for `ssh-agent`.
- **H3** — Allowlisted / validated `ssh_key_path` under `~/.ssh`; hardened setup probe and save endpoints behind auth + path checks.
- **M1** — Pinned SSH host-key fingerprints into a dedicated `data/ssh_known_hosts` and used `StrictHostKeyChecking=yes` after pin.
- **M3** — Applied `chmod 0600` to secret files (`config.json`, Cloudflare config, API token, known_hosts, generated private keys).
- **M4** — Elevated TLS certificate pin mismatches against the HTTP baseline to CRITICAL (fail closed on pin change).
- **M5** — Replaced committed real-host baselines with gitignored live files and tracked `*_baseline.example.json` templates.
- **M6** — Used Authorization-header auth (not cookies) for CSRF-resistant browser API calls.

#### [#2](https://github.com/9-Security/NAS-Sentinel/pull/2) — Remaining M2 / L1 / L3 (stacks on #1)

- **M2** — Returned SSH private-key references to clients only as `~/.ssh/<basename>` (never absolute paths).
- **L1** — Mapped SSH connection / collect failures to coarse `error_code` values; kept raw stderr in server logs only.
- **L3** — Removed hard-coded historical attacker IPs from the default Security tab; optional RFC 5737 demo rows only when `NAS_SENTINEL_DEMO_AUTH_INTEL=1`.

### Changed

- Updated `.env.example`, `README.md`, `README.zh-TW.md`, and start scripts for API token unlock and localhost Docker bind defaults.
- Added an in-browser API token gate that stores the Bearer token in `localStorage` for this origin.

### Notes

Deferred review items (still open): **L2** (collector/inotify JSON schema validation), **L4** (webshell heuristic coverage).

[Unreleased]: https://github.com/9-Security/NAS-Sentinel/compare/main...HEAD
