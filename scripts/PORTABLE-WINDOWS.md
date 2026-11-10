# Windows portable launcher (P2 first slice)

## What a novice double-clicks

**`start-nas-sentinel.bat`** at the repo root.

That is the only required click after extracting the zip / cloning the repo.

## What happens

1. The bat looks for Python in this order:
   1. `runtime\python\pythonw.exe` (portable embed, preferred)
   2. `python` / `pythonw` on PATH (**Windows Store `WindowsApps` stubs are ignored**)
   3. Common `AppData\Local\Programs\Python\Python3*` installs (smoke-tested)
2. If none are usable, it runs `scripts\ensure-portable-python.ps1`, which downloads the **official** FTP artifact `python-<ver>-embed-<arch>.zip` from `www.python.org` into `runtime\python\` (no installer, **PATH unchanged**).
3. Download integrity: **SHA-256 pinned in-repo** in `ensure-portable-python.ps1` (fail closed on mismatch; staging deleted). Artifact name is `-embed-` (not the `-embeddable-` JSON alias — different file/hash).
4. Extract is path-contained (zip-slip refused); `-Version` must match `x.y.z` and a pinned hash key.
5. `start-nas-sentinel-background.vbs` starts `nas-sentinel\server.py` hidden on loopback (`http://127.0.0.1:8088`). No bare `pythonw.exe` PATH fallback.
6. The browser opens; localhost auto-unlock still applies (P0). Bearer auth is unchanged.

### Pinned 3.12.10 embed zips (SHA-256)

| Artifact | SHA-256 |
|----------|---------|
| `python-3.12.10-embed-amd64.zip` | `4acbed6dd1c744b0376e3b1cf57ce906f9dc9e95e68824584c8099a63025a3c3` |
| `python-3.12.10-embed-arm64.zip` | `3065efc3d382d1cda66757ac71ade11904fa6e350f5a97eb74811acd71ba5532` |
| `python-3.12.10-embed-win32.zip` | `084b9eb24cb848605c895d05b738fbc2572efc8b4c18c415a824065864a2b853` |

## Optional single-zip layout (fully offline)

Ship or zip this tree so the first click never needs a download:

```
NAS-Sentinel/
├── start-nas-sentinel.bat          ← double-click this
├── start-nas-sentinel-background.vbs
├── stop-nas-sentinel.bat
├── nas-sentinel/                   ← app code + data/
├── scripts/
│   ├── ensure-portable-python.ps1  ← used only if runtime/ missing
│   └── PORTABLE-WINDOWS.md
└── runtime/
    └── python/                     ← pre-extracted embeddable CPython
        ├── python.exe
        ├── pythonw.exe
        └── python3XX._pth          ← must list ..\..\nas-sentinel + import site
```

Populate `runtime\python\` once with:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\ensure-portable-python.ps1
```

Then zip the whole folder. Recipients double-click `start-nas-sentinel.bat` with no network and no system Python.

## Still required on the PC (not replaced by portable Python)

- A browser
- **OpenSSH Client** for NAS setup / scans (`ssh`, `ssh-keygen`, `ssh-keyscan`). Windows 10/11: Settings → Apps → Optional features → OpenSSH Client.
- DSM-side SSH enable + key authorize (P1 wizard) — Synology physics, not packager scope

## Security (do not weaken)

- Default bind remains `127.0.0.1`
- `/api/auth/local-token` remains TCP-loopback only
- All other `/api/*` still require `Authorization: Bearer`
- Portable runtime is local files only; it does not open firewall ports or change auth
- First-run download is fail-closed on hash mismatch (does not execute a bad zip)
