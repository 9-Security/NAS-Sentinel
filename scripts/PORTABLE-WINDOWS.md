# Windows portable launcher (P2 first slice)

## What a novice double-clicks

**`start-nas-sentinel.bat`** at the repo root.

That is the only required click after extracting the zip / cloning the repo.

## What happens

1. The bat looks for Python in this order:
   1. `runtime\python\pythonw.exe` (portable embed, preferred)
   2. `python` / `pythonw` on PATH
   3. Common `AppData\Local\Programs\Python\Python3*` installs
2. If none exist, it runs `scripts\ensure-portable-python.ps1`, which downloads the **official** Windows embeddable CPython zip from `python.org` into `runtime\python\` (no installer, **PATH unchanged**).
3. `start-nas-sentinel-background.vbs` starts `nas-sentinel\server.py` hidden on loopback (`http://127.0.0.1:8088`).
4. The browser opens; localhost auto-unlock still applies (P0). Bearer auth is unchanged.

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
