# Sentinel Antivirus

Sentinel is a Windows desktop **on-demand malware scanner** built on the official
[ClamAV](https://www.clamav.net) engine. It discovers or installs ClamAV, updates
signatures, scans files and folders with live progress, and puts detections into an
encrypted quarantine from which they can be verified and restored.

> **Sentinel is not real-time protection.** It scans what you point it at, when you
> ask it to. It has no background monitor, no shell integration, and no behaviour
> blocking. **Keep Microsoft Defender (or another antivirus) enabled.** Sentinel
> deliberately does not add Defender exclusions, because doing so would make the
> machine less safe.

---

## Contents

- [Features](#features)
- [Install and first run](#install-and-first-run)
- [Performance tuning](#performance-tuning)
- [Build from source](#build-from-source)
- [Run the test suite](#run-the-test-suite)
- [ClamAV: official sources only](#clamav-official-sources-only)
- [Testing with EICAR](#testing-with-eicar)
- [Microsoft Defender compatibility](#microsoft-defender-compatibility)
- [Where Sentinel stores its data](#where-sentinel-stores-its-data)
- [Uninstalling](#uninstalling)
- [Limitations](#limitations)

---

## Features

- **Engine discovery and one-click install.** Sentinel looks for ClamAV in Settings,
  in its own managed folder, in `Program Files`, and on `PATH`. If none is found the
  dashboard offers an install that downloads the official ClamAV portable Windows
  package from the Cisco Talos GitHub release and **verifies its SHA-256 digest**
  against the GitHub release metadata before extracting it. No administrator rights
  are required.
- **Signature updates.** Runs the bundled `freshclam.exe` with live streamed output
  and maps its failures to readable messages. Warns when definitions are older than
  the configured threshold.
- **Scanning.** File or folder targets, optional archive scanning, live progress with
  file counts and throughput, and cancellation that kills the engine's process tree.
  A scan starts immediately — the folder file count runs in the background instead of
  blocking the first file — and a background ClamAV daemon keeps the signature
  database loaded so scans after the first take milliseconds rather than a minute.
  Exit codes `0` (clean), `1` (detections) and `2` (error) are handled correctly.
- **Encrypted quarantine.** Detections are copied into an AES-256-CBC encrypted
  payload (`SNQT1` header) with a DPAPI-protected key, hash-verified before and
  after, and only then is the original deleted. If Windows refuses to delete the
  original, Sentinel says so instead of pretending the threat is gone.
- **Restore and delete.** Restore re-verifies the payload hash before writing
  anything, uses a temp file plus an atomic move, and confirms the restored file
  matches the original. Secure delete overwrites the payload bytes before removal.
  Legacy plaintext quarantine manifests from the original prototype are still
  importable.
- **Scan history.** Persisted, capped JSON history with per-session detection lists
  and one-click rescan.

## Install and first run

1. Run `Sentinel-Setup-1.3.0.exe`. The installer is **per-user** (`PrivilegesRequired=lowest`)
   and needs no UAC prompt. It installs to `%LOCALAPPDATA%\Programs\Sentinel` and
   creates a Start-menu shortcut (a desktop shortcut is optional).
2. On first run the dashboard shows a **setup card**: Sentinel will tell you that no
   engine was found and offer **Install ClamAV**. That downloads the official package
   (roughly 225 MB, plus about 110 MB of signatures) and extracts it to
   `%LOCALAPPDATA%\Sentinel\ClamAV`.
3. After the engine is installed, Sentinel prompts you to fetch virus definitions.
   The first signature download is large; subsequent checks are small and infrequent.
4. Use **Quick scan** (Downloads, Desktop, Documents and OneDrive) or pick a folder.

You can also point Sentinel at an existing ClamAV install from **Settings → Engine**
if you would rather manage ClamAV yourself.

## Performance tuning

Almost all of a scan's wall-clock time is **loading the signature database**, not
reading files. On this machine `clamscan` needs **over a minute** to load and verify
ClamAV's 107 MB of `.cvd` files before it looks at a single file — and it does that
again on *every* invocation.

Sentinel therefore keeps ClamAV running in the background:

- **Background engine (default on).** Sentinel starts ClamAV's `clamd` daemon at
  launch. It loads the database once and then answers each scan in milliseconds.
  Measured here: the first scan took **99 s** while the database loaded, and every
  scan after that took **0.00 s** — against 62–74 s per scan for a one-off
  `clamscan`. The daemon also scans files in parallel by itself.
- **Fallback.** If the daemon cannot start, Sentinel falls back to `clamscan`
  automatically. The Scan page always says which path is in use, so a slow scan is
  never a mystery.
- The daemon needs roughly **500 MB of memory** while it is running. Turn it off in
  **Settings → Scan options** if that matters more than speed.

Other things Sentinel does to keep scans quick:

- **No blocking pre-count.** Older builds enumerated every file before scanning
  started, so a full-drive scan spent its first minutes just counting. Now the scan
  starts at once and the count happens in the background; the progress bar switches
  to a real percentage as soon as the count lands, and counts are cached briefly.
- **One engine pass for many targets.** A Quick scan of Downloads, Desktop and
  Documents scans all three together rather than starting the engine three times.
- **Lazy hashing.** Detections are no longer SHA-256 hashed after every scan. A file
  is hashed only when you select it or quarantine it.

**Settings → Limits (advanced)** exposes safety valves if a scan ever feels
unbounded: skip files above a size, cap the bytes scanned per file, or cap the time
spent on a single file. Leave them blank to use ClamAV's own defaults.

## Build from source

Requirements: Windows 10/11 and the **.NET 10 SDK**.

If `dotnet` is not on your `PATH` (for example when the SDK was installed per-user),
call it by its full path:

```powershell
$dotnet = "$env:LOCALAPPDATA\Microsoft\dotnet\dotnet.exe"
& $dotnet --version
```

Build, run, and publish:

```powershell
$root   = "C:\path\to\Sentinel-Windows-Prototype"
$dotnet = "$env:LOCALAPPDATA\Microsoft\dotnet\dotnet.exe"

& $dotnet build "$root\Sentinel-Windows-Prototype.sln" -c Release
& $dotnet run   --project "$root\Sentinel\Sentinel.csproj" -c Release

# Single self-contained executable (~59 MB) in publish\app
& $dotnet publish "$root\Sentinel\Sentinel.csproj" -c Release -r win-x64 `
    --self-contained true -o "$root\publish\app"
```

Build the installer (Inno Setup 6.3 or newer):

```powershell
& "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe" "$root\installer\Sentinel.iss"
```

The setup program is written to `publish\installer\`.

## Run the test suite

The tests are a self-contained console runner — no test framework to install.

```powershell
# Unit + stub-engine tests
& $dotnet run --project "$root\tests\Sentinel.Tests\Sentinel.Tests.csproj" -c Release

# Also exercise a real ClamAV install (engine is found in
# %LOCALAPPDATA%\Sentinel\ClamAV, or set SENTINEL_CLAMAV_DIR)
& $dotnet run --project "$root\tests\Sentinel.Tests\Sentinel.Tests.csproj" -c Release -- --real-engine

# Regenerate the app icon (Sentinel\resources\sentinel.ico) from WPF geometry
& $dotnet run --project "$root\tools\IconGen\IconGen.csproj" -c Release
```

The suite includes a **UI smoke test** that builds the real `Application`, window and
every screen, then lays each one out. WPF resolves `{StaticResource}` keys lazily, so a
missing theme key or a broken control template only shows up at runtime — where it takes
the whole app down with it. That test is what stops that from shipping.

> If Sentinel ever fails to start, the full exception is written to
> `%LOCALAPPDATA%\Sentinel\Logs\sentinel-error.log`. That file is the first place to
> look.

Every run redirects Sentinel's data folder to a throwaway temp directory via the
`SENTINEL_DATA_ROOT` environment variable, so tests never touch your real quarantine,
history or settings. That variable is also how you make Sentinel portable: set it
before launching and all data (including the quarantine key) follows it.

### Rendering the UI

Sentinel can draw itself to a PNG, which is the only reliable way to check a WPF
layout (screen-grab tooling fights with focus stealing and DPI virtualisation):

```powershell
$env:SENTINEL_PAGE = "dashboard"      # dashboard | scan | results | quarantine | history | settings
$env:SENTINEL_SHOT = "$root\dashboard.png"
& $dotnet run --project "$root\Sentinel\Sentinel.csproj" -c Release
```

The app renders the requested screen and exits. Both variables are ignored unless
they are set, so this has no effect on a normal run.

The real-engine run covers engine discovery, the generated `freshclam.conf`, a live
signature update, detection through a purpose-built hash signature, and a full
quarantine/restore/delete cycle against the real `clamscan.exe`. It also attempts an
EICAR scan and reports what Microsoft Defender did about it (see below).

## ClamAV: official sources only

Sentinel obtains ClamAV **only** from the Cisco Talos release on GitHub:

```
https://github.com/Cisco-Talos/clamav/releases
```

The installer pins a specific version (`EngineInstaller.ClamAvVersion`, currently
**1.5.4**) and verifies the downloaded archive's SHA-256 against the digest published
in the GitHub release API before extracting anything. Virus signatures are downloaded
**only** by the `freshclam.exe` that ships inside that package, from the official
ClamAV mirrors.

Sentinel will never download signatures from a third-party site, and it will never
disable signature verification. If you want a different ClamAV version, install it
yourself and point Sentinel at it in Settings.

## Testing with EICAR

The [EICAR test file](https://www.eicar.org/download-anti-malware-testfile/) is the
standard harmless string used to confirm that an antivirus detects anything at all.
It is not malware, but **every antivirus — including Microsoft Defender — will
react to it**.

Guidance for testing Sentinel with EICAR:

1. Download EICAR only from the official EICAR site, or create it yourself. It is
   exactly these 68 bytes with no trailing newline:

   ```
   X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
   ```

2. Put it in a dedicated scratch folder, never in a Windows system directory.
3. Expect **both** Sentinel and Defender to react. Defender typically quarantines the
   file the moment it is written. When that happens Sentinel's scan may report a
   warning such as *"Can't open file … Invalid argument"* and an engine exit code of
   `2`, because Defender had already neutralised the file before `clamscan` could open
   it. **That is Defender working correctly, not a Sentinel bug.**
4. Defender may also flag or block the *restored* copy, since restoring deliberately
   puts the sample back on disk. That is the intended result of a restore.

If Defender keeps eating the sample before you can scan it, test detection with the
hash-signature approach used by the test suite instead: write a small `.hdb` signature
for a file you control. That exercises the same real-engine detection path without
tripping any antivirus.

## Microsoft Defender compatibility

Sentinel is designed to coexist with Defender rather than fight it:

- Quarantined payloads are **AES-256-CBC encrypted at rest**, not plaintext malware
  sitting in AppData for Defender to flag or for another tool to execute.
- Sentinel runs `asInvoker` and installs per-user. It never requests elevation.
- Sentinel **never** adds, and will never offer to add, Defender exclusions.
- The app is unsigned, so SmartScreen may warn about a downloaded `Sentinel.exe`.
  That is expected for an unsigned build and cannot be fixed from this repository —
  it requires a code-signing certificate.

## Where Sentinel stores its data

Everything lives under `%LOCALAPPDATA%\Sentinel` (or the folder named by
`SENTINEL_DATA_ROOT` if that is set):

| Path | Contents |
|---|---|
| `Quarantine\` | Encrypted payloads (`*.qtn`), per-item manifests (`*.json`), and the DPAPI-protected `quarantine.key` |
| `Manifests\` | Legacy plaintext manifests from the original prototype (read-only import) |
| `ClamAV\` | The managed engine install, including `database\` and `freshclam.conf` |
| `history.json` | Scan history |
| `settings.json` | Settings |
| `Logs\` | `freshclam.log` and `sentinel-error.log` |

The quarantine key is protected with DPAPI for the current Windows user, so the
quarantine store **cannot** be unlocked by another account or copied to another
machine and restored there.

## Uninstalling

Uninstalling Sentinel removes the application and its Start-menu/desktop shortcuts,
but **keeps** `%LOCALAPPDATA%\Sentinel` — your quarantine, history, settings and
downloaded engine are not deleted without asking.

To remove the data folder too, run the uninstaller with `/PURGE`:

```
"%LOCALAPPDATA%\Programs\Sentinel\unins000.exe" /VERYSILENT /PURGE
```

## Limitations

- **No real-time protection.** On-demand scanning only. Keep Defender enabled.
- **ClamAV's detection is not a verdict.** A detection can be a false positive and a
  clean result is not a guarantee that a file is safe. Treat quarantine decisions as
  something you confirm, not something you automate.
- **No code signing.** Expect SmartScreen warnings on downloaded builds.
- **Not elevated.** Sentinel cannot scan protected system locations it has no read
  access to; those show up as scan warnings.
- **English output parsing.** Detection lines are parsed as `<path>: <threat> FOUND`.
  A heavily localised or modified ClamAV build could break the parser.
- **The background engine needs memory.** Keeping ClamAV resident costs roughly
  500 MB of RAM. Disable it in Settings if that is a problem — scans then take about
  a minute each because the signature database has to be reloaded every time.
- **The first scan after launch is slow.** The daemon needs a minute or two to load
  the signature database. Scans started before it is ready fall back to a one-off
  engine start and are correspondingly slow.
- **ARM64 and x86 untested.** The published build and installer target x64. The
  installer allows ARM64 under x64 emulation (`x64compatible`) but that path has not
  been exercised.
