# Real-ROM Smoke Test Runner

A Docker-based workflow that runs the Ghidra SNES loader against a corpus of
real cartridge dumps. This is how we catch bugs that the synthetic-ROM CI suite
cannot — anything depending on real cartridge headers, real file sizes, or
real coprocessor register windows.

> **Important:** Real ROMs never leave the developer's machine. The smoke runner
> is local-only by design; its output directory (`.local-test/`) is gitignored.
> Never commit cartridge dumps or derived data.

## Prerequisites

The `ghidra-mcp` container must have:

1. **A full JDK, not just a JRE.** `analyzeHeadless` silently fails without
   `javac`. Install `openjdk-21-jdk-headless`.

2. **`JAVA_HOME_OVERRIDE`** in `/opt/ghidra/support/launch.properties`:
   ```
   JAVA_HOME_OVERRIDE=/usr/lib/jvm/java-21-openjdk-amd64
   ```
   Without this, Ghidra 12.0.4's `LaunchSupport.jar` runs an interactive Java
   picker that nobody answers in a non-TTY exec.

3. **Gradle 8.5+** on `PATH` (e.g. at `/opt/gradle-8.5/bin/gradle`). Ubuntu
   22.04's apt Gradle is 4.4.1 and won't build a Ghidra 12.x extension.

4. **The current loader extension** installed under
   `/opt/ghidra/Ghidra/Extensions/SnesLoader/`.

> **Note:** `launch.properties` overrides on the container are not persistent
> across `docker rm`. If the container is recreated, re-apply step 2.

## Rebuilding the Loader

After code changes, rebuild and reinstall inside the container:

```pwsh
# from the ghidra-snes-loader repo root
docker cp .\SnesLoader ghidra-mcp:/work/SnesLoader
docker exec ghidra-mcp bash -lc 'cd /work/SnesLoader && /opt/gradle-8.5/bin/gradle buildExtension -PGHIDRA_INSTALL_DIR=/opt/ghidra'
docker exec ghidra-mcp bash -lc 'rm -rf /opt/ghidra/Ghidra/Extensions/SnesLoader && \
  unzip -q /work/SnesLoader/dist/ghidra_12.0.4_PUBLIC_*_SnesLoader.zip -d /opt/ghidra/Ghidra/Extensions/'
```

> **Important:** `gradle build` alone does **not** produce the extension zip.
> You must run `buildExtension`. If you forget, the next `analyzeHeadless`
> will load the stale extension and you'll waste time chasing a bug you
> already fixed.

## Running the Corpus Sweep

```pwsh
cd path\to\ghidra-snes-loader
.\tests\real-rom-smoke.ps1 -RomDir 'path\to\your\roms\directory'
```

### What It Does

1. Creates `.\.local-test\` (gitignored) for output artifacts.
2. Stages `tests/PrintRealRomSnapshot.java` inside the container at
   `/tmp/snes-smoke/scripts/`.
3. For each `*.smc` / `*.sfc` / `*.swc` file under `-RomDir`:
   - Sanitises the filename (`[^A-Za-z0-9._-]` → `_`) so `bash -c` quoting
     survives names with spaces and parentheses.
   - `docker cp`s the ROM into `/tmp/snes-smoke/roms/` in the container.
   - Runs `analyzeHeadless` against a fresh project directory, pointing the
     post-script at `PrintRealRomSnapshot.java`.
   - Captures stdout into `<rom>.headless.log`, greps `MARK:` lines into
     `<rom>.marks.txt`, and accumulates a per-ROM summary row.
4. Prints a summary table at the end: `TITLE | KIND | COPROC | FUNCS | HW_SYMS | DBR_SITES | DP_SITES`.

### What a Passing Run Looks Like

After a successful sweep, the summary table shows all cartridges imported
correctly with the expected mapping mode and coprocessor detection. Example
baseline (11 cartridges, v1.2.1):

| Title | Kind | Coproc | HW syms |
|---|---|---|---|
| EarthBound | HiROM | NONE | ≥208 |
| Final Fantasy III (FF6) | HiROM | NONE | 208 |
| Mega Man X2 | LoROM | Cx4 | ≥208 |
| Star Fox | LoROM | GSU | ≥221 |
| Star Ocean | HiROM | SPC7110 | ≥208 |
| Super Mario Kart | LoROM | DSP1 | ≥208 |
| Super Mario RPG | LoROM/SA-1 | SA1 | ≥208 |
| Super Mario World | LoROM | NONE | 208 |
| Yoshi's Island | LoROM | GSU | ≥208 |
| Tales of Phantasia | HiROM | NONE | 208 |
| Zelda: A Link to the Past | LoROM | NONE | 208 |

The exact counts live in `.local-test\*.marks.txt` on the dev box. Re-run the
sweep to regenerate them; they should be stable across reruns of the same
container + loader build.

`HW syms` is the count of distinct symbols in the primary `hwregs` block only
(mirrors are excluded). 208 is the baseline; coprocessor cartridges add 13–25
more labels for their register window.

### PowerShell Footguns

- `Select-String` returns either a single match object or an array. The runner
  forces `@(...)` so `.Count` always works.
- `Get-ChildItem -Recurse -Include *.sfc,*.smc,*.swc` is unreliable on
  PowerShell 7.x; the runner uses
  `Where-Object { $_.Extension -in '.sfc','.smc','.swc' }` instead.
- Filenames with spaces and parentheses go through `bash -c` inside
  `docker exec`. Always sanitise before copying — don't try to quote your way
  out of it.

## Pre-Release Checklist

Before tagging a new loader release:

1. Rebuild the loader in the container (see [Rebuilding](#rebuilding-the-loader)).
2. Run the corpus sweep (see [Running](#running-the-corpus-sweep)).
3. Verify every cartridge shows the expected `KIND`, `COPROC`, and `HW_SYMS`
   against the established baseline.
4. If adding support for a new coprocessor or mapping mode, include at least
   one real cartridge in the sweep that exercises it.
