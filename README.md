# xkzuto's mod analyzer

Console-first Minecraft mod analyzer for catching suspicious or disguised cheat mods with clear reasons.

## One Command

Use this exact GitHub raw command:

```powershell
powershell -ExecutionPolicy Bypass -Command "Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/xkzuto96/xkzutos-mod-analyzer/main/XkzutosModAnalyzer.ps1')"
```

That runs the analyzer directly in console mode and prompts for the mods folder or jar path.

Important: it does not auto-pick `.minecraft\mods`. You must enter a folder or jar path (or type `.` for the current folder).

One-command run with an explicit path (no prompt):

```powershell
powershell -ExecutionPolicy Bypass -Command "& ([scriptblock]::Create((Invoke-RestMethod 'https://raw.githubusercontent.com/xkzuto96/xkzutos-mod-analyzer/main/XkzutosModAnalyzer.ps1'))) -Path 'C:\Path\To\mods'"
```

## Local Run

```powershell
powershell -ExecutionPolicy Bypass -File .\XkzutosModAnalyzer.ps1
```

## Optional Flags

Scan a specific folder:

```powershell
powershell -ExecutionPolicy Bypass -File .\XkzutosModAnalyzer.ps1 -Path "C:\Path\To\mods"
```

Scan one jar:

```powershell
powershell -ExecutionPolicy Bypass -File .\XkzutosModAnalyzer.ps1 -Path "C:\path\to\mod.jar"
```

Skip runtime JVM argument scan:

```powershell
powershell -ExecutionPolicy Bypass -File .\XkzutosModAnalyzer.ps1 -Path "C:\Path\To\mods" -SkipRuntimeScan
```

Skip java/javaw memory scan:

```powershell
powershell -ExecutionPolicy Bypass -File .\XkzutosModAnalyzer.ps1 -Path "C:\Path\To\mods" -SkipMemoryScan
```

Disable Modrinth/Megabase verification:

```powershell
powershell -ExecutionPolicy Bypass -File .\XkzutosModAnalyzer.ps1 -Path "C:\Path\To\mods" -NoModVerification
```

Disable only Megabase verification fallback:

```powershell
powershell -ExecutionPolicy Bypass -File .\XkzutosModAnalyzer.ps1 -Path "C:\Path\To\mods" -NoMegabase
```

Hidden/system jar attributes are auto-revealed before scanning.
Legacy manual flag (still accepted):

```powershell
powershell -ExecutionPolicy Bypass -File .\XkzutosModAnalyzer.ps1 -Path "C:\Path\To\mods" -RevealHidden
```

Memory scan cap (MB per process):

```powershell
powershell -ExecutionPolicy Bypass -File .\XkzutosModAnalyzer.ps1 -Path "C:\Path\To\mods" -MemoryScanMB 256
```

Print full per-status mod lists:

```powershell
powershell -ExecutionPolicy Bypass -File .\XkzutosModAnalyzer.ps1 -Path "C:\Path\To\mods"
```

Hide status lists (compact output):

```powershell
powershell -ExecutionPolicy Bypass -File .\XkzutosModAnalyzer.ps1 -Path "C:\Path\To\mods" -NoStatusLists
```

## Report Output

- Verified Modrinth entries show the project versions page and matched version download count.
- After a normal interactive scan, the analyzer can save a readable TXT report to Downloads, save to a custom folder or file path, or upload a temporary share link and copy it.
- `-Quiet` mode skips the final interactive report menu for automation.

## What It Checks

- Mod jar content indicators:
  - known cheat-client behavior families and suspicious feature naming
  - expanded private-client signature patterns without publishing the raw match list
  - metadata, resource text, and printable class-byte text
  - tolerant matching for obfuscated UI/module text patterns
  - per-jar match reporting inside the tool output
- Obfuscation and loader markers:
  - abnormal class naming density and short-name bursts
  - deep or repeated package namespace patterns in large jars
  - class-byte hidden-loader and encoded-payload signals
- Hidden/system jar attributes in the target mods folder
- JVM runtime injection argument patterns (prioritizes likely Minecraft java processes)
- JVM runtime output is split into:
  - suspicious injection findings
  - likely-legit runtime notes (trusted javaagents / low-risk launcher args)
- Runtime session check:
  - shows Java process uptime/start time
  - flags jars edited while Minecraft Java was actively running
  - edit-window flags are only applied when the scan target looks like a launcher mods folder
  - notes that exact before/after content diff needs a baseline snapshot
- JVM argument injection findings now include:
  - matched argument position in the command line
  - the full matched argument text
  - resolved jar paths when present
  - semicolon/comma-separated jar lists are parsed and each jar path is extracted
  - automatic scan/flagging of referenced injected jars only when high-risk JVM injection findings are present
- Javaagent trust tuning includes common launcher/dev hints (for example Lombok/toolchain jars) to reduce false positives
- Unrecognized javaagents are now separated from suspicious javaagents to reduce false positives
- High-confidence signature density and critical behavior identifiers can escalate directly to `Suspicious`
- Combined hidden-loader markers + namespace recursion can escalate directly to `Suspicious`
- Java memory hits for known suspicious identifiers (Mapped + Private memory scan)
- Mod hash verification via Modrinth and Megabase

## Credits

- Yumiko Mod Analyzer by Veridon: https://github.com/veridondevvv/YumikoModAnalyzer
- Yarp's Mod Analyzer by YarpLetapStan: https://github.com/YarpLetapStan/PowershellScripts
- Meow Mod Analyzer inspiration by MeowTonynoh: https://github.com/MeowTonynoh
