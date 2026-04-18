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

Reveal hidden/system jar attributes while scanning:

```powershell
powershell -ExecutionPolicy Bypass -File .\XkzutosModAnalyzer.ps1 -Path "C:\Path\To\mods" -RevealHidden
```

Memory scan cap (MB per process):

```powershell
powershell -ExecutionPolicy Bypass -File .\XkzutosModAnalyzer.ps1 -Path "C:\Path\To\mods" -MemoryScanMB 256
```

## What It Flags

- Token checks inside mod jars for:
  - `autoclicker`, `aimassist`, `reach`, `velocity`, `killaura`, `scaffold`, `fly`, `speed`, `esp`, `xray`, `selfdestruct`, `bypass`, `exploit`
- Obfuscation markers:
  - `a.class`, `b.class`, high counts of single-letter class names
- Hidden/system jar attributes in the target mods folder
- JVM runtime injection argument patterns in `javaw.exe`/`java.exe`
- Java memory string hits for known cheat identifiers (Mapped + Private memory scan with minimum string length 5)
- Mod hash verification via Modrinth and Megabase

## Credits

- Yumiko Mod Analyzer by Veridon: https://github.com/veridondevvv/YumikoModAnalyzer
- Yarp's Mod Analyzer by YarpLetapStan: https://github.com/YarpLetapStan/PowershellScripts
- Meow Mod Analyzer inspiration by MeowTonynoh: https://github.com/MeowTonynoh
