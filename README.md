# xkzuto's mod analyzer

`xkzuto's mod analyzer` is a Windows PowerShell analyzer for Minecraft jars that focuses on explainable detections instead of one giant wall of keyword hits.

It is designed to catch disguised or bypass-oriented jars by combining:

- metadata review
- namespace and packaging heuristics
- suspicious mixin and helper detection
- direct cheat-string detection
- runtime Java command-line checks
- optional Java memory scanning
- GUI review and JSON or CSV export
- EXE packaging support

## Why this build is stronger

This analyzer does more than look for obvious cheat words.

It also flags:

- placeholder or template metadata like `template-mod`, `com.example`, or `Hello Fabric world!`
- hidden implementation pushed into short packages like `a/` or `b/`
- class trees that repeat the same namespace segments over and over
- jars that claim to be performance or utility mods but contain client UI, rendering, keybinding, or crystal-combat classes
- bytecode helper names such as `ClassTransformer`, `CallbackInjector`, `RefmapResolver`, `AccessWidenerHelper`, and similar runtime hooks
- suspicious mixin targets and injected client paths
- runtime `javaagent`, Fabric or Forge injection arguments, and optional process-memory matches

## Quick Start

Run it locally:

```powershell
powershell -ExecutionPolicy Bypass -File .\XkzutosModAnalyzer.ps1
```

Run it against a specific folder:

```powershell
powershell -ExecutionPolicy Bypass -File .\XkzutosModAnalyzer.ps1 -Path "$env:APPDATA\.minecraft\mods"
```

Run it against a single jar:

```powershell
powershell -ExecutionPolicy Bypass -File .\XkzutosModAnalyzer.ps1 -Path "C:\path\to\mod.jar"
```

Run it with runtime Java checks:

```powershell
powershell -ExecutionPolicy Bypass -File .\XkzutosModAnalyzer.ps1 -Path "$env:APPDATA\.minecraft\mods" -RuntimeScan
```

Run it with runtime Java checks plus memory scan:

```powershell
powershell -ExecutionPolicy Bypass -File .\XkzutosModAnalyzer.ps1 -Path "$env:APPDATA\.minecraft\mods" -RuntimeScan -MemoryScan -MemoryScanMB 96
```

Launch the GUI:

```powershell
powershell -ExecutionPolicy Bypass -File .\XkzutosModAnalyzer.ps1 -Gui
```

Export JSON:

```powershell
powershell -ExecutionPolicy Bypass -File .\XkzutosModAnalyzer.ps1 -Path "$env:APPDATA\.minecraft\mods" -OutFile ".\report.json" -OutputFormat Json
```

Export CSV:

```powershell
powershell -ExecutionPolicy Bypass -File .\XkzutosModAnalyzer.ps1 -Path "$env:APPDATA\.minecraft\mods" -OutFile ".\report.csv" -OutputFormat Csv
```

## GitHub Raw One-Liner

After you upload this repository to GitHub, the simple raw command looks like this:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -Command "$url='https://raw.githubusercontent.com/xkzuto96/xkzutos-mod-analyzer/main/XkzutosModAnalyzer.ps1'; $tmp=Join-Path $env:TEMP 'XkzutosModAnalyzer.ps1'; Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $tmp; & $tmp -Gui"
```

That version is safer than `Invoke-Expression` because it downloads the script to a temp file first and then runs it normally, which avoids a bunch of quoting and parameter-passing issues.

If you rename the repository or use a different GitHub owner, update the URL to match.

## Publish To GitHub

This repo also includes `publish-github.ps1`.

After you fix `gh` authentication, publish the repo with:

```powershell
.\publish-github.ps1
```

If you want a different repo name:

```powershell
.\publish-github.ps1 -RepoName "your-repo-name"
```

## EXE Build

This repo includes `build-release.ps1`.

Build the zip and, if `ps2exe` is installed, an executable:

```powershell
.\build-release.ps1
```

Skip the EXE build:

```powershell
.\build-release.ps1 -NoExe
```

If `ps2exe` is missing:

```powershell
Install-Module ps2exe -Scope CurrentUser
```

## Notes

- A clean result does not guarantee a jar is safe.
- This tool is meant to surface suspicious or disguised behavior quickly and explain why it was flagged.
- Online Modrinth verification is attempted when available and can be disabled with `-NoOnlineVerification`.
- Java memory scanning may need elevated privileges to read every process cleanly.

## Credits

This build was inspired by earlier community analyzers and keeps clear credit to the original creators:

- Yumiko Mod Analyzer by Veridon: https://github.com/veridondevvv/YumikoModAnalyzer
- Yarp's Mod Analyzer by YarpLetapStan: https://github.com/YarpLetapStan/PowershellScripts
- Meow Mod Analyzer inspiration by MeowTonynoh: https://github.com/MeowTonynoh

## Suggested Repository Name

`xkzutos-mod-analyzer`
