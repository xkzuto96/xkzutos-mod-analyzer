# xkzuto's mod analyzer

Console-first Minecraft mod analyzer for catching suspicious or disguised cheat mods with clear reasons.

## One Command

Use this exact GitHub raw command:

```powershell
powershell -ExecutionPolicy Bypass -Command "Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/xkzuto96/xkzutos-mod-analyzer/main/XkzutosModAnalyzer.ps1')"
```

That runs the analyzer directly in console mode and prompts for the mods folder or jar path, similar to a simple single-file analyzer script.

## Local Run

```powershell
powershell -ExecutionPolicy Bypass -File .\XkzutosModAnalyzer.ps1
```

## Optional Flags

Scan a specific folder:

```powershell
powershell -ExecutionPolicy Bypass -File .\XkzutosModAnalyzer.ps1 -Path "$env:APPDATA\.minecraft\mods"
```

Scan one jar:

```powershell
powershell -ExecutionPolicy Bypass -File .\XkzutosModAnalyzer.ps1 -Path "C:\path\to\mod.jar"
```

Include runtime Java checks:

```powershell
powershell -ExecutionPolicy Bypass -File .\XkzutosModAnalyzer.ps1 -Path "$env:APPDATA\.minecraft\mods" -RuntimeScan
```

Include memory scan:

```powershell
powershell -ExecutionPolicy Bypass -File .\XkzutosModAnalyzer.ps1 -Path "$env:APPDATA\.minecraft\mods" -RuntimeScan -MemoryScan
```

Export JSON:

```powershell
powershell -ExecutionPolicy Bypass -File .\XkzutosModAnalyzer.ps1 -Path "$env:APPDATA\.minecraft\mods" -OutFile ".\report.json" -OutputFormat Json
```

## What It Flags

- placeholder or fake metadata like `template-mod` or `com.example`
- large hidden short-name packages like `a/` or `b/`
- suspicious mixins and client-side injection helpers
- role mismatches, like a fake performance mod containing combat or UI code
- runtime Java agent and loader injection arguments
- optional memory hits for suspicious runtime strings

## Credits

- Yumiko Mod Analyzer by Veridon: https://github.com/veridondevvv/YumikoModAnalyzer
- Yarp's Mod Analyzer by YarpLetapStan: https://github.com/YarpLetapStan/PowershellScripts
- Meow Mod Analyzer inspiration by MeowTonynoh: https://github.com/MeowTonynoh
