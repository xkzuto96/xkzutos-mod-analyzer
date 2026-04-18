[CmdletBinding()]
param(
    [switch]$NoExe
)

Set-StrictMode -Version 3
$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$scriptPath = Join-Path $projectRoot "XkzutosModAnalyzer.ps1"
$distRoot = Join-Path $projectRoot "dist"
$releaseRoot = Join-Path $distRoot "release"
$zipPath = Join-Path $distRoot "xkzutos-mod-analyzer.zip"
$exePath = Join-Path $distRoot "XkzutosModAnalyzer.exe"

New-Item -ItemType Directory -Path $distRoot -Force | Out-Null
New-Item -ItemType Directory -Path $releaseRoot -Force | Out-Null

Copy-Item -LiteralPath $scriptPath -Destination (Join-Path $releaseRoot "XkzutosModAnalyzer.ps1") -Force
Copy-Item -LiteralPath (Join-Path $projectRoot "README.md") -Destination (Join-Path $releaseRoot "README.md") -Force
if (Test-Path -LiteralPath (Join-Path $projectRoot ".gitignore")) {
    Copy-Item -LiteralPath (Join-Path $projectRoot ".gitignore") -Destination (Join-Path $releaseRoot ".gitignore") -Force
}

if (Test-Path -LiteralPath $zipPath) {
    Remove-Item -LiteralPath $zipPath -Force
}

Compress-Archive -Path (Join-Path $releaseRoot "*") -DestinationPath $zipPath -Force
Write-Host "Created archive: $zipPath" -ForegroundColor Green

if ($NoExe) {
    Write-Host "Skipped EXE build." -ForegroundColor Yellow
    return
}

$ps2exeCommand = Get-Command Invoke-PS2EXE -ErrorAction SilentlyContinue
$ps2exeScript = $null
$desktopPowerShell = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"
if (-not $ps2exeCommand) {
    try {
        Import-Module ps2exe -ErrorAction Stop
        $ps2exeCommand = Get-Command Invoke-PS2EXE -ErrorAction SilentlyContinue
    } catch {
        $ps2exeCommand = $null
    }
}

try {
    $ps2exeModule = Get-Module -ListAvailable ps2exe | Select-Object -First 1
    if ($ps2exeModule) {
        $candidateScript = Join-Path $ps2exeModule.ModuleBase "ps2exe.ps1"
        if (Test-Path -LiteralPath $candidateScript) {
            $ps2exeScript = $candidateScript
        }
    }
} catch {
    $ps2exeScript = $null
}

if (-not $ps2exeCommand) {
    Write-Warning "PS2EXE is not installed. Install it with: Install-Module ps2exe -Scope CurrentUser"
    return
}

if ($ps2exeScript) {
    if (-not (Test-Path -LiteralPath $desktopPowerShell)) {
        throw "Windows PowerShell 5.1 was not found at $desktopPowerShell"
    }

    $escapedPs2ExeScript = $ps2exeScript.Replace("'", "''")
    $escapedInput = $scriptPath.Replace("'", "''")
    $escapedOutput = $exePath.Replace("'", "''")
    $command = @"
. '$escapedPs2ExeScript'
Invoke-ps2exe -inputFile '$escapedInput' -outputFile '$escapedOutput' -title 'Xkzutos Mod Analyzer' -description 'Minecraft mod analyzer with explainable heuristics and console-first runtime scanning.' -company 'xKzuto' -product 'Xkzutos Mod Analyzer' -nested
"@
    & $desktopPowerShell -NoProfile -ExecutionPolicy Bypass -Command $command
    if ($LASTEXITCODE -ne 0) {
        throw "Windows PowerShell PS2EXE compile failed with exit code $LASTEXITCODE"
    }
} else {
    Invoke-PS2EXE -InputFile $scriptPath -OutputFile $exePath -Title "Xkzutos Mod Analyzer" -Description "Minecraft mod analyzer with explainable heuristics and console-first runtime scanning." -Company "xKzuto" -Product "Xkzutos Mod Analyzer"
}
if (-not (Test-Path -LiteralPath $exePath)) {
    throw "PS2EXE did not create the expected executable at $exePath"
}

Write-Host "Created executable: $exePath" -ForegroundColor Green
