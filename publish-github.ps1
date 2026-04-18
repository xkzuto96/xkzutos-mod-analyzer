[CmdletBinding()]
param(
    [string]$Owner = "xkzuto96",
    [string]$RepoName = "xkzutos-mod-analyzer",
    [ValidateSet("public", "private")]
    [string]$Visibility = "public",
    [string]$GitName = "xkzuto",
    [string]$GitEmail = "237636234+xkzuto96@users.noreply.github.com"
)

Set-StrictMode -Version 3
$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $projectRoot

if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
    throw "GitHub CLI was not found. Install it from https://cli.github.com/"
}

$authStatus = & gh auth status 2>&1
if ($LASTEXITCODE -ne 0) {
    throw "GitHub CLI is not authenticated. Run 'gh auth login -h github.com' first, then run this script again."
}

if (-not (Test-Path -LiteralPath (Join-Path $projectRoot ".git"))) {
    & git init -b main | Out-Null
}

$localName = & git config user.name 2>$null
if (-not $localName) {
    & git config user.name $GitName
}

$localEmail = & git config user.email 2>$null
if (-not $localEmail) {
    & git config user.email $GitEmail
}

& git add .

$stagedOutput = & git diff --cached --name-only
$hasStagedChanges = if ($null -ne $stagedOutput) { ($stagedOutput | Out-String).Trim() } else { "" }
$hasCommits = $true
& git rev-parse --verify HEAD 1>$null 2>$null
if ($LASTEXITCODE -ne 0) {
    $hasCommits = $false
}

if ($hasStagedChanges -or -not $hasCommits) {
    & git commit -m "Initial release of xkzuto's mod analyzer"
}

$fullRepo = "$Owner/$RepoName"
& gh repo view $fullRepo 1>$null 2>$null
if ($LASTEXITCODE -ne 0) {
    & gh repo create $fullRepo --$Visibility --source . --remote origin --push
} else {
    & git remote get-url origin 1>$null 2>$null
    if ($LASTEXITCODE -ne 0) {
        & git remote add origin "https://github.com/$fullRepo.git"
    }

    & git push -u origin main
}

Write-Host ""
Write-Host "GitHub repo ready: https://github.com/$fullRepo" -ForegroundColor Green
Write-Host "Safe GUI run command:" -ForegroundColor Cyan
$safeCommand = "powershell -NoProfile -ExecutionPolicy Bypass -Command `"`$url='https://raw.githubusercontent.com/$Owner/$RepoName/main/XkzutosModAnalyzer.ps1'; `$tmp=Join-Path `$env:TEMP 'XkzutosModAnalyzer.ps1'; Invoke-WebRequest -UseBasicParsing -Uri `$url -OutFile `$tmp; & `$tmp -Gui`""
Write-Host $safeCommand -ForegroundColor White
