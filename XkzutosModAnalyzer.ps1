[CmdletBinding()]
param(
    [string]$Path,
    [switch]$SkipRuntimeScan,
    [switch]$SkipMemoryScan,
    [ValidateRange(32, 1024)]
    [int]$MemoryScanMB = 192,
    [switch]$NoModVerification,
    [switch]$NoMegabase,
    [switch]$RevealHidden,
    [switch]$NoStatusLists,
    [switch]$ShowStatusLists,
    [switch]$Quiet
)

Set-StrictMode -Version 3
$ErrorActionPreference = "Stop"

$script:Config = @{
    Name = "xkzuto's mod analyzer"
    Version = "2.0.10"
    Creator = "xKzuto"
    Credits = @(
        [pscustomobject]@{
            Name = "MeowTonynoh"
            Project = "Meow Mod Analyzer"
            Url = "https://github.com/MeowTonynoh"
        },
        [pscustomobject]@{
            Name = "YarpLetapStan"
            Project = "Yarp's Mod Analyzer"
            Url = "https://github.com/YarpLetapStan/PowershellScripts"
        },
        [pscustomobject]@{
            Name = "veridondevvv"
            Project = "Yumiko Mod Analyzer"
            Url = "https://github.com/veridondevvv/YumikoModAnalyzer"
        }
    )
    ModCheatTokens = @(
        "autoclicker",
        "aimassist",
        "aim assist",
        "autocrystal",
        "auto crystal",
        "autohitcrystal",
        "autoanchor",
        "anchor macro",
        "anchortweaks",
        "doubleanchor",
        "safeanchor",
        "airanchor",
        "autototem",
        "auto totem",
        "inventorytotem",
        "hovertotem",
        "legittotem",
        "autopot",
        "autoarmor",
        "autoeat",
        "automine",
        "automace",
        "maceswap",
        "spearswap",
        "autodoublehand",
        "shielddisabler",
        "shieldbreaker",
        "triggerbot",
        "silentaim",
        "silent rotations",
        "fakelag",
        "pingspoof",
        "fakeinv",
        "webmacro",
        "authbypass",
        "obfuscatedauth",
        "licensecheckmixin",
        "clientplayerinteractionmanageraccessor",
        "clientplayerentitymixim",
        "itemexploit",
        "invsee",
        "basefinder",
        "packspoof",
        "antiknockback",
        "lagreach",
        "jumpreset",
        "axespam",
        "autofirework",
        "elytraswap",
        "fastxp",
        "fastexp",
        "nojumpdelay",
        "noclip",
        "freecam",
        "freezeplayer",
        "autobreach",
        "keypearl",
        "lootyeeter",
        "walksyoptimizer",
        "walskyoptimizer",
        "walksycrystaloptimizermod",
        "dqrkis",
        "argon",
        "xenon",
        "catlean",
        "gypsy",
        "hellion",
        "dev.krypton",
        "dev.gambleclient",
        "org.chainlibs.module.impl.modules.crystal",
        "org.chainlibs.module.impl.modules.blatant",
        "jnativehook",
        "phantom-refmap",
        "ghost client",
        "cracked client",
        "cracked",
        "reach",
        "velocity",
        "killaura",
        "scaffold",
        "fly",
        "speed",
        "esp",
        "xray",
        "selfdestruct",
        "self destruct",
        "bypass",
        "exploit"
    )
    TokenWeights = @{
        autoclicker = 3
        aimassist = 3
        "aim assist" = 3
        autocrystal = 3
        "auto crystal" = 2
        autohitcrystal = 3
        autoanchor = 3
        "anchor macro" = 2
        doubleanchor = 2
        safeanchor = 2
        autototem = 3
        "auto totem" = 3
        inventorytotem = 3
        hovertotem = 3
        legittotem = 2
        autopot = 2
        autoarmor = 2
        automace = 2
        maceswap = 2
        spearswap = 2
        shielddisabler = 3
        shieldbreaker = 3
        triggerbot = 3
        silentaim = 3
        pingspoof = 2
        fakeinv = 2
        fakelag = 2
        webmacro = 2
        authbypass = 4
        obfuscatedauth = 4
        licensecheckmixin = 4
        itemexploit = 3
        basefinder = 2
        packspoof = 2
        antiknockback = 2
        lagreach = 2
        jumpreset = 2
        axespam = 2
        autofirework = 2
        elytraswap = 2
        fastxp = 2
        fastexp = 2
        nojumpdelay = 2
        noclip = 2
        freecam = 2
        freezeplayer = 2
        autobreach = 2
        lootyeeter = 2
        walksyoptimizer = 4
        walskyoptimizer = 4
        walksycrystaloptimizermod = 4
        dqrkis = 4
        argon = 3
        xenon = 3
        catlean = 3
        gypsy = 3
        hellion = 3
        "dev.krypton" = 4
        "dev.gambleclient" = 4
        "org.chainlibs.module.impl.modules.crystal" = 4
        "org.chainlibs.module.impl.modules.blatant" = 4
        jnativehook = 3
        "phantom-refmap" = 3
        "ghost client" = 4
        "cracked client" = 4
        cracked = 2
        killaura = 3
        xray = 3
        selfdestruct = 3
        "self destruct" = 3
        bypass = 3
        exploit = 3
        scaffold = 2
        fly = 2
        reach = 2
        esp = 2
        velocity = 1
        speed = 1
    }
    CriticalCheatTokens = @(
        "dqrkis",
        "walksyoptimizer",
        "walskyoptimizer",
        "walksycrystaloptimizermod",
        "authbypass",
        "obfuscatedauth",
        "licensecheckmixin",
        "dev.krypton",
        "dev.gambleclient",
        "org.chainlibs.module.impl.modules.crystal",
        "org.chainlibs.module.impl.modules.blatant",
        "ghost client",
        "cracked client",
        "catlean",
        "xenon",
        "gypsy",
        "hellion"
    )
    MemoryFilterStrings = @(
        "Doomsday",
        "DoomsdayClient",
        "DoomsdayClient:::bot),%.R",
        "DoomsdayClient:::u;<r,7NVce;Ga25",
        "DoomsdayClient:::eObOiPdFJR 2",
        "DoomsdayClient:::Wu&XNC]30?3=7",
        "prestige",
        "*.prestigeclient.vip0",
        "prestigeclient.vip",
        "prestigeclient.vip0Y0",
        "prestige_4.properties",
        ".prestigeclient.vip0",
        "assets/minecraft/optifine/cit/profile/prestige/",
        ".psaclient",
        "198m",
        "Auto Crystal",
        "Anchor Macro",
        "fastplace",
        "autocrystal",
        "legit totem",
        "CrystalAura",
        "AnchorAura",
        "LegitRetotem",
        "Auto Dtap",
        "Auto Hit Crystal",
        "Self Destruct",
        "AutoInventoryTotem",
        "Auto Shield Disabler",
        "Auto Mace",
        "Aimbot"
    )
    RuntimeInjectionPatterns = @(
        [pscustomobject]@{ Label = "Java agent injection"; Pattern = "(?i)-javaagent:" },
        [pscustomobject]@{ Label = "Native agent injection"; Pattern = "(?i)-agentpath:" },
        [pscustomobject]@{ Label = "Agent library injection"; Pattern = "(?i)-agentlib:" },
        [pscustomobject]@{ Label = "Boot classpath injection"; Pattern = "(?i)-Xbootclasspath" },
        [pscustomobject]@{ Label = "Fabric addMods injection"; Pattern = "(?i)-Dfabric\.addMods=" },
        [pscustomobject]@{ Label = "Fabric loadMods injection"; Pattern = "(?i)-Dfabric\.loadMods=" },
        [pscustomobject]@{ Label = "Fabric classPathGroups injection"; Pattern = "(?i)-Dfabric\.classPathGroups=" },
        [pscustomobject]@{ Label = "Fabric gameJarPath override"; Pattern = "(?i)-Dfabric\.gameJarPath=" },
        [pscustomobject]@{ Label = "Fabric skipMcProvider override"; Pattern = "(?i)-Dfabric\.skipMcProvider=" },
        [pscustomobject]@{ Label = "Fabric development override"; Pattern = "(?i)-Dfabric\.development=" },
        [pscustomobject]@{ Label = "Fabric unsupported version override"; Pattern = "(?i)-Dfabric\.allowUnsupportedVersion=" },
        [pscustomobject]@{ Label = "Fabric remapClasspathFile injection"; Pattern = "(?i)-Dfabric\.remapClasspathFile=" },
        [pscustomobject]@{ Label = "Fabric skipIntermediary override"; Pattern = "(?i)-Dfabric\.skipIntermediary=" },
        [pscustomobject]@{ Label = "Fabric configDir override"; Pattern = "(?i)-Dfabric\.configDir=" },
        [pscustomobject]@{ Label = "Fabric loader config override"; Pattern = "(?i)-Dfabric\.loader\.config=" },
        [pscustomobject]@{ Label = "Fabric log level override"; Pattern = "(?i)-Dfabric\.log\.level=" },
        [pscustomobject]@{ Label = "Fabric debug classpath dump"; Pattern = "(?i)-Dfabric\.debug\.dumpClasspath=" },
        [pscustomobject]@{ Label = "Fabric log config override"; Pattern = "(?i)-Dfabric\.log\.config=" },
        [pscustomobject]@{ Label = "Fabric DLI config override"; Pattern = "(?i)-Dfabric\.dli\.config=" },
        [pscustomobject]@{ Label = "Fabric mixin configs injection"; Pattern = "(?i)-Dfabric\.mixin\.configs=" },
        [pscustomobject]@{ Label = "Fabric mixin hotSwap override"; Pattern = "(?i)-Dfabric\.mixin\.hotSwap=" },
        [pscustomobject]@{ Label = "Fabric mixin debug export"; Pattern = "(?i)-Dfabric\.mixin\.debug\.export=" },
        [pscustomobject]@{ Label = "Fabric mixin verbose debug"; Pattern = "(?i)-Dfabric\.mixin\.debug\.verbose=" },
        [pscustomobject]@{ Label = "Fabric gameVersion override"; Pattern = "(?i)-Dfabric\.gameVersion=" },
        [pscustomobject]@{ Label = "Fabric forceVersion override"; Pattern = "(?i)-Dfabric\.forceVersion=" },
        [pscustomobject]@{ Label = "Fabric autoDetectVersion override"; Pattern = "(?i)-Dfabric\.autoDetectVersion=" },
        [pscustomobject]@{ Label = "Fabric launcher name override"; Pattern = "(?i)-Dfabric\.launcher\.name=" },
        [pscustomobject]@{ Label = "Fabric launcher brand override"; Pattern = "(?i)-Dfabric\.launcher\.brand=" },
        [pscustomobject]@{ Label = "Fabric mods.toml path override"; Pattern = "(?i)-Dfabric\.mods\.toml\.path=" },
        [pscustomobject]@{ Label = "Fabric custom mod list injection"; Pattern = "(?i)-Dfabric\.customModList=" },
        [pscustomobject]@{ Label = "Fabric resolve modFiles override"; Pattern = "(?i)-Dfabric\.resolve\.modFiles=" },
        [pscustomobject]@{ Label = "Fabric skip dependency resolution"; Pattern = "(?i)-Dfabric\.skipDependencyResolution=" },
        [pscustomobject]@{ Label = "Fabric loader entrypoints injection"; Pattern = "(?i)-Dfabric\.loader\.entrypoints=" },
        [pscustomobject]@{ Label = "Fabric language providers injection"; Pattern = "(?i)-Dfabric\.language\.providers=" },
        [pscustomobject]@{ Label = "Forge addMods injection"; Pattern = "(?i)-Dforge\.addMods=" },
        [pscustomobject]@{ Label = "Forge mods override"; Pattern = "(?i)-Dforge\.mods=" },
        [pscustomobject]@{ Label = "Forge coremod load injection"; Pattern = "(?i)-Dfml\.coreMods\.load=" },
        [pscustomobject]@{ Label = "Forge coreMods dir override"; Pattern = "(?i)-Dforge\.coreMods\.dir=" },
        [pscustomobject]@{ Label = "Forge modDir override"; Pattern = "(?i)-Dforge\.modDir=" },
        [pscustomobject]@{ Label = "Forge modsDirectories override"; Pattern = "(?i)-Dforge\.modsDirectories=" },
        [pscustomobject]@{ Label = "FML custom mod list injection"; Pattern = "(?i)-Dfml\.customModList=" },
        [pscustomobject]@{ Label = "Forge disable mod scan override"; Pattern = "(?i)-Dforge\.disableModScan=" },
        [pscustomobject]@{ Label = "Forge modList override"; Pattern = "(?i)-Dforge\.modList=" },
        [pscustomobject]@{ Label = "Forge forceVersion override"; Pattern = "(?i)-Dforge\.forceVersion=" },
        [pscustomobject]@{ Label = "Forge disable update check"; Pattern = "(?i)-Dforge\.disableUpdateCheck=" },
        [pscustomobject]@{ Label = "Forge Mojang logging override"; Pattern = "(?i)-Dforge\.logging\.mojang\.level=" },
        [pscustomobject]@{ Label = "Forge mixin hotSwap override"; Pattern = "(?i)-Dforge\.mixin\.hotSwap=" },
        [pscustomobject]@{ Label = "Forge resourcePack override"; Pattern = "(?i)-Dforge\.resourcePack=" },
        [pscustomobject]@{ Label = "Forge defaultResourcePack override"; Pattern = "(?i)-Dforge\.defaultResourcePack=" },
        [pscustomobject]@{ Label = "Forge texturePacks override"; Pattern = "(?i)-Dforge\.texturePacks=" },
        [pscustomobject]@{ Label = "Forge assetIndex override"; Pattern = "(?i)-Dforge\.assetIndex=" },
        [pscustomobject]@{ Label = "Forge assetsDir override"; Pattern = "(?i)-Dforge\.assetsDir=" },
        [pscustomobject]@{ Label = "System classloader override"; Pattern = "(?i)-Djava\.system\.class\.loader=" },
        [pscustomobject]@{ Label = "Class path override"; Pattern = "(?i)-Djava\.class\.path=" },
        [pscustomobject]@{ Label = "Encoded injection symbols"; Pattern = "(?i)(%3B|%26%26|%7C%7C|%7C|%60|%24|%3C|%3E)" }
    )
    LegitAgentHints = @(
        "jmxremote",
        "jacoco",
        "newrelic",
        "jrebel",
        "yjp",
        "theseus",
        "lombok",
        "byte-buddy",
        "idea_rt",
        "intellij",
        "jetbrains",
        "visualvm",
        "async-profiler",
        "hprof",
        "flightrecorder",
        "jfr"
    )
    LegitAgentPathHints = @(
        "\\projectlombok\\",
        "\\.gradle\\caches\\",
        "\\m2\\repository\\",
        "\\jetbrains\\",
        "\\intellij",
        "\\eclipse\\",
        "\\jdk\\",
        "\\java\\",
        "\\microsoft\\jdk\\",
        "\\temurin\\",
        "\\modrinthapp\\",
        "\\prismlauncher\\",
        "\\multimc\\",
        "\\lunarclient\\",
        "\\badlion\\",
        "\\curseforge\\",
        "\\.minecraft\\libraries\\"
    )
    SuspiciousAgentHints = @(
        "inject",
        "bypass",
        "cheat",
        "ghost",
        "clicker",
        "aim",
        "killaura",
        "triggerbot",
        "reach",
        "velocity",
        "xray",
        "selfdestruct",
        "dqrkis",
        "argon",
        "walksy",
        "walsky",
        "catlean",
        "xenon",
        "gypsy"
    )
    RuntimeHighRiskLabels = @(
        "Native agent injection",
        "Agent library injection",
        "Boot classpath injection",
        "Fabric addMods injection",
        "Fabric loadMods injection",
        "Fabric remapClasspathFile injection",
        "Fabric custom mod list injection",
        "Fabric resolve modFiles override",
        "Fabric loader entrypoints injection",
        "Fabric language providers injection",
        "Forge addMods injection",
        "Forge coremod load injection",
        "Forge coreMods dir override",
        "Forge modDir override",
        "Forge modsDirectories override",
        "FML custom mod list injection",
        "Forge modList override",
        "System classloader override",
        "Encoded injection symbols"
    )
    RuntimeEditGraceSeconds = 3
}

$script:ModTokenPatterns = @()
foreach ($token in $script:Config.ModCheatTokens) {
    $escaped = [regex]::Escape($token) -replace "\\ ", "[\\s_\\-]*"
    $pattern = "(?i)(?<![a-z0-9])$escaped(?![a-z0-9])"
    $script:ModTokenPatterns += [pscustomobject]@{
        Token = $token
        Regex = [regex]::new($pattern)
    }
}

$script:MemoryNeedlesNormalized = @(
    $script:Config.MemoryFilterStrings |
        ForEach-Object {
            $n = ([string]$_).Trim().ToLowerInvariant()
            if ($n.StartsWith("*")) { $n = $n.TrimStart("*") }
            if ($n.EndsWith("*")) { $n = $n.TrimEnd("*") }
            $n
        } |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        Select-Object -Unique
)

$script:MemoryApiLoaded = $false
$script:PathWasExplicit = $PSBoundParameters.ContainsKey("Path") -and -not [string]::IsNullOrWhiteSpace($Path)
$script:ProgressIds = @{
    Hidden = 10
    Mods = 11
    Runtime = 12
    MemoryTargets = 13
    MemoryBytes = 14
}

function Disable-XmaConsoleQuickEdit {
    # Prevent console freeze when the user clicks/selects text in the window.
    try {
        if (-not ("XmaConsoleNative" -as [type])) {
            Add-Type @"
using System;
using System.Runtime.InteropServices;

public static class XmaConsoleNative {
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr GetStdHandle(int nStdHandle);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool GetConsoleMode(IntPtr hConsoleHandle, out int lpMode);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool SetConsoleMode(IntPtr hConsoleHandle, int dwMode);
}
"@ -ErrorAction Stop
        }

        $stdInputHandle = [XmaConsoleNative]::GetStdHandle(-10)
        $invalidHandle = [IntPtr]::new(-1)
        if ($stdInputHandle -eq [IntPtr]::Zero -or $stdInputHandle -eq $invalidHandle) {
            return
        }

        $mode = 0
        if (-not [XmaConsoleNative]::GetConsoleMode($stdInputHandle, [ref]$mode)) {
            return
        }

        $enableExtendedFlags = 0x0080
        $enableQuickEditMode = 0x0040
        $newMode = $mode -bor $enableExtendedFlags
        $newMode = $newMode -band (-bnot $enableQuickEditMode)
        if ($newMode -ne $mode) {
            [void][XmaConsoleNative]::SetConsoleMode($stdInputHandle, $newMode)
        }
    } catch {
    }
}

function Write-XmaProgress {
    param(
        [Parameter(Mandatory)]
        [int]$Id,
        [Parameter(Mandatory)]
        [string]$Activity,
        [Parameter(Mandatory)]
        [string]$Status,
        [double]$Current = 0,
        [double]$Total = 100
    )

    if ($Quiet) { return }
    $safeTotal = if ($Total -le 0) { 1 } else { $Total }
    $safeCurrent = [Math]::Max(0, [Math]::Min($Current, $safeTotal))
    $percent = [int][Math]::Floor(($safeCurrent / [double]$safeTotal) * 100)
    Write-Progress -Id $Id -Activity $Activity -Status $Status -PercentComplete $percent
}

function Complete-XmaProgress {
    param(
        [Parameter(Mandatory)]
        [int]$Id,
        [Parameter(Mandatory)]
        [string]$Activity
    )

    if ($Quiet) { return }
    Write-Progress -Id $Id -Activity $Activity -Completed
}

function Write-XmaRule {
    param([string]$Color = "DarkGray")
    if ($Quiet) { return }
    Write-Host ("=" * 70) -ForegroundColor $Color
}

function Write-XmaSection {
    param(
        [Parameter(Mandatory)]
        [string]$Title,
        [string]$Color = "Cyan"
    )

    if ($Quiet) { return }
    Write-Host ""
    Write-Host ("[ " + $Title + " ]") -ForegroundColor $Color
}

function Write-XmaSummaryLine {
    param(
        [Parameter(Mandatory)]
        [string]$Label,
        [Parameter(Mandatory)]
        [int]$Count,
        [Parameter(Mandatory)]
        [int]$Total,
        [Parameter(Mandatory)]
        [string]$Color
    )

    $safeTotal = if ($Total -le 0) { 1 } else { $Total }
    $pct = [math]::Round(($Count / [double]$safeTotal) * 100, 1)
    $line = "{0,-18} {1,4}/{2,-4} ({3,5}%)" -f ($Label + ":"), $Count, $Total, $pct
    Write-Host $line -ForegroundColor $Color
}

function Format-XmaDuration {
    param([timespan]$Span)

    if ($Span.TotalSeconds -lt 0) {
        $Span = [timespan]::Zero
    }

    $hours = [int][math]::Floor($Span.TotalHours)
    return "{0:00}:{1:00}:{2:00}" -f $hours, $Span.Minutes, $Span.Seconds
}

function Test-XmaLikelyLauncherModsPath {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return $false
    }

    $normalized = ([string]$Path).Trim().Trim('"').Trim("'").ToLowerInvariant()
    if ($normalized.EndsWith("\\")) {
        $normalized = $normalized.TrimEnd('\\')
    }

    $leaf = ""
    try {
        $leaf = ([System.IO.Path]::GetFileName($normalized)).ToLowerInvariant()
    } catch {
        $leaf = ""
    }

    if ($leaf -ne "mods") {
        return $false
    }

    if ($normalized -match '(?i)\.minecraft|modrinthapp|prismlauncher|multimc|curseforge|lunarclient|badlion|feather|launcher') {
        return $true
    }

    return $false
}

function Get-XmaRuntimeWindowInfo {
    param(
        [object[]]$RuntimeTargets,
        [datetime]$WindowEndUtc
    )

    $targetsWithStart = @($RuntimeTargets | Where-Object { $_.StartTimeUtc -is [datetime] })
    if ($targetsWithStart.Count -eq 0) {
        return [pscustomobject]@{
            HasWindow = $false
            WindowStartUtc = $null
            WindowEndUtc = $WindowEndUtc
            TargetCount = 0
        }
    }

    $windowStartUtc = ($targetsWithStart | Measure-Object -Property StartTimeUtc -Minimum).Minimum
    return [pscustomobject]@{
        HasWindow = $true
        WindowStartUtc = $windowStartUtc
        WindowEndUtc = $WindowEndUtc
        TargetCount = $targetsWithStart.Count
    }
}

function Apply-XmaRuntimeEditFlags {
    param(
        [object[]]$Reports,
        [object]$RuntimeWindowInfo,
        [int]$GraceSeconds = 3
    )

    $flagged = New-Object System.Collections.Generic.List[object]
    if (-not $RuntimeWindowInfo -or -not $RuntimeWindowInfo.HasWindow) {
        return @($flagged.ToArray())
    }

    $startUtc = $RuntimeWindowInfo.WindowStartUtc.AddSeconds(-1 * [Math]::Max(0, $GraceSeconds))
    $endUtc = $RuntimeWindowInfo.WindowEndUtc.AddSeconds([Math]::Max(0, $GraceSeconds))

    foreach ($r in $Reports) {
        $lastWriteUtc = $null
        try {
            $lastWriteUtc = (Get-Item -LiteralPath $r.FilePath -Force -ErrorAction Stop).LastWriteTimeUtc
        } catch {
            continue
        }

        if (-not ($lastWriteUtc -is [datetime])) {
            continue
        }

        if ($lastWriteUtc -lt $startUtc -or $lastWriteUtc -gt $endUtc) {
            continue
        }

        $startLocal = $RuntimeWindowInfo.WindowStartUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss")
        $endLocal = $RuntimeWindowInfo.WindowEndUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss")
        $editLocal = $lastWriteUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss")
        $reasonA = "Jar edit time overlaps active Java runtime window ($startLocal -> $endLocal, edited: $editLocal)."
        $reasonB = "Exact content diff is unavailable without a baseline snapshot from before launch."

        $existingReasons = @($r.Reasons)
        $existingReasons += $reasonA
        $existingReasons += $reasonB
        $r.Reasons = @($existingReasons | Select-Object -Unique)

        if ($r.Status -eq "Verified") {
            $r.Status = "Review (Verified)"
        } elseif ($r.Status -eq "Unknown") {
            $r.Status = "Review"
        }

        $r | Add-Member -NotePropertyName EditedDuringRuntime -NotePropertyValue $true -Force
        $r | Add-Member -NotePropertyName LastWriteTimeLocal -NotePropertyValue $editLocal -Force
        $flagged.Add($r)
    }

    return @($flagged.ToArray())
}

function Get-XmaCommandTokens {
    param([string]$CommandLine)

    if ([string]::IsNullOrWhiteSpace($CommandLine)) {
        return @()
    }

    $tokens = New-Object System.Collections.Generic.List[object]
    $matches = [regex]::Matches($CommandLine, '"[^"]*"|''[^'']*''|\S+')
    foreach ($m in $matches) {
        $tokens.Add([pscustomobject]@{
            Text = $m.Value
            Start = $m.Index
            End = ($m.Index + $m.Length - 1)
        })
    }

    return @($tokens.ToArray())
}

function Get-XmaTokenAtPosition {
    param(
        [object[]]$Tokens,
        [int]$Position
    )

    foreach ($token in @($Tokens)) {
        if ($Position -ge $token.Start -and $Position -le $token.End) {
            return $token
        }
    }

    return $null
}

function Normalize-XmaJarPathCandidate {
    param([string]$Candidate)

    if ([string]::IsNullOrWhiteSpace($Candidate)) {
        return ""
    }

    $normalized = [string]$Candidate
    $normalized = $normalized.Trim().Trim('"').Trim("'").Trim()

    if ($normalized -match '^[^=]+=(.+)$') {
        $normalized = $matches[1].Trim()
    }
    if ($normalized -match '^(?i)-javaagent:(.+)$') {
        $normalized = $matches[1].Trim()
    } elseif ($normalized -match '^(?i)-agentpath:(.+)$') {
        $normalized = $matches[1].Trim()
    }

    $normalized = $normalized.Trim().Trim('"').Trim("'").Trim()
    $normalized = $normalized.TrimEnd(",", ";")

    try {
        $expanded = [Environment]::ExpandEnvironmentVariables($normalized)
        if (-not [string]::IsNullOrWhiteSpace($expanded)) {
            $normalized = $expanded
        }
    } catch {
    }

    try {
        if ($normalized.Contains("%")) {
            $decoded = [uri]::UnescapeDataString($normalized)
            if (-not [string]::IsNullOrWhiteSpace($decoded)) {
                $normalized = $decoded
            }
        }
    } catch {
    }

    if ($normalized -match '^(?i)file:(/+)?(.+)$') {
        $normalized = $matches[2]
        $normalized = $normalized -replace '/', '\\'
    }

    $normalized = $normalized -replace '[?#].*$', ''
    $normalized = $normalized.Trim().Trim('"').Trim("'").Trim()

    if ([string]::IsNullOrWhiteSpace($normalized)) {
        return ""
    }

    if ($normalized -notmatch '(?i)\.(jar|zip)$') {
        return ""
    }

    return $normalized
}

function Get-XmaJavaAgentAssessment {
    param([string]$AgentArgument)

    $agentPath = Normalize-XmaJarPathCandidate -Candidate $AgentArgument
    if ([string]::IsNullOrWhiteSpace($agentPath)) {
        $agentPath = ([string]$AgentArgument).Trim().Trim('"').Trim("'")
    }

    $agentName = [System.IO.Path]::GetFileName($agentPath)
    $lowerName = ([string]$agentName).ToLowerInvariant()
    $lowerPath = ([string]$agentPath).ToLowerInvariant()

    $trustedByName = $false
    foreach ($hint in @($script:Config.LegitAgentHints)) {
        $hintText = ([string]$hint).ToLowerInvariant()
        if (-not [string]::IsNullOrWhiteSpace($hintText) -and $lowerName.Contains($hintText)) {
            $trustedByName = $true
            break
        }
    }

    $trustedByPath = $false
    foreach ($hint in @($script:Config.LegitAgentPathHints)) {
        $hintText = ([string]$hint).ToLowerInvariant()
        if (-not [string]::IsNullOrWhiteSpace($hintText) -and $lowerPath.Contains($hintText)) {
            $trustedByPath = $true
            break
        }
    }

    $suspiciousByHint = $false
    foreach ($hint in @($script:Config.SuspiciousAgentHints)) {
        $hintText = ([string]$hint).ToLowerInvariant()
        if ([string]::IsNullOrWhiteSpace($hintText)) {
            continue
        }

        if ($lowerName.Contains($hintText) -or $lowerPath.Contains($hintText)) {
            $suspiciousByHint = $true
            break
        }
    }

    $suspiciousByLocation = $false
    if ($lowerPath.Contains("\\mods\\") -or $lowerPath.Contains("\\versions\\")) {
        $suspiciousByLocation = $true
    }

    $riskLevel = "unrecognized"
    $trustReason = "No trusted hint matched."
    if ($trustedByName) {
        $riskLevel = "trusted"
        $trustReason = "Matched trusted agent name hint."
    } elseif ($trustedByPath) {
        $riskLevel = "trusted"
        $trustReason = "Matched trusted toolchain path hint."
    } elseif ($suspiciousByHint) {
        $riskLevel = "suspicious"
        $trustReason = "Matched suspicious agent hint."
    } elseif ($suspiciousByLocation) {
        $riskLevel = "suspicious"
        $trustReason = "Agent path points to mods/versions location."
    }

    [pscustomobject]@{
        AgentName = $agentName
        AgentPath = $agentPath
        RiskLevel = $riskLevel
        TrustReason = $trustReason
    }
}

function Get-XmaReferencedJarPaths {
    param([string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return @()
    }

    $results = New-Object System.Collections.Generic.List[string]
    $candidates = New-Object System.Collections.Generic.List[string]
    $patterns = @(
        '(?i)"((?:[A-Z]:\\|\\\\)[^"]+\.(?:jar|zip))"',
        "(?i)'((?:[A-Z]:\\|\\\\)[^']+\.(?:jar|zip))'",
        '(?i)((?:[A-Z]:\\|\\\\|\.{1,2}[\\/])[^"''\s,;]+\.(?:jar|zip))'
    )

    foreach ($pattern in $patterns) {
        $matches = [regex]::Matches($Text, $pattern)
        foreach ($m in $matches) {
            $candidate = if ($m.Groups.Count -gt 1) { $m.Groups[1].Value } else { $m.Value }
            if (-not [string]::IsNullOrWhiteSpace($candidate)) {
                $candidates.Add($candidate)
            }
        }
    }

    foreach ($part in @($Text -split "[,;]")) {
        if ([string]::IsNullOrWhiteSpace($part)) {
            continue
        }

        $trimmed = $part.Trim()
        if ([string]::IsNullOrWhiteSpace($trimmed)) {
            continue
        }

        if ($trimmed -match '^[^=]+=(.+)$') {
            $trimmed = $matches[1].Trim()
        }

        if ($trimmed -match '(?i)\.(jar|zip)') {
            $candidates.Add($trimmed)
        }
    }

    foreach ($candidate in @($candidates | Select-Object -Unique)) {
        $normalized = Normalize-XmaJarPathCandidate -Candidate $candidate
        if ([string]::IsNullOrWhiteSpace($normalized)) {
            continue
        }

            if (Test-Path -LiteralPath $normalized) {
                try {
                    $normalized = (Resolve-Path -LiteralPath $normalized -ErrorAction Stop).Path
                } catch {
                }
            }

            $results.Add($normalized)
        }

    return @($results | Select-Object -Unique)
}

function Apply-XmaRuntimeInjectedJarFlags {
    param(
        [object[]]$Reports,
        [object[]]$RuntimeFindings
    )

    $existingByPath = @{}
    foreach ($report in @($Reports)) {
        $existingByPath[$report.FilePath] = $report
    }

    $addedReports = New-Object System.Collections.Generic.List[object]
    $annotatedReports = New-Object System.Collections.Generic.List[object]
    $allReferencedPaths = @(
        $RuntimeFindings |
            ForEach-Object { @($_.ReferencedJarPaths) } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            Select-Object -Unique
    )

    foreach ($path in $allReferencedPaths) {
        $reason = "Referenced by JVM argument injection."
        if ($existingByPath.ContainsKey($path)) {
            $report = $existingByPath[$path]
            $report.Reasons = @(@($report.Reasons) + $reason | Select-Object -Unique)
            if ($report.Status -eq "Verified") {
                $report.Status = "Review (Verified)"
            } elseif ($report.Status -eq "Unknown") {
                $report.Status = "Review"
            }
            $annotatedReports.Add($report)
            continue
        }

        if (-not (Test-Path -LiteralPath $path)) {
            continue
        }

        try {
            attrib -h -s "$path" 2>$null | Out-Null
        } catch {
        }

        try {
            $report = Measure-XmaJar -JarPath $path
            $report.Reasons = @(@($report.Reasons) + $reason | Select-Object -Unique)
            if ($report.Status -eq "Verified") {
                $report.Status = "Review (Verified)"
            } elseif ($report.Status -eq "Unknown") {
                $report.Status = "Review"
            }
            $addedReports.Add($report)
            $existingByPath[$path] = $report
        } catch {
            $addedReports.Add([pscustomobject]@{
                FileName = [System.IO.Path]::GetFileName($path)
                FilePath = $path
                SizeKB = 0
                Sha1 = ""
                Sha256 = ""
                Metadata = $null
                Verification = $null
                DownloadSource = Get-XmaDownloadSource -Path $path
                TokenHits = @()
                SingleLetterClassCount = 0
                ContainsAClass = $false
                ContainsBClass = $false
                Reasons = @($reason, "Injected jar scan error: $($_.Exception.Message)")
                Status = "Review"
            })
        }
    }

    return [pscustomobject]@{
        AddedReports = @($addedReports.ToArray())
        AnnotatedReports = @($annotatedReports.ToArray())
        ReferencedJarPaths = $allReferencedPaths
    }
}

function Write-XmaBanner {
    if ($Quiet) { return }
    Write-Host ""
    Write-XmaRule -Color DarkCyan
    Write-Host "$($script:Config.Name) v$($script:Config.Version)" -ForegroundColor Cyan
    Write-Host "Built by $($script:Config.Creator)" -ForegroundColor White
    Write-Host "Credits: $((@($script:Config.Credits | ForEach-Object { $_.Project + ' / ' + $_.Name }) -join '; '))" -ForegroundColor DarkGray
    Write-XmaRule -Color DarkCyan
    Write-Host ""
}

function Resolve-XmaPath {
    while ($true) {
        $candidate = $Path
        if (-not $candidate) {
            Write-Host "Enter the jar file or mods folder path to scan." -ForegroundColor Cyan
            Write-Host "Type . to use the current folder." -ForegroundColor DarkGray
            Write-Host "Examples: C:\Path\To\mods   or   C:\Path\To\mod.jar" -ForegroundColor DarkGray
            $candidate = Read-Host "Path"
            if ([string]::IsNullOrWhiteSpace($candidate)) {
                Write-Host "A path is required. Paste a path, or type . for current folder." -ForegroundColor Yellow
                Write-Host ""
                continue
            }
        }

        $candidate = $candidate.Trim()
        if ($candidate.StartsWith('"') -and $candidate.EndsWith('"') -and $candidate.Length -ge 2) {
            $candidate = $candidate.Trim('"')
        }

        if ($candidate -eq "." -or $candidate -eq ".\") {
            $candidate = (Get-Location).Path
        }

        if (Test-Path -LiteralPath $candidate) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }

        if ($script:PathWasExplicit) {
            throw "That path does not exist: $candidate"
        }

        Write-Host "That path does not exist: $candidate" -ForegroundColor Yellow
        Write-Host ""
        $Path = $null
    }
}

function Get-XmaFileHashSafe {
    param(
        [Parameter(Mandatory)]
        [string]$Path,
        [ValidateSet("SHA1", "SHA256")]
        [string]$Algorithm = "SHA1"
    )

    try {
        return (Get-FileHash -LiteralPath $Path -Algorithm $Algorithm -ErrorAction Stop).Hash.ToLowerInvariant()
    } catch {
        return ""
    }
}

function Get-XmaDownloadSource {
    param([string]$Path)

    $zoneData = Get-Content -LiteralPath $Path -Raw -Stream Zone.Identifier -ErrorAction SilentlyContinue
    if (-not $zoneData) {
        return ""
    }

    if ($zoneData -match "HostUrl=(.+)") {
        $url = $matches[1].Trim()
        if ($url -match "modrinth\.com") { return "Modrinth" }
        if ($url -match "curseforge\.com") { return "CurseForge" }
        if ($url -match "github\.com") { return "GitHub" }
        if ($url -match "discord\.com|discordapp\.com|cdn\.discordapp\.com") { return "Discord" }
        if ($url -match "mega\.nz|mega\.co\.nz") { return "MEGA" }
        if ($url -match "mediafire\.com") { return "MediaFire" }
        if ($url -match "dropbox\.com") { return "Dropbox" }
        if ($url -match "drive\.google\.com") { return "Google Drive" }
        if ($url -match "https?://(?:www\.)?([^/]+)") { return $matches[1] }
        return $url
    }

    return ""
}

function Get-XmaHiddenJarReport {
    param(
        [Parameter(Mandatory)]
        [string]$FolderPath,
        [switch]$ShowProgress
    )

    $results = New-Object System.Collections.Generic.List[object]
    $jars = @(Get-ChildItem -LiteralPath $FolderPath -Force -File -Filter "*.jar" -ErrorAction SilentlyContinue)
    $total = @($jars).Count
    $index = 0

    foreach ($jar in $jars) {
        $index++
        if ($ShowProgress) {
            Write-XmaProgress -Id $script:ProgressIds.Hidden -Activity "Hidden/system scan" -Status "[$index/$total] $($jar.Name)" -Current $index -Total $total
        }

        try {
            $item = Get-Item -LiteralPath $jar.FullName -Force -ErrorAction Stop
            $attrs = $item.Attributes
            $hasHidden = ($attrs -band [System.IO.FileAttributes]::Hidden) -ne 0
            $hasSystem = ($attrs -band [System.IO.FileAttributes]::System) -ne 0
            if (-not ($hasHidden -or $hasSystem)) {
                continue
            }

            $before = $attrs.ToString()
            attrib -h -s "$($jar.FullName)" 2>$null | Out-Null
            $after = (Get-Item -LiteralPath $jar.FullName -Force).Attributes.ToString()

            $results.Add([pscustomobject]@{
                FileName = $jar.Name
                FilePath = $jar.FullName
                WasHidden = $hasHidden
                WasSystem = $hasSystem
                Before = $before
                After = $after
            })
        } catch {
        }
    }

    if ($ShowProgress) {
        Complete-XmaProgress -Id $script:ProgressIds.Hidden -Activity "Hidden/system scan"
    }

    return @($results.ToArray())
}

function Invoke-XmaModrinthLookup {
    param([string]$Sha1)

    if ([string]::IsNullOrWhiteSpace($Sha1)) {
        return $null
    }

    try {
        $versionInfo = Invoke-RestMethod -Uri "https://api.modrinth.com/v2/version_file/$Sha1" -Method Get -UseBasicParsing -TimeoutSec 6 -ErrorAction Stop
        if (-not $versionInfo.project_id) {
            return $null
        }

        $projectInfo = Invoke-RestMethod -Uri "https://api.modrinth.com/v2/project/$($versionInfo.project_id)" -Method Get -UseBasicParsing -TimeoutSec 6 -ErrorAction Stop
        return [pscustomobject]@{
            Source = "Modrinth"
            Name = [string]$projectInfo.title
            Slug = [string]$projectInfo.slug
            ProjectId = [string]$versionInfo.project_id
            Version = [string]$versionInfo.version_number
        }
    } catch {
        return $null
    }
}

function Invoke-XmaMegabaseLookup {
    param([string]$Sha1)

    if ([string]::IsNullOrWhiteSpace($Sha1) -or $NoMegabase) {
        return $null
    }

    try {
        $result = Invoke-RestMethod -Uri "https://megabase.vercel.app/api/query?hash=$Sha1" -Method Get -UseBasicParsing -TimeoutSec 6 -ErrorAction Stop
        if ($result.error -or -not $result.data) {
            return $null
        }

        return [pscustomobject]@{
            Source = "Megabase"
            Name = [string]$result.data.name
            Slug = [string]$result.data.slug
            Version = [string]$result.data.version
        }
    } catch {
        return $null
    }
}

function Get-XmaEntryText {
    param(
        [Parameter(Mandatory)]
        [System.IO.Compression.ZipArchiveEntry]$Entry,
        [int]$MaxChars = 200000
    )

    $stream = $Entry.Open()
    $reader = New-Object System.IO.StreamReader($stream)
    try {
        $text = $reader.ReadToEnd()
        if ($text.Length -gt $MaxChars) {
            return $text.Substring(0, $MaxChars)
        }
        return $text
    } catch {
        return ""
    } finally {
        $reader.Dispose()
        $stream.Dispose()
    }
}

function Get-XmaEntryBytes {
    param(
        [Parameter(Mandatory)]
        [System.IO.Compression.ZipArchiveEntry]$Entry,
        [int]$MaxBytes = 262144
    )

    $length = [int][Math]::Min([int64]$Entry.Length, [int64][Math]::Max(0, $MaxBytes))
    if ($length -le 0) {
        return @()
    }

    $stream = $Entry.Open()
    try {
        $buffer = New-Object byte[] $length
        $offset = 0
        while ($offset -lt $length) {
            $read = $stream.Read($buffer, $offset, $length - $offset)
            if ($read -le 0) {
                break
            }
            $offset += $read
        }

        if ($offset -eq $length) {
            return $buffer
        }

        if ($offset -le 0) {
            return @()
        }

        $trimmed = New-Object byte[] $offset
        [Array]::Copy($buffer, 0, $trimmed, 0, $offset)
        return $trimmed
    } finally {
        $stream.Dispose()
    }
}

function Convert-XmaTokenMatchText {
    param([string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return ""
    }

    try {
        return $Text.Normalize([Text.NormalizationForm]::FormKC)
    } catch {
        return $Text
    }
}

function Get-XmaPrintableStrings {
    param(
        [byte[]]$Bytes,
        [int]$MinLength = 5
    )

    if (-not $Bytes -or $Bytes.Length -eq 0) {
        return @()
    }

    $text = [System.Text.Encoding]::ASCII.GetString($Bytes)
    $pattern = "[ -~]{$MinLength,}"
    $matches = [regex]::Matches($text, $pattern)
    if ($matches.Count -eq 0) {
        return @()
    }

    $values = foreach ($m in $matches) {
        $m.Value.Trim()
    }

    return @($values | Where-Object { $_.Length -ge $MinLength } | Select-Object -Unique)
}

function Find-XmaTokenHits {
    param([string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return @()
    }

    $normalizedText = Convert-XmaTokenMatchText -Text $Text
    $hits = New-Object System.Collections.Generic.List[string]
    foreach ($tp in $script:ModTokenPatterns) {
        if ($tp.Regex.IsMatch($normalizedText)) {
            $hits.Add($tp.Token)
        }
    }
    return @($hits | Select-Object -Unique)
}

function Get-XmaJarMetadata {
    param(
        [Parameter(Mandatory)]
        [System.IO.Compression.ZipArchive]$Zip
    )

    $meta = [ordered]@{
        Loader = ""
        ModId = ""
        Name = ""
        Version = ""
        MetadataText = ""
    }

    $fabricEntry = $Zip.Entries | Where-Object { $_.FullName -eq "fabric.mod.json" } | Select-Object -First 1
    if ($fabricEntry) {
        $text = Get-XmaEntryText -Entry $fabricEntry
        $meta.Loader = "Fabric"
        $meta.MetadataText = $text
        try {
            $json = $text | ConvertFrom-Json -ErrorAction Stop
            $meta.ModId = [string]$json.id
            $meta.Name = [string]$json.name
            $meta.Version = [string]$json.version
        } catch {
        }
        return [pscustomobject]$meta
    }

    $quiltEntry = $Zip.Entries | Where-Object { $_.FullName -eq "quilt.mod.json" } | Select-Object -First 1
    if ($quiltEntry) {
        $text = Get-XmaEntryText -Entry $quiltEntry
        $meta.Loader = "Quilt"
        $meta.MetadataText = $text
        try {
            $json = $text | ConvertFrom-Json -ErrorAction Stop
            $meta.ModId = [string]$json.quilt_loader.id
            $meta.Name = [string]$json.quilt_loader.metadata.name
            $meta.Version = [string]$json.quilt_loader.version
        } catch {
        }
        return [pscustomobject]$meta
    }

    $modsTomlEntry = $Zip.Entries | Where-Object { $_.FullName -eq "META-INF/mods.toml" } | Select-Object -First 1
    if ($modsTomlEntry) {
        $text = Get-XmaEntryText -Entry $modsTomlEntry
        $meta.Loader = "Forge"
        $meta.MetadataText = $text
        if ($text -match '(?m)^\s*modId\s*=\s*"([^"]+)"') { $meta.ModId = $matches[1] }
        if ($text -match '(?m)^\s*displayName\s*=\s*"([^"]+)"') { $meta.Name = $matches[1] }
        if ($text -match '(?m)^\s*version\s*=\s*"([^"]+)"') { $meta.Version = $matches[1] }
    }

    return [pscustomobject]$meta
}

function Measure-XmaJar {
    param(
        [Parameter(Mandatory)]
        [string]$JarPath
    )

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $sizeKB = 0
    try {
        $sizeKB = [math]::Round(((Get-Item -LiteralPath $JarPath -Force -ErrorAction Stop).Length / 1KB), 1)
    } catch {
        try {
            $sizeKB = [math]::Round(([System.IO.FileInfo]::new($JarPath).Length / 1KB), 1)
        } catch {
            $sizeKB = 0
        }
    }
    $zip = [System.IO.Compression.ZipFile]::OpenRead($JarPath)

    try {
        $meta = Get-XmaJarMetadata -Zip $zip
        $entryNames = @($zip.Entries | Select-Object -ExpandProperty FullName)
        $classEntries = @($zip.Entries | Where-Object { $_.FullName -match "(?i)\.class$" })
        $classBaseNames = @($classEntries | ForEach-Object { [System.IO.Path]::GetFileNameWithoutExtension($_.FullName) })
        $classPathEntries = @($classEntries | ForEach-Object { ([string]$_.FullName -replace '(?i)\.class$','') })

        $repeatedSegmentClassCount = 0
        foreach ($classPath in $classPathEntries) {
            $segments = @(([string]$classPath).Split('/'))
            if ($segments.Count -eq 0) {
                continue
            }

            $seen = @{}
            $hasRepeatSegment = $false
            foreach ($segment in $segments) {
                if ($seen.ContainsKey($segment)) {
                    $hasRepeatSegment = $true
                    break
                }
                $seen[$segment] = $true
            }

            if ($hasRepeatSegment) {
                $repeatedSegmentClassCount++
            }
        }

        $repeatedSegmentRatio = 0.0
        if ($classEntries.Count -gt 0) {
            $repeatedSegmentRatio = [math]::Round(($repeatedSegmentClassCount / [double]$classEntries.Count), 3)
        }

        $tokenHits = New-Object System.Collections.Generic.List[string]
        $reasonList = New-Object System.Collections.Generic.List[string]
        $structuralIndicator = 0
        $strongStructuralIndicator = 0

        $binaryIndicatorCounts = @{
            SecretKeySpec = 0
            Cipher = 0
            Base64 = 0
            DefineClass = 0
            UrlClassLoader = 0
            AgentHooks = 0
        }

        $entryText = ($entryNames -join "`n") + "`n" + $meta.MetadataText
        foreach ($hit in Find-XmaTokenHits -Text $entryText) {
            $tokenHits.Add($hit)
        }

        $textEntries = @(
            $zip.Entries | Where-Object { $_.FullName -match "(?i)\.(json|toml|mf|txt|cfg|properties|xml)$" } | Select-Object -First 80
        )
        foreach ($entry in $textEntries) {
            $text = Get-XmaEntryText -Entry $entry
            foreach ($hit in Find-XmaTokenHits -Text $text) {
                $tokenHits.Add($hit)
            }
        }

        $binaryClassEntries = @($classEntries | Select-Object -First 120)
        foreach ($entry in $binaryClassEntries) {
            $bytes = @(Get-XmaEntryBytes -Entry $entry -MaxBytes 262144)
            if ($bytes.Count -eq 0) {
                continue
            }

            $printable = @(Get-XmaPrintableStrings -Bytes $bytes -MinLength 5)
            if ($printable.Count -eq 0) {
                continue
            }

            foreach ($chunk in @($printable | Select-Object -First 220)) {
                $chunkText = [string]$chunk
                foreach ($hit in Find-XmaTokenHits -Text $chunk) {
                    $tokenHits.Add($hit)
                }

                if ($chunkText -match '(?i)SecretKeySpec') { $binaryIndicatorCounts.SecretKeySpec++ }
                if ($chunkText -match '(?i)\bCipher\b|javax/crypto/Cipher') { $binaryIndicatorCounts.Cipher++ }
                if ($chunkText -match '(?i)\bBase64\b|java/util/Base64') { $binaryIndicatorCounts.Base64++ }
                if ($chunkText -match '(?i)defineClass') { $binaryIndicatorCounts.DefineClass++ }
                if ($chunkText -match '(?i)URLClassLoader') { $binaryIndicatorCounts.UrlClassLoader++ }
                if ($chunkText -match '(?i)javaagent|agentmain|premain|instrumentation|java/lang/instrument') { $binaryIndicatorCounts.AgentHooks++ }
            }
        }

        $hasCryptoStringHidingPair =
            (($binaryIndicatorCounts.SecretKeySpec -gt 0 -and $binaryIndicatorCounts.Base64 -gt 0) -or
             ($binaryIndicatorCounts.Cipher -gt 0 -and $binaryIndicatorCounts.Base64 -gt 0))

        $hasLoaderAndEncodedPayloadSignals =
            (($binaryIndicatorCounts.DefineClass -gt 0 -or $binaryIndicatorCounts.UrlClassLoader -gt 0) -and
             ($binaryIndicatorCounts.Base64 -gt 0 -or $binaryIndicatorCounts.SecretKeySpec -gt 0 -or $binaryIndicatorCounts.Cipher -gt 0))

        if ($hasCryptoStringHidingPair -or $hasLoaderAndEncodedPayloadSignals) {
            $reasonList.Add(
                "String-hiding/loader markers in class bytes: SecretKeySpec=$($binaryIndicatorCounts.SecretKeySpec), Cipher=$($binaryIndicatorCounts.Cipher), Base64=$($binaryIndicatorCounts.Base64), defineClass=$($binaryIndicatorCounts.DefineClass), URLClassLoader=$($binaryIndicatorCounts.UrlClassLoader), agentHooks=$($binaryIndicatorCounts.AgentHooks)"
            )
            $structuralIndicator = 1
        }

        $hasNamespaceRecursionAnomaly = ($classEntries.Count -ge 120 -and $repeatedSegmentClassCount -ge 10 -and $repeatedSegmentRatio -ge 0.08)
        if ($classEntries.Count -ge 120 -and $repeatedSegmentClassCount -ge 10 -and $repeatedSegmentRatio -ge 0.08) {
            $reasonList.Add("Class namespace recursion anomaly: repeated-segment classes=$repeatedSegmentClassCount/$($classEntries.Count) (ratio=$repeatedSegmentRatio).")
            $structuralIndicator = 1
        }

        $fileStem = [System.IO.Path]::GetFileNameWithoutExtension($JarPath).ToLowerInvariant()
        $metaId = ([string]$meta.ModId).Trim().ToLowerInvariant()
        $metaNameToken = (([string]$meta.Name) -replace '[^a-z0-9]', '').ToLowerInvariant()
        $nameLooksRandom = $fileStem -match '^[a-z0-9]{3,6}$'
        $matchesMetaId = (-not [string]::IsNullOrWhiteSpace($metaId)) -and ($fileStem.Contains($metaId))
        $matchesMetaName = (-not [string]::IsNullOrWhiteSpace($metaNameToken)) -and ($metaNameToken.Contains($fileStem) -or $fileStem.Contains($metaNameToken))
        if ($nameLooksRandom -and -not $matchesMetaId -and -not $matchesMetaName -and $classEntries.Count -ge 80) {
            $reasonList.Add("Jar filename/metadata mismatch: file '$fileStem' does not align with declared mod id/name '$($meta.ModId)'/'$($meta.Name)'.")
            $structuralIndicator = 1
        }

        if (($hasCryptoStringHidingPair -or $hasLoaderAndEncodedPayloadSignals) -and $hasNamespaceRecursionAnomaly) {
            $reasonList.Add("Combined hidden-string and namespace-recursion pattern is strongly suspicious.")
            $strongStructuralIndicator = 1
        }

        $tokenHitsUnique = @($tokenHits | Select-Object -Unique | Sort-Object)
        $tokenScore = 0
        $scoredHits = New-Object System.Collections.Generic.List[string]
        foreach ($hit in $tokenHitsUnique) {
            $weight = 1
            if ($script:Config.TokenWeights.ContainsKey($hit)) {
                $weight = [int]$script:Config.TokenWeights[$hit]
            }
            $tokenScore += $weight
            $scoredHits.Add("$hit(w$weight)")
        }

        $tokenIndicator = 0
        if ($tokenScore -ge 3) {
            $reasonList.Add("Cheat-term score $tokenScore from: $($scoredHits -join ', ')")
            $tokenIndicator = 1
        }

        $strongTokenIndicator = 0
        $criticalTokenHits = @(
            $tokenHitsUnique |
                Where-Object {
                    $script:Config.CriticalCheatTokens -contains $_
                }
        )
        if ($criticalTokenHits.Count -gt 0) {
            $reasonList.Add("Critical cheat identifiers: $($criticalTokenHits -join ', ')")
            $strongTokenIndicator = 1
        }

        if ($tokenScore -ge 6) {
            $reasonList.Add("High-confidence cheat signature density (score >= 6).")
            $strongTokenIndicator = 1
        }

        $containsAClass = $false
        $containsBClass = $false
        foreach ($n in $classBaseNames) {
            if ($n -ceq "a") { $containsAClass = $true }
            if ($n -ceq "b") { $containsBClass = $true }
        }
        $singleLetterClasses = @($classBaseNames | Where-Object { $_ -match "^[a-zA-Z]$" })
        $singleLetterPathClasses = @(
            $classEntries |
                Where-Object {
                    ([string]$_.FullName) -match '^(?:[a-zA-Z]/){3,}[a-zA-Z]\.class$'
                }
        )
        $nonAsciiShortClasses = @(
            $classBaseNames |
                Where-Object {
                    ([string]$_) -match '^[^\x00-\x7F]{1,2}$'
                }
        )

        if ($containsAClass -or $containsBClass -or $singleLetterClasses.Count -gt 0 -or $singleLetterPathClasses.Count -gt 0 -or $nonAsciiShortClasses.Count -gt 0) {
            $reasonList.Add(
                "Obfuscation markers: a.class=$containsAClass, b.class=$containsBClass, single-letter classes=$($singleLetterClasses.Count), nested single-letter paths=$($singleLetterPathClasses.Count), non-ascii short classes=$($nonAsciiShortClasses.Count)"
            )
        }

        $sha1 = Get-XmaFileHashSafe -Path $JarPath -Algorithm "SHA1"
        $sha256 = Get-XmaFileHashSafe -Path $JarPath -Algorithm "SHA256"
        $verification = $null
        if (-not $NoModVerification) {
            $verification = Invoke-XmaModrinthLookup -Sha1 $sha1
            if (-not $verification) {
                $verification = Invoke-XmaMegabaseLookup -Sha1 $sha1
            }
        }

        $obfuscationIndicator = 0
        if (
            ($containsAClass -and $containsBClass) -or
            $singleLetterClasses.Count -ge 12 -or
            $singleLetterPathClasses.Count -ge 20 -or
            $nonAsciiShortClasses.Count -ge 5
        ) {
            $obfuscationIndicator = 1
        }

        $indicatorCount = 0
        if ($tokenIndicator -gt 0) { $indicatorCount++ }
        if ($strongTokenIndicator -gt 0) { $indicatorCount++ }
        if ($structuralIndicator -gt 0) { $indicatorCount++ }
        if ($strongStructuralIndicator -gt 0) { $indicatorCount++ }
        if ($obfuscationIndicator -gt 0) { $indicatorCount++ }

        $status = "Unknown"
        if ($verification -and $indicatorCount -eq 0) {
            $status = "Verified"
        } elseif ($verification -and $indicatorCount -gt 0) {
            $status = "Review (Verified)"
        } elseif (-not $verification -and $indicatorCount -eq 0) {
            $status = "Unknown"
        } elseif (-not $verification -and $indicatorCount -eq 1) {
            $status = "Review"
        } else {
            $status = "Suspicious"
        }

        [pscustomobject]@{
            FileName = [System.IO.Path]::GetFileName($JarPath)
            FilePath = $JarPath
            SizeKB = $sizeKB
            Sha1 = $sha1
            Sha256 = $sha256
            Metadata = $meta
            Verification = $verification
            DownloadSource = Get-XmaDownloadSource -Path $JarPath
            TokenHits = $tokenHitsUnique
            SingleLetterClassCount = $singleLetterClasses.Count
            ContainsAClass = $containsAClass
            ContainsBClass = $containsBClass
            Reasons = @($reasonList.ToArray())
            Status = $status
        }
    } finally {
        $zip.Dispose()
    }
}

function Get-XmaJavaProcesses {
    $processes = @(Get-CimInstance Win32_Process -Filter "name = 'javaw.exe' OR name = 'java.exe'" -ErrorAction SilentlyContinue)
    $rows = foreach ($p in $processes) {
        $startTime = $null
        $startTimeUtc = $null
        try {
            $liveProc = Get-Process -Id ([int]$p.ProcessId) -ErrorAction SilentlyContinue
            if ($liveProc -and $liveProc.StartTime) {
                $startTime = [datetime]$liveProc.StartTime
                $startTimeUtc = $startTime.ToUniversalTime()
            }
        } catch {
        }

        try {
            if (-not $startTime -and -not [string]::IsNullOrWhiteSpace([string]$p.CreationDate)) {
                $startTime = [System.Management.ManagementDateTimeConverter]::ToDateTime([string]$p.CreationDate)
                $startTimeUtc = $startTime.ToUniversalTime()
            }
        } catch {
        }

        [pscustomobject]@{
            ProcessId = [int]$p.ProcessId
            Name = [string]$p.Name
            CommandLine = [string]$p.CommandLine
            ExecutablePath = [string]$p.ExecutablePath
            StartTimeLocal = $startTime
            StartTimeUtc = $startTimeUtc
        }
    }
    return @($rows)
}

function Get-XmaLikelyMinecraftJavaTargets {
    param(
        [object[]]$JavaProcesses,
        [switch]$AllowJavaExeFallback
    )

    $pattern = "(?i)minecraft|fabric|forge|modrinth|prism|multimc|lunar|feather|badlion|\\.minecraft|--gamedir|--assetsdir|--versiontype"
    $targets = @(
        $JavaProcesses | Where-Object {
            ([string]$_.CommandLine) -match $pattern -or
            ([string]$_.ExecutablePath) -match $pattern
        }
    )

    if ($targets.Count -eq 0) {
        $targets = @($JavaProcesses | Where-Object { $_.Name -ieq "javaw.exe" })
    }

    if ($targets.Count -eq 0 -and $AllowJavaExeFallback) {
        $targets = @($JavaProcesses | Where-Object { $_.Name -ieq "java.exe" })
    }

    return @($targets | Sort-Object ProcessId -Unique)
}

function Measure-XmaRuntimeInjection {
    param(
        [object[]]$JavaProcesses,
        [switch]$ShowProgress
    )

    $results = New-Object System.Collections.Generic.List[object]
    $total = @($JavaProcesses).Count
    $index = 0
    foreach ($proc in $JavaProcesses) {
        $index++
        if ($ShowProgress) {
            Write-XmaProgress -Id $script:ProgressIds.Runtime -Activity "JVM injection scan" -Status "[$index/$total] PID $($proc.ProcessId) ($($proc.Name))" -Current $index -Total $total
        }

        $cmd = [string]$proc.CommandLine
        if ([string]::IsNullOrWhiteSpace($cmd)) {
            continue
        }

        $findings = New-Object System.Collections.Generic.List[string]
        $findingDetails = New-Object System.Collections.Generic.List[object]
        $informationalFindings = New-Object System.Collections.Generic.List[string]
        $informationalDetails = New-Object System.Collections.Generic.List[object]
        $highRiskLabels = @($script:Config.RuntimeHighRiskLabels)
        $commandTokens = @(Get-XmaCommandTokens -CommandLine $cmd)
        foreach ($rule in $script:Config.RuntimeInjectionPatterns) {
            $matches = [regex]::Matches($cmd, $rule.Pattern)
            if ($matches.Count -gt 0) {
                $isHighRisk = $highRiskLabels -contains $rule.Label
                if ($isHighRisk) {
                    $findings.Add($rule.Label)
                } else {
                    $informationalFindings.Add($rule.Label)
                }

                foreach ($m in $matches) {
                    $token = Get-XmaTokenAtPosition -Tokens $commandTokens -Position $m.Index
                    $argumentText = if ($token) { [string]$token.Text } else { [string]$m.Value }
                    $referencedPaths = @(Get-XmaReferencedJarPaths -Text $argumentText)
                    $detail = [pscustomobject]@{
                        Label = $rule.Label
                        Position = [int]$m.Index
                        Argument = $argumentText
                        ReferencedPaths = $referencedPaths
                        Notes = ""
                    }

                    if ($isHighRisk) {
                        $findingDetails.Add($detail)
                    } else {
                        $informationalDetails.Add($detail)
                    }
                }
            }
        }

        foreach ($token in @($commandTokens | Where-Object { ([string]$_.Text) -match '^(?i)-javaagent:.+' })) {
            $argumentText = [string]$token.Text
            $agentArgument = ""
            if ($argumentText -match '^(?i)-javaagent:(.+)$') {
                $agentArgument = $matches[1]
            }

            $assessment = Get-XmaJavaAgentAssessment -AgentArgument $agentArgument
            $agentName = if ([string]::IsNullOrWhiteSpace($assessment.AgentName)) { "unknown" } else { $assessment.AgentName }
            $agentPath = [string]$assessment.AgentPath
            $referencedPaths = @(Get-XmaReferencedJarPaths -Text $argumentText)
            if ($referencedPaths.Count -eq 0 -and -not [string]::IsNullOrWhiteSpace($agentPath) -and $agentPath -match '(?i)\.(jar|zip)$') {
                $referencedPaths = @($agentPath)
            }

            if ($assessment.RiskLevel -eq "trusted") {
                $label = "Trusted javaagent: $agentName"
                $informationalFindings.Add($label)
                $informationalDetails.Add([pscustomobject]@{
                    Label = $label
                    Position = [int]$token.Start
                    Argument = $argumentText
                    ReferencedPaths = @($referencedPaths)
                    Notes = [string]$assessment.TrustReason
                })
            } elseif ($assessment.RiskLevel -eq "suspicious") {
                $label = "Suspicious javaagent: $agentName"
                $findings.Add($label)
                $findingDetails.Add([pscustomobject]@{
                    Label = $label
                    Position = [int]$token.Start
                    Argument = $argumentText
                    ReferencedPaths = @($referencedPaths)
                    Notes = [string]$assessment.TrustReason
                })
            } else {
                $label = "Unrecognized javaagent: $agentName"
                $informationalFindings.Add($label)
                $informationalDetails.Add([pscustomobject]@{
                    Label = $label
                    Position = [int]$token.Start
                    Argument = $argumentText
                    ReferencedPaths = @($referencedPaths)
                    Notes = [string]$assessment.TrustReason
                })
            }
        }

        $findingsUnique = @($findings | Select-Object -Unique)
        $informationalUnique = @($informationalFindings | Select-Object -Unique)
        if ($findingsUnique.Count -gt 0 -or $informationalUnique.Count -gt 0) {
            $allReferencedPaths = @(
                $findingDetails |
                    ForEach-Object { @($_.ReferencedPaths) } |
                    Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
                    Select-Object -Unique
            )
            $results.Add([pscustomobject]@{
                ProcessId = $proc.ProcessId
                Name = $proc.Name
                CommandLine = $cmd
                Findings = $findingsUnique
                FindingDetails = @($findingDetails.ToArray())
                InformationalFindings = $informationalUnique
                InformationalDetails = @($informationalDetails.ToArray())
                ReferencedJarPaths = $allReferencedPaths
            })
        }
    }

    if ($ShowProgress) {
        Complete-XmaProgress -Id $script:ProgressIds.Runtime -Activity "JVM injection scan"
    }

    return @($results.ToArray())
}

function Initialize-XmaMemoryApi {
    if ($script:MemoryApiLoaded) {
        return
    }

    try {
        Add-Type @"
using System;
using System.Runtime.InteropServices;

public static class XmaMem {
    public const uint PROCESS_QUERY_INFORMATION = 0x0400;
    public const uint PROCESS_VM_READ = 0x0010;
    public const uint MEM_COMMIT = 0x1000;
    public const uint MEM_PRIVATE = 0x20000;
    public const uint MEM_MAPPED = 0x40000;
    public const uint PAGE_GUARD = 0x100;
    public const uint PAGE_NOACCESS = 0x01;

    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORY_BASIC_INFORMATION {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public IntPtr RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr OpenProcess(uint desiredAccess, bool inheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern int VirtualQueryEx(IntPtr processHandle, IntPtr address, out MEMORY_BASIC_INFORMATION memoryInfo, uint length);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool ReadProcessMemory(IntPtr processHandle, IntPtr baseAddress, byte[] buffer, int size, out int bytesRead);
}
"@ -ErrorAction Stop

        $script:MemoryApiLoaded = $true
    } catch {
        $script:MemoryApiLoaded = $false
    }
}

function Search-XmaProcessMemory {
    param(
        [Parameter(Mandatory)]
        [int]$ProcessId,
        [int]$MaxMemoryMB = 192,
        [switch]$ShowProgress,
        [int]$ProgressId = 0,
        [string]$ProgressActivity = ""
    )

    Initialize-XmaMemoryApi
    if (-not $script:MemoryApiLoaded) {
        if ($ShowProgress -and $ProgressId -gt 0) {
            $activity = if ([string]::IsNullOrWhiteSpace($ProgressActivity)) { "Memory strings scan PID $ProcessId" } else { $ProgressActivity }
            Complete-XmaProgress -Id $ProgressId -Activity $activity
        }
        return [pscustomobject]@{
            ProcessId = $ProcessId
            Error = "Memory API is unavailable on this host."
            Hits = @()
        }
    }

    $handle = [XmaMem]::OpenProcess(([XmaMem]::PROCESS_QUERY_INFORMATION -bor [XmaMem]::PROCESS_VM_READ), $false, $ProcessId)
    if ($handle -eq [IntPtr]::Zero) {
        if ($ShowProgress -and $ProgressId -gt 0) {
            $activity = if ([string]::IsNullOrWhiteSpace($ProgressActivity)) { "Memory strings scan PID $ProcessId" } else { $ProgressActivity }
            Complete-XmaProgress -Id $ProgressId -Activity $activity
        }
        return [pscustomobject]@{
            ProcessId = $ProcessId
            Error = "Could not open process. Try running PowerShell as administrator."
            Hits = @()
        }
    }

    $maxBytes = [math]::Max(32, $MaxMemoryMB) * 1MB
    $scannedBytes = 0L
    $nextProgressBytes = 0L
    $address = [IntPtr]::Zero
    $mbi = New-Object XmaMem+MEMORY_BASIC_INFORMATION
    $mbiSize = [uint32][System.Runtime.InteropServices.Marshal]::SizeOf([type]([XmaMem+MEMORY_BASIC_INFORMATION]))
    $hitMap = @{}
    $activity = if ([string]::IsNullOrWhiteSpace($ProgressActivity)) { "Memory strings scan PID $ProcessId" } else { $ProgressActivity }

    try {
        while ($scannedBytes -lt $maxBytes) {
            $queryResult = [XmaMem]::VirtualQueryEx($handle, $address, [ref]$mbi, $mbiSize)
            if ($queryResult -le 0) {
                break
            }

            $regionSize = [int64]$mbi.RegionSize
            if ($regionSize -le 0) {
                break
            }

            $isReadable = ($mbi.State -eq [XmaMem]::MEM_COMMIT) -and (($mbi.Protect -band [XmaMem]::PAGE_GUARD) -eq 0) -and (($mbi.Protect -band [XmaMem]::PAGE_NOACCESS) -eq 0)
            $isWantedType = ($mbi.Type -eq [XmaMem]::MEM_PRIVATE) -or ($mbi.Type -eq [XmaMem]::MEM_MAPPED)

            if ($isReadable -and $isWantedType) {
                $toRead = [int][Math]::Min($regionSize, 262144)
                if (($scannedBytes + $toRead) -gt $maxBytes) {
                    $toRead = [int]($maxBytes - $scannedBytes)
                }

                if ($toRead -gt 0) {
                    $buffer = New-Object byte[] $toRead
                    $bytesRead = 0
                    $ok = [XmaMem]::ReadProcessMemory($handle, $mbi.BaseAddress, $buffer, $toRead, [ref]$bytesRead)
                    if ($ok -and $bytesRead -gt 0) {
                        $ascii = [System.Text.Encoding]::ASCII.GetString($buffer, 0, $bytesRead)
                        $matches = [regex]::Matches($ascii, "[ -~]{5,}")
                        foreach ($m in $matches) {
                            $candidate = $m.Value.Trim()
                            if ($candidate.Length -lt 5) { continue }
                            $lower = $candidate.ToLowerInvariant()
                            foreach ($needle in $script:MemoryNeedlesNormalized) {
                                if ($lower.Contains($needle)) {
                                    $key = "$needle|$candidate"
                                    if (-not $hitMap.ContainsKey($key)) {
                                        $hitMap[$key] = [pscustomobject]@{
                                            Needle = $needle
                                            Sample = if ($candidate.Length -gt 180) { $candidate.Substring(0, 180) } else { $candidate }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    $scannedBytes += $toRead
                }
            }

            if ($ShowProgress -and $ProgressId -gt 0 -and $scannedBytes -ge $nextProgressBytes) {
                $status = "{0}MB / {1}MB scanned" -f [math]::Round(($scannedBytes / 1MB), 1), [math]::Round(($maxBytes / 1MB), 0)
                Write-XmaProgress -Id $ProgressId -Activity $activity -Status $status -Current $scannedBytes -Total $maxBytes
                $nextProgressBytes = $scannedBytes + 4MB
            }

            $nextAddress = $mbi.BaseAddress.ToInt64() + $regionSize
            if ($nextAddress -le $address.ToInt64()) {
                break
            }
            $address = [IntPtr]::new($nextAddress)
        }
    } catch {
        return [pscustomobject]@{
            ProcessId = $ProcessId
            Error = "Memory scan failed: $($_.Exception.Message)"
            Hits = @($hitMap.Values | Select-Object -First 100)
        }
    } finally {
        [void][XmaMem]::CloseHandle($handle)
        if ($ShowProgress -and $ProgressId -gt 0) {
            Complete-XmaProgress -Id $ProgressId -Activity $activity
        }
    }

    [pscustomobject]@{
        ProcessId = $ProcessId
        Error = ""
        Hits = @($hitMap.Values | Select-Object -First 100)
    }
}

function Get-XmaSummaryBucket {
    param([object[]]$Reports)
    $buckets = @{
        Verified = 0
        Unknown = 0
        "Review" = 0
        "Review (Verified)" = 0
        Suspicious = 0
    }

    foreach ($r in $Reports) {
        if ($buckets.ContainsKey($r.Status)) {
            $buckets[$r.Status]++
        }
    }
    return $buckets
}

function Write-XmaStatusList {
    param(
        [Parameter(Mandatory)]
        [string]$Label,
        [Parameter(Mandatory)]
        [string]$Color,
        [object[]]$Items
    )

    $rows = @($Items | Sort-Object FileName)
    Write-Host "$Label ($($rows.Count))" -ForegroundColor $Color
    if ($rows.Count -eq 0) {
        Write-Host "  (none)" -ForegroundColor DarkGray
        Write-Host ""
        return
    }

    foreach ($row in $rows) {
        Write-Host "  - $($row.FileName)" -ForegroundColor $Color
    }
    Write-Host ""
}

Disable-XmaConsoleQuickEdit
Write-XmaBanner
$resolvedPath = Resolve-XmaPath
$target = Get-Item -LiteralPath $resolvedPath -ErrorAction Stop

$jarFiles = @()
if ($target.PSIsContainer) {
    $jarFiles = @(Get-ChildItem -LiteralPath $target.FullName -Force -File -Filter "*.jar" | Sort-Object Name)
} else {
    if ($target.Extension -ne ".jar") {
        throw "The selected file is not a jar."
    }
    $jarFiles = @($target)
}

if (-not $Quiet) {
    Write-XmaSection -Title "Scan Target" -Color Cyan
    Write-Host "Path: $($target.FullName)" -ForegroundColor Gray
    Write-Host "Jar files: $(@($jarFiles).Count)" -ForegroundColor Cyan
    Write-Host ""
}

$hiddenReport = @()
if ($target.PSIsContainer) {
    $hiddenReport = @(Get-XmaHiddenJarReport -FolderPath $target.FullName -ShowProgress:(-not $Quiet))
    if (-not $Quiet) {
        Write-XmaSection -Title "Hidden/System Attribute Check" -Color Yellow
        if (@($hiddenReport).Count -gt 0) {
            Write-Host "Hidden/system jars found and revealed: $(@($hiddenReport).Count)" -ForegroundColor Yellow
        } else {
            Write-Host "Hidden/system jars found: 0" -ForegroundColor DarkGray
        }
        Write-Host ""
    }
}

if ($jarFiles.Count -eq 0) {
    Write-Host "No jar files were found at the selected path." -ForegroundColor Yellow
    return
}

$reports = New-Object System.Collections.Generic.List[object]
$total = $jarFiles.Count
$index = 0
$scanStartedAtUtc = [datetime]::UtcNow
foreach ($jar in $jarFiles) {
    $index++
    if (-not $Quiet) {
        Write-XmaProgress -Id $script:ProgressIds.Mods -Activity "Mod jar scan" -Status "[$index/$total] $($jar.Name)" -Current $index -Total $total
        Write-Host ("[{0}/{1}] Scanning {2}" -f $index, $total, $jar.Name) -ForegroundColor DarkCyan
    }

    try {
        attrib -h -s "$($jar.FullName)" 2>$null | Out-Null
    } catch {
    }

    try {
        $reports.Add((Measure-XmaJar -JarPath $jar.FullName))
    } catch {
        $reports.Add([pscustomobject]@{
            FileName = $jar.Name
            FilePath = $jar.FullName
            SizeKB = 0
            Sha1 = ""
            Sha256 = ""
            Metadata = $null
            Verification = $null
            DownloadSource = Get-XmaDownloadSource -Path $jar.FullName
            TokenHits = @()
            SingleLetterClassCount = 0
            ContainsAClass = $false
            ContainsBClass = $false
            Reasons = @("Scan error: $($_.Exception.Message)")
            Status = "Review"
        })
    }
}
$scanCompletedAtUtc = [datetime]::UtcNow
if (-not $Quiet) {
    Complete-XmaProgress -Id $script:ProgressIds.Mods -Activity "Mod jar scan"
    Write-Host ""
}

$javaProcesses = @()
$runtimeTargets = @()
$runtimeFindings = @()
$memoryResults = @()
$runtimeWindowInfo = $null
$runtimeEditedReports = @()
$runtimeInjectionJarReport = $null
$isLikelyLauncherModsTarget = $false

$javaProcesses = @(Get-XmaJavaProcesses)
$runtimeTargets = @(Get-XmaLikelyMinecraftJavaTargets -JavaProcesses $javaProcesses)
if ($runtimeTargets.Count -eq 0) {
    $runtimeTargets = @(Get-XmaLikelyMinecraftJavaTargets -JavaProcesses $javaProcesses -AllowJavaExeFallback)
}
$runtimeWindowInfo = Get-XmaRuntimeWindowInfo -RuntimeTargets $runtimeTargets -WindowEndUtc $scanCompletedAtUtc

if ($target.PSIsContainer) {
    $isLikelyLauncherModsTarget = Test-XmaLikelyLauncherModsPath -Path $target.FullName
} else {
    $parentPath = Split-Path -LiteralPath $target.FullName -Parent
    $isLikelyLauncherModsTarget = Test-XmaLikelyLauncherModsPath -Path $parentPath
}

if ($target.PSIsContainer -and $isLikelyLauncherModsTarget) {
    $runtimeEditedReports = @(Apply-XmaRuntimeEditFlags -Reports @($reports.ToArray()) -RuntimeWindowInfo $runtimeWindowInfo -GraceSeconds $script:Config.RuntimeEditGraceSeconds)
}

if (-not $SkipRuntimeScan) {
    if (-not $Quiet) {
        Write-XmaSection -Title "JVM Runtime Scan" -Color DarkYellow
    }
    $runtimeFindings = @(Measure-XmaRuntimeInjection -JavaProcesses $runtimeTargets -ShowProgress:(-not $Quiet))
    $runtimeInjectionJarReport = Apply-XmaRuntimeInjectedJarFlags -Reports @($reports.ToArray()) -RuntimeFindings $runtimeFindings
    foreach ($addedReport in @($runtimeInjectionJarReport.AddedReports)) {
        $reports.Add($addedReport)
    }
}

if (-not $SkipMemoryScan) {
    $memoryTargets = @(Get-XmaLikelyMinecraftJavaTargets -JavaProcesses $javaProcesses)
    if (-not $Quiet) {
        Write-XmaSection -Title "Memory Strings Scan" -Color DarkYellow
        Write-Host "Memory targets: $(@($memoryTargets).Count)" -ForegroundColor Gray
    }

    $memoryTargetTotal = @($memoryTargets).Count
    $memoryTargetIndex = 0
    foreach ($proc in $memoryTargets) {
        $memoryTargetIndex++
        if (-not $Quiet) {
            Write-XmaProgress -Id $script:ProgressIds.MemoryTargets -Activity "Memory target scan" -Status "[$memoryTargetIndex/$memoryTargetTotal] PID $($proc.ProcessId) ($($proc.Name))" -Current $memoryTargetIndex -Total $memoryTargetTotal
            Write-Host "Memory scan: PID $($proc.ProcessId) ($($proc.Name))" -ForegroundColor DarkYellow
        }
        $memoryResults += @(Search-XmaProcessMemory -ProcessId $proc.ProcessId -MaxMemoryMB $MemoryScanMB -ShowProgress:(-not $Quiet) -ProgressId $script:ProgressIds.MemoryBytes -ProgressActivity "Memory strings PID $($proc.ProcessId)")
    }

    if (-not $Quiet) {
        Complete-XmaProgress -Id $script:ProgressIds.MemoryTargets -Activity "Memory target scan"
    }
}

$reportArray = @($reports.ToArray())
$summary = Get-XmaSummaryBucket -Reports $reportArray
$totalMods = @($reportArray).Count

if (-not $Quiet) {
    Write-XmaSection -Title "Runtime Session + Edit-Time Check" -Color DarkYellow
    Write-Host "Java processes detected: $(@($javaProcesses).Count)" -ForegroundColor Gray
    Write-Host "Minecraft-like runtime targets: $(@($runtimeTargets).Count)" -ForegroundColor Gray

    foreach ($proc in @($runtimeTargets | Sort-Object ProcessId)) {
        $startText = "unknown"
        $uptimeText = "unknown"
        if ($proc.StartTimeUtc -is [datetime]) {
            $startText = $proc.StartTimeUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss")
            $uptimeText = Format-XmaDuration -Span ($scanCompletedAtUtc - $proc.StartTimeUtc)
        }
        Write-Host ("  - PID {0} ({1}) started {2}, uptime {3}" -f $proc.ProcessId, $proc.Name, $startText, $uptimeText) -ForegroundColor Gray
    }

    if ($runtimeWindowInfo -and $runtimeWindowInfo.HasWindow) {
        $windowStartText = $runtimeWindowInfo.WindowStartUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss")
        $windowEndText = $runtimeWindowInfo.WindowEndUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss")
        Write-Host "Runtime window: $windowStartText -> $windowEndText" -ForegroundColor Gray
    } else {
        Write-Host "Runtime window: unavailable (no start time found)." -ForegroundColor DarkGray
    }

    if ($target.PSIsContainer) {
        if (-not $isLikelyLauncherModsTarget) {
            Write-Host "Mods edited during active runtime: skipped (target path is not a launcher mods folder)." -ForegroundColor DarkGray
        } elseif ($runtimeEditedReports.Count -gt 0) {
            Write-Host "Mods edited during active runtime: $($runtimeEditedReports.Count)" -ForegroundColor Red
            foreach ($rr in @($runtimeEditedReports | Sort-Object FileName)) {
                $editText = if ($rr.PSObject.Properties.Name -contains "LastWriteTimeLocal") { [string]$rr.LastWriteTimeLocal } else { "unknown" }
                Write-Host ("  - {0} (edited: {1})" -f $rr.FileName, $editText) -ForegroundColor DarkYellow
            }
        } elseif ($runtimeWindowInfo -and $runtimeWindowInfo.HasWindow) {
            Write-Host "Mods edited during active runtime: 0" -ForegroundColor Green
        } else {
            Write-Host "Mods edited during active runtime: skipped (no runtime window)." -ForegroundColor DarkGray
        }
    }
    Write-Host ""
}

Write-XmaSection -Title "Summary" -Color Cyan
Write-XmaSummaryLine -Label "Verified" -Count $summary['Verified'] -Total $totalMods -Color Green
Write-XmaSummaryLine -Label "Unknown" -Count $summary['Unknown'] -Total $totalMods -Color Yellow
Write-XmaSummaryLine -Label "Review" -Count $summary['Review'] -Total $totalMods -Color DarkYellow
Write-XmaSummaryLine -Label "Review (Verified)" -Count $summary['Review (Verified)'] -Total $totalMods -Color DarkYellow
Write-XmaSummaryLine -Label "Suspicious" -Count $summary['Suspicious'] -Total $totalMods -Color Red
Write-Host ""

if (-not $NoStatusLists -or $ShowStatusLists) {
    Write-XmaSection -Title "Status Lists" -Color Cyan
    Write-XmaStatusList -Label "Verified" -Color Green -Items @($reportArray | Where-Object { $_.Status -eq "Verified" })
    Write-XmaStatusList -Label "Unknown" -Color Yellow -Items @($reportArray | Where-Object { $_.Status -eq "Unknown" })
    Write-XmaStatusList -Label "Review" -Color DarkYellow -Items @($reportArray | Where-Object { $_.Status -eq "Review" })
    Write-XmaStatusList -Label "Review (Verified)" -Color DarkYellow -Items @($reportArray | Where-Object { $_.Status -eq "Review (Verified)" })
    Write-XmaStatusList -Label "Suspicious" -Color Red -Items @($reportArray | Where-Object { $_.Status -eq "Suspicious" })
}

$flagged = @($reportArray | Where-Object { $_.Status -ne "Verified" -and $_.Status -ne "Unknown" })
if ($flagged.Count -gt 0) {
    Write-XmaSection -Title "Flagged Mods (Reasons)" -Color Magenta
    foreach ($r in $flagged) {
        Write-Host ""
        Write-Host "$($r.FileName) [$($r.Status)]" -ForegroundColor White
        if ($r.Verification) {
            Write-Host "  Verified source: $($r.Verification.Source) / $($r.Verification.Name)" -ForegroundColor DarkGray
        } else {
            Write-Host "  Verified source: none" -ForegroundColor DarkGray
        }
        if ($r.DownloadSource) {
            Write-Host "  Download source: $($r.DownloadSource)" -ForegroundColor DarkGray
        }
        foreach ($reason in $r.Reasons) {
            Write-Host "  - $reason" -ForegroundColor Yellow
        }
    }
    Write-Host ""
}

$runtimeSuspiciousFindings = @($runtimeFindings | Where-Object { @($_.FindingDetails).Count -gt 0 })
$runtimeInformationalFindings = @($runtimeFindings | Where-Object { @($_.InformationalDetails).Count -gt 0 })

if ($runtimeSuspiciousFindings.Count -gt 0) {
    Write-XmaSection -Title "JVM Runtime Injection Findings" -Color Red
    foreach ($rf in $runtimeSuspiciousFindings) {
        Write-Host ""
        Write-Host "PID $($rf.ProcessId) ($($rf.Name))" -ForegroundColor White
        foreach ($detail in @($rf.FindingDetails)) {
            Write-Host "  - $($detail.Label)" -ForegroundColor Yellow
            Write-Host "      position: $($detail.Position)" -ForegroundColor DarkGray
            Write-Host "      argument: $($detail.Argument)" -ForegroundColor DarkGray
            if (-not [string]::IsNullOrWhiteSpace([string]$detail.Notes)) {
                Write-Host "      note: $($detail.Notes)" -ForegroundColor DarkGray
            }
            foreach ($path in @($detail.ReferencedPaths | Select-Object -Unique)) {
                Write-Host "      jar: $path" -ForegroundColor DarkYellow
            }
        }
    }
    if ($runtimeInjectionJarReport) {
        $addedCount = @($runtimeInjectionJarReport.AddedReports).Count
        $annotatedCount = @($runtimeInjectionJarReport.AnnotatedReports).Count
        if ($addedCount -gt 0 -or $annotatedCount -gt 0) {
            Write-Host ""
            Write-Host "Runtime-injected jar scan results: added=$addedCount, annotated=$annotatedCount" -ForegroundColor Magenta
        }
    }
    Write-Host ""
} elseif (-not $SkipRuntimeScan) {
    Write-XmaSection -Title "JVM Runtime Injection Findings" -Color Green
    Write-Host "none" -ForegroundColor Green
    Write-Host ""
}

if ($runtimeInformationalFindings.Count -gt 0) {
    Write-XmaSection -Title "JVM Runtime Notes (Likely Legit)" -Color DarkCyan
    foreach ($rf in $runtimeInformationalFindings) {
        Write-Host ""
        Write-Host "PID $($rf.ProcessId) ($($rf.Name))" -ForegroundColor White
        foreach ($detail in @($rf.InformationalDetails)) {
            Write-Host "  - $($detail.Label)" -ForegroundColor Cyan
            Write-Host "      position: $($detail.Position)" -ForegroundColor DarkGray
            Write-Host "      argument: $($detail.Argument)" -ForegroundColor DarkGray
            if (-not [string]::IsNullOrWhiteSpace([string]$detail.Notes)) {
                Write-Host "      note: $($detail.Notes)" -ForegroundColor DarkGray
            }
            foreach ($path in @($detail.ReferencedPaths | Select-Object -Unique)) {
                Write-Host "      jar: $path" -ForegroundColor DarkCyan
            }
        }
    }
    Write-Host ""
}

if (-not $SkipMemoryScan) {
    $allMemoryHits = @($memoryResults | ForEach-Object { @($_.Hits) })
    if ($allMemoryHits.Count -gt 0) {
        Write-XmaSection -Title "Java Memory String Hits" -Color Red
        foreach ($res in $memoryResults) {
            $proc = $javaProcesses | Where-Object { $_.ProcessId -eq $res.ProcessId } | Select-Object -First 1
            $procName = if ($proc) { "$($proc.Name) PID $($res.ProcessId)" } else { "PID $($res.ProcessId)" }
            Write-Host ""
            Write-Host $procName -ForegroundColor White
            if ($res.Error) {
                Write-Host "  - $($res.Error)" -ForegroundColor Yellow
                continue
            }

            $needleBuckets = @{}
            foreach ($hit in @($res.Hits)) {
                if (-not $needleBuckets.ContainsKey($hit.Needle)) {
                    $needleBuckets[$hit.Needle] = New-Object System.Collections.Generic.List[string]
                }
                if ($needleBuckets[$hit.Needle].Count -lt 3) {
                    $needleBuckets[$hit.Needle].Add($hit.Sample)
                }
            }

            foreach ($needle in ($needleBuckets.Keys | Sort-Object)) {
                Write-Host "  - hit: $needle" -ForegroundColor Yellow
                foreach ($sample in @($needleBuckets[$needle])) {
                    Write-Host "      sample: $sample" -ForegroundColor DarkGray
                }
            }
        }
        Write-Host ""
    } else {
        Write-XmaSection -Title "Java Memory String Hits" -Color Green
        Write-Host "none" -ForegroundColor Green
        Write-Host ""
    }
}

if (@($hiddenReport).Count -gt 0) {
    Write-Host "Hidden/system jar report" -ForegroundColor Yellow
    foreach ($h in $hiddenReport) {
        Write-Host "- $($h.FileName): before=$($h.Before), after=$($h.After)" -ForegroundColor DarkYellow
    }
    Write-Host ""
}
