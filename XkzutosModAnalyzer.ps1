[CmdletBinding()]
param(
    [string]$Path,
    [switch]$RuntimeScan,
    [switch]$MemoryScan,
    [ValidateRange(16, 512)]
    [int]$MemoryScanMB = 64,
    [ValidateSet("Console", "Json", "Csv")]
    [string]$OutputFormat = "Console",
    [string]$OutFile,
    [switch]$NoOnlineVerification,
    [switch]$Quiet
)

Set-StrictMode -Version 3
$ErrorActionPreference = "Stop"

$script:XmaConfig = @{
    Name = "xkzuto's mod analyzer"
    Version = "1.0.3"
    Creator = "xKzuto"
    Credits = @(
        [pscustomobject]@{
            Name = "Veridon"
            Project = "Yumiko Mod Analyzer"
            Url = "https://github.com/veridondevvv/YumikoModAnalyzer"
        },
        [pscustomobject]@{
            Name = "YarpLetapStan"
            Project = "Yarp's Mod Analyzer"
            Url = "https://github.com/YarpLetapStan/PowershellScripts"
        },
        [pscustomobject]@{
            Name = "MeowTonynoh"
            Project = "Meow Mod Analyzer inspiration"
            Url = "https://github.com/MeowTonynoh"
        }
    )
    DirectCheatTokens = @(
        "autocrystal", "auto crystal", "crystalaura", "crystalaura", "triggerbot",
        "killaura", "kill aura", "aimassist", "silentaim", "xray",
        "antiknockback", "anti knockback", "nofall", "scaffold",
        "surround", "autototem", "hover totem", "inventorytotem", "clickgui",
        "selfdestruct", "silent aim", "safewalk", "trigger bot", "backtrack",
        "packetfly", "packet fly", "blink", "fake lag", "pingspoof"
    )
    SuspiciousClassTokens = @(
        "endkrystal", "crystal", "aura", "trigger", "aim", "totem", "clickgui",
        "hud", "module", "setting", "clientui", "renderutils", "crosshair",
        "handledscreen", "keybinding", "interactionmanager", "minecraftclientmixin",
        "playerentity", "classtransformer", "callbackinjector", "refmapresolver",
        "accesswidenerhelper", "mixinconfigparser", "bytecodeanalyzer",
        "unsafe", "instrument", "transformer", "webhook", "injector"
    )
    RuntimeNeedles = @(
        "-javaagent", "-agentlib", "-agentpath", "-Dfabric.addMods",
        "-Dfabric.loadMods", "-Dforge.addMods", "-Dfml.coreMods.load",
        "-Xbootclasspath", "java.lang.instrument", "classloader", "defineclass",
        "sun/misc/unsafe", "jdk/internal/misc/unsafe", "org/objectweb/asm",
        "discord.com/api/webhooks", "pastebin", "webhook", "fabric.mixin.debug.export",
        "java/system/class/loader"
    )
    NetworkTokens = @(
        "discord.com/api/webhooks", "discordapp.com/api/webhooks",
        "pastebin", "hastebin", "rentry", "anonfiles",
        "raw.githubusercontent.com", "mega.nz", "mediafire"
    )
    PlaceholderTokens = @(
        "template-mod", "com.example", "hello fabric world!",
        "this is an example description", "me!", "examplemixin"
    )
    PerformanceTokens = @(
        "very many players", "vmp", "performance", "optimization",
        "optimisation", "server performance"
    )
    ClientSideTokens = @(
        "ui/", "shaders/", "render", "screen", "crosshair", "keybinding",
        "hud", "client", "rounded_rect", "setting", "clickgui"
    )
    InjectionTokens = @(
        "classloader", "defineclass", "unsafe", "org/objectweb/asm",
        "java/lang/reflect", "processbuilder", "java/lang/runtime",
        "appendtosystemclassloadersearch", "java/lang/instrument",
        "loadlibrary", "attachprovider", "socket", "urlconnection"
    )
    RuntimeArgCategories = @{
        "Java agent injection" = @("-javaagent", "-agentpath", "-agentlib")
        "Fabric or Forge injection" = @("-Dfabric.addMods", "-Dfabric.loadMods", "-Dforge.addMods", "-Dfml.coreMods.load")
        "Classpath manipulation" = @("-Xbootclasspath", "-Djava.system.class.loader", "-Djava.class.path")
        "Mixin debug export" = @("-Dfabric.mixin.debug.export", "-Dmixin.debug.export")
    }
}

$script:XmaMemoryApiLoaded = $false
function New-XmaFinding {
    param(
        [Parameter(Mandatory)]
        [string]$Severity,
        [Parameter(Mandatory)]
        [string]$Category,
        [Parameter(Mandatory)]
        [string]$Reason,
        [string[]]$Evidence = @(),
        [int]$Score = 0
    )

    [pscustomobject]@{
        Severity = $Severity
        Category = $Category
        Reason = $Reason
        Evidence = @($Evidence | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)
        Score = $Score
    }
}

function Get-XmaLower {
    param([AllowNull()][string]$Value)
    if ($null -eq $Value) {
        return ""
    }

    return $Value.ToLowerInvariant()
}

function Get-XmaFileHashSafe {
    param(
        [Parameter(Mandatory)]
        [string]$Path,
        [string]$Algorithm = "SHA256"
    )

    try {
        return (Get-FileHash -LiteralPath $Path -Algorithm $Algorithm -ErrorAction Stop).Hash.ToLowerInvariant()
    } catch {
        return ""
    }
}

function Get-XmaEntryText {
    param(
        [Parameter(Mandatory)]
        [System.IO.Compression.ZipArchive]$Zip,
        [Parameter(Mandatory)]
        [string]$EntryName
    )

    $entry = $Zip.Entries | Where-Object { $_.FullName -eq $EntryName } | Select-Object -First 1
    if (-not $entry) {
        return $null
    }

    $reader = [System.IO.StreamReader]::new($entry.Open())
    try {
        return $reader.ReadToEnd()
    } finally {
        $reader.Dispose()
    }
}

function Get-XmaEntryBytes {
    param(
        [Parameter(Mandatory)]
        [System.IO.Compression.ZipArchiveEntry]$Entry,
        [int64]$MaxBytes = 786432
    )

    $length = [int][Math]::Min([int64]$Entry.Length, $MaxBytes)
    if ($length -le 0) {
        return @()
    }

    $buffer = New-Object byte[] $length
    $stream = $Entry.Open()
    try {
        $offset = 0
        while ($offset -lt $length) {
            $read = $stream.Read($buffer, $offset, $length - $offset)
            if ($read -le 0) {
                break
            }

            $offset += $read
        }

        if ($offset -lt $length) {
            if ($offset -eq 0) {
                return @()
            }

            return $buffer[0..($offset - 1)]
        }

        return $buffer
    } finally {
        $stream.Dispose()
    }
}

function Get-XmaPrintableStrings {
    param([byte[]]$Bytes)

    if (-not $Bytes -or $Bytes.Length -eq 0) {
        return @()
    }

    $ascii = [System.Text.Encoding]::ASCII.GetString($Bytes)
    $matches = [regex]::Matches($ascii, "[ -~]{4,}")
    if ($matches.Count -eq 0) {
        return @()
    }

    $values = foreach ($match in $matches) {
        $match.Value.Trim()
    }

    return [string[]]@($values | Where-Object { $_.Length -ge 4 } | Select-Object -Unique)
}

function Get-XmaMatches {
    param(
        [Parameter(Mandatory)]
        [string]$Text,
        [Parameter(Mandatory)]
        [string[]]$Tokens
    )

    $lower = Get-XmaLower $Text
    $found = foreach ($token in $Tokens) {
        $normalized = Get-XmaLower $token
        if ($normalized -and $lower.Contains($normalized)) {
            $token
        }
    }

    return [string[]]@($found | Select-Object -Unique)
}

function Get-XmaNamespacePrefix {
    param([string]$TypeName)

    $normalized = ($TypeName -replace "\\", "/") -replace "\.", "/"
    $parts = $normalized -split "/"
    if ($parts.Count -lt 2) {
        return $normalized.Trim("/")
    }

    $maxIndex = [Math]::Min(2, $parts.Count - 2)
    return ($parts[0..$maxIndex] -join "/")
}

function Get-XmaExpectedNamespacePrefixes {
    param([object[]]$EntryPoints)

    $prefixes = foreach ($item in @($EntryPoints)) {
        if ($item) {
            Get-XmaNamespacePrefix -TypeName ([string]$item)
        }
    }

    return [string[]]@($prefixes | Where-Object { $_ } | Select-Object -Unique)
}

function Get-XmaJarMetadata {
    param(
        [Parameter(Mandatory)]
        [System.IO.Compression.ZipArchive]$Zip
    )

    $metadata = [ordered]@{
        Loader = "Unknown"
        MetadataFile = ""
        Id = ""
        Name = ""
        Version = ""
        Description = ""
        Authors = @()
        EntryPoints = @()
        Mixins = @()
        AccessWidener = ""
        Contact = ""
        Manifest = ""
        RawMetadataText = @()
    }

    $manifest = Get-XmaEntryText -Zip $Zip -EntryName "META-INF/MANIFEST.MF"
    if ($manifest) {
        $metadata.Manifest = $manifest
        $metadata.RawMetadataText += $manifest
    }

    $fabricEntry = $Zip.Entries | Where-Object { $_.FullName -eq "fabric.mod.json" } | Select-Object -First 1
    if ($fabricEntry) {
        $fabricText = Get-XmaEntryText -Zip $Zip -EntryName "fabric.mod.json"
        $metadata.RawMetadataText += $fabricText
        try {
            $json = $fabricText | ConvertFrom-Json -ErrorAction Stop
            $metadata.Loader = "Fabric"
            $metadata.MetadataFile = "fabric.mod.json"
            $metadata.Id = [string]$json.id
            $metadata.Name = [string]$json.name
            $metadata.Version = [string]$json.version
            $metadata.Description = [string]$json.description
            $metadata.Authors = @($json.authors)
            $metadata.Mixins = @($json.mixins)
            $metadata.AccessWidener = [string]$json.accessWidener
            $metadata.Contact = [string]$json.contact.sources
            if ($json.entrypoints) {
                $entryPointList = New-Object System.Collections.Generic.List[string]
                foreach ($property in $json.entrypoints.PSObject.Properties) {
                    foreach ($value in @($property.Value)) {
                        if ($value) {
                            $entryPointList.Add([string]$value)
                        }
                    }
                }
                $metadata.EntryPoints = @($entryPointList.ToArray())
            }
        } catch {
        }
    } else {
        $quiltEntry = $Zip.Entries | Where-Object { $_.FullName -eq "quilt.mod.json" } | Select-Object -First 1
        if ($quiltEntry) {
            $quiltText = Get-XmaEntryText -Zip $Zip -EntryName "quilt.mod.json"
            $metadata.RawMetadataText += $quiltText
            try {
                $json = $quiltText | ConvertFrom-Json -ErrorAction Stop
                $metadata.Loader = "Quilt"
                $metadata.MetadataFile = "quilt.mod.json"
                $metadata.Id = [string]$json.quilt_loader.id
                $metadata.Name = [string]$json.quilt_loader.metadata.name
                $metadata.Version = [string]$json.quilt_loader.version
                $metadata.Description = [string]$json.quilt_loader.metadata.description
                $metadata.Authors = @($json.quilt_loader.metadata.contributors.PSObject.Properties.Name)
                $metadata.EntryPoints = @($json.quilt_loader.entrypoints.main)
            } catch {
            }
        } else {
            $modsTomlEntry = $Zip.Entries | Where-Object { $_.FullName -eq "META-INF/mods.toml" } | Select-Object -First 1
            if ($modsTomlEntry) {
                $modsToml = Get-XmaEntryText -Zip $Zip -EntryName "META-INF/mods.toml"
                $metadata.RawMetadataText += $modsToml
                $metadata.Loader = "Forge"
                $metadata.MetadataFile = "META-INF/mods.toml"
                if ($modsToml -match '(?m)^\s*modId\s*=\s*"([^"]+)"') {
                    $metadata.Id = $matches[1]
                }
                if ($modsToml -match '(?m)^\s*displayName\s*=\s*"([^"]+)"') {
                    $metadata.Name = $matches[1]
                }
                if ($modsToml -match '(?m)^\s*version\s*=\s*"([^"]+)"') {
                    $metadata.Version = $matches[1]
                }
                if ($modsToml -match '(?m)^\s*description\s*=\s*"""([\s\S]+?)"""') {
                    $metadata.Description = ($matches[1] -replace "\r", "" -replace "^\s+|\s+$", "")
                }
            }
        }
    }

    $metadata.RawMetadataText = @($metadata.RawMetadataText | Where-Object { $_ })
    return [pscustomobject]$metadata
}

function Get-XmaModrinthVerification {
    param(
        [Parameter(Mandatory)]
        [string]$JarPath
    )

    if ($NoOnlineVerification) {
        return $null
    }

    $sha1 = Get-XmaFileHashSafe -Path $JarPath -Algorithm "SHA1"
    if (-not $sha1) {
        return $null
    }

    try {
        $headers = @{ "User-Agent" = "xkzutos-mod-analyzer/1.0.0" }
        $versionInfo = Invoke-RestMethod -Method Get -Uri "https://api.modrinth.com/v2/version_file/$sha1" -Headers $headers -TimeoutSec 10 -ErrorAction Stop
        if (-not $versionInfo.project_id) {
            return $null
        }

        $projectInfo = Invoke-RestMethod -Method Get -Uri "https://api.modrinth.com/v2/project/$($versionInfo.project_id)" -Headers $headers -TimeoutSec 10 -ErrorAction Stop
        return [pscustomobject]@{
            Verified = $true
            Project = [string]$projectInfo.title
            Slug = [string]$projectInfo.slug
            Version = [string]$versionInfo.version_number
        }
    } catch {
        return $null
    }
}

function Initialize-XmaMemoryApi {
    if ($script:XmaMemoryApiLoaded) {
        return
    }

    try {
        Add-Type @"
using System;
using System.Runtime.InteropServices;

public static class XmaMemoryNative {
    public const uint PROCESS_VM_READ = 0x0010;
    public const uint PROCESS_QUERY_INFORMATION = 0x0400;
    public const uint MEM_COMMIT = 0x1000;
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

    [DllImport("kernel32.dll")]
    public static extern IntPtr OpenProcess(uint desiredAccess, bool inheritHandle, int processId);

    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll")]
    public static extern Int32 VirtualQueryEx(
        IntPtr hProcess,
        IntPtr lpAddress,
        out MEMORY_BASIC_INFORMATION lpBuffer,
        UInt32 dwLength
    );

    [DllImport("kernel32.dll")]
    public static extern bool ReadProcessMemory(
        IntPtr hProcess,
        IntPtr lpBaseAddress,
        byte[] lpBuffer,
        int dwSize,
        out int lpNumberOfBytesRead
    );
}
"@ -ErrorAction Stop
        $script:XmaMemoryApiLoaded = $true
    } catch {
        $script:XmaMemoryApiLoaded = $false
    }
}

function Get-XmaJavaRuntimeFindings {
    param(
        [switch]$EnableMemoryScan,
        [int]$MaxMemoryMB = 64
    )

    $findings = New-Object System.Collections.Generic.List[object]
    $processes = Get-CimInstance Win32_Process -Filter "name = 'java.exe' OR name = 'javaw.exe'" -ErrorAction SilentlyContinue
    if (-not $processes) {
        return @()
    }

    Initialize-XmaMemoryApi
    foreach ($process in $processes) {
        $commandLine = [string]$process.CommandLine
        $lowerCommandLine = Get-XmaLower $commandLine
        $processFindings = New-Object System.Collections.Generic.List[object]

        foreach ($category in $script:XmaConfig.RuntimeArgCategories.Keys) {
            $hits = foreach ($needle in $script:XmaConfig.RuntimeArgCategories[$category]) {
                if ($lowerCommandLine.Contains((Get-XmaLower $needle))) {
                    $needle
                }
            }

            $hits = @($hits | Select-Object -Unique)
            if ($hits.Count -gt 0) {
                $processFindings.Add((New-XmaFinding -Severity "High" -Category "Runtime" -Reason "$category detected in the Java command line." -Evidence $hits -Score 25))
            }
        }

        $clientHits = Get-XmaMatches -Text $commandLine -Tokens @("meteor", "future", "impact", "aristois", "wurst", "vape", "rise", "novoline", "tenacity", "konas", "phobos")
        if ($clientHits.Count -gt 0) {
            $processFindings.Add((New-XmaFinding -Severity "High" -Category "Runtime" -Reason "Known cheat-client names were found in the Java command line." -Evidence $clientHits -Score 35))
        }

        if ($EnableMemoryScan -and $script:XmaMemoryApiLoaded) {
            $memoryHits = Search-XmaProcessMemory -ProcessId $process.ProcessId -MaxMemoryMB $MaxMemoryMB -Needles $script:XmaConfig.RuntimeNeedles
            if ($memoryHits.Count -gt 0) {
                $processFindings.Add((New-XmaFinding -Severity "High" -Category "Memory" -Reason "Suspicious runtime strings were found in Java process memory." -Evidence $memoryHits -Score 35))
            }
        }

        if ($processFindings.Count -gt 0) {
            $findings.Add([pscustomobject]@{
                ProcessId = [int]$process.ProcessId
                Name = [string]$process.Name
                ExecutablePath = [string]$process.ExecutablePath
                CommandLine = $commandLine
                Findings = @($processFindings)
            })
        }
    }

    return @($findings)
}

function Search-XmaProcessMemory {
    param(
        [int]$ProcessId,
        [int]$MaxMemoryMB,
        [string[]]$Needles
    )

    $hits = New-Object System.Collections.Generic.List[string]
    $access = [XmaMemoryNative]::PROCESS_QUERY_INFORMATION -bor [XmaMemoryNative]::PROCESS_VM_READ
    $handle = [XmaMemoryNative]::OpenProcess($access, $false, $ProcessId)
    if ($handle -eq [IntPtr]::Zero) {
        return @()
    }

    try {
        $maximumBytes = [Math]::Max(16, $MaxMemoryMB) * 1MB
        $scannedBytes = 0L
        $address = [IntPtr]::Zero
        $mbi = New-Object XmaMemoryNative+MEMORY_BASIC_INFORMATION
        $mbiSize = [System.Runtime.InteropServices.Marshal]::SizeOf([type]([XmaMemoryNative+MEMORY_BASIC_INFORMATION]))

        while ($scannedBytes -lt $maximumBytes) {
            $queryResult = [XmaMemoryNative]::VirtualQueryEx($handle, $address, [ref]$mbi, [uint32]$mbiSize)
            if ($queryResult -eq 0) {
                break
            }

            $regionSize = [int64]$mbi.RegionSize
            if ($regionSize -le 0) {
                break
            }

            $isReadable = ($mbi.State -eq [XmaMemoryNative]::MEM_COMMIT) -and (($mbi.Protect -band [XmaMemoryNative]::PAGE_GUARD) -eq 0) -and (($mbi.Protect -band [XmaMemoryNative]::PAGE_NOACCESS) -eq 0)
            if ($isReadable) {
                $bytesToRead = [int][Math]::Min($regionSize, 262144)
                if ($scannedBytes + $bytesToRead -gt $maximumBytes) {
                    $bytesToRead = [int]($maximumBytes - $scannedBytes)
                }

                if ($bytesToRead -gt 0) {
                    $buffer = New-Object byte[] $bytesToRead
                    $bytesRead = 0
                    if ([XmaMemoryNative]::ReadProcessMemory($handle, $mbi.BaseAddress, $buffer, $bytesToRead, [ref]$bytesRead)) {
                        if ($bytesRead -gt 0) {
                            $text = [System.Text.Encoding]::ASCII.GetString($buffer, 0, $bytesRead)
                            foreach ($needle in $Needles) {
                                $normalized = Get-XmaLower $needle
                                if ($normalized -and (Get-XmaLower $text).Contains($normalized)) {
                                    $hits.Add($needle)
                                }
                            }
                        }
                    }

                    $scannedBytes += $bytesToRead
                }
            }

            $nextAddress = $mbi.BaseAddress.ToInt64() + $regionSize
            if ($nextAddress -le $address.ToInt64()) {
                break
            }

            $address = [IntPtr]::new($nextAddress)
        }
    } catch {
        return @($hits | Select-Object -Unique)
    } finally {
        [void][XmaMemoryNative]::CloseHandle($handle)
    }

    return @($hits | Select-Object -Unique)
}

function Measure-XmaJarRisk {
    param(
        [Parameter(Mandatory)]
        [string]$JarPath
    )

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [System.IO.Compression.ZipFile]::OpenRead($JarPath)
    try {
        $metadata = Get-XmaJarMetadata -Zip $zip
        $entryNames = @($zip.Entries | Select-Object -ExpandProperty FullName)
        $classEntries = @($zip.Entries | Where-Object { $_.FullName -like "*.class" })
        $classNames = @($classEntries | ForEach-Object { $_.FullName })
        $entryText = (($entryNames -join "`n") + "`n" + ($metadata.RawMetadataText -join "`n"))
        $findings = New-Object System.Collections.Generic.List[object]

        $expectedPrefixes = @(Get-XmaExpectedNamespacePrefixes -EntryPoints $metadata.EntryPoints)
        $lowerMetadata = Get-XmaLower (($metadata.RawMetadataText -join "`n") + "`n" + $metadata.Name + "`n" + $metadata.Description)

        $placeholderHits = @(Get-XmaMatches -Text $lowerMetadata -Tokens $script:XmaConfig.PlaceholderTokens)
        if (@($placeholderHits).Count -gt 0) {
            $findings.Add((New-XmaFinding -Severity "High" -Category "Metadata" -Reason "The mod ships placeholder or template metadata instead of real project information." -Evidence $placeholderHits -Score 35))
        }

        $shortRootBuckets = @{}
        foreach ($className in $classNames) {
            $normalized = $className -replace "\\", "/"
            $parts = $normalized -split "/"
            if ($parts.Count -lt 2) {
                continue
            }

            $root = $parts[0]
            if (-not $shortRootBuckets.ContainsKey($root)) {
                $shortRootBuckets[$root] = 0
            }

            $shortRootBuckets[$root]++
        }

        if (@($expectedPrefixes).Count -gt 0 -and @($classNames).Count -gt 0) {
            $outOfNamespace = @()
            foreach ($className in $classNames) {
                $normalized = $className -replace "\\", "/"
                $matchesExpected = $false
                foreach ($prefix in $expectedPrefixes) {
                    if ($normalized.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
                        $matchesExpected = $true
                        break
                    }
                }

                if (-not $matchesExpected) {
                    $outOfNamespace += $normalized
                }
            }

            if (@($outOfNamespace).Count -gt 0) {
                $outsideRootCounts = $outOfNamespace | Group-Object { ($_.Split("/"))[0] } | Sort-Object Count -Descending
                $topOutside = $outsideRootCounts | Select-Object -First 1
                $ratio = [math]::Round((@($outOfNamespace).Count / [double]@($classNames).Count) * 100, 1)
                if ($topOutside -and $topOutside.Name.Length -le 2 -and $ratio -ge 25) {
                    $findings.Add((New-XmaFinding -Severity "High" -Category "Namespace" -Reason "A large part of the jar lives outside the declared entrypoint namespace in a very short package name, which is common in disguised or repackaged mods." -Evidence @("Outside namespace classes: $(@($outOfNamespace).Count)/$(@($classNames).Count) ($ratio%)", "Largest hidden root package: $($topOutside.Name) ($($topOutside.Count) classes)") -Score 30))
                }
            }
        }

        $shortRootEvidence = @()
        foreach ($bucket in $shortRootBuckets.GetEnumerator() | Sort-Object Value -Descending) {
            if ($bucket.Key.Length -le 2 -and $bucket.Value -ge 20) {
                $shortRootEvidence += "$($bucket.Key)/ ($($bucket.Value) classes)"
            }
        }

        if (@($shortRootEvidence).Count -gt 0) {
            $findings.Add((New-XmaFinding -Severity "Medium" -Category "Obfuscation" -Reason "The jar uses large short-name root packages that make review harder and often hide real implementation code." -Evidence $shortRootEvidence -Score 18))
        }

        $repeatedSegmentCount = 0
        foreach ($className in $classNames) {
            $segments = ($className -replace "\.class$", "") -split "/"
            if (@($segments | Select-Object -Unique).Count -lt @($segments).Count) {
                $repeatedSegmentCount++
            }
        }

        if ($repeatedSegmentCount -ge 10) {
            $findings.Add((New-XmaFinding -Severity "Medium" -Category "Structure" -Reason "Many class paths repeat the same namespace segments, which often indicates repackaging, namespace spoofing, or stitched-together code." -Evidence @("$repeatedSegmentCount class paths reuse one or more segments") -Score 16))
        }

        $suspiciousEntryHits = @(Get-XmaMatches -Text $entryText -Tokens $script:XmaConfig.SuspiciousClassTokens)
        $directCheatHits = @(Get-XmaMatches -Text $entryText -Tokens $script:XmaConfig.DirectCheatTokens)
        $networkHits = @(Get-XmaMatches -Text $entryText -Tokens $script:XmaConfig.NetworkTokens)
        $injectionHits = @(Get-XmaMatches -Text $entryText -Tokens $script:XmaConfig.InjectionTokens)

        if (@($directCheatHits).Count -gt 0) {
            $findings.Add((New-XmaFinding -Severity "High" -Category "Cheat Signals" -Reason "Direct cheat-oriented terms were found in class names, metadata, or embedded text." -Evidence $directCheatHits -Score 45))
        }

        $transformerEvidence = @($suspiciousEntryHits | Where-Object { $_ -in @("classtransformer", "callbackinjector", "refmapresolver", "accesswidenerhelper", "mixinconfigparser", "bytecodeanalyzer", "instrument", "injector", "transformer") } | Select-Object -Unique)
        if (@($transformerEvidence).Count -gt 0 -or @($injectionHits).Count -gt 0) {
            $evidence = @((@($transformerEvidence) + @($injectionHits)) | Select-Object -Unique)
            $findings.Add((New-XmaFinding -Severity "High" -Category "Injection" -Reason "The jar exposes bytecode transformation or runtime injection helpers that deserve manual review." -Evidence $evidence -Score 28))
        }

        if (@($networkHits).Count -gt 0) {
            $findings.Add((New-XmaFinding -Severity "High" -Category "Network" -Reason "The jar references suspicious external services commonly used for loaders, webhooks, or hidden control paths." -Evidence $networkHits -Score 20))
        }

        $mixinFiles = @($entryNames | Where-Object { $_ -match "(?i)(^|/).+mixin.*\.json$|\.mixins\.json$" })
        if (@($mixinFiles).Count -gt 0) {
            foreach ($mixinFile in $mixinFiles) {
                $mixinText = Get-XmaEntryText -Zip $zip -EntryName $mixinFile
                if (-not $mixinText) {
                    continue
                }

                $mixinHits = @(Get-XmaMatches -Text $mixinText -Tokens @("minecraftclient", "handledscreen", "keybinding", "interactionmanager", "crosshair", "endkrystal", "clientplayer", "screen", "examplemixin"))
                if (@($mixinHits).Count -gt 0) {
                    $evidence = @(@($mixinFile) + @($mixinHits))
                    $findings.Add((New-XmaFinding -Severity "High" -Category "Mixin" -Reason "The mixin configuration targets client-only, UI, input, or combat-related code paths." -Evidence $evidence -Score 26))
                }
            }
        }

        $suspiciousClientClasses = @($classNames | Where-Object {
            $lowerName = Get-XmaLower $_
            $lowerName.Contains("clientui") -or
            $lowerName.Contains("renderutils") -or
            $lowerName.Contains("keybinding") -or
            $lowerName.Contains("handledscreen") -or
            $lowerName.Contains("crosshair") -or
            $lowerName.Contains("endkrystal")
        } | Select-Object -First 10)

        $metadataClaimsPerformance = @(
            Get-XmaMatches -Text ($metadata.Name + "`n" + $metadata.Description + "`n" + $metadata.Id) -Tokens $script:XmaConfig.PerformanceTokens
        ).Count -gt 0
        if ($metadataClaimsPerformance -and @($suspiciousClientClasses).Count -gt 0) {
            $findings.Add((New-XmaFinding -Severity "High" -Category "Role Mismatch" -Reason "The metadata looks like a performance or utility mod, but the jar contains client UI, rendering, input, or crystal-related classes that do not fit that role." -Evidence $suspiciousClientClasses -Score 34))
        }

        $weirdNestedMeta = @($entryNames | Where-Object { $_ -like "META-INF/jars/*" -and $_ -notlike "*.jar" })
        if (@($weirdNestedMeta).Count -gt 0) {
            $findings.Add((New-XmaFinding -Severity "Medium" -Category "Packaging" -Reason "Suspicious files were found under META-INF/jars even though they are not jars." -Evidence $weirdNestedMeta -Score 15))
        }

        $selectedEntries = @(
            $classEntries | Sort-Object @{ Expression = { if ((Get-XmaLower $_.FullName) -match "crystal|mixin|client|render|transform|inject|unsafe|refmap|callback|ui|screen|key") { 0 } else { 1 } } }, @{ Expression = { $_.Length }; Descending = $true } | Select-Object -First 80
        )

        $bytecodeEvidence = New-Object System.Collections.Generic.List[string]
        foreach ($entry in $selectedEntries) {
            $strings = Get-XmaPrintableStrings -Bytes (Get-XmaEntryBytes -Entry $entry)
            if (-not $strings -or @($strings).Count -eq 0) {
                continue
            }

            $joined = $strings -join "`n"
            $hits = @(
                (Get-XmaMatches -Text $joined -Tokens $script:XmaConfig.DirectCheatTokens) +
                (Get-XmaMatches -Text $joined -Tokens $script:XmaConfig.InjectionTokens) +
                (Get-XmaMatches -Text $joined -Tokens $script:XmaConfig.NetworkTokens) +
                (Get-XmaMatches -Text $joined -Tokens $script:XmaConfig.PlaceholderTokens)
            ) | Select-Object -Unique

            if (@($hits).Count -gt 0) {
                $preview = ($hits | Select-Object -First 4) -join ", "
                $bytecodeEvidence.Add("$($entry.FullName): $preview")
            }
        }

        if (@($bytecodeEvidence).Count -gt 0) {
            $findings.Add((New-XmaFinding -Severity "Medium" -Category "Bytecode" -Reason "Review of printable class strings found suspicious embedded terms beyond filenames alone." -Evidence @($bytecodeEvidence | Select-Object -First 10) -Score 18))
        }

        $verification = Get-XmaModrinthVerification -JarPath $JarPath
        if ($verification) {
            $metadata | Add-Member -NotePropertyName VerifiedProject -NotePropertyValue $verification.Project -Force
            $metadata | Add-Member -NotePropertyName VerifiedVersion -NotePropertyValue $verification.Version -Force
            $metadata | Add-Member -NotePropertyName VerifiedSlug -NotePropertyValue $verification.Slug -Force
        }

        $findingArray = @($findings.ToArray())
        $score = 0
        foreach ($finding in $findingArray) {
            if ($null -ne $finding -and $finding.PSObject.Properties["Score"]) {
                $score += [int]$finding.Score
            }
        }

        $verdict = if ($score -ge 70) {
            "High Risk"
        } elseif ($score -ge 40) {
            "Suspicious"
        } elseif ($score -ge 20) {
            "Needs Review"
        } else {
            "Low Risk"
        }

        return [pscustomobject]@{
            FileName = [System.IO.Path]::GetFileName($JarPath)
            FilePath = (Resolve-Path -LiteralPath $JarPath).Path
            SizeBytes = (Get-Item -LiteralPath $JarPath).Length
            Sha256 = Get-XmaFileHashSafe -Path $JarPath -Algorithm "SHA256"
            Verdict = $verdict
            Score = [int]$score
            Metadata = $metadata
            Findings = @(
                $findingArray | Sort-Object -Property @(
                    @{ Expression = "Score"; Descending = $true },
                    @{ Expression = "Severity"; Descending = $false },
                    @{ Expression = "Category"; Descending = $false }
                )
            )
            Stats = [pscustomobject]@{
                TotalEntries = @($entryNames).Count
                ClassCount = @($classNames).Count
                Mixins = @($mixinFiles).Count
                ExpectedNamespaces = @($expectedPrefixes)
            }
        }
    } finally {
        $zip.Dispose()
    }
}

function Invoke-XmaScan {
    param(
        [Parameter(Mandatory)]
        [string]$TargetPath,
        [switch]$IncludeRuntimeScan,
        [switch]$EnableMemoryScan,
        [int]$MaxMemoryMB = 64
    )

    $resolvedTarget = Resolve-Path -LiteralPath $TargetPath -ErrorAction Stop
    $targetItem = Get-Item -LiteralPath $resolvedTarget.Path -ErrorAction Stop

    if ($targetItem.PSIsContainer) {
        $jarFiles = @(Get-ChildItem -LiteralPath $targetItem.FullName -File -Filter "*.jar" | Sort-Object Name)
    } else {
        if ($targetItem.Extension -ne ".jar") {
            throw "The selected file is not a jar."
        }

        $jarFiles = @($targetItem)
    }

    $reports = New-Object System.Collections.Generic.List[object]
    foreach ($jarFile in $jarFiles) {
        $reports.Add((Measure-XmaJarRisk -JarPath $jarFile.FullName))
    }

    $runtimeFindings = @()
    if ($IncludeRuntimeScan) {
        $runtimeFindings = Get-XmaJavaRuntimeFindings -EnableMemoryScan:$EnableMemoryScan -MaxMemoryMB $MaxMemoryMB
    }

    $reportArray = @($reports.ToArray())
    $runtimeArray = @($runtimeFindings)

    [pscustomobject]@{
        Analyzer = [pscustomobject]@{
            Name = $script:XmaConfig.Name
            Version = $script:XmaConfig.Version
            Creator = $script:XmaConfig.Creator
        }
        Target = $targetItem.FullName
        ScannedAt = (Get-Date).ToString("s")
        ModFindings = $reportArray
        RuntimeFindings = $runtimeArray
    }
}

function Convert-XmaReportToText {
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Report
    )

    $lines = New-Object System.Collections.Generic.List[string]
    $null = $lines.Add("$($Report.FileName)  [$($Report.Verdict)]  Score: $($Report.Score)")
    $null = $lines.Add("Path: $($Report.FilePath)")
    if ($Report.Metadata.Name -or $Report.Metadata.Id) {
        $null = $lines.Add("Metadata: $($Report.Metadata.Name)  id=$($Report.Metadata.Id)  loader=$($Report.Metadata.Loader)")
    }
    if ($Report.Metadata.PSObject.Properties["VerifiedProject"]) {
        $null = $lines.Add("Verified Project: $($Report.Metadata.VerifiedProject)  version=$($Report.Metadata.VerifiedVersion)")
    }
    $null = $lines.Add("Classes: $($Report.Stats.ClassCount)  Entries: $($Report.Stats.TotalEntries)  Mixins: $($Report.Stats.Mixins)")
    $null = $lines.Add("")

    if ($Report.Findings.Count -eq 0) {
        $null = $lines.Add("No strong cheat indicators were found. This does not guarantee the jar is safe.")
    } else {
        foreach ($finding in $Report.Findings) {
            $null = $lines.Add("$($finding.Severity) - $($finding.Category): $($finding.Reason)")
            foreach ($evidence in $finding.Evidence) {
                $null = $lines.Add("  * $evidence")
            }
        }
    }

    return ($lines -join [Environment]::NewLine)
}

function Convert-XmaRuntimeToText {
    param([object[]]$RuntimeFindings)

    if (-not $RuntimeFindings -or $RuntimeFindings.Count -eq 0) {
        return "No suspicious Java runtime findings were detected."
    }

    $lines = New-Object System.Collections.Generic.List[string]
    foreach ($runtime in $RuntimeFindings) {
        $null = $lines.Add("$($runtime.Name) PID $($runtime.ProcessId)")
        if ($runtime.ExecutablePath) {
            $null = $lines.Add("Path: $($runtime.ExecutablePath)")
        }
        foreach ($finding in $runtime.Findings) {
            $null = $lines.Add("$($finding.Severity) - $($finding.Category): $($finding.Reason)")
            foreach ($evidence in $finding.Evidence) {
                $null = $lines.Add("  * $evidence")
            }
        }
        $null = $lines.Add("")
    }

    return ($lines -join [Environment]::NewLine).Trim()
}

function Show-XmaConsoleReport {
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$ScanResult
    )

    if (-not $Quiet) {
        Write-Host ""
        Write-Host "$($script:XmaConfig.Name) v$($script:XmaConfig.Version)" -ForegroundColor Cyan
        Write-Host "Built by $($script:XmaConfig.Creator)" -ForegroundColor White
        Write-Host "Credits: $((@($script:XmaConfig.Credits | ForEach-Object { $_.Project + ' / ' + $_.Name }) -join '; '))" -ForegroundColor DarkGray
        Write-Host ""
    }

    $summaryBuckets = @{
        "High Risk" = 0
        "Suspicious" = 0
        "Needs Review" = 0
        "Low Risk" = 0
    }

    foreach ($report in $ScanResult.ModFindings) {
        if ($summaryBuckets.ContainsKey($report.Verdict)) {
            $summaryBuckets[$report.Verdict]++
        }
    }

    Write-Host "Target: $($ScanResult.Target)" -ForegroundColor Gray
    Write-Host "Files scanned: $($ScanResult.ModFindings.Count)" -ForegroundColor Gray
    Write-Host "High Risk: $($summaryBuckets['High Risk'])  Suspicious: $($summaryBuckets['Suspicious'])  Needs Review: $($summaryBuckets['Needs Review'])  Low Risk: $($summaryBuckets['Low Risk'])" -ForegroundColor Yellow
    Write-Host ""

    foreach ($report in $ScanResult.ModFindings) {
        $color = switch ($report.Verdict) {
            "High Risk" { "Red" }
            "Suspicious" { "DarkYellow" }
            "Needs Review" { "Yellow" }
            default { "Green" }
        }

        Write-Host "$($report.FileName) [$($report.Verdict)] Score $($report.Score)" -ForegroundColor $color
        if ($report.Metadata.Name -or $report.Metadata.Id) {
            Write-Host "  Metadata: $($report.Metadata.Name) / $($report.Metadata.Id) / $($report.Metadata.Loader)" -ForegroundColor Gray
        }
        if ($report.Metadata.PSObject.Properties["VerifiedProject"]) {
            Write-Host "  Verified: $($report.Metadata.VerifiedProject) ($($report.Metadata.VerifiedVersion))" -ForegroundColor Green
        }

        if ($report.Findings.Count -eq 0) {
            Write-Host "  No strong cheat signals found. Still review unknown jars manually." -ForegroundColor DarkGray
        } else {
            foreach ($finding in $report.Findings | Select-Object -First 6) {
                Write-Host "  - $($finding.Category): $($finding.Reason)" -ForegroundColor White
                foreach ($evidence in $finding.Evidence | Select-Object -First 5) {
                    Write-Host "    * $evidence" -ForegroundColor DarkGray
                }
            }
        }

        Write-Host ""
    }

    if ($ScanResult.RuntimeFindings.Count -gt 0) {
        Write-Host "Runtime Findings" -ForegroundColor Magenta
        Write-Host (Convert-XmaRuntimeToText -RuntimeFindings $ScanResult.RuntimeFindings) -ForegroundColor White
        Write-Host ""
    }
}

function Export-XmaResults {
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$ScanResult,
        [Parameter(Mandatory)]
        [string]$Destination,
        [ValidateSet("Json", "Csv")]
        [string]$Format = "Json"
    )

    $resolvedDestination = [System.IO.Path]::GetFullPath($Destination)
    $parent = Split-Path -Parent $resolvedDestination
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }

    if ($Format -eq "Json") {
        $ScanResult | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $resolvedDestination -Encoding UTF8
        return
    }

    $rows = foreach ($report in $ScanResult.ModFindings) {
        [pscustomobject]@{
            FileName = $report.FileName
            Verdict = $report.Verdict
            Score = $report.Score
            ModId = $report.Metadata.Id
            ModName = $report.Metadata.Name
            Loader = $report.Metadata.Loader
            Reasons = (($report.Findings | ForEach-Object { $_.Reason }) -join " | ")
        }
    }

    $rows | Export-Csv -NoTypeInformation -LiteralPath $resolvedDestination -Encoding UTF8
}

function Resolve-XmaInteractivePath {
    while ($true) {
        $candidate = $Path
        if (-not $candidate) {
            Write-Host "Enter the jar file or mods folder path to scan." -ForegroundColor Cyan
            Write-Host "No default launcher path is used automatically because different launchers store mods in different places." -ForegroundColor DarkGray
            Write-Host "Press Enter to use the current folder only if you are already inside the folder you want to scan." -ForegroundColor DarkGray
            Write-Host "Examples: C:\Path\To\mods   or   C:\Path\To\mod.jar" -ForegroundColor DarkGray
            $candidate = Read-Host "Path"
            if ([string]::IsNullOrWhiteSpace($candidate)) {
                $currentDirectory = (Get-Location).Path
                $currentJarCount = @(Get-ChildItem -LiteralPath $currentDirectory -File -Filter "*.jar" -ErrorAction SilentlyContinue).Count
                if ($currentJarCount -gt 0) {
                    Write-Host "Using the current folder because it contains $currentJarCount jar file(s)." -ForegroundColor Green
                    return $currentDirectory
                }

                Write-Host "A path is required, or run the command from inside the target mods folder before pressing Enter." -ForegroundColor Yellow
                Write-Host ""
                continue
            }
        }

        if (Test-Path -LiteralPath $candidate) {
            return $candidate
        }

        Write-Host "That path does not exist: $candidate" -ForegroundColor Yellow
        Write-Host "Paste a valid jar file or mods folder path." -ForegroundColor DarkGray
        Write-Host ""
        $Path = $null
    }
}

$resolvedPath = Resolve-XmaInteractivePath
$scanResult = Invoke-XmaScan -TargetPath $resolvedPath -IncludeRuntimeScan:($RuntimeScan -or $MemoryScan) -EnableMemoryScan:$MemoryScan -MaxMemoryMB $MemoryScanMB

if ($OutFile) {
    Export-XmaResults -ScanResult $scanResult -Destination $OutFile -Format $OutputFormat
}

if ($OutputFormat -eq "Json" -and -not $OutFile) {
    $scanResult | ConvertTo-Json -Depth 10
} elseif ($OutputFormat -eq "Csv" -and -not $OutFile) {
    $rows = foreach ($report in $scanResult.ModFindings) {
        [pscustomobject]@{
            FileName = $report.FileName
            Verdict = $report.Verdict
            Score = $report.Score
            ModId = $report.Metadata.Id
            ModName = $report.Metadata.Name
            Loader = $report.Metadata.Loader
            Reasons = (($report.Findings | ForEach-Object { $_.Reason }) -join " | ")
        }
    }
    $rows | ConvertTo-Csv -NoTypeInformation
} else {
    Show-XmaConsoleReport -ScanResult $scanResult
}
