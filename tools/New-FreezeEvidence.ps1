[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $JavaRepository,

    [Parameter(Mandatory = $true)]
    [string] $SkibidiRepository,

    [Parameter(Mandatory = $true)]
    [string] $JavaCommit,

    [Parameter(Mandatory = $true)]
    [string] $SkibidiCommit,

    [Parameter(Mandatory = $true)]
    [string] $OracleJar
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)

function Invoke-GitText {
    param(
        [string] $Repository,
        [string[]] $Arguments
    )

    $output = & git -C $Repository @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "git failed in ${Repository}: $($Arguments -join ' ')"
    }
    return ($output -join "`n")
}

function Get-GitObjectBytes {
    param(
        [string] $Repository,
        [string] $Object
    )

    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = 'git.exe'
    $escapedRepository = $Repository.Replace('"', '\"')
    $escapedObject = $Object.Replace('"', '\"')
    $startInfo.Arguments = "-C `"$escapedRepository`" cat-file blob `"$escapedObject`""
    $startInfo.UseShellExecute = $false
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $startInfo
    [void] $process.Start()
    $memory = New-Object System.IO.MemoryStream
    $process.StandardOutput.BaseStream.CopyTo($memory)
    $stderr = $process.StandardError.ReadToEnd()
    $process.WaitForExit()
    if ($process.ExitCode -ne 0) {
        throw "git cat-file failed for ${Object}: $stderr"
    }
    return $memory.ToArray()
}

function Get-Sha256Hex {
    param([byte[]] $Bytes)

    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
}

function Get-FileSha256Hex {
    param([string] $Path)
    return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
}

function Quote-Csv {
    param([AllowEmptyString()][string] $Value)
    return '"' + $Value.Replace('"', '""') + '"'
}

function Write-Utf8Lines {
    param(
        [string] $Path,
        [string[]] $Lines
    )
    [System.IO.File]::WriteAllText($Path, (($Lines -join "`n") + "`n"), $utf8NoBom)
}

$javaEvidence = Join-Path $repoRoot 'evidence\freeze\java-oracle'
$skibidiEvidence = Join-Path $repoRoot 'evidence\freeze\skibidi-1.8.0'
[System.IO.Directory]::CreateDirectory($javaEvidence) | Out-Null
[System.IO.Directory]::CreateDirectory($skibidiEvidence) | Out-Null

$javaHead = (Invoke-GitText $JavaRepository @('rev-parse', $JavaCommit)).Trim()
$javaParent = (Invoke-GitText $JavaRepository @('rev-parse', "$JavaCommit^" )).Trim()
$skibidiHead = (Invoke-GitText $SkibidiRepository @('rev-parse', $SkibidiCommit)).Trim()
$skibidiParent = (Invoke-GitText $SkibidiRepository @('rev-parse', "$SkibidiCommit^" )).Trim()

$propertiesBytes = Get-GitObjectBytes $JavaRepository "${javaHead}:application.properties"
$propertiesText = [System.Text.Encoding]::UTF8.GetString($propertiesBytes)
$configLines = New-Object System.Collections.Generic.List[string]
$configLines.Add('# Frozen configuration keys. Sensitive values are intentionally omitted.')
foreach ($line in ($propertiesText -split "`n")) {
    $trimmed = $line.TrimEnd("`r")
    if ($trimmed -match '^\s*#' -or $trimmed -match '^\s*$') {
        continue
    }
    $separator = $trimmed.IndexOf('=')
    if ($separator -lt 1) {
        continue
    }
    $key = $trimmed.Substring(0, $separator).Trim()
    $value = $trimmed.Substring($separator + 1)
    $sensitive = $key -match '(?i)(password|secret|token|api[._-]?key|private[._-]?key|credential)'
    $embeddedCredential = $value -match '^[a-z][a-z0-9+.-]*://[^/@:]+:[^/@]+@'
    if ($sensitive -or $embeddedCredential) {
        $configLines.Add("$key=<redacted>")
    } else {
        $configLines.Add("$key=$value")
    }
}
Write-Utf8Lines (Join-Path $javaEvidence 'application.properties.redacted') $configLines.ToArray()

Add-Type -AssemblyName System.IO.Compression.FileSystem
$resourceLines = New-Object System.Collections.Generic.List[string]
$resourceLines.Add('path,size,sha256')
$archive = [System.IO.Compression.ZipFile]::OpenRead($OracleJar)
try {
    foreach ($entry in ($archive.Entries | Where-Object { -not $_.FullName.EndsWith('/') } | Sort-Object FullName)) {
        $stream = $entry.Open()
        try {
            $sha = [System.Security.Cryptography.SHA256]::Create()
            try {
                $hash = ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '').ToLowerInvariant()
            } finally {
                $sha.Dispose()
            }
        } finally {
            $stream.Dispose()
        }
        $resourceLines.Add("$(Quote-Csv $entry.FullName),$($entry.Length),$hash")
    }
} finally {
    $archive.Dispose()
}
Write-Utf8Lines (Join-Path $javaEvidence 'jar-resources.csv') $resourceLines.ToArray()

$javaPatch = Join-Path $javaEvidence 'java-oracle.patch'
$skibidiPatch = Join-Path $skibidiEvidence 'skibidi-1.8.0.patch'
$javaManifest = [ordered]@{
    schema_version = 1
    branch = 'codex/java-oracle-freeze'
    commit = $javaHead
    parent = $javaParent
    patch_sha256 = Get-FileSha256Hex $javaPatch
    configuration = [ordered]@{
        git_blob = (Invoke-GitText $JavaRepository @('rev-parse', "${javaHead}:application.properties")).Trim()
        canonical_sha256 = Get-Sha256Hex $propertiesBytes
        sanitized_file = 'application.properties.redacted'
    }
    oracle_jar = [ordered]@{
        local_name = 'lmyzmail-java-oracle.jar'
        bytes = (Get-Item -LiteralPath $OracleJar).Length
        provided_pre_rebuild_sha256 = '040bfa648cd0b3a1826ca61811dd6c71c8f2bd906578392f914020eb766fb70e'
        forced_rebuild_sha256 = Get-FileSha256Hex $OracleJar
        resource_inventory = 'jar-resources.csv'
        reproducibility_observation = 'Gradle bootJar preserved compile and resource timestamps, so a forced rebuild did not reproduce the provided pre-rebuild hash.'
    }
    verification = [ordered]@{
        command = '.\gradlew.bat clean test bootJar --rerun-tasks --no-daemon'
        gradle = '8.14.3'
        java = '22'
        tests = 93
        failures = 0
        errors = 0
        skipped = 0
    }
    excluded = @(
        'build products and ignored artifacts',
        'secrets and production credentials',
        'asciiart_linux/ffmpeg_src Windows executable-bit-only changes'
    )
}
[System.IO.File]::WriteAllText(
    (Join-Path $javaEvidence 'baseline.json'),
    (($javaManifest | ConvertTo-Json -Depth 8) + "`n"),
    $utf8NoBom
)

$skibidiSources = @('LICENSE', 'skibidi_avx.c', 'skibidi_avx.h', 'tests/test_skibidi.c')
$skibidiSourceLines = New-Object System.Collections.Generic.List[string]
$skibidiSourceLines.Add('path,size,sha256')
foreach ($path in $skibidiSources) {
    $bytes = Get-GitObjectBytes $SkibidiRepository "${skibidiHead}:$path"
    $skibidiSourceLines.Add("$(Quote-Csv $path),$($bytes.Length),$(Get-Sha256Hex $bytes)")
}
Write-Utf8Lines (Join-Path $skibidiEvidence 'source-inventory.csv') $skibidiSourceLines.ToArray()

$skibidiManifest = [ordered]@{
    schema_version = 1
    version = '1.8.0'
    branch = 'codex/skibidi-1.8.0-freeze'
    commit = $skibidiHead
    parent = $skibidiParent
    patch_sha256 = Get-FileSha256Hex $skibidiPatch
    verified_worktree_sha256 = [ordered]@{
        'skibidi_avx.c' = '7e8e7f3ee5bea0ac8d0857bd5bc8d806b44e5142c17ec8b5b6583db7c62fc613'
        'skibidi_avx.h' = 'bde8e9d19d6668c644aba1cdd81fb9f56c2236ff827ddd16fb366369bc68bbea'
    }
    source_inventory = 'source-inventory.csv'
    verification = @(
        [ordered]@{ command = './tests/run-tests.sh'; modes = @('avx2', 'scalar'); result = 'pass' },
        [ordered]@{ command = './tests/run-sanitizers.sh'; sanitizers = @('asan', 'ubsan'); modes = @('avx2', 'scalar'); result = 'pass' }
    )
    excluded = @('build directory', 'compiled binaries and libraries', 'secrets')
}
[System.IO.File]::WriteAllText(
    (Join-Path $skibidiEvidence 'baseline.json'),
    (($skibidiManifest | ConvertTo-Json -Depth 8) + "`n"),
    $utf8NoBom
)

Write-Host "Freeze evidence generated under $($repoRoot)"
