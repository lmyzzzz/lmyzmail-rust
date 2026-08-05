param(
    [Parameter(Mandatory = $true)]
    [string]$JavaRepository,
    [Parameter(Mandatory = $true)]
    [string]$OutputPath
)

$ErrorActionPreference = "Stop"
$commit = "5dac2ab2922c30c726c4a83d7626c95ad4e231c8"
$sourcePath = "src/main/java/net/lmyz/lmyzmail/mailbox/api/ApiStatusController.java"
$object = "${commit}:$sourcePath"
$lines = @(git -C $JavaRepository show $object)
if ($LASTEXITCODE -ne 0) {
    throw "Unable to read $object"
}

$inside = $false
$lore = @()
foreach ($line in $lines) {
    if ($line -match 'SKIBIDI_LORE = List\.of\(') {
        $inside = $true
        continue
    }
    if ($inside -and $line -match '^\s*\);') {
        break
    }
    if ($inside) {
        if ($line -notmatch '^\s*"(?<value>.*)"[,]?\s*$') {
            throw "Unexpected lore source line: $line"
        }
        if ($Matches.value.Contains('\')) {
            throw "Java escape decoding is not implemented for lore: $line"
        }
        $lore += $Matches.value
    }
}

if ($lore.Count -ne 233) {
    throw "Expected 233 lore strings, found $($lore.Count)"
}

$manifest = [ordered]@{
    schema_version = 1
    oracle_commit = $commit
    source = $sourcePath
    count = $lore.Count
    lore = $lore
}
$json = $manifest | ConvertTo-Json -Depth 4
$absoluteOutput = [IO.Path]::GetFullPath($OutputPath)
$parent = [IO.Path]::GetDirectoryName($absoluteOutput)
if (-not [IO.Directory]::Exists($parent)) {
    [IO.Directory]::CreateDirectory($parent) | Out-Null
}
[IO.File]::WriteAllText(
    $absoluteOutput,
    $json + [Environment]::NewLine,
    [Text.UTF8Encoding]::new($false)
)
