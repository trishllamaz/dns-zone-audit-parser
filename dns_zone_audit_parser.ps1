<#
.SYNOPSIS
    Parses a DNS zone audit CSV and flags redirect, hosting and resolution patterns.

.DESCRIPTION
    Reads a CSV of DNS records (one row per record, with resolution and HTTP
    check results), then adds:
      - RedirectDomain / RedirectPath   where each record ultimately lands
      - CNAMEProvider                   which hosting provider a CNAME points to
      - IPCluster                       which known host the resolved IP belongs to
      - Status                          Valid / Garbage / DNSFailure
      - *Count columns                  how many records share the same pattern

    Provider and IP mappings live in a JSON config so no infrastructure details
    are hardcoded in the script.

.PARAMETER InputCsv
    Path to the zone audit CSV.

.PARAMETER OutputCsv
    Where to write the enriched CSV. Defaults to .\AllPatterns.csv

.PARAMETER ConfigPath
    Path to the JSON config. Defaults to config.json next to this script,
    falling back to config.sample.json.

.EXAMPLE
    .\dns_zone_audit_parser.ps1 -InputCsv .\sample_input.csv -OutputCsv .\out.csv
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateScript({ Test-Path $_ -PathType Leaf })]
    [string]$InputCsv,

    [string]$OutputCsv = ".\AllPatterns.csv",

    [string]$ConfigPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
if (-not $ConfigPath) {
    $ConfigPath = Join-Path $PSScriptRoot 'config.json'
    if (-not (Test-Path $ConfigPath)) {
        $ConfigPath = Join-Path $PSScriptRoot 'config.sample.json'
    }
}
$config = Get-Content $ConfigPath -Raw | ConvertFrom-Json

# IP -> cluster name lookup
$ipClusterMap = @{}
foreach ($prop in $config.ipClusters.PSObject.Properties) {
    $ipClusterMap[$prop.Name] = $prop.Value
}

# ---------------------------------------------------------------------------
# Import, with header whitespace trimmed
# (Import-Csv property names are read-only, so trim the header line first)
# ---------------------------------------------------------------------------
$lines   = Get-Content $InputCsv
$headers = $lines[0] -split ',' | ForEach-Object { $_.Trim().Trim('"').Trim() }
$data    = $lines | Select-Object -Skip 1 | ConvertFrom-Csv -Header $headers

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
function ConvertTo-Url {
    param([string]$Url)

    if ([string]::IsNullOrWhiteSpace($Url)) { return $null }

    $Url = $Url.Trim()

    # Drop trailing junk the scanner sometimes appends (e.g. "United States")
    $Url = ($Url -split '\s+')[0]

    if ($Url -notmatch '://') { $Url = "http://$Url" }
    return $Url
}

function Get-RedirectDomain {
    param([string]$Url)

    $Url = ConvertTo-Url $Url
    if ($Url -and $Url -match '://([^/:]+)') { return $Matches[1].ToLower() }
    return 'NoRedirect'
}

function Get-RedirectPath {
    param([string]$Url)

    $Url = ConvertTo-Url $Url
    if ($Url -and $Url -match '://[^/]+(/.*)') { return $Matches[1].ToLower() }
    return 'None'
}

function Get-CNAMEProvider {
    param([string]$RecordType, [string]$RecordValue)

    if ($RecordType -ne 'CNAME') { return 'N/A' }

    foreach ($provider in $config.cnameProviders) {
        if ($RecordValue -match $provider.pattern) { return $provider.name }
    }
    return 'Other'
}

function Get-IPCluster {
    param([string]$IPs)

    if ([string]::IsNullOrWhiteSpace($IPs)) { return 'NoIP' }

    # Multiple IPs: classify by the first one
    # @() matters: with one IP, indexing a bare string returns its first character
    $first = @($IPs -split '[,;\s]+' | Where-Object { $_ })[0]

    if ($ipClusterMap.ContainsKey($first)) { return $ipClusterMap[$first] }
    return 'Other'
}

function Get-RecordStatus {
    # Note: avoids naming a parameter $error, which shadows PowerShell's
    # automatic $Error variable.
    param([string]$EffectiveUrl, [string]$DnsResolves, [string]$ErrorText)

    if ($ErrorText -match 'DNS Resolution Failed') { return 'DNSFailure' }

    if ($DnsResolves -eq 'No' -and [string]::IsNullOrWhiteSpace($EffectiveUrl)) {
        return 'Garbage'   # doesn't resolve and goes nowhere: likely stale/parked
    }
    return 'Valid'
}

function Get-Column {
    # Returns a column value, or $null if the column isn't in the CSV
    param($Row, [string]$Name)
    $prop = $Row.PSObject.Properties[$Name]
    if ($prop) { return $prop.Value }
    return $null
}

# ---------------------------------------------------------------------------
# Parse rows
# ---------------------------------------------------------------------------
$parsed = foreach ($row in $data) {
    $effective = Get-Column $row 'Effective URL'
    $type      = Get-Column $row 'Record Type'
    $value     = Get-Column $row 'Record Value'
    $ips       = Get-Column $row 'Resolved IPs'
    $resolves  = Get-Column $row 'DNS Resolves'
    $err       = Get-Column $row 'Error'

    [PSCustomObject]@{
        ZoneFile       = Get-Column $row 'Zone File'
        FQDN           = Get-Column $row 'FQDN'
        RecordName     = Get-Column $row 'Record Name'
        RecordType     = $type
        RecordValue    = $value
        DNSResolves    = $resolves
        ResolvedIPs    = $ips
        HTTPStatus     = Get-Column $row 'HTTP Status Code'
        EffectiveURL   = $effective
        RedirectType   = Get-Column $row 'Redirect Type'

        RedirectDomain = Get-RedirectDomain $effective
        RedirectPath   = Get-RedirectPath   $effective
        CNAMEProvider  = Get-CNAMEProvider  $type $value
        IPCluster      = Get-IPCluster      $ips
        Status         = Get-RecordStatus   $effective $resolves $err
        Error          = $err
    }
}

# ---------------------------------------------------------------------------
# Pattern counts (hashtable lookups instead of re-scanning per row)
# ---------------------------------------------------------------------------
function Get-CountMap {
    param($Rows, [string]$Property)
    $map = @{}
    foreach ($group in ($Rows | Group-Object -Property $Property)) {
        $map[$group.Name] = $group.Count
    }
    return $map
}

$redirectCounts = Get-CountMap $parsed 'RedirectDomain'
$clusterCounts  = Get-CountMap $parsed 'IPCluster'
$providerCounts = Get-CountMap $parsed 'CNAMEProvider'

foreach ($row in $parsed) {
    $row | Add-Member -NotePropertyName RedirectDomainCount -NotePropertyValue $redirectCounts[$row.RedirectDomain]
    $row | Add-Member -NotePropertyName IPClusterCount      -NotePropertyValue $clusterCounts[$row.IPCluster]
    $row | Add-Member -NotePropertyName CNAMEProviderCount  -NotePropertyValue $providerCounts[$row.CNAMEProvider]
}

# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------
$columns = 'ZoneFile', 'FQDN', 'RecordName', 'RecordType', 'RecordValue',
           'DNSResolves', 'ResolvedIPs', 'HTTPStatus', 'EffectiveURL',
           'RedirectDomain', 'RedirectPath', 'RedirectType', 'RedirectDomainCount',
           'IPCluster', 'IPClusterCount', 'CNAMEProvider', 'CNAMEProviderCount',
           'Status', 'Error'

$parsed | Select-Object $columns | Export-Csv -Path $OutputCsv -NoTypeInformation

# Quick summary to the console
Write-Host "Parsed $(@($parsed).Count) records -> $OutputCsv"
$parsed | Group-Object Status | Sort-Object Count -Descending |
    ForEach-Object { Write-Host ("  {0,-10} {1}" -f $_.Name, $_.Count) }
