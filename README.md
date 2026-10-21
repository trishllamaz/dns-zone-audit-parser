# DNS Zone Audit Parser

A PowerShell tool for making sense of large DNS zone audits. Point it at a CSV of DNS records and it tells you where each record actually lands, which hosting provider or IP cluster serves it, and which records are dead weight.

## Why

Organizations accumulate hundreds of DNS records over the years: old campaign sites, retired apps, redirects to redirects. A raw audit export answers "does this resolve?" one row at a time. This script groups records into patterns so you can answer the bigger questions quickly:

- Which domains redirect to the same destination, and could be consolidated?
- How many records sit on each hosting provider or IP?
- Which records don't resolve or go nowhere, and are candidates for cleanup? (Dangling CNAMEs are also a subdomain-takeover risk.)

## What it adds to each row

| Column | Meaning |
|---|---|
| `RedirectDomain` | Host the record ultimately lands on (from `Effective URL`) |
| `RedirectPath` | Path on that host, e.g. `/landing` |
| `CNAMEProvider` | Hosting provider a CNAME points to (Azure, Pantheon, CloudFront, ...) |
| `IPCluster` | Named group for the resolved IP, from your config |
| `Status` | `Valid`, `DNSFailure` (resolution failed), or `Garbage` (doesn't resolve and goes nowhere) |
| `*Count` | How many records share that redirect domain, IP cluster, or provider |

## Usage

Requires PowerShell 5.1+ or PowerShell 7 (Windows, macOS, Linux).

```powershell
.\dns_zone_audit_parser.ps1 -InputCsv .\sample_input.csv -OutputCsv .\out.csv
```

```
Parsed 8 records -> .\out.csv
  Valid      6
  Garbage    1
  DNSFailure 1
```

Open the output in Excel and pivot on `RedirectDomain`, `IPCluster` or `Status` to see the patterns.

### Parameters

| Parameter | Required | Default |
|---|---|---|
| `-InputCsv` | yes | |
| `-OutputCsv` | no | `.\AllPatterns.csv` |
| `-ConfigPath` | no | `config.json`, then `config.sample.json` |

## Configuration

Copy `config.sample.json` to `config.json` and fill in your own mappings. `config.json` is git-ignored so real infrastructure details stay local.

```json
{
  "ipClusters": {
    "192.0.2.10": "HostingProviderA"
  },
  "cnameProviders": [
    { "pattern": "azurewebsites\\.net", "name": "Azure App Service" }
  ]
}
```

`pattern` is a regular expression matched against the CNAME target.

## Input format

A CSV with these columns (extra columns are ignored, and stray spaces in headers are handled):

`Zone File, FQDN, Record Name, Record Type, Record Value, DNS Resolves, Resolved IPs, HTTP Status Code, Effective URL, Redirect Type, Error`

See [`sample_input.csv`](sample_input.csv). All of its domains and IPs are reserved documentation values (`example.com`, `192.0.2.0/24`, etc.).
