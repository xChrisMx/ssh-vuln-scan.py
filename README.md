run the file, by default it scans 192.168.0.1/24 - feel free to modify the subnet.

# ssh-network-scan

Subnet-wide SSH weakness sweep. Runs `nmap` against port 22 across a subnet,
scores every host that actually has SSH open, and produces both a flat CSV
and a formatted `.xlsx` audit report with an at-a-glance Overview sheet.

**Single-file tool.** `ssh_vuln_scan.py` runs the scan, parses it, and builds
both output files — no separate generator script, no bash/awk step.

## Requirements

- `nmap` on PATH
- Python 3.8+
- `openpyxl` — only needed to build the `.xlsx`. If it's missing, the script
  still writes the CSV and prints a note instead of crashing.

```bash
pip install openpyxl
```

## Usage

```bash
python ssh_vuln_scan.py [subnet] [--keep-temp] [--no-xlsx]
                         [--csv-out FILE] [--xlsx-out FILE]
```

- `subnet` — defaults to `192.168.0.1/24` if omitted
- `--keep-temp` — keep the raw nmap XML (`nmap_temp_output.xml`) instead of deleting it
- `--no-xlsx` — stop after the CSV
- `--csv-out` / `--xlsx-out` — override the default output filenames

Run with `sudo` for a SYN scan (faster, more reliable on a busy subnet). It
also works unprivileged — nmap falls back to a TCP connect scan, just slower.

```bash
sudo python ssh_vuln_scan.py 192.168.10.0/24
```

To rebuild just the `.xlsx` from an existing CSV (e.g. one you hand-edited,
or after tweaking the report code) without re-scanning:

```bash
python ssh_vuln_scan.py --from-csv insecure_ssh_hosts.csv --xlsx-out insecure_ssh_hosts.xlsx
```

## How it parses nmap's output

Uses `-oX` (nmap's structured XML output), not the human-readable text
format. This matters for one thing specifically: `ssh2-enum-algos` returns
its algorithm lists as a structured table in the XML (`<table
key="kex_algorithms"><elem>...`), which the script reads directly — no
regex, no "read until the next blank line" text scraping.

For the other three NSE scripts (`sshv1`, `ssh-auth-methods`, `ssh-hostkey`),
the script reads the flattened `output` text nmap always attaches to every
script result regardless of format, since their structured-table field
names aren't things this script depends on being exactly right. If
`ssh2-enum-algos` for some reason doesn't come back with the tables expected
(a different nmap/script version, say), it falls back to the same
text-scraping approach automatically, so a schema surprise degrades rather
than breaks the scan.

## What it checks

Per host, via `-sV` and NSE scripts `sshv1`, `ssh2-enum-algos`,
`ssh-hostkey`, `ssh-auth-methods`:

- **SSHv1 support** — the protocol itself, not an algorithm choice
- **Weak KEX algorithms** — `diffie-hellman-group1-sha1`, `-group-exchange-sha1`
- **Weak MAC algorithms** — `hmac-sha1`, `hmac-md5`
- **Weak host-key algorithms** — `ssh-dss`, `ecdsa-sha2-nistp*`
- **Weak ciphers** — `arcfour`, any `-cbc` mode, `3des`, `none`
- **Password authentication advertised**
- **Host key info** (informational, not scored) — the actual key type,
  size and fingerprint nmap read off the host (e.g. `1024 SHA256:AAAA...
  (DSA)`). This is a different fact from "weak host-key algorithms": that
  count is what the server would *accept*; this is the specific key it's
  *actually presenting*.

Each weak category is a **count** of how many matching algorithms a host
offers, not just a yes/no flag.

**Only hosts confirmed to be running SSH are included.** This means two
things, not just one:

- A host with port 22 closed or filtered doesn't appear at all — scanned,
  nothing to audit, not counted toward "hosts scanned."
- A host with port 22 *open* but running something other than SSH (a
  relocated web service, say) is also excluded. The script treats a host as
  a real SSH host only if nmap's service probe identified it as `ssh`, OR
  at least one of the SSH-specific NSE scripts actually produced output
  (covers the rare case where the service-name probe is inconclusive but
  the SSH protocol probes still succeeded). Without this check, a non-SSH
  service on port 22 would show zero findings across every category and get
  counted as a "Fully Hardened" host on the Overview sheet — which would be
  actively misleading, not just imprecise.

## Output

### `insecure_ssh_hosts.csv`

One row per host (wide format):

```
ScanDate,IP,Hostname,Banner,SSHv1Supported,WeakKexCount,WeakMacCount,WeakHostKeyAlgoCount,WeakCipherCount,PasswordAuthEnabled,HostKeyInfo
```

`Hostname` is blank when the host has no reverse DNS (PTR) entry — distinct
from the IP field, which is always populated. If nmap has some *other* name
for the host (e.g. one supplied on the scan command line) but no PTR record,
that name is used instead.

### `insecure_ssh_hosts.xlsx`

**Overview sheet** (opens active):
- A 3x3 KPI tile grid — hosts scanned, SSHv1, weak ciphers, weak MACs, weak
  KEX, weak host-key algorithms, password auth, fully-hardened hosts, and a
  headline "any weakness" at-risk percentage. Tiles are conditionally
  color-coded: red/green for protocol-level or credential exposures
  (SSHv1, weak ciphers, password auth), red/amber/green by percentage of
  fleet for the more common findings (weak MAC/KEX/host-key algorithms).
- A horizontal bar chart ranking which weakness category is most prevalent,
  color-matched to the tiles above it.
- A **Top Offenders** table — the 10 highest-risk hosts, ranked by a
  Weakness Score (`100` if SSHv1 is supported, plus the sum of the four weak
  algorithm counts; password auth is shown for context but not scored,
  since it's a separate attack surface — brute force — not a broken crypto
  primitive). This table is **precomputed in Python**, not a live Excel
  formula: ranking the top N by score needs `LARGE()` + `INDEX`/`MATCH` with
  a manual tie-break column in Excel, which is exactly the kind of
  clever-but-fragile mechanism worth avoiding when a plain sort in Python
  does the same job and is easier to hand-verify.

**Report sheet** — the raw per-host data every Overview number is computed
from, plus two live per-row formulas (`Weak Algo Total`, `Weakness Score`)
that mirror the same score used to build the Top Offenders list, so a
manual sort of this sheet by Weakness Score always matches it. `Host Key
Info` is the last column, purely informational.

Every Overview KPI tile is a **live formula** against the Report sheet
(`COUNTIF`/`COUNTIFS` over a bounded range), not a value baked in at
generation time — the workbook re-aggregates itself if you edit or extend
the Report sheet by hand later. Only the Top Offenders table is static.

## Limitations

**Assumes one scan run per workbook.** Every Overview formula aggregates
over the *entire* Report table (`Report!$X$3:$X$100000`). If you ever append
rows from a second scan run into the same file, "Hosts Scanned" and every
other tile will count re-scanned hosts twice. The Report sheet already
carries a per-row Scan Date for exactly this reason, but the Overview
formulas don't yet filter on "latest date only" — that would need a
`MAXIFS`-based filter, a small follow-on change not implemented here since
the pipeline currently produces one fresh file per run.

**Percentages don't sum to 100%.** The weakness categories aren't mutually
exclusive — one host can have SSHv1 *and* weak ciphers *and* password auth
enabled. Each tile's percentage is independently "% of hosts scanned," not
a slice of a pie.

**`-sV` adds scan time.** The version-banner grab needs nmap's service
detection probe, which the SSH-vs-not-SSH guard above also depends on.
Negligible on a /24; more noticeable on something much larger.

**No automatic CVE mapping.** The banner (e.g. `OpenSSH 7.4 (protocol
2.0)`) is captured for manual triage — the script does not attempt to match
version strings to known CVEs.

**`ssh-hostkey`'s structured fields aren't parsed, just its flattened
text.** Confident about `ssh2-enum-algos`'s table key names (they mirror
the NSE script's own display labels), less confident about `ssh-hostkey`'s
internal field names without a live nmap install to check against — so
`Host Key Info` is the script's plain text output, not individually broken
out into type/bits/fingerprint columns. Good enough for manual triage;
would need verifying against a real nmap install to parse further.
