# ssh_vuln_scan.py

Subnet-wide SSH weakness sweep, built the same way as `quantum_readiness_spray.py`:
masscan for fast discovery, then a worker pool for the actual assessment,
with the same live progress bar / logging conventions. Single Python file —
scan, parse, CSV, and `.xlsx` are all in it.

## Why two phases

The configured scope (`SUBNETS` below) includes a `/8`. Pointing nmap's own
host discovery at that much address space would dominate the entire run.
**Phase 1** uses masscan — a stateless SYN scanner — to find which hosts
across all configured subnets actually have TCP/22 open, in a fraction of
the time. **Phase 2** then only touches real hosts: a pool of worker threads
each run a single, narrowly-targeted `nmap -Pn -n` against one host, skipping
nmap's own (slower) host discovery and DNS resolution entirely, since Phase 1
and a direct reverse-DNS lookup already did both.

## Scope

```python
SUBNETS: List[str] = [
    "1.0.0.0/16",
    "2.0.0.0/16",
    "3.0.0.0/16",
    "4.0.0.0/16",
    "5.0.0.0/16",
    # "6.0.0.0/16",
    "7.0.0.0/16",
    "8.0.0.0/12",
    "9.0.0.0/8",
]
```

Edit this list in the script to change scope — same convention as
`quantum_readiness_spray.py`.

## Requirements

- `masscan` on PATH (unless `--skip-masscan` with a valid `--masscan-output-file`) — needs root/administrator to run
- `nmap` on PATH — always required; there's no fallback algorithm-collection path here
- Python 3.8+
- `openpyxl` — only for the `.xlsx` step. If missing, the run degrades to CSV-only instead of failing.

```bash
pip install openpyxl
```

## Usage

```bash
sudo python ssh_vuln_scan.py
```

Common options:

| Flag | Default | Purpose |
|---|---|---|
| `--workers` | `16` | Concurrent nmap processes in Phase 2. Lower than the sibling tool's 30 — each unit of work here is a full nmap process + NSE script engine, not one raw socket connect. Raise if the host running this has headroom. |
| `--rate` | `25000` | masscan packets/sec |
| `--host-timeout` | `30s` | nmap `--host-timeout` per host, so one hung host can't stall a worker slot indefinitely |
| `--retries` | `1` | Retries per host if a scan comes back empty (covers a transient miss; a genuinely non-SSH host won't change on retry, but this keeps the logic simple and bounded either way) |
| `--output-dir` | script's own directory | Where the log/CSV/xlsx are written |
| `--interface` | *(none)* | Passed to masscan's `-e` |
| `--skip-masscan` + `--masscan-output-file` | — | Reuse a previous masscan run instead of re-scanning |
| `--keep-temp` | off | Keep each host's raw nmap XML under `<output-dir>/nmap_xml_<date>/` |
| `--no-xlsx` | off | Stop after the CSV |
| `--from-csv FILE` | — | Skip scanning entirely; rebuild the `.xlsx` from an existing CSV |

Resume from a previous masscan run (e.g. discovery already done, iterating on Phase 2 only):

```bash
python ssh_vuln_scan.py --skip-masscan --masscan-output-file .masscan_output_2026-09-09.txt
```

Rebuild just the `.xlsx` from an existing CSV without re-scanning:

```bash
python ssh_vuln_scan.py --from-csv ssh_vuln_scan_2026-09-09.csv
```

## Output

Everything is timestamped and written to `--output-dir` (same convention as
`quantum_readiness_spray.py`):

- `ssh_vuln_scan_<date>.log` — full run log (DEBUG-level to file, INFO-level to console)
- `ssh_vuln_scan_<date>.csv` — wide format, one row per confirmed SSH host
- `ssh_vuln_scan_<date>.xlsx` — Overview + Report sheets
- `.masscan_output_<date>.txt` — raw masscan hit list (hidden file, kept so `--skip-masscan` can reuse it)

### `ssh_vuln_scan_<date>.csv`

```
ScanDate,IP,Hostname,Banner,SSHv1Supported,WeakKexCount,WeakMacCount,WeakHostKeyAlgoCount,WeakCipherCount,PasswordAuthEnabled,HostKeyInfo,ConfiguredSubnet
```

`ConfiguredSubnet` is new since the single-subnet version — which of the
entries in `SUBNETS` this host falls under, so results can be filtered or
pivoted by scope range (matches `quantum_readiness_spray.py`'s "Subnet
Range" column).

### `ssh_vuln_scan_<date>.xlsx`

Same Overview + Report layout as before: a 3×3 KPI tile grid (hosts scanned,
SSHv1, weak ciphers, weak MACs, weak KEX, weak host-key algorithms, password
auth, fully-hardened hosts, at-risk %), a findings-breakdown bar chart, and a
precomputed Top-10 Offenders table on Overview; the full per-host data plus
two live formulas (`Weak Algo Total`, `Weakness Score`) on Report. See the
in-file comments in `build_workbook()` for the formula/column details — they
haven't changed except for the two new columns (`Host Key Info`,
`Configured Subnet`), both appended at the end so no existing formula's
column-letter reference shifts.

## What it checks

Per host, via `-sV` and NSE scripts `sshv1`, `ssh2-enum-algos`,
`ssh-hostkey`, `ssh-auth-methods`:

- **SSHv1 support**
- **Weak KEX**: `diffie-hellman-group1-sha1`, `diffie-hellman-group14-sha1`,
  `diffie-hellman-group-exchange-sha1`, `ecdh-sha2-nistp*`
- **Weak MACs**: `hmac-sha1`, `hmac-md5`, `umac-64` (both `@openssh.com` and
  `-etm@openssh.com` variants)
- **Weak host-key algorithms**: `ssh-dss`, `ecdsa-sha2-nistp*`, `ssh-rsa`
  (including its cert variant)
- **Weak ciphers**: `arcfour`, any `-cbc` mode, `3des`, `none`
- **Password authentication advertised**
- **Host key info** (informational, not scored) — actual key type/size/fingerprint

### What changed in this pass, and why

Cross-checked against a real `ssh-audit` run (OpenSSH 10.4p1) during this
rewrite. Three real gaps, now fixed:

1. **`ecdh-sha2-nistp256/384/521`** — the NSA-curve-suspicion finding
   (`ssh-audit [fail]`) was never checked for KEX at all; only the
   `diffie-hellman-*-sha1` variants were. Also added
   `diffie-hellman-group14-sha1` (SHA-1-based, deprecated).
2. **`ssh-rsa`** — the SHA-1 RSA signature scheme, disabled by default since
   OpenSSH 8.8, was never flagged as a weak host-key algorithm; only
   `ssh-dss` and `ecdsa-sha2-nistp*` were.
3. **`umac-64`** / **`umac-64-etm@openssh.com`** — the small-64-bit-tag
   finding (`ssh-audit [warn]`) was never flagged as a weak MAC.

**Deliberately not added**: the "encrypt-and-mac ordering" warnings
(non-ETM `hmac-sha2-256`/`hmac-sha2-512`, non-ETM `umac-128`). `ssh-audit`
itself only warns, not fails, on these — they still carry strong
128/256/512-bit tags. Stated here as a scope decision, not a silent gap.

**Only hosts confirmed to be running SSH are included** — this matters more
now than in a single-nmap-sweep design, since masscan's Phase 1 hit only
proves TCP/22 is open, not that SSH is what's listening there. A host is
counted as SSH only if nmap's `-sV` named it `ssh`, or at least one
SSH-specific NSE script actually produced output.

## Architecture notes

**Phase 1 (masscan)** is ported near-verbatim from `quantum_readiness_spray.py`
— same live progress bar (percent/ETA parsed from masscan's own stderr),
same `-oL` list-output parsing, same dedup-by-key approach. Only the port
spec changed (`T:22` instead of `T:22,3389,443`).

**Phase 2** trades the sibling script's per-service raw-socket probing for a
worker pool of concurrent `nmap` processes — each host gets exactly one
short-lived nmap invocation (`-p 22 -Pn -n -sV --host-timeout ... --script
...`) writing to its own temp XML file, parsed the same way a full-subnet
nmap XML would be. This was the more faithful and easier-to-verify choice
than trying to scrape a live progress bar out of one giant nmap process's
own status output — nmap's periodic stats text varies by scan phase and
isn't as cleanly regexable as masscan's, whereas "N workers, each one task,
counted as they finish" is the same simple, testable shape the sibling
script already uses.

**Retry logic** mirrors `quantum_readiness_spray.py`'s "only retry a `No
Response`-shaped outcome" pattern, adapted to this script's shape: an empty
parse result (host didn't respond in time, or a transient miss) is retried
up to `--retries` times; a host nmap successfully determined isn't running
SSH won't change on a retry, so nothing is gained by retrying that case
specifically, but the bounded-retry-on-empty-result logic stays simple
either way and doesn't need to special-case it.

## Limitations

**Assumes one scan run per workbook.** Every Overview formula aggregates
over the *entire* Report table. Re-running into the same file would double
count. Unchanged from the single-subnet version — see the in-file comments
for the `MAXIFS`-based fix this would need if that ever becomes a real use
case.

**Percentages don't sum to 100%** — the weakness categories aren't mutually exclusive.

**Masscan needs elevated privileges** (raw sockets) — run with `sudo` /
as Administrator. nmap's per-host scan works either way; unprivileged just
means a TCP connect scan instead of SYN, which given Phase 1 already
confirmed the port is open, has minimal practical impact on Phase 2's speed.

**No automatic CVE mapping.** The banner is captured for manual triage only.

**`ssh-hostkey`'s structured fields aren't parsed, just its flattened
text** — confident about `ssh2-enum-algos`'s table key names (they mirror
the NSE script's own display labels), less confident about `ssh-hostkey`'s
without a live nmap install to verify against.

**Ctrl+C behavior**: first interrupt finishes in-flight work and writes
partial reports; second interrupt force-exits. Same as
`quantum_readiness_spray.py` — ported, not independently re-tested under an
actual live long-running scan in this pass.
