#!/usr/bin/env python3
# =============================================================================
# ssh_vuln_scan.py
#
# AUTHORIZED INTERNAL SECURITY ASSESSMENT TOOL
# Scope: SSH (TCP/22) weak-algorithm discovery and audit on internal
#        company networks. Same two-phase architecture as
#        quantum_readiness_spray.py, applied to SSH-only scope.
#
# -----------------------------------------------------------------------------
# WHAT THIS SCRIPT DOES
# -----------------------------------------------------------------------------
# Phase 1 (Discovery): Uses masscan to rapidly identify hosts on the
#   configured internal subnets with TCP/22 open. This is what makes the
#   large ranges in SUBNETS (including a /8) tractable at all -- nmap's own
#   host discovery across that much address space would dominate the whole
#   run; masscan's stateless SYN scan finds the live hosts in a fraction of
#   the time, and Phase 2 then only has to touch real hosts.
#
# Phase 2 (Assessment): For every host discovered in Phase 1, runs nmap
#   -Pn -n (skip nmap's own host discovery and DNS -- both already done)
#   with the sshv1 / ssh2-enum-algos / ssh-hostkey / ssh-auth-methods NSE
#   scripts against that single host, in a worker-pool of concurrent nmap
#   processes (mirrors quantum_readiness_spray's per-service worker pool,
#   just with nmap doing the per-host work instead of a hand-rolled probe).
#   Each host's weak-algorithm counts, SSHv1 support, password-auth
#   advertisement, and host key info are extracted from nmap's XML output.
#
# Only masscan's TCP-connect confirmation is used to decide what to probe;
# nmap's own -sV service-name detection (or, failing that, whether any
# SSH-specific NSE script produced output at all) is what decides whether a
# host actually counts as SSH in the final report -- a masscan hit on port
# 22 only proves the port is open, not that SSH is what's listening on it.
#
# -----------------------------------------------------------------------------
# NON-DESTRUCTIVE / SAFETY GUARANTEES
# -----------------------------------------------------------------------------
# No authentication is ever attempted. The NSE scripts used here
# (sshv1, ssh2-enum-algos, ssh-hostkey, ssh-auth-methods) only exchange
# identification strings and KEXINIT-stage data, or query which auth
# methods a server advertises -- none of them send credentials or complete
# a login. No brute-forcing, no credential guessing, no data modification.
#
# THIS TOOL MUST ONLY BE RUN AGAINST NETWORKS YOU ARE EXPLICITLY AUTHORIZED
# TO ASSESS. Confirm written authorization / an active engagement scope
# before running this script.
#
# -----------------------------------------------------------------------------
# LIMITATIONS AND ASSUMPTIONS
# -----------------------------------------------------------------------------
#   - Requires `masscan` on PATH (unless --skip-masscan with a valid
#     --masscan-output-file) and `nmap` on PATH (always -- unlike
#     quantum_readiness_spray's optional ssh-audit, there is no fallback
#     algorithm-collection path here; nmap+NSE is the only engine).
#   - `openpyxl` is only needed for the .xlsx step; its absence degrades to
#     CSV-only rather than failing the run.
#   - A masscan hit only proves TCP/22 is open, not that SSH is running --
#     see the service-name / script-fired guard in parse_host() below.
#   - Reverse DNS depends on corporate DNS infrastructure; failures resolve
#     to "" (blank), matching how a missing PTR record is already handled,
#     and do not stop the scan.
#   - ssh2-enum-algos's algorithm lists are read from nmap's structured XML
#     <table>/<elem> output, which is trusted; the other three NSE scripts
#     are read from their flattened text output, since this script isn't
#     confident of their internal table field names without a live nmap
#     install to verify against -- see README.
# =============================================================================

import argparse
import csv
import ipaddress
import logging
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from xml.etree import ElementTree as ET

# =============================================================================
# CONFIGURATION
# =============================================================================

SCRIPT_DIR: str = os.path.dirname(os.path.abspath(__file__))

# Same subnets in scope as the user's other sweep tools. Edit this list to
# change scope.
SUBNETS: List[str] = [
    "156.141.0.0/16",
    "156.140.0.0/16",
    "146.208.0.0/16",
    "141.184.0.0/16",
    "141.183.0.0/16",
    # "141.121.0.0/16",
    "192.168.0.0/16",
    "172.16.0.0/12",
    "10.0.0.0/8",
]

DEFAULT_WORKERS = 16   # lower than quantum_readiness_spray's 30: each unit of
                        # work here is a full nmap process + NSE script engine,
                        # not a single raw socket connect, so it costs more per
                        # worker. Raise if the host running this has headroom.
DEFAULT_RATE = 25000    # masscan packets/sec, same default as the sibling tool
DEFAULT_HOST_TIMEOUT = "30s"  # nmap --host-timeout per host, so one hung host
                              # can't stall a worker slot indefinitely
DEFAULT_RETRIES = 1
MASSCAN_PORT_SPEC = "T:22"
SSH_PORT = 22

NMAP_SCRIPTS = "sshv1,ssh2-enum-algos,ssh-hostkey,ssh-auth-methods"

# ---------------------------------------------------------------------------
# Weak-algorithm patterns. Cross-checked against a real ssh-audit run
# (OpenSSH 10.4p1) during this rewrite - see README for what's deliberately
# excluded and why.
# ---------------------------------------------------------------------------
WEAK_KEX_RE = re.compile(
    r"diffie-hellman-group1-sha1"
    r"|diffie-hellman-group14-sha1"
    r"|diffie-hellman-group-exchange-sha1"
    r"|ecdh-sha2-nistp"          # NSA-curve suspicion, same family as the
)                                 # host-key check below - ssh-audit [fail]
WEAK_MAC_RE = re.compile(
    r"hmac-sha1"
    r"|hmac-md5"
    r"|umac-64"                  # 64-bit tag - ssh-audit [warn], both
)                                 # umac-64@ and umac-64-etm@ variants
WEAK_HOSTKEYALGO_RE = re.compile(
    r"ssh-dss"
    r"|ecdsa-sha2-nistp"
    r"|ssh-rsa"                  # SHA-1 RSA signature scheme, disabled by
)                                 # default since OpenSSH 8.8
WEAK_CIPHER_RE = re.compile(r"arcfour|-cbc|3des|none")

REPORT_HEADERS = [
    "Scan Date", "IP Address", "Hostname", "Banner", "SSHv1 Supported",
    "Weak KEX Count", "Weak MAC Count", "Weak HostKeyAlgo Count",
    "Weak Cipher Count", "Password Auth Enabled", "Weak Algo Total",
    "Weakness Score", "Host Key Info", "Configured Subnet",
]
CSV_HEADERS = [
    "ScanDate", "IP", "Hostname", "Banner", "SSHv1Supported",
    "WeakKexCount", "WeakMacCount", "WeakHostKeyAlgoCount",
    "WeakCipherCount", "PasswordAuthEnabled", "HostKeyInfo", "ConfiguredSubnet",
]


# =============================================================================
# LOGGING / PROGRESS DISPLAY (mirrors quantum_readiness_spray.py)
# =============================================================================

_progress_lock = threading.Lock()
_last_progress_len = 0


class ProgressAwareHandler(logging.StreamHandler):
    def emit(self, record: logging.LogRecord) -> None:
        global _last_progress_len
        with _progress_lock:
            if _last_progress_len:
                sys.stdout.write("\r" + " " * _last_progress_len + "\r")
                sys.stdout.flush()
            super().emit(record)
            _last_progress_len = 0


def setup_logging(log_path: str) -> logging.Logger:
    logger = logging.getLogger("ssh_vuln_scan")
    logger.setLevel(logging.DEBUG)
    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s", "%Y-%m-%d %H:%M:%S"))
    console_handler = ProgressAwareHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    return logger


def draw_progress_line(line: str) -> None:
    global _last_progress_len
    with _progress_lock:
        pad = max(0, _last_progress_len - len(line))
        sys.stdout.write("\r" + line + (" " * pad))
        sys.stdout.flush()
        _last_progress_len = len(line)


def finish_progress_line() -> None:
    global _last_progress_len
    with _progress_lock:
        if _last_progress_len:
            sys.stdout.write("\n")
            sys.stdout.flush()
        _last_progress_len = 0


def fmt_elapsed(seconds: float) -> str:
    seconds = int(max(0, seconds))
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    return f"{h:02d}:{m:02d}:{s:02d}"


def render_bar(pct: Optional[float], width: int = 30) -> str:
    if pct is None:
        return "[" + "-" * width + "]  n/a"
    pct = max(0.0, min(100.0, pct))
    filled = int(width * pct / 100.0)
    return "[" + "#" * filled + "-" * (width - filled) + f"] {pct:5.1f}%"


# =============================================================================
# DEPENDENCY / VALIDATION HELPERS (mirrors quantum_readiness_spray.py)
# =============================================================================

def check_external_tool(name: str) -> Optional[str]:
    return shutil.which(name)


def validate_subnets(raw_subnets: List[str], logger: logging.Logger) -> List[ipaddress.IPv4Network]:
    networks = []
    for entry in raw_subnets:
        try:
            networks.append(ipaddress.ip_network(entry, strict=False))
        except ValueError as exc:
            logger.error(f"Skipping invalid CIDR '{entry}': {exc}")
    return networks


def subnet_for_ip(ip: str, networks: List[ipaddress.IPv4Network]) -> str:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "UNKNOWN"
    for net in networks:
        if addr in net:
            return str(net)
    return "UNKNOWN"


def resolve_hostname(ip: str, timeout: float) -> str:
    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        name, _, _ = socket.gethostbyaddr(ip)
        return name
    except (socket.herror, socket.gaierror, socket.timeout, OSError):
        return ""
    finally:
        socket.setdefaulttimeout(old_timeout)


# =============================================================================
# PHASE 1: MASSCAN DISCOVERY (verbatim approach from quantum_readiness_spray.py)
# =============================================================================

class MasscanStatus:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.percent: Optional[float] = None
        self.eta: str = ""

    def update_from_line(self, line: str) -> None:
        m = re.search(r"(\d+(?:\.\d+)?)%\s+done", line)
        eta_m = re.search(r"done,\s*([\d:]+)\s*remaining", line)
        with self.lock:
            if m:
                try:
                    self.percent = float(m.group(1))
                except ValueError:
                    pass
            if eta_m:
                self.eta = eta_m.group(1)


def _masscan_stderr_reader(proc: subprocess.Popen, status: MasscanStatus) -> None:
    buf = b""
    stream = proc.stderr
    if stream is None:
        return
    try:
        while True:
            chunk = stream.read(256)
            if not chunk:
                break
            buf += chunk
            while True:
                idx_r = buf.find(b"\r")
                idx_n = buf.find(b"\n")
                candidates = [i for i in (idx_r, idx_n) if i != -1]
                if not candidates:
                    break
                idx = min(candidates)
                line = buf[:idx].decode(errors="ignore").strip()
                buf = buf[idx + 1:]
                if line:
                    status.update_from_line(line)
    except (ValueError, OSError):
        pass


def build_masscan_command(masscan_path: str, subnets: List[str], rate: int,
                           output_file: str, interface: Optional[str]) -> List[str]:
    cmd = [masscan_path, "-p", MASSCAN_PORT_SPEC, "--rate", str(rate), "-oL", output_file]
    if interface:
        cmd += ["-e", interface]
    cmd += subnets
    return cmd


def parse_masscan_list_output(path: str, start_offset: int = 0) -> Tuple[List[Tuple[str, int, str]], int]:
    records: List[Tuple[str, int, str]] = []
    if not os.path.exists(path):
        return records, start_offset
    with open(path, "rb") as f:
        f.seek(start_offset)
        chunk = f.read()
    if not chunk:
        return records, start_offset
    last_newline = chunk.rfind(b"\n")
    if last_newline == -1:
        return records, start_offset
    usable, new_offset = chunk[:last_newline + 1], start_offset + last_newline + 1
    for raw_line in usable.split(b"\n"):
        line = raw_line.decode(errors="ignore").strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 5:
            continue
        status, proto, port_s, ip, _ts = parts[:5]
        if status != "open":
            continue
        try:
            port = int(port_s)
        except ValueError:
            continue
        records.append((ip, port, proto))
    return records, new_offset


def run_masscan_phase1(masscan_path: str, subnets: List[str], rate: int,
                        output_file: str, interface: Optional[str],
                        logger: logging.Logger, stop_event: threading.Event
                        ) -> List[Tuple[str, int, str]]:
    cmd = build_masscan_command(masscan_path, subnets, rate, output_file, interface)
    logger.info("Phase 1 - DISCOVERY starting")
    logger.debug(f"Masscan command: {' '.join(cmd)}")

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    except FileNotFoundError:
        logger.error(f"masscan executable not found at '{masscan_path}'.")
        return []
    except PermissionError as exc:
        logger.error(f"Permission error launching masscan: {exc}. "
                      f"Masscan typically requires root/administrator privileges.")
        return []
    except OSError as exc:
        logger.error(f"Failed to launch masscan: {exc}")
        return []

    status = MasscanStatus()
    reader_thread = threading.Thread(target=_masscan_stderr_reader, args=(proc, status), daemon=True)
    reader_thread.start()

    start_time = time.time()
    ssh_count = 0
    offset = 0
    seen: set = set()

    def _drain_new_records() -> None:
        nonlocal offset, ssh_count
        new_records, offset = parse_masscan_list_output(output_file, offset)
        for ip, port, _proto in new_records:
            key = (ip, port)
            if key in seen:
                continue
            seen.add(key)
            if port == SSH_PORT:
                ssh_count += 1

    try:
        while True:
            if stop_event.is_set():
                logger.warning("Interrupt received, terminating masscan...")
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                break

            retcode = proc.poll()
            _drain_new_records()

            elapsed = time.time() - start_time
            with status.lock:
                pct = status.percent
                eta = status.eta

            bar = render_bar(pct)
            eta_str = eta if eta else "n/a"
            line = (f"Phase 1 - DISCOVERY {bar} | SSH hosts found: {ssh_count} | "
                     f"Elapsed: {fmt_elapsed(elapsed)} | ETA: {eta_str}")
            draw_progress_line(line)

            if retcode is not None:
                time.sleep(0.3)
                _drain_new_records()
                break
            time.sleep(0.5)
    finally:
        finish_progress_line()

    if proc.returncode not in (0, None) and not stop_event.is_set():
        logger.warning(f"masscan exited with return code {proc.returncode}. "
                        f"Results collected so far will still be used.")

    final_records, _ = parse_masscan_list_output(output_file, 0)
    logger.info(f"Phase 1 - DISCOVERY complete. SSH hits: {ssh_count}, "
                f"elapsed: {fmt_elapsed(time.time() - start_time)}")
    return final_records


# =============================================================================
# XML PARSING (nmap -oX output, one host at a time in Phase 2)
# =============================================================================

def _table_values(script_elem, key: str) -> Optional[List[str]]:
    """Structured NSE output: <table key="..."><elem>value</elem>...</table>.
    Returns None (not an empty list) if no table with this key exists at
    all, so the caller can tell "no weak algorithms" apart from "nmap didn't
    emit structured output this time"."""
    for table in script_elem.findall("table"):
        if table.get("key") == key:
            return [e.text or "" for e in table.findall("elem")]
    return None


def _parse_algos_block_fallback(output_text: str, header: str) -> List[str]:
    """Fallback if structured <table> children are absent: scan the
    flattened `output` attribute text for the labeled block and take every
    line until the next blank line."""
    values = []
    in_block = False
    for line in output_text.splitlines():
        if header in line:
            in_block = True
            continue
        if in_block:
            if line.strip() == "":
                break
            values.append(line.strip())
    return values


def parse_ssh2_enum_algos(script_elem) -> Dict[str, List[str]]:
    """Returns {category: [algorithm names]} for the four categories we
    score. Tries structured <table> children first; falls back to text
    parsing only if none of the four expected tables were found at all."""
    keys = ("kex_algorithms", "server_host_key_algorithms",
            "encryption_algorithms", "mac_algorithms")
    result = {k: _table_values(script_elem, k) for k in keys}

    if all(v is None for v in result.values()):
        output = script_elem.get("output", "") or ""
        result = {k: _parse_algos_block_fallback(output, k + ":") for k in keys}

    return {k: (v or []) for k, v in result.items()}


def parse_host(host_elem, scan_date: str, hostname_override: str = "",
               subnet_label: str = "") -> Optional[dict]:
    """Returns a row dict, or None if this host isn't a countable SSH host
    (down, port 22 not open, or port 22 open but not actually speaking SSH)."""
    status = host_elem.find("status")
    if status is None or status.get("state") != "up":
        return None

    ip = None
    for addr in host_elem.findall("address"):
        if addr.get("addrtype") in ("ipv4", "ipv6"):
            ip = addr.get("addr")
            break
    if ip is None:
        return None

    hostname = hostname_override
    if not hostname:
        hostnames_el = host_elem.find("hostnames")
        if hostnames_el is not None:
            chosen = hostnames_el.find("hostname[@type='PTR']")
            if chosen is None:
                chosen = hostnames_el.find("hostname")
            if chosen is not None:
                hostname = chosen.get("name", "")

    port_el = None
    ports_el = host_elem.find("ports")
    if ports_el is not None:
        for p in ports_el.findall("port"):
            if p.get("portid") == "22":
                port_el = p
                break
    if port_el is None:
        return None

    state_el = port_el.find("state")
    if state_el is None or state_el.get("state") != "open":
        return None  # closed / filtered / open|filtered - nothing to audit

    service_el = port_el.find("service")
    service_name = service_el.get("name", "") if service_el is not None else ""

    banner = ""
    if service_el is not None:
        product = service_el.get("product", "")
        version = service_el.get("version", "")
        extrainfo = service_el.get("extrainfo", "")
        banner = " ".join(p for p in (product, version) if p)
        if extrainfo:
            banner = f"{banner} ({extrainfo})" if banner else f"({extrainfo})"

    sshv1 = False
    kex_weak = mac_weak = hka_weak = cipher_weak = 0
    pwauth = False
    hostkey_info = ""
    ssh_script_seen = False

    for script in port_el.findall("script"):
        sid = script.get("id")
        output = script.get("output", "") or ""

        if sid == "sshv1":
            sshv1 = True
            ssh_script_seen = True
        elif sid == "ssh2-enum-algos":
            algos = parse_ssh2_enum_algos(script)
            kex_weak = sum(1 for a in algos["kex_algorithms"] if WEAK_KEX_RE.search(a))
            mac_weak = sum(1 for a in algos["mac_algorithms"] if WEAK_MAC_RE.search(a))
            hka_weak = sum(1 for a in algos["server_host_key_algorithms"] if WEAK_HOSTKEYALGO_RE.search(a))
            cipher_weak = sum(1 for a in algos["encryption_algorithms"] if WEAK_CIPHER_RE.search(a))
            ssh_script_seen = True
        elif sid == "ssh-auth-methods":
            if "password" in output.lower():
                pwauth = True
            ssh_script_seen = True
        elif sid == "ssh-hostkey":
            hostkey_info = " | ".join(line.strip() for line in output.splitlines() if line.strip())
            ssh_script_seen = True

    # Guard against counting a non-SSH service that happens to be sitting on
    # port 22 as a "clean SSH host" - this matters MORE now than in a plain
    # nmap sweep, since masscan's Phase 1 hit only proves TCP/22 is open, not
    # that SSH is what's listening there.
    if service_name != "ssh" and not ssh_script_seen:
        return None

    weak_total = kex_weak + mac_weak + hka_weak + cipher_weak
    score = (100 if sshv1 else 0) + weak_total

    return {
        "scan_date": scan_date, "ip": ip, "hostname": hostname, "banner": banner,
        "sshv1": sshv1, "kex": kex_weak, "mac": mac_weak, "hka": hka_weak,
        "cip": cipher_weak, "pwauth": pwauth, "hostkey_info": hostkey_info,
        "weak_total": weak_total, "score": score, "subnet": subnet_label,
    }


def parse_xml_file(xml_path: str, scan_date: str, hostname_override: str = "",
                    subnet_label: str = "") -> List[dict]:
    tree = ET.parse(xml_path)
    root = tree.getroot()
    rows = []
    for host_elem in root.findall("host"):
        row = parse_host(host_elem, scan_date, hostname_override, subnet_label)
        if row is not None:
            rows.append(row)
    return rows


# =============================================================================
# PHASE 2: PER-HOST NMAP WORKER POOL
# =============================================================================

@dataclass
class DiscoveredHost:
    ip: str
    hostname: str = ""
    subnet: str = "UNKNOWN"


@dataclass
class Phase2Stats:
    lock: threading.Lock = field(default_factory=threading.Lock)
    total: int = 0
    completed: int = 0
    active_workers: int = 0
    ssh_confirmed: int = 0
    weak_found: int = 0


def _run_nmap_single_host(nmap_path: str, ip: str, xml_path: str, host_timeout: str) -> bool:
    """Runs nmap against exactly one host. -Pn/-n skip nmap's own host
    discovery and DNS - both already done in Phase 1 / the resolve step.
    Returns True if nmap ran (regardless of whether SSH was found), False
    on a launch failure."""
    cmd = [nmap_path, "-p", "22", "-Pn", "-n", "-sV",
           "--host-timeout", host_timeout,
           "--script", NMAP_SCRIPTS, "-oX", xml_path, ip]
    try:
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except (FileNotFoundError, OSError):
        return False


def scan_one_host(host: DiscoveredHost, args: argparse.Namespace) -> Optional[dict]:
    scan_date = datetime.now().strftime("%Y-%m-%d")
    fd, xml_path = tempfile.mkstemp(prefix="ssh_scan_", suffix=".xml")
    os.close(fd)
    try:
        row = None
        for _attempt in range(max(1, args.retries + 1)):
            ok = _run_nmap_single_host(args.nmap_path, host.ip, xml_path, args.host_timeout)
            if not ok:
                continue
            try:
                rows = parse_xml_file(xml_path, scan_date, host.hostname, host.subnet)
            except ET.ParseError:
                rows = []
            if rows:
                row = rows[0]
                break
            # empty result: either genuinely not SSH, or a transient miss -
            # only worth retrying, same rationale as quantum_readiness_spray's
            # "No Response" retry - a deterministic non-SSH result won't
            # change on a retry, but this keeps the same shape of logic simple
            # and bounded by args.retries either way.
        if args.keep_temp:
            keep_dir = os.path.join(args.output_dir, f"nmap_xml_{scan_date}")
            os.makedirs(keep_dir, exist_ok=True)
            dest = os.path.join(keep_dir, f"{host.ip.replace(':', '_')}.xml")
            try:
                shutil.move(xml_path, dest)
            except OSError:
                pass
        return row
    finally:
        try:
            os.remove(xml_path)
        except OSError:
            pass


def render_phase2_line(stats: Phase2Stats, start_time: float) -> str:
    with stats.lock:
        completed = stats.completed
        total = stats.total
        active = stats.active_workers
        confirmed = stats.ssh_confirmed
        weak = stats.weak_found
    pct = (completed / total * 100.0) if total else 0.0
    elapsed = time.time() - start_time
    if 0 < completed < total:
        eta = fmt_elapsed((elapsed / completed) * (total - completed))
    elif completed >= total and total > 0:
        eta = "00:00:00"
    else:
        eta = "n/a"
    bar = render_bar(pct)
    return (f"Phase 2 - SSH AUDIT {bar} | Completed: {completed}/{total} | "
            f"Workers: {active} | Confirmed SSH: {confirmed} | "
            f"With weakness: {weak} | Elapsed: {fmt_elapsed(elapsed)} | ETA: {eta}")


def run_phase2(hosts: List[DiscoveredHost], args: argparse.Namespace,
               logger: logging.Logger, stop_event: threading.Event) -> List[dict]:
    stats = Phase2Stats()
    stats.total = len(hosts)
    rows: List[dict] = []
    start_time = time.time()
    logger.info(f"Phase 2 - SSH AUDIT starting ({stats.total} hosts, {args.workers} workers)")

    def wrapped(host: DiscoveredHost) -> Optional[dict]:
        with stats.lock:
            stats.active_workers += 1
        try:
            return scan_one_host(host, args)
        finally:
            with stats.lock:
                stats.active_workers -= 1

    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as executor:
        futures = {executor.submit(wrapped, host): host for host in hosts}
        try:
            for future in as_completed(futures):
                row = future.result()
                with stats.lock:
                    stats.completed += 1
                    if row is not None:
                        stats.ssh_confirmed += 1
                        if row["sshv1"] or row["weak_total"] > 0 or row["pwauth"]:
                            stats.weak_found += 1
                if row is not None:
                    rows.append(row)
                draw_progress_line(render_phase2_line(stats, start_time))
                if stop_event.is_set():
                    logger.warning("Interrupt received, cancelling remaining audits...")
                    for f in futures:
                        f.cancel()
                    break
        finally:
            finish_progress_line()

    logger.info(f"Phase 2 - SSH AUDIT complete. {stats.completed}/{stats.total} hosts "
                f"probed, {stats.ssh_confirmed} confirmed SSH, "
                f"finished in {fmt_elapsed(time.time() - start_time)}.")
    return rows


# =============================================================================
# CSV
# =============================================================================

def write_csv(rows: List[dict], csv_path: str, logger: logging.Logger) -> None:
    try:
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(CSV_HEADERS)
            for r in rows:
                w.writerow([
                    r["scan_date"], r["ip"], r["hostname"], r["banner"],
                    "TRUE" if r["sshv1"] else "FALSE",
                    r["kex"], r["mac"], r["hka"], r["cip"],
                    "TRUE" if r["pwauth"] else "FALSE",
                    r["hostkey_info"], r.get("subnet", ""),
                ])
        logger.info(f"CSV saved to: {csv_path}")
    except OSError as exc:
        logger.error(f"Failed to write CSV to {csv_path}: {exc}")


def read_rows_from_csv(csv_path: str) -> List[dict]:
    """Rebuild the same row-dict shape parse_host() produces, from a
    previously-written (or hand-edited) CSV. Used by --from-csv."""
    rows = []
    with open(csv_path, newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            sshv1 = r["SSHv1Supported"].strip().upper() == "TRUE"
            pwauth = r["PasswordAuthEnabled"].strip().upper() == "TRUE"
            kex = int(r["WeakKexCount"])
            mac = int(r["WeakMacCount"])
            hka = int(r["WeakHostKeyAlgoCount"])
            cip = int(r["WeakCipherCount"])
            weak_total = kex + mac + hka + cip
            score = (100 if sshv1 else 0) + weak_total
            rows.append({
                "scan_date": r["ScanDate"], "ip": r["IP"], "hostname": r["Hostname"],
                "banner": r["Banner"], "sshv1": sshv1, "kex": kex, "mac": mac,
                "hka": hka, "cip": cip, "pwauth": pwauth,
                "hostkey_info": r.get("HostKeyInfo", ""),
                "subnet": r.get("ConfiguredSubnet", ""),
                "weak_total": weak_total, "score": score,
            })
    return rows


# =============================================================================
# XLSX report
# =============================================================================

def build_workbook(rows: List[dict]):
    from openpyxl import Workbook
    from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
    from openpyxl.formatting.rule import CellIsRule, FormulaRule, ColorScaleRule
    from openpyxl.chart import BarChart, Reference
    from openpyxl.chart.marker import DataPoint
    from openpyxl.chart.shapes import GraphicalProperties
    from openpyxl.utils import get_column_letter

    RED_FILL = PatternFill("solid", fgColor="FFC7CE")
    RED_FONT = Font(color="9C0006", bold=True)
    AMBER_FILL = PatternFill("solid", fgColor="FFEB9C")
    AMBER_FONT = Font(color="9C6500")
    GREEN_FILL = PatternFill("solid", fgColor="C6EFCE")
    GREEN_FONT = Font(color="006100")
    NEUTRAL_FILL = PatternFill("solid", fgColor="DCE6F1")
    HEADER_FILL = PatternFill("solid", fgColor="1F3864")
    HEADER_FONT = Font(color="FFFFFF", bold=True, size=18)
    SECTION_FONT = Font(bold=True, size=13)
    LABEL_FONT = Font(bold=True, size=10, color="595959")
    SUBTEXT_FONT = Font(italic=True, size=9, color="808080")
    TILE_NUM_FONT = Font(bold=True, size=32)
    THIN_BORDER = Border(bottom=Side(style="thin", color="BFBFBF"))
    RED_BAR = "FFC7CE"
    AMBER_BAR = "FFEB9C"

    COL = {name: i + 1 for i, name in enumerate(REPORT_HEADERS)}

    def build_report_sheet(wb):
        ws = wb.create_sheet("Report")
        ws["A1"] = "SSH Weakness Scan - Detailed Report"
        ws["A1"].font = Font(bold=True, size=14)

        for c, name in enumerate(REPORT_HEADERS, start=1):
            cell = ws.cell(row=2, column=c, value=name)
            cell.font = Font(bold=True)
            cell.fill = PatternFill("solid", fgColor="D9D9D9")

        for i, r in enumerate(rows):
            row_num = 3 + i
            try:
                date_val = datetime.strptime(r["scan_date"], "%Y-%m-%d").date()
            except (ValueError, TypeError):
                date_val = r["scan_date"]
            ws.cell(row=row_num, column=COL["Scan Date"], value=date_val).number_format = "yyyy-mm-dd"
            ws.cell(row=row_num, column=COL["IP Address"], value=r["ip"])
            ws.cell(row=row_num, column=COL["Hostname"], value=r["hostname"] or None)
            ws.cell(row=row_num, column=COL["Banner"], value=r["banner"] or None)
            ws.cell(row=row_num, column=COL["SSHv1 Supported"], value=r["sshv1"])
            ws.cell(row=row_num, column=COL["Weak KEX Count"], value=r["kex"])
            ws.cell(row=row_num, column=COL["Weak MAC Count"], value=r["mac"])
            ws.cell(row=row_num, column=COL["Weak HostKeyAlgo Count"], value=r["hka"])
            ws.cell(row=row_num, column=COL["Weak Cipher Count"], value=r["cip"])
            ws.cell(row=row_num, column=COL["Password Auth Enabled"], value=r["pwauth"])
            wk_col = get_column_letter(COL["Weak KEX Count"])
            cip_col = get_column_letter(COL["Weak Cipher Count"])
            sshv1_col = get_column_letter(COL["SSHv1 Supported"])
            total_col = get_column_letter(COL["Weak Algo Total"])
            ws.cell(row=row_num, column=COL["Weak Algo Total"],
                    value=f"=SUM({wk_col}{row_num}:{cip_col}{row_num})")
            ws.cell(row=row_num, column=COL["Weakness Score"],
                    value=f"=IF({sshv1_col}{row_num}=TRUE,100,0)+{total_col}{row_num}")
            ws.cell(row=row_num, column=COL["Host Key Info"], value=r["hostkey_info"] or None)
            ws.cell(row=row_num, column=COL["Configured Subnet"], value=r.get("subnet") or None)

        last_row = 2 + len(rows) if rows else 2
        ws.freeze_panes = "A3"
        if rows:
            last_col = get_column_letter(len(REPORT_HEADERS))
            ws.auto_filter.ref = f"A2:{last_col}{last_row}"

        widths = {"A": 12, "B": 16, "C": 24, "D": 32, "E": 14, "F": 12,
                  "G": 12, "H": 18, "I": 14, "J": 16, "K": 14, "L": 14,
                  "M": 40, "N": 18}
        for col, w in widths.items():
            ws.column_dimensions[col].width = w
        return ws

    def add_tile(ws, top_row, left_col, label, number_formula, subtext_formula, number_format=None):
        c1 = get_column_letter(left_col)
        c2 = get_column_letter(left_col + 1)

        num_cell = ws[f"{c1}{top_row}"]
        ws.merge_cells(f"{c1}{top_row}:{c2}{top_row}")
        num_cell.value = number_formula
        num_cell.font = TILE_NUM_FONT
        num_cell.alignment = Alignment(horizontal="center")
        if number_format:
            num_cell.number_format = number_format

        lbl_cell = ws[f"{c1}{top_row + 1}"]
        ws.merge_cells(f"{c1}{top_row + 1}:{c2}{top_row + 1}")
        lbl_cell.value = label
        lbl_cell.font = LABEL_FONT
        lbl_cell.alignment = Alignment(horizontal="center")

        sub_cell = ws[f"{c1}{top_row + 2}"]
        ws.merge_cells(f"{c1}{top_row + 2}:{c2}{top_row + 2}")
        sub_cell.value = subtext_formula
        sub_cell.font = SUBTEXT_FONT
        sub_cell.alignment = Alignment(horizontal="center")

        return num_cell.coordinate

    def build_overview_sheet(wb):
        ws = wb.create_sheet("Overview")
        ws.sheet_view.showGridLines = False

        ws.merge_cells("A1:I1")
        ws["A1"] = "SSH SECURITY POSTURE — SUBNET AUDIT"
        ws["A1"].font = HEADER_FONT
        ws["A1"].fill = HEADER_FILL
        ws["A1"].alignment = Alignment(horizontal="center", vertical="center")
        ws.row_dimensions[1].height = 30

        ws.merge_cells("A2:I2")
        ws["A2"] = ('="Report generated: "&TEXT(MAX(Report!$A$3:$A$100000),"mmmm d, yyyy")'
                     '&"   |   Full per-host detail on the Report tab"')
        ws["A2"].font = SUBTEXT_FONT
        ws["A2"].alignment = Alignment(horizontal="center")
        ws.row_dimensions[2].height = 18

        def pct_of_hosts(cell_ref):
            return f'=IFERROR(TEXT({cell_ref}/$B$4,"0%")&" of scanned hosts","—")'

        def coord(top_row, left_col):
            return f"{get_column_letter(left_col)}{top_row}"

        hosts_cell = add_tile(ws, 4, 2, "HOSTS SCANNED",
                               "=COUNTA(Report!$B$3:$B$100000)",
                               '="Subnet scan — "&TEXT(MAX(Report!$A$3:$A$100000),"mmm d, yyyy")')
        ws[hosts_cell].fill = NEUTRAL_FILL

        add_tile(ws, 4, 5, "HOSTS WITH SSHv1 ENABLED",
                 "=COUNTIF(Report!$E$3:$E$100000,TRUE)", pct_of_hosts(coord(4, 5)))
        add_tile(ws, 4, 8, "HOSTS WITH WEAK CIPHERS",
                 '=COUNTIF(Report!$I$3:$I$100000,">0")', pct_of_hosts(coord(4, 8)))
        add_tile(ws, 8, 2, "HOSTS WITH WEAK MACs",
                 '=COUNTIF(Report!$G$3:$G$100000,">0")', pct_of_hosts(coord(8, 2)))
        add_tile(ws, 8, 5, "HOSTS WITH PASSWORD AUTH ENABLED",
                 "=COUNTIF(Report!$J$3:$J$100000,TRUE)", pct_of_hosts(coord(8, 5)))
        add_tile(ws, 8, 8, "HOSTS WITH WEAK KEY EXCHANGE",
                 '=COUNTIF(Report!$F$3:$F$100000,">0")', pct_of_hosts(coord(8, 8)))
        add_tile(ws, 12, 2, "HOSTS WITH WEAK HOST-KEY ALGOS",
                 '=COUNTIF(Report!$H$3:$H$100000,">0")', pct_of_hosts(coord(12, 2)))

        clean_formula = ('=COUNTIFS(Report!$E$3:$E$100000,FALSE,Report!$F$3:$F$100000,0,'
                          'Report!$G$3:$G$100000,0,Report!$H$3:$H$100000,0,'
                          'Report!$I$3:$I$100000,0,Report!$J$3:$J$100000,FALSE)')
        add_tile(ws, 12, 5, "FULLY HARDENED HOSTS (CLEAN)", clean_formula, pct_of_hosts(coord(12, 5)))

        add_tile(ws, 12, 8, "HOSTS WITH ANY SSH WEAKNESS (AT RISK)",
                 "=IFERROR(($B$4-$E$12)/$B$4,0)", '=($B$4-$E$12)&" of "&$B$4&" hosts"',
                 number_format="0%")

        for coord_ in ("E4", "H4", "E8"):
            ws.conditional_formatting.add(
                coord_, CellIsRule(operator="greaterThan", formula=["0"], fill=RED_FILL, font=RED_FONT))
            ws.conditional_formatting.add(
                coord_, CellIsRule(operator="equal", formula=["0"], fill=GREEN_FILL, font=GREEN_FONT))

        for coord_ in ("B8", "H8", "B12"):
            ws.conditional_formatting.add(
                coord_, FormulaRule(formula=[f"AND($B$4>0,{coord_}/$B$4>=0.5)"], fill=RED_FILL, font=RED_FONT, stopIfTrue=True))
            ws.conditional_formatting.add(
                coord_, FormulaRule(formula=[f"AND($B$4>0,{coord_}>0,{coord_}/$B$4<0.5)"], fill=AMBER_FILL, font=AMBER_FONT, stopIfTrue=True))
            ws.conditional_formatting.add(
                coord_, FormulaRule(formula=[f"{coord_}=0"], fill=GREEN_FILL, font=GREEN_FONT, stopIfTrue=True))

        ws.conditional_formatting.add(
            "E12", FormulaRule(formula=["IFERROR(E12/$B$4>=0.75,FALSE)"], fill=GREEN_FILL, font=GREEN_FONT, stopIfTrue=True))
        ws.conditional_formatting.add(
            "E12", FormulaRule(formula=["IFERROR(AND(E12/$B$4>=0.4,E12/$B$4<0.75),FALSE)"], fill=AMBER_FILL, font=AMBER_FONT, stopIfTrue=True))
        ws.conditional_formatting.add(
            "E12", FormulaRule(formula=["IFERROR(E12/$B$4<0.4,TRUE)"], fill=RED_FILL, font=RED_FONT, stopIfTrue=True))

        ws.conditional_formatting.add(
            "H12", CellIsRule(operator="greaterThanOrEqual", formula=["0.5"], fill=RED_FILL, font=RED_FONT))
        ws.conditional_formatting.add(
            "H12", FormulaRule(formula=["AND(H12>=0.25,H12<0.5)"], fill=AMBER_FILL, font=AMBER_FONT))
        ws.conditional_formatting.add(
            "H12", CellIsRule(operator="lessThan", formula=["0.25"], fill=GREEN_FILL, font=GREEN_FONT))

        for col, w in {"A": 3, "B": 16, "C": 16, "D": 3, "E": 16, "F": 16,
                        "G": 3, "H": 16, "I": 16}.items():
            ws.column_dimensions[col].width = w

        ws.merge_cells("A16:I16")
        ws["A16"] = "FINDINGS BREAKDOWN BY CATEGORY"
        ws["A16"].font = SECTION_FONT
        ws["A16"].border = THIN_BORDER

        breakdown = [
            ("SSHv1 Enabled", "=$E$4", RED_BAR),
            ("Weak Ciphers", "=$H$4", RED_BAR),
            ("Password Auth Enabled", "=$E$8", RED_BAR),
            ("Weak MACs", "=$B$8", AMBER_BAR),
            ("Weak Key Exchange", "=$H$8", AMBER_BAR),
            ("Weak Host-Key Algorithms", "=$B$12", AMBER_BAR),
        ]
        for i, (label, formula, _) in enumerate(breakdown):
            r = 18 + i
            ws.cell(row=r, column=2, value=label)
            ws.cell(row=r, column=3, value=formula)

        chart = BarChart()
        chart.type = "bar"
        chart.x_axis.title = "Hosts Affected"
        chart.y_axis.majorGridlines = None
        chart.legend = None
        cats = Reference(ws, min_col=2, min_row=18, max_row=23)
        vals = Reference(ws, min_col=3, min_row=18, max_row=23)
        chart.add_data(vals, titles_from_data=False)
        chart.set_categories(cats)
        chart.series[0].data_points = [
            DataPoint(idx=i, spPr=GraphicalProperties(solidFill=color))
            for i, (_, _, color) in enumerate(breakdown)
        ]
        ws.add_chart(chart, "E18")

        ws.merge_cells("A35:I35")
        ws["A35"] = "TOP OFFENDERS — HIGHEST-RISK HOSTS (WORK THESE FIRST)"
        ws["A35"].font = SECTION_FONT
        ws["A35"].fill = PatternFill("solid", fgColor="D9D9D9")

        ws.merge_cells("A36:I36")
        ws["A36"] = ("Ranked by Weakness Score = (100 if SSHv1 supported) + weak KEX + weak MAC "
                     "+ weak host-key + weak cipher counts. Password auth shown for context, not "
                     "scored. Static snapshot from this scan run (precomputed, not a live formula).")
        ws["A36"].font = SUBTEXT_FONT

        headers = ["Rank", "IP Address", "Hostname", "Scan Date", "SSHv1",
                   "Weak Algo Total", "Password Auth", "Weakness Score"]
        for c, h in enumerate(headers, start=1):
            cell = ws.cell(row=37, column=c, value=h)
            cell.font = Font(bold=True)
            cell.border = THIN_BORDER

        top10 = sorted(rows, key=lambda r: r["score"], reverse=True)[:10]
        for i, r in enumerate(top10):
            row_num = 38 + i
            ws.cell(row=row_num, column=1, value=i + 1)
            ws.cell(row=row_num, column=2, value=r["ip"])
            ws.cell(row=row_num, column=3, value=r["hostname"] or "(no reverse DNS)")
            date_val = r["scan_date"]
            try:
                date_val = datetime.strptime(r["scan_date"], "%Y-%m-%d").date()
            except (ValueError, TypeError):
                pass
            c4 = ws.cell(row=row_num, column=4, value=date_val)
            c4.number_format = "yyyy-mm-dd"
            ws.cell(row=row_num, column=5, value=r["sshv1"])
            ws.cell(row=row_num, column=6, value=r["weak_total"])
            ws.cell(row=row_num, column=7, value=r["pwauth"])
            ws.cell(row=row_num, column=8, value=r["score"])

        if top10:
            last = 37 + len(top10)
            ws.conditional_formatting.add(
                f"E38:E{last}", CellIsRule(operator="equal", formula=["TRUE"], fill=RED_FILL, font=Font(color="FFFFFF", bold=True)))
            ws.conditional_formatting.add(
                f"H38:H{last}", ColorScaleRule(
                    start_type="min", start_color="C6EFCE",
                    mid_type="percentile", mid_value=50, mid_color="FFEB9C",
                    end_type="max", end_color="FFC7CE"))
            footnote_row = last + 2
        else:
            footnote_row = 39

        ws.cell(row=footnote_row, column=1,
                value="Full per-host, per-algorithm detail (including hosts beyond the top 10): see Report sheet.")
        ws.cell(row=footnote_row, column=1).font = SUBTEXT_FONT
        return ws

    wb = Workbook()
    wb.remove(wb.active)
    build_overview_sheet(wb)
    build_report_sheet(wb)
    wb.active = 0
    return wb


def write_xlsx(rows: List[dict], xlsx_path: str, logger: logging.Logger) -> None:
    try:
        wb = build_workbook(rows)
    except ImportError:
        logger.warning("openpyxl not installed - skipping .xlsx generation. "
                        "Install with: pip install openpyxl")
        return
    wb.save(xlsx_path)
    logger.info(f"Workbook saved to: {xlsx_path} ({len(rows)} host(s))")


# =============================================================================
# MAIN
# =============================================================================

def parse_args(argv: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Authorized internal SSH weak-algorithm assessment.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("--workers", type=int, default=DEFAULT_WORKERS)
    parser.add_argument("--rate", type=int, default=DEFAULT_RATE)
    parser.add_argument("--host-timeout", type=str, default=DEFAULT_HOST_TIMEOUT,
                         help="nmap --host-timeout per host, so one hung host can't stall a worker")
    parser.add_argument("--retries", type=int, default=DEFAULT_RETRIES)
    parser.add_argument("--output-dir", type=str, default=SCRIPT_DIR)
    parser.add_argument("--masscan-path", type=str, default="masscan")
    parser.add_argument("--nmap-path", type=str, default="nmap")
    parser.add_argument("--interface", type=str, default=None)
    parser.add_argument("--skip-masscan", action="store_true")
    parser.add_argument("--masscan-output-file", type=str, default=None)
    parser.add_argument("--keep-temp", action="store_true",
                         help="keep each host's raw nmap XML under <output-dir>/nmap_xml_<date>/")
    parser.add_argument("--no-xlsx", action="store_true")
    parser.add_argument("--csv-out", type=str, default=None)
    parser.add_argument("--xlsx-out", type=str, default=None)
    parser.add_argument("--from-csv", metavar="FILE",
                         help="skip scanning entirely; rebuild the .xlsx from an existing CSV")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])

    scan_date = datetime.now().strftime("%Y-%m-%d")
    try:
        os.makedirs(args.output_dir, exist_ok=True)
    except OSError as exc:
        print(f"ERROR: Could not create output directory '{args.output_dir}': {exc}", file=sys.stderr)
        return 1

    log_path = os.path.join(args.output_dir, f"ssh_vuln_scan_{scan_date}.log")
    csv_path = args.csv_out or os.path.join(args.output_dir, f"ssh_vuln_scan_{scan_date}.csv")
    xlsx_path = args.xlsx_out or os.path.join(args.output_dir, f"ssh_vuln_scan_{scan_date}.xlsx")

    try:
        logger = setup_logging(log_path)
    except OSError as exc:
        print(f"ERROR: Could not open log file '{log_path}': {exc}", file=sys.stderr)
        return 1

    if args.from_csv:
        rows = read_rows_from_csv(args.from_csv)
        if not args.no_xlsx:
            write_xlsx(rows, xlsx_path, logger)
        return 0

    stop_event = threading.Event()

    def handle_sigint(signum, frame):  # noqa: ANN001
        if stop_event.is_set():
            logger.warning("Second interrupt received, forcing exit.")
            sys.exit(130)
        logger.warning("Ctrl+C received - finishing current work and writing "
                        "partial reports. Press Ctrl+C again to force exit.")
        stop_event.set()

    signal.signal(signal.SIGINT, handle_sigint)

    logger.info("=" * 70)
    logger.info("AUTHORIZED SSH WEAK-ALGORITHM ASSESSMENT")
    logger.info("=" * 70)
    logger.info("Configured subnets in scope:")
    for s in SUBNETS:
        logger.info(f"  - {s}")
    logger.info(f"Workers: {args.workers} | Masscan rate: {args.rate} | "
                f"Host timeout: {args.host_timeout} | Retries: {args.retries}")

    networks = validate_subnets(SUBNETS, logger)
    if not networks:
        logger.error("No valid subnets configured. Exiting.")
        return 1

    masscan_path = check_external_tool(args.masscan_path) or args.masscan_path
    if not args.skip_masscan and check_external_tool(args.masscan_path) is None:
        logger.error(f"Required tool '{args.masscan_path}' was not found on PATH.")
        return 1

    resolved_nmap = check_external_tool(args.nmap_path)
    if resolved_nmap is None:
        logger.error(f"Required tool '{args.nmap_path}' was not found on PATH. "
                      f"Unlike masscan, there is no fallback for Phase 2 - nmap+NSE "
                      f"is the only algorithm-collection engine this script has.")
        return 1
    args.nmap_path = resolved_nmap

    raw_records: List[Tuple[str, int, str]] = []
    if args.skip_masscan:
        if not args.masscan_output_file or not os.path.exists(args.masscan_output_file):
            logger.error("--skip-masscan requires a valid --masscan-output-file.")
            return 1
        raw_records, _ = parse_masscan_list_output(args.masscan_output_file, 0)
    else:
        masscan_out = args.masscan_output_file or os.path.join(
            args.output_dir, f".masscan_output_{scan_date}.txt")
        try:
            raw_records = run_masscan_phase1(masscan_path, SUBNETS, args.rate, masscan_out,
                                              args.interface, logger, stop_event)
        except Exception as exc:  # noqa: BLE001
            logger.error(f"Phase 1 discovery failed unexpectedly: {exc}")
            raw_records = []

    dedup: Dict[str, Tuple[str, int, str]] = {}
    for ip, port, proto in raw_records:
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            logger.warning(f"Skipping malformed IP address from scan output: {ip}")
            continue
        dedup[ip] = (ip, port, proto)

    logger.info(f"Discovered {len(dedup)} unique host(s) with TCP/22 open after deduplication.")

    hosts: List[DiscoveredHost] = []
    for ip, _port, _proto in dedup.values():
        if stop_event.is_set():
            break
        hostname = resolve_hostname(ip, timeout=2.0)
        subnet = subnet_for_ip(ip, networks)
        hosts.append(DiscoveredHost(ip=ip, hostname=hostname, subnet=subnet))

    rows: List[dict] = []
    if hosts and not stop_event.is_set():
        rows = run_phase2(hosts, args, logger, stop_event)
    elif not hosts:
        logger.info("No hosts with TCP/22 open discovered; skipping Phase 2 audit.")

    write_csv(rows, csv_path, logger)
    if not args.no_xlsx:
        write_xlsx(rows, xlsx_path, logger)

    weak = sum(1 for r in rows if r["sshv1"] or r["weak_total"] > 0 or r["pwauth"])
    logger.info("=" * 70)
    logger.info("SCAN SUMMARY")
    logger.info(f"  SSH hosts confirmed: {len(rows)} | With at least one weakness: {weak}")
    logger.info("=" * 70)
    logger.info(f"Reports written to: {os.path.abspath(args.output_dir)}")

    if stop_event.is_set():
        logger.warning("Scan was interrupted by user; reports reflect partial results.")
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
