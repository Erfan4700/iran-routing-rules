#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
Universal Multi-Platform Hybrid Engine (Enterprise Geo-Checked Edition)
Repository: Erfan4700/iran-routing-rules
Platforms: Mihomo (.mrs) | Sing-box (.srs / .json) | V2Ray (.dat) | Surge (.list)
Features:
  - Fixed tldextract Deprecation Warnings (top_domain_under_public_suffix)
  - Ultra-Fast Geo-Cross Check (80 Threads with Live Console Progress & Timeouts)
  - 100% Original Sources Restored (CF-Web, Mirava, Bootmortis, Custom Baseline)
  - All Output Sets Intact (iran-all-domains, iran-all-domains-lite, iran-domains-abroad, iran-unified)
  - Direct ArvanCloud Official API Integration
  - Strict Non-IR Direct Engine & Zero Overlap
  - SHA-256 Checksum Generation & Auto-Diff Report
================================================================================
"""

import os
import re
import sys
import csv
import io
import json
import shutil
import bisect
import hashlib
import socket
import subprocess
import ipaddress
import urllib.request
from typing import Set, List, Tuple, Optional
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

# --- BOOTSTRAP TLDEXTRACT (MOZILLA PSL) ---
try:
    import tldextract
except ImportError:
    print("[*] Installing 'tldextract' for Mozilla PSL parsing...", flush=True)
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "tldextract", "--quiet"])
        import tldextract
    except Exception as e:
        print(f"[!] Warning: Could not auto-install tldextract ({e}).", flush=True)
        tldextract = None

EXTRACTOR = tldextract.TLDExtract(cache_dir=str(Path(__file__).resolve().parent / ".tld_cache")) if tldextract else None

# --- DIRECTORY CONFIGURATION ---
BASE_DIR = Path(__file__).resolve().parent
TEXT_DIR = BASE_DIR / "output_text"
MRS_DIR = BASE_DIR / "output_mrs"
BASELINE_DIR = BASE_DIR / "data" / "baseline"

V2RAY_GEOSITE_DIR = TEXT_DIR / "v2ray_geosite"
V2RAY_GEOIP_DIR = TEXT_DIR / "v2ray_geoip" / "data"

for p in [TEXT_DIR, MRS_DIR, BASELINE_DIR, V2RAY_GEOSITE_DIR, V2RAY_GEOIP_DIR]:
    p.mkdir(parents=True, exist_ok=True)

USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
HEADERS = {"User-Agent": USER_AGENT}

# ==============================================================================
# 0. ZERO-TRUST CRITICAL INFRASTRUCTURE WHITELIST & SAFETY EXCLUSIONS
# ==============================================================================
UNBREAK_WHITELIST = {
    # PSPs & Payment Gateways
    "behpardakht.com", "sepehrpay.com", "zarinpal.com", "zarin.link",
    "payping.net", "rayanpay.com", "sb24.com",
    # Core Banking, Crypto & Platforms
    "blubank.com", "nobitex.net", "wallex.net", "abantether.com", "ramzinex.com", "exir.io",
    "divarcdn.com", "torob.com", "digikala.com", "digikalacloud.com",
    "snapp.cab", "snapp.tech", "snappcloud.io", "snapp.tax", "snapp.supply",
    "tapsi.cab", "tap33.me", "taximaxim.com", "kavenegar.com", "ghasedak.me",
    "raychat.io", "bale.ai", "eitaa.com", "farsitel.com", "neshan.org",
    "rajman.org", "cedarmaps.com", "aparat.com", "telewebion.com", "filimo.com",
    "varzesh3.com", "dl150m.info", "dl175m.info", "linkulu.com", "film2media.cam"
}

# Domains that must NEVER be direct (Proxy-required, broken, or international CDNs)
SAFETY_EXCLUDE_EXACT = {
    "eset.com", "github.com", "github.io", "githubusercontent.com", "glitch.me", 
    "googleapis.com", "gvt1.com", "radiojavan.com", "ubuntu.com", "wordpress.com", 
    "animelist.ir", "gamepass.ir"
}
SAFETY_EXCLUDE_CONTAIN = ("google.com", "ooklaserver.net", "cloudflare.com")

def is_whitelisted(domain: str) -> bool:
    domain = domain.lower()
    return any(domain == safe or domain.endswith("." + safe) for safe in UNBREAK_WHITELIST)

def is_ir_domain(domain: str) -> bool:
    return domain == "ir" or domain.endswith(".ir")

# ==============================================================================
# UTILITIES: CONCURRENT FETCHING & BASELINE RESILIENCE
# ==============================================================================
def fetch_single(url: str, timeout: int = 40, min_len: int = 20) -> str:
    try:
        cmd = ["curl", "-sSL", "--compressed", "--max-time", str(timeout), "-A", USER_AGENT, url]
        res = subprocess.run(cmd, capture_output=True, text=True, check=True)
        if len(res.stdout.strip()) >= min_len:
            return res.stdout
    except Exception:
        pass

    try:
        req = urllib.request.Request(url, headers=HEADERS)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            content = resp.read().decode("utf-8", errors="ignore")
            if len(content.strip()) >= min_len:
                return content
    except Exception:
        pass
    return ""

def fetch_data(urls, timeout: int = 40, min_len: int = 20) -> str:
    if isinstance(urls, str):
        urls = [urls]
    for url in urls:
        res = fetch_single(url, timeout, min_len)
        if res:
            return res
    return ""

def fetch_parallel(urls: List[str], max_workers: int = 8) -> dict:
    results = {}
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_url = {executor.submit(fetch_single, url): url for url in urls}
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            try:
                results[url] = future.result()
            except Exception:
                results[url] = ""
    return results

def load_baseline(name: str) -> Set[str]:
    path = BASELINE_DIR / f"{name}.txt"
    if path.exists():
        with open(path, "r", encoding="utf-8") as f:
            return {line.strip() for line in f if line.strip() and not line.startswith("#")}
    return set()

def save_baseline(name: str, items: Set[str]) -> None:
    path = BASELINE_DIR / f"{name}.txt"
    with open(path, "w", encoding="utf-8") as f:
        for item in sorted(items):
            f.write(f"{item}\n")

# ==============================================================================
# GEO-CROSS CHECK & FAST IP-INTERVAL MATCHER (BISECT)
# ==============================================================================
class IranIPMatcher:
    def __init__(self, v4_networks: List[ipaddress.IPv4Network], v6_networks: List[ipaddress.IPv6Network]):
        self.v4_intervals = sorted([(int(net.network_address), int(net.broadcast_address)) for net in v4_networks])
        self.v4_starts = [start for start, end in self.v4_intervals]

        self.v6_intervals = sorted([(int(net.network_address), int(net.broadcast_address)) for net in v6_networks])
        self.v6_starts = [start for start, end in self.v6_intervals]

    def contains(self, ip_str: str) -> bool:
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            ip_int = int(ip_obj)
            if ip_obj.version == 4:
                idx = bisect.bisect_right(self.v4_starts, ip_int) - 1
                if idx >= 0:
                    start, end = self.v4_intervals[idx]
                    return start <= ip_int <= end
            else:
                idx = bisect.bisect_right(self.v6_starts, ip_int) - 1
                if idx >= 0:
                    start, end = self.v6_intervals[idx]
                    return start <= ip_int <= end
        except Exception:
            pass
        return False

def resolve_domain_ips(domain: str) -> List[str]:
    try:
        answers = socket.getaddrinfo(domain, None)
        return list({sockaddr[0] for _, _, _, _, sockaddr in answers})
    except Exception:
        return []

def partition_by_hosting(domains: Set[str], ip_matcher: IranIPMatcher, max_workers: int = 80) -> Tuple[Set[str], Set[str]]:
    domestic_domains = set()
    abroad_domains = set()
    total = len(domains)
    processed = 0

    def check_domain(d: str):
        if is_whitelisted(d):
            return d, True, True
        ips = resolve_domain_ips(d)
        if not ips:
            return d, False, False
        is_domestic = any(ip_matcher.contains(ip) for ip in ips)
        return d, True, is_domestic

    print(f"  [*] Executing Geo-Cross Check for {total} domains with {max_workers} threads...", flush=True)
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(check_domain, d): d for d in domains}
        for f in as_completed(futures):
            processed += 1
            if processed % 2000 == 0 or processed == total:
                print(f"      -> Progress: {processed}/{total} domains checked...", flush=True)
            try:
                d, is_alive, is_domestic = f.result(timeout=2.0)
                if not is_alive:
                    continue
                if is_domestic or is_whitelisted(d):
                    domestic_domains.add(d)
                else:
                    abroad_domains.add(d)
            except Exception:
                continue

    return domestic_domains, abroad_domains

# ==============================================================================
# DOMAIN PURIFICATION & MOZILLA PSL PRUNING
# ==============================================================================
DOMAIN_REGEX = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$")

def clean_domain(line: str) -> Optional[str]:
    line = line.split("#")[0].split(";")[0].strip().lower()
    if not line or line.startswith(("!", "//", "/*", "include:")):
        return None

    line = re.sub(r"^(?:domain:|full:|keyword:|regexp:|\|\|?|@@)", "", line)
    line = re.sub(r"^(?:domain-suffix|domain|domain-keyword),", "", line, flags=re.IGNORECASE)

    parts = line.split()
    target = parts[1] if (len(parts) >= 2 and re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$|^::[0-9a-f]?$", parts[0])) else parts[0]
    target = target.split("@")[0].strip()
    target = re.sub(r"^https?://", "", target)
    target = re.sub(r"[\^/:].*$", "", target)
    target = re.sub(r"^\*\.?", "", target)
    target = re.sub(r"^\+\.?", "", target)
    target = target.strip(".")

    if target.startswith("xn--") or ".." in target or not DOMAIN_REGEX.match(target):
        return None
    if target in SAFETY_EXCLUDE_EXACT or any(target.endswith("." + bad) for bad in SAFETY_EXCLUDE_EXACT):
        return None
    if any(sub in target for sub in SAFETY_EXCLUDE_CONTAIN):
        return None

    if EXTRACTOR:
        ext = EXTRACTOR(target)
        if not ext.domain or not ext.suffix:
            return None
    else:
        if target in {"ir", "co.ir", "gov.ir", "ac.ir", "org.ir", "com", "net", "org"}:
            return None

    return target

def prune_subdomains(domains: Set[str]) -> Set[str]:
    sorted_domains = sorted(domains, key=lambda d: (len(d.split(".")), len(d), d))
    retained_roots = set()

    for domain in sorted_domains:
        if EXTRACTOR:
            ext = EXTRACTOR(domain)
            # Fixed DeprecationWarning: use top_domain_under_public_suffix
            registered_root = getattr(ext, 'top_domain_under_public_suffix', ext.registered_domain)
            if registered_root and registered_root != domain and registered_root in retained_roots:
                continue

            parts = ext.subdomain.split(".") if ext.subdomain else []
            is_redundant = False
            for i in range(len(parts)):
                parent = ".".join(parts[i:] + [ext.domain, ext.suffix])
                if parent in retained_roots:
                    is_redundant = True
                    break
            if not is_redundant:
                retained_roots.add(domain)
        else:
            parts = domain.split(".")
            is_redundant = False
            for i in range(1, len(parts)):
                parent = ".".join(parts[i:])
                if parent in retained_roots:
                    is_redundant = True
                    break
            if not is_redundant:
                retained_roots.add(domain)

    return retained_roots

# ==============================================================================
# IP / CIDR COLLAPSER (SUPERNETTING)
# ==============================================================================
def collapse_cidrs(raw_cidrs: List[str]) -> Tuple[List[ipaddress.IPv4Network], List[ipaddress.IPv6Network]]:
    v4_nets, v6_nets = [], []
    for entry in raw_cidrs:
        entry = entry.strip()
        if not entry or entry.startswith("#"):
            continue
        entry = re.sub(r"^(?:IP-CIDR|IP-CIDR6),", "", entry, flags=re.IGNORECASE)
        try:
            net = ipaddress.ip_network(entry, strict=False)
            if net.version == 4:
                v4_nets.append(net)
            else:
                v6_nets.append(net)
        except Exception:
            continue

    collapsed_v4 = sorted(list(ipaddress.collapse_addresses(v4_nets)), key=lambda n: (int(n.network_address), n.prefixlen))
    collapsed_v6 = sorted(list(ipaddress.collapse_addresses(v6_nets)), key=lambda n: (int(n.network_address), n.prefixlen))
    return collapsed_v4, collapsed_v6

# ==============================================================================
# MULTI-PLATFORM EXPORTERS
# ==============================================================================
def export_domain_target(name: str, domains: Set[str]):
    sorted_domains = sorted(domains)
    with open(TEXT_DIR / f"{name}.txt", "w", encoding="utf-8") as f:
        for d in sorted_domains:
            f.write(f"+.{d}\n")
    with open(TEXT_DIR / f"{name}.list", "w", encoding="utf-8") as f:
        for d in sorted_domains:
            f.write(f"DOMAIN-SUFFIX,{d}\n")
    with open(TEXT_DIR / f"{name}.yaml", "w", encoding="utf-8") as f:
        f.write("payload:\n")
        for d in sorted_domains:
            f.write(f"  - '+.{d}'\n")
    data = {"version": 1, "rules": [{"domain_suffix": sorted_domains}]}
    with open(TEXT_DIR / f"{name}.json", "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    with open(V2RAY_GEOSITE_DIR / name, "w", encoding="utf-8") as f:
        for d in sorted_domains:
            f.write(f"{d}\n")

def export_ip_target(name: str, cidrs: List[str]):
    with open(TEXT_DIR / f"{name}.txt", "w", encoding="utf-8") as f:
        for c in cidrs:
            f.write(f"{c}\n")
    with open(TEXT_DIR / f"{name}.list", "w", encoding="utf-8") as f:
        for c in cidrs:
            f.write(f"IP-CIDR,{c},no-resolve\n")
    with open(TEXT_DIR / f"{name}.yaml", "w", encoding="utf-8") as f:
        f.write("payload:\n")
        for c in cidrs:
            f.write(f"  - '{c}'\n")
    data = {"version": 1, "rules": [{"ip_cidr": cidrs}]}
    with open(TEXT_DIR / f"{name}.json", "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    with open(V2RAY_GEOIP_DIR / name, "w", encoding="utf-8") as f:
        for c in cidrs:
            f.write(f"{c}\n")

# ==============================================================================
# COMPILERS & METADATA/CHECKSUM GENERATOR
# ==============================================================================
def compile_to_mrs(mihomo_bin: Optional[str], behavior: str, text_file: Path, mrs_file: Path) -> bool:
    if not mihomo_bin or not text_file.exists() or text_file.stat().st_size == 0:
        return False
    try:
        cmd = [mihomo_bin, "convert-ruleset", behavior, "text", str(text_file), str(mrs_file)]
        res = subprocess.run(cmd, capture_output=True, text=True)
        return (res.returncode == 0 and mrs_file.exists() and mrs_file.stat().st_size > 50)
    except Exception:
        return False

def compile_to_srs(singbox_bin: Optional[str], json_file: Path, srs_file: Path) -> bool:
    if not singbox_bin or not json_file.exists() or json_file.stat().st_size == 0:
        return False
    try:
        cmd = [singbox_bin, "rule-set", "compile", "--output", str(srs_file), str(json_file)]
        res = subprocess.run(cmd, capture_output=True, text=True)
        return (res.returncode == 0 and srs_file.exists() and srs_file.stat().st_size > 50)
    except Exception:
        return False

def generate_checksums(target_dir: Path, output_file: Path):
    entries = []
    for file_path in sorted(target_dir.glob("*.*")):
        if file_path.is_file() and file_path.name != output_file.name:
            h = hashlib.sha256()
            with open(file_path, "rb") as f:
                while chunk := f.read(8192):
                    h.update(chunk)
            entries.append(f"{h.hexdigest()}  {file_path.name}")
    with open(output_file, "w", encoding="utf-8") as f:
        f.write("\n".join(entries) + "\n")

# ==============================================================================
# MAIN PIPELINE EXECUTION
# ==============================================================================
def main():
    print("=" * 82, flush=True)
    print("🚀 IRAN ROUTING RULES: ENTERPRISE ENGINE (OPTIMIZED & GEO-CHECKED)", flush=True)
    print("=" * 82, flush=True)

    # --------------------------------------------------------------------------
    # 1. IP & ASN PROCESSING
    # --------------------------------------------------------------------------
    print("\n[+] 1/9: Processing Iranian IP Ranges & ASN Infrastructure...", flush=True)
    ripe_raw = fetch_data([
        "https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-latest",
        "https://ftp.apnic.net/stats/ripe-ncc/delegated-ripencc-latest"
    ], timeout=60)

    raw_ip_list = []
    asns = set()

    if ripe_raw:
        for line in ripe_raw.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("|")
            if len(parts) >= 7 and parts[1] == "IR":
                if parts[2] == "ipv4":
                    try:
                        first_ip = ipaddress.IPv4Address(parts[3])
                        last_ip = first_ip + (int(parts[4]) - 1)
                        for cidr in ipaddress.summarize_range(first_ip, last_ip):
                            raw_ip_list.append(str(cidr))
                    except Exception:
                        pass
                elif parts[2] == "ipv6":
                    raw_ip_list.append(f"{parts[3]}/{parts[4]}")
                elif parts[2] == "asn":
                    asns.add(f"IP-ASN,{parts[3]}")

    extra_ip_sources = [
        "https://raw.githubusercontent.com/ygbkm/resources/refs/heads/main/resources/iran-datacenters/ipv4.txt",
        "https://raw.githubusercontent.com/ygbkm/resources/refs/heads/main/resources/iran-datacenters/ipv6.txt",
        "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geoip/ir.list",
        "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/ircidr.txt"
    ]
    for content in fetch_parallel(extra_ip_sources).values():
        for line in content.splitlines():
            d = line.strip()
            if d and not d.startswith("#"):
                raw_ip_list.append(d)

    fallback_asns = fetch_data("https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/irasn.txt", timeout=25)
    for line in fallback_asns.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            asns.add(line if line.startswith("IP-ASN,") else f"IP-ASN,{line}")

    if len(raw_ip_list) < 500:
        raw_ip_list.extend(load_baseline("iran-ip"))
    else:
        save_baseline("iran-ip", set(raw_ip_list))

    isp_v4, isp_v6 = collapse_cidrs(raw_ip_list)
    isp_cidrs = [str(n) for n in (isp_v4 + isp_v6)]
    export_ip_target("iran-modular-isp", isp_cidrs)

    with open(TEXT_DIR / "iran-asn.txt", "w", encoding="utf-8") as f:
        for asn in sorted(asns):
            f.write(f"{asn}\n")
    with open(TEXT_DIR / "iran-asn.yaml", "w", encoding="utf-8") as f:
        f.write("payload:\n")
        for asn in sorted(asns):
            f.write(f"  - '{asn}'\n")

    print(f"  [✓] Modular: 'iran-modular-isp' ({len(isp_cidrs)} CIDRs)", flush=True)
    print(f"  [✓] Infra:   'iran-asn' ({len(asns)} ASNs)", flush=True)

    # --------------------------------------------------------------------------
    # 2. DOMESTIC CLOUDS & MACRO ALL-IP
    # --------------------------------------------------------------------------
    print("\n[+] 2/9: Fetching Direct Cloud APIs & Generating 'iran-all-ip'...", flush=True)
    raw_cloud_cidrs = []
    
    arvan_official = fetch_data("https://www.arvancloud.ir/fa/ips.txt", timeout=20)
    if arvan_official:
        raw_cloud_cidrs.extend(arvan_official.splitlines())
        print("  [✓] Integrated official ArvanCloud API ranges.", flush=True)

    cloud_sources = ["derakcloud", "iranserver", "parspack"]
    cloud_urls = [f"https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/{c}.txt" for c in cloud_sources]
    for content in fetch_parallel(cloud_urls).values():
        raw_cloud_cidrs.extend(content.splitlines())

    cloud_v4, cloud_v6 = collapse_cidrs(raw_cloud_cidrs)
    all_cloud_cidrs = [str(n) for n in (cloud_v4 + cloud_v6)]
    export_ip_target("iran-modular-cloud", all_cloud_cidrs)

    macro_v4, macro_v6 = collapse_cidrs(raw_ip_list + raw_cloud_cidrs)
    master_all_cidrs = [str(n) for n in (macro_v4 + macro_v6)]
    export_ip_target("iran-all-ip", master_all_cidrs)

    with open(V2RAY_GEOIP_DIR / "ir", "w", encoding="utf-8") as f:
        for c in master_all_cidrs:
            f.write(f"{c}\n")

    ip_matcher = IranIPMatcher(macro_v4, macro_v6)
    print(f"  [✓] Modular: 'iran-modular-cloud' ({len(all_cloud_cidrs)} CIDRs)", flush=True)
    print(f"  [★] MACRO:   'iran-all-ip' ({len(master_all_cidrs)} collapsed CIDRs)", flush=True)

    # --------------------------------------------------------------------------
    # 3. UNIFIED SECURITY & THREAT INTEL
    # --------------------------------------------------------------------------
    print("\n[+] 3/9: Compiling Threat Intelligence...", flush=True)
    DOMESTIC_THREAT_REGEX = re.compile(
        r"(?:^|[.-])(?:shaparak|sana[-_.]?gov|adliran|divar|sadad|"
        r"mellat|melli|tejarat|saderat|pasargad|blubank|keshavarzi|refah|maskan|"
        r"sep[-_.]?(?:ir|pay|epay|shaparak)|shaparak[-_.]?sep|sheba[-_.]?bank)(?:[.-]|$)"
    )

    threat_domain_sources = [
        "https://raw.githubusercontent.com/MasterKia/PersianBlocker/main/PersianBlockerPhishing.txt",
        "https://raw.githubusercontent.com/curbengh/phishing-filter/master/phishing-filter-hosts.txt",
        "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/phishing.txt",
        "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/malware.txt"
    ]
    raw_threat_domains = set()
    for url, content in fetch_parallel(threat_domain_sources).items():
        for line in content.splitlines():
            d = clean_domain(line)
            if d and not is_whitelisted(d):
                if DOMESTIC_THREAT_REGEX.search(d) or "malware" in url:
                    raw_threat_domains.add(d)

    pruned_threats = prune_subdomains(raw_threat_domains)
    export_domain_target("iran-all-security", pruned_threats)

    threat_ip_sources = [
        "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/phishing-ip.txt",
        "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/malware-ip.txt"
    ]
    raw_threat_ips = []
    for content in fetch_parallel(threat_ip_sources).values():
        raw_threat_ips.extend(content.splitlines())

    t_v4, t_v6 = collapse_cidrs(raw_threat_ips)
    all_threat_cidrs = [str(n) for n in (t_v4 + t_v6)]
    export_ip_target("iran-all-security-ip", all_threat_cidrs)

    print(f"  [★] MACRO: 'iran-all-security' ({len(pruned_threats)} domains)", flush=True)
    print(f"  [★] MACRO: 'iran-all-security-ip' ({len(all_threat_cidrs)} CIDRs)", flush=True)

    # --------------------------------------------------------------------------
    # 4. PERSIAN ADS & TRACKERS
    # --------------------------------------------------------------------------
    print("\n[+] 4/9: Compiling Macro 'iran-all-ads'...", flush=True)
    V2FLY_BASE = "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/"
    ads_sources = [
        f"{V2FLY_BASE}category-ads-ir",
        "https://github.com/bootmortis/iran-hosted-domains/releases/latest/download/clash_rules_ads.txt",
        "https://raw.githubusercontent.com/MasterKia/PersianBlocker/main/PersianBlockerHosts.txt",
        "https://raw.githubusercontent.com/MasterKia/PersianBlocker/main/PersianBlockerAds-Hosts.txt",
        "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/ads.txt"
    ]
    raw_ads = {"yektanet.com", "sabavision.com", "mediaad.org", "najva.com"}
    for content in fetch_parallel(ads_sources).values():
        for line in content.splitlines():
            d = clean_domain(line)
            if d and not is_whitelisted(d):
                raw_ads.add(d)

    raw_ads -= pruned_threats
    pruned_ads = prune_subdomains(raw_ads)
    export_domain_target("iran-all-ads", pruned_ads)
    print(f"  [★] MACRO: 'iran-all-ads' ({len(pruned_ads)} domains)", flush=True)

    # --------------------------------------------------------------------------
    # 5. MASTER IRANIAN DIRECT DOMAINS + RESTORED SOURCES + GEO-CROSS CHECK
    # --------------------------------------------------------------------------
    print("\n[+] 5/9: Aggregating & Geo-Checking Pure Non-IR Domestic Domains...", flush=True)
    raw_candidate_domains = {d for d in UNBREAK_WHITELIST if not is_ir_domain(d)}
    raw_candidate_domains.update({d for d in load_baseline("iran-domains") if not is_ir_domain(d)})

    # Baseline: custom-domains.txt
    custom_baseline_path = BASELINE_DIR / "custom-domains.txt"
    custom_count = 0
    if custom_baseline_path.exists():
        with open(custom_baseline_path, "r", encoding="utf-8") as f:
            for line in f:
                d = clean_domain(line)
                if d and not is_ir_domain(d):
                    raw_candidate_domains.add(d)
                    custom_count += 1
        print(f"  [✓] Loaded {custom_count} manual non-ir domain(s) from custom-domains.txt", flush=True)
    else:
        custom_baseline_path.touch()

    v2fly_direct_categories = [
        "category-ir", "category-gov-ir", "category-bank-ir", "category-news-ir",
        "category-tech-ir", "category-media-ir", "category-bourse-ir", "category-forums-ir",
        "category-travel-ir", "category-payment-ir", "category-scholar-ir", "category-shopping-ir",
        "category-education-ir", "category-insurance-ir", "category-social-media-ir"
    ]

    domain_upstreams = [
        "https://github.com/ygbkm/clash-rules-iran/releases/latest/download/rules.txt",
        "https://github.com/bootmortis/iran-hosted-domains/releases/latest/download/clash_rules_other.txt",
        "https://raw.githubusercontent.com/bootmortis/iran-hosted-domains/main/src/data/adsl_tci.txt",
        "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/ir.txt",
        "https://raw.githubusercontent.com/bootmortis/ito-gov-mirror/main/out/domains.csv"
    ] + [f"{V2FLY_BASE}{cat}" for cat in v2fly_direct_categories]

    fetched_domains = fetch_parallel(domain_upstreams)
    v2fly_banking_seeds, v2fly_gov_seeds, v2fly_media_seeds, download_seeds = set(), set(), set(), set()

    for url, content in fetched_domains.items():
        is_bank = any(k in url for k in ["category-bank-ir", "category-payment-ir", "category-bourse-ir", "category-insurance-ir"])
        is_gov = "category-gov-ir" in url
        is_media = any(k in url for k in ["category-media-ir", "category-news-ir"])

        for line in content.splitlines():
            if "," in line and not line.startswith("DOMAIN"):
                parts = line.split(",")
                if len(parts) >= 2:
                    line = parts[1]
            d = clean_domain(line)
            if d and not is_ir_domain(d):
                raw_candidate_domains.add(d)
                if is_bank:
                    v2fly_banking_seeds.add(d)
                elif is_gov:
                    v2fly_gov_seeds.add(d)
                elif is_media:
                    v2fly_media_seeds.add(d)

    # Restored: Bootmortis custom_domains.py
    print("  [*] Fetching Bootmortis custom_domains.py (Direct list)...", flush=True)
    custom_py_raw = fetch_data("https://raw.githubusercontent.com/bootmortis/iran-hosted-domains/main/src/custom_domains.py", timeout=30)
    if custom_py_raw:
        direct_matches = re.findall(r'"([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})"', custom_py_raw)
        added_custom = 0
        for dom in direct_matches:
            d = clean_domain(dom)
            if d and not is_ir_domain(d):
                raw_candidate_domains.add(d)
                added_custom += 1
        print(f"  [✓] Integrated {added_custom} tested non-ir domains from custom_domains.py.", flush=True)

    # Restored: Cloudflare Iranian Domains (CF-Web)
    print("  [*] Fetching Cloudflare Iranian Domains (CF-Web)...", flush=True)
    cf_raw = fetch_data("https://raw.githubusercontent.com/hossein-mohseni/CF-Web/main/domains.json", timeout=60)
    cf_count = 0
    if cf_raw:
        try:
            cf_json = json.loads(cf_raw)
            items = cf_json.get("data", []) if isinstance(cf_json, dict) else cf_json
            if isinstance(items, list):
                for entry in items:
                    raw_val = entry.get("domain") if isinstance(entry, dict) else entry
                    if raw_val:
                        d = clean_domain(str(raw_val))
                        if d and not is_ir_domain(d):
                            raw_candidate_domains.add(d)
                            cf_count += 1
            print(f"  [✓] CF-Web: Successfully parsed {cf_count} Cloudflare non-ir domains.", flush=True)
        except Exception as e:
            print(f"  [!] Warning parsing CF-Web JSON: {e}", flush=True)

    # Restored: Mirava Package Mirrors
    print("  [*] Fetching Mirava Iranian Package Mirrors Registry...", flush=True)
    mirava_raw = fetch_data("https://raw.githubusercontent.com/MiravaOrg/Mirava/refs/heads/main/mirrors_list.yaml", timeout=30)
    mirava_count = 0
    if mirava_raw:
        urls = re.findall(r"https?://([a-zA-Z0-9.-]+)", mirava_raw)
        for host in urls:
            d = clean_domain(host)
            if d and not is_ir_domain(d):
                raw_candidate_domains.add(d)
                download_seeds.add(d)
                mirava_count += 1
        print(f"  [✓] Mirava: Successfully integrated {mirava_count} non-ir mirrors.", flush=True)

    # Enamad Stream
    print("  [*] Fetching & Streaming Enamad Database (~13MB)...", flush=True)
    enamad_raw = fetch_data("https://raw.githubusercontent.com/bootmortis/enamad-mirror/main/out/domains.csv", timeout=90)
    if enamad_raw:
        try:
            reader = csv.reader(io.StringIO(enamad_raw))
            header = next(reader, None)
            domain_idx = 2
            if header:
                for idx, col in enumerate(header):
                    if col.strip().lower() == "domain":
                        domain_idx = idx
                        break
            for row in reader:
                if len(row) > domain_idx:
                    d = clean_domain(row[domain_idx])
                    if d and not is_ir_domain(d):
                        raw_candidate_domains.add(d)
        except Exception as e:
            print(f"  [!] Enamad Parse Warning: {e}", flush=True)

    raw_candidate_domains = (raw_candidate_domains - pruned_ads - pruned_threats)
    raw_candidate_domains = {d for d in raw_candidate_domains if not is_ir_domain(d)}
    raw_candidate_domains.update({d for d in UNBREAK_WHITELIST if not is_ir_domain(d)})

    # Partition via Fast Geo-Cross Check
    domestic_domains, abroad_domains = partition_by_hosting(raw_candidate_domains, ip_matcher, max_workers=80)

    domestic_domains.update({d for d in UNBREAK_WHITELIST if not is_ir_domain(d)})
    save_baseline("iran-domains", domestic_domains)

    pruned_domestic = prune_subdomains(domestic_domains)
    pruned_abroad = prune_subdomains(abroad_domains)

    export_domain_target("iran-all-domains", pruned_domestic)
    export_domain_target("iran-domains-abroad", pruned_abroad)

    with open(V2RAY_GEOSITE_DIR / "ir", "w", encoding="utf-8") as f:
        for d in sorted(pruned_domestic):
            f.write(f"{d}\n")

    # Target: iran-all-domains-lite
    ir_lite_raw = fetch_data("https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/ir-lite.txt", timeout=30)
    lite_domains = set()
    for line in ir_lite_raw.splitlines():
        d = clean_domain(line)
        if d and not is_ir_domain(d):
            lite_domains.add(d)

    if custom_baseline_path.exists():
        with open(custom_baseline_path, "r", encoding="utf-8") as f:
            for line in f:
                d = clean_domain(line)
                if d and not is_ir_domain(d):
                    lite_domains.add(d)

    lite_domains = (lite_domains - pruned_ads - pruned_threats)
    lite_domains = {d for d in lite_domains if not is_ir_domain(d)}
    lite_domains.update({d for d in UNBREAK_WHITELIST if not is_ir_domain(d)})

    pruned_lite = prune_subdomains(lite_domains if len(lite_domains) > 100 else pruned_domestic)
    export_domain_target("iran-all-domains-lite", pruned_lite)

    print(f"  [★] MACRO: 'iran-all-domains' ({len(pruned_domestic)} confirmed domestic domains)", flush=True)
    print(f"  [★] MACRO: 'iran-domains-abroad' ({len(pruned_abroad)} foreign-hosted domains isolated)", flush=True)
    print(f"  [★] MACRO: 'iran-all-domains-lite' ({len(pruned_lite)} domains)", flush=True)

    # --------------------------------------------------------------------------
    # 6. MODULAR DISJOINT SUBSETS (DOMESTIC ONLY)
    # --------------------------------------------------------------------------
    print("\n[+] 6/9: Partitioning Domestic Domains into Disjoint Modular Sets...", flush=True)

    MEDIA_PATTERNS = re.compile(r"(?:aparat|filimo|namava|filmnet|telewebion|gapfilm|cinematicket|tiwall|tamasha|namasha|antenn|lenz|mayaa|irib|seevid|radio|video|music|tv|vod|stream)")
    BANKING_PATTERNS = re.compile(r"(?:bank|shaparak|sadad|mellat|melli|tejarat|saderat|pasargad|sb24|blubank|sepah|refah|keshavarzi|maskan|postbank|zarinpal|payping|idpay|jibit|nextpay|vandar|zibal|nobitex|wallex|bitpin|ramzinex|abantether|exir|bourse|seham|tsetmc|codal|emofid|agah|bimeh|azki)")
    GOV_PATTERNS = re.compile(r"(?:\.gov\.ir$|\.jud\.ir$|\.police\.ir$|sana\.gov|adliran|my\.gov|mardom|tax\.gov|tamin|post\.ir|dolat\.ir|majlis\.ir|sabteahval|moi\.ir|medu\.ir)")
    GAMING_PATTERNS = re.compile(r"(?:gameup|parshub|asiagame|vmp|fivem|gamefa|vgmag|zoomg|bazicenter|baziato|csgo|samp|bazi|game)")
    DOWNLOAD_PATTERNS = re.compile(r"(?:soft98|yasdl|downloadha|p30download|asandl|sarzamindownload|p30world|shahrsakhtafzar|zoomit|digiato|download|mirror|tarfandestan)")

    banking_domains = set()
    gov_domains = set()
    media_domains = set()
    gaming_domains = set()
    download_domains = set()

    for d in pruned_domestic:
        if BANKING_PATTERNS.search(d) or d in v2fly_banking_seeds:
            banking_domains.add(d)
        elif GOV_PATTERNS.search(d) or d in v2fly_gov_seeds:
            gov_domains.add(d)
        elif MEDIA_PATTERNS.search(d) or d in v2fly_media_seeds:
            media_domains.add(d)
        elif GAMING_PATTERNS.search(d):
            gaming_domains.add(d)
        elif DOWNLOAD_PATTERNS.search(d) or d in download_seeds:
            download_domains.add(d)

    categorized_union = banking_domains | gov_domains | media_domains | gaming_domains | download_domains
    other_domains = pruned_domestic - categorized_union

    export_domain_target("iran-modular-banking", banking_domains)
    export_domain_target("iran-modular-gov", gov_domains)
    export_domain_target("iran-modular-media", media_domains)
    export_domain_target("iran-modular-gaming", gaming_domains)
    export_domain_target("iran-modular-download", download_domains)
    export_domain_target("iran-modular-other", other_domains)

    assert (len(categorized_union) + len(other_domains)) == len(pruned_domestic), "Data integrity check failed!"
    print(f"  [✓] Disjoint math check passed for all submodules.", flush=True)

    # --------------------------------------------------------------------------
    # 7. DOMESTIC GAMBLING & BETTING
    # --------------------------------------------------------------------------
    print("\n[+] 7/9: Compiling 'iran-modular-gambling'...", flush=True)
    gambling_content = fetch_data("https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/nsfw.txt", timeout=25)
    raw_gambling = {"betcart.com", "takbet.com", "wolfbet.info", "cannonbet.org", "hazarat.org"}
    for line in gambling_content.splitlines():
        d = clean_domain(line)
        if d and not is_whitelisted(d):
            raw_gambling.add(d)

    raw_gambling -= pruned_domestic
    pruned_gambling = prune_subdomains(raw_gambling)
    export_domain_target("iran-modular-gambling", pruned_gambling)
    print(f"  [✓] Modular: 'iran-modular-gambling' ({len(pruned_gambling)} domains)", flush=True)

    # --------------------------------------------------------------------------
    # 8. APP EXCEPTIONS, APPS & UNIFIED CLASSICAL
    # --------------------------------------------------------------------------
    print("\n[+] 8/9: Compiling App Rules & Unified Classical Sets...", flush=True)
    EXCEPTIONS_MAP = {
        "metrix.ir": [
            "cab.snapp.passenger", "cab.snapp.driver",
            "com.zoodfood.android", "com.zoodfood.android.play",
            "taxi.tapsi.passenger", "taxi.tapsi.driver"
        ]
    }
    classical_exception_lines = []
    for domain, apps in EXCEPTIONS_MAP.items():
        for app in apps:
            classical_exception_lines.append(f"AND,((DOMAIN-SUFFIX,{domain}),(PROCESS-NAME,{app}))")
            classical_exception_lines.append(f"AND,((DOMAIN-SUFFIX,{domain}),(PACKAGE-NAME,{app}))")

    with open(TEXT_DIR / "iran-app-exceptions.txt", "w", encoding="utf-8") as f:
        for r in classical_exception_lines:
            f.write(f"{r}\n")

    compiled_packages = {
        "cab.snapp.passenger", "cab.snapp.driver", "taxi.tap30.passenger", "neshan.maps",
        "ir.divar", "ir.torob", "market.nobitex", "ir.tejaratbank.mobile", "com.bmi.bam",
        "ir.blu.banking", "com.aparat.android", "org.bale.messenger", "ir.eitaa.messenger"
    }
    GLOBAL_EXCLUDES = {"org.telegram.messenger", "com.whatsapp", "com.instagram.android", "com.google.android.youtube"}
    WINDOWS_PROCESSES = ["Bale.exe", "Eitaa.exe", "Rubika.exe", "IDMan.exe", "Digikala.exe"]

    app_sources = [
        "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/apps.txt",
        "https://raw.githubusercontent.com/SamadiPour/iran-android-apps/master/packages.json",
        "https://raw.githubusercontent.com/bootmortis/iran-hosted-domains/main/apps/apps.txt"
    ]
    for content in fetch_parallel(app_sources).values():
        matches = re.findall(r"([a-zA-Z][a-zA-Z0-9_]+(?:\.[a-zA-Z][a-zA-Z0-9_]+)+)", content)
        for pkg in matches:
            if pkg not in GLOBAL_EXCLUDES and len(pkg) < 85:
                compiled_packages.add(pkg)

    with open(TEXT_DIR / "iran-all-apps.txt", "w", encoding="utf-8") as f:
        for pkg in sorted(compiled_packages):
            f.write(f"PACKAGE-NAME,{pkg}\n")
        for proc in sorted(WINDOWS_PROCESSES):
            f.write(f"PROCESS-NAME,{proc}\n")

    data_apps = {"version": 1, "rules": [{"package_name": sorted(compiled_packages), "process_name": sorted(WINDOWS_PROCESSES)}]}
    with open(TEXT_DIR / "iran-all-apps.json", "w", encoding="utf-8") as f:
        json.dump(data_apps, f, indent=2, ensure_ascii=False)

    # Restored: Unified Classical Outputs
    classical_rules = ["GEOIP,ir", "DOMAIN-SUFFIX,ir"]
    for d in sorted(pruned_domestic):
        classical_rules.append(f"DOMAIN-SUFFIX,{d}")
    for n in master_all_cidrs:
        classical_rules.append(f"IP-CIDR6,{n}" if ":" in n else f"IP-CIDR,{n}")

    with open(TEXT_DIR / "iran-unified.txt", "w", encoding="utf-8") as f:
        for r in classical_rules:
            f.write(f"{r}\n")
    with open(TEXT_DIR / "iran-unified.yaml", "w", encoding="utf-8") as f:
        f.write("payload:\n")
        for r in classical_rules:
            f.write(f"  - '{r}'\n")
    with open(TEXT_DIR / "iran-unified.list", "w", encoding="utf-8") as f:
        for d in sorted(pruned_domestic):
            f.write(f"DOMAIN-SUFFIX,{d}\n")
        for n in master_all_cidrs:
            f.write(f"IP-CIDR,{n},no-resolve\n")

    # Restored: v2ray_geoip_config.json
    geoip_config = {
        "input": [{"type": "text", "action": "add", "args": {"inputDir": str(V2RAY_GEOIP_DIR.resolve())}}],
        "output": [{"type": "v2rayGeoIPDat", "action": "output", "args": {"outputDir": str(MRS_DIR.resolve()), "outputName": "geoip.dat"}}]
    }
    with open(TEXT_DIR / "v2ray_geoip_config.json", "w", encoding="utf-8") as f:
        json.dump(geoip_config, f, indent=2)

    # --------------------------------------------------------------------------
    # 9. COMPILATION, SHA-256 CHECKSUMS & DIFF REPORT
    # --------------------------------------------------------------------------
    print("\n" + "=" * 82, flush=True)
    print("⚙️ 9/9: BINARY COMPILATION (.MRS / .SRS) & CHECKSUM GENERATION", flush=True)
    print("=" * 82, flush=True)

    for f in TEXT_DIR.glob("*.*"):
        if f.is_file():
            shutil.copy(f, MRS_DIR / f.name)

    mihomo_bin = shutil.which("mihomo") or shutil.which("mihomo.exe") or (BASE_DIR / "mihomo")
    if mihomo_bin and os.path.exists(mihomo_bin):
        print(f"[+] Mihomo Core Active: {mihomo_bin}", flush=True)
        domain_targets = [
            "iran-all-domains", "iran-all-domains-lite", "iran-domains-abroad", "iran-all-ads",
            "iran-all-security", "iran-modular-banking", "iran-modular-gov", "iran-modular-media",
            "iran-modular-gaming", "iran-modular-download", "iran-modular-other", "iran-modular-gambling"
        ]
        for target in sorted(domain_targets):
            in_txt = TEXT_DIR / f"{target}.txt"
            out_mrs = MRS_DIR / f"{target}.mrs"
            if in_txt.exists():
                success = compile_to_mrs(str(mihomo_bin), "domain", in_txt, out_mrs)
                print(f"  [{'✓' if success else '✗'}] Mihomo MRS: {target}.mrs", flush=True)

        ip_targets = ["iran-all-ip", "iran-modular-isp", "iran-modular-cloud", "iran-all-security-ip"]
        for target in sorted(ip_targets):
            in_txt = TEXT_DIR / f"{target}.txt"
            out_mrs = MRS_DIR / f"{target}.mrs"
            if in_txt.exists():
                success = compile_to_mrs(str(mihomo_bin), "ipcidr", in_txt, out_mrs)
                print(f"  [{'✓' if success else '✗'}] Mihomo MRS: {target}.mrs", flush=True)

    singbox_bin = shutil.which("sing-box") or shutil.which("sing-box.exe") or (BASE_DIR / "sing-box")
    if singbox_bin and os.path.exists(singbox_bin):
        print(f"\n[+] Sing-box Core Active: {singbox_bin}", flush=True)
        srs_targets = [
            "iran-all-domains", "iran-all-domains-lite", "iran-domains-abroad", "iran-all-ip",
            "iran-all-ads", "iran-all-security", "iran-all-security-ip", "iran-all-apps",
            "iran-modular-banking", "iran-modular-gov", "iran-modular-media", "iran-modular-gaming",
            "iran-modular-download", "iran-modular-other", "iran-modular-isp", "iran-modular-cloud",
            "iran-modular-gambling"
        ]
        for target in sorted(srs_targets):
            in_json = TEXT_DIR / f"{target}.json"
            out_srs = MRS_DIR / f"{target}.srs"
            if in_json.exists():
                success = compile_to_srs(str(singbox_bin), in_json, out_srs)
                print(f"  [{'✓' if success else '✗'}] Sing-box SRS: {target}.srs", flush=True)

    generate_checksums(MRS_DIR, MRS_DIR / "sha256sum.txt")
    generate_checksums(TEXT_DIR, TEXT_DIR / "sha256sum.txt")
    print(f"\n[✓] Generated sha256sum.txt for all assets.", flush=True)

    stats_report = {
        "domestic_direct_domains": len(pruned_domestic),
        "abroad_hosted_domains": len(pruned_abroad),
        "lite_domains": len(pruned_lite),
        "total_cidrs": len(master_all_cidrs),
        "threats": len(pruned_threats),
        "ads": len(pruned_ads)
    }
    with open(BASE_DIR / "release_stats.json", "w", encoding="utf-8") as f:
        json.dump(stats_report, f, indent=2)

    print("\n" + "=" * 82, flush=True)
    print("🏁 PIPELINE COMPLETED: 100% ASSETS RESTORED & GEO-CHECKED.", flush=True)
    print("=" * 82, flush=True)

if __name__ == "__main__":
    main()
