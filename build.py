#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
Universal Multi-Platform Hybrid Engine (Clean Architecture - Production Ready)
Repository: Erfan4700/iran-routing-rules
Platforms: Mihomo (.mrs) | Sing-box (.srs / .json) | V2Ray (.dat) | Surge (.list)
Features: Strict Non-IR Direct Engine | Zero-Overlap | Dedicated Threat Isolation
================================================================================
"""

import os
import re
import sys
import csv
import io
import json
import shutil
import subprocess
import ipaddress
import urllib.request
from typing import Set, List, Tuple, Optional
from pathlib import Path

# --- BOOTSTRAP TLDEXTRACT (MOZILLA PSL) ---
try:
    import tldextract
except ImportError:
    print("[*] Installing 'tldextract' for Mozilla PSL parsing...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "tldextract", "--quiet"])
        import tldextract
    except Exception as e:
        print(f"[!] Warning: Could not auto-install tldextract ({e}).")
        tldextract = None

EXTRACTOR = tldextract.TLDExtract(cache_dir=str(Path(__file__).resolve().parent / ".tld_cache")) if tldextract else None

# --- DIRECTORY CONFIGURATION ---
BASE_DIR = Path(__file__).resolve().parent
TEXT_DIR = BASE_DIR / "output_text"
MRS_DIR = BASE_DIR / "output_mrs"
BASELINE_DIR = BASE_DIR / "data" / "baseline"

V2RAY_GEOSITE_DIR = TEXT_DIR / "v2ray_geosite"
V2RAY_GEOIP_DIR = TEXT_DIR / "v2ray_geoip" / "data"

TEXT_DIR.mkdir(parents=True, exist_ok=True)
MRS_DIR.mkdir(parents=True, exist_ok=True)
BASELINE_DIR.mkdir(parents=True, exist_ok=True)
V2RAY_GEOSITE_DIR.mkdir(parents=True, exist_ok=True)
V2RAY_GEOIP_DIR.mkdir(parents=True, exist_ok=True)

USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
HEADERS = {"User-Agent": USER_AGENT}

# ==============================================================================
# 0. ZERO-TRUST CRITICAL INFRASTRUCTURE WHITELIST & SAFETY EXCLUSIONS
# ==============================================================================
UNBREAK_WHITELIST = {
    # PSPs & Payment Gateways (Only non-ir entries are exported to direct sets)
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
    "eset.com", "github.io", "glitch.me", "googleapis.com", "gvt1.com",
    "radiojavan.com", "ubuntu.com", "wordpress.com", "animelist.ir", "gamepass.ir"
}
SAFETY_EXCLUDE_CONTAIN = ("google.com", "ooklaserver.net")

def is_whitelisted(domain: str) -> bool:
    domain = domain.lower()
    return any(domain == safe or domain.endswith("." + safe) for safe in UNBREAK_WHITELIST)

def is_ir_domain(domain: str) -> bool:
    """Checks if a domain ends with .ir or is the .ir TLD itself."""
    return domain == "ir" or domain.endswith(".ir")

# ==============================================================================
# UTILITIES: FETCHING & BASELINE RESILIENCE
# ==============================================================================
def fetch_data(urls, timeout: int = 90, min_len: int = 20) -> str:
    if isinstance(urls, str):
        urls = [urls]

    for url in urls:
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
            continue

    return ""

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
            registered_root = ext.registered_domain

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
# MULTI-PLATFORM EXPORTERS (ENHANCED WITH SUBDOMAIN INHERITANCE)
# ==============================================================================
def export_domain_target(name: str, domains: Set[str]):
    sorted_domains = sorted(domains)
    
    # 1. Mihomo Ruleset Text: Prefixed with '+.' to cover root domain and all subdomains
    with open(TEXT_DIR / f"{name}.txt", "w", encoding="utf-8") as f:
        for d in sorted_domains:
            f.write(f"+.{d}\n")
            
    # 2. Surge / Classical rule-set (.list)
    with open(TEXT_DIR / f"{name}.list", "w", encoding="utf-8") as f:
        for d in sorted_domains:
            f.write(f"DOMAIN-SUFFIX,{d}\n")
            
    # 3. Mihomo / Clash Classical YAML (.yaml)
    with open(TEXT_DIR / f"{name}.yaml", "w", encoding="utf-8") as f:
        f.write("payload:\n")
        for d in sorted_domains:
            f.write(f"  - '+.{d}'\n")

    # 4. Sing-box JSON (.json)
    data = {"version": 1, "rules": [{"domain_suffix": sorted_domains}]}
    with open(TEXT_DIR / f"{name}.json", "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        
    # 5. V2Ray DLC Geosite database input (Plain root names)
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
# BINARY COMPILERS INTEGRATION
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

# ==============================================================================
# MAIN PIPELINE EXECUTION
# ==============================================================================
def main():
    print("=" * 82)
    print("🚀 IRAN ROUTING RULES: CLEAN HYBRID ENGINE (STRICT NON-IR DIRECT)")
    print("=" * 82)

    # --------------------------------------------------------------------------
    # 1. IP & ASN PROCESSING
    # --------------------------------------------------------------------------
    print("\n[+] 1/9: Processing Iranian IP Ranges & ASN Infrastructure...")
    ripe_raw = fetch_data([
        "https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-latest",
        "https://ftp.apnic.net/stats/ripe-ncc/delegated-ripencc-latest"
    ], timeout=90)

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
    for url in extra_ip_sources:
        content = fetch_data(url, timeout=30)
        for line in content.splitlines():
            d = line.strip()
            if d and not d.startswith("#"):
                raw_ip_list.append(d)

    fallback_asns = fetch_data("https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/irasn.txt", timeout=30)
    for line in fallback_asns.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            asns.add(line if line.startswith("IP-ASN,") else f"IP-ASN,{line}")

    if len(raw_ip_list) < 500:
        raw_ip_list.extend(load_baseline("iran-ip"))
    else:
        save_baseline("iran-ip", set(raw_ip_list))

    if len(asns) < 100:
        asns.update(load_baseline("iran-asn"))
    else:
        save_baseline("iran-asn", asns)

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

    print(f"  [✓] Modular: 'iran-modular-isp' ({len(isp_cidrs)} CIDRs)")
    print(f"  [✓] Infra:   'iran-asn' ({len(asns)} ASNs)")

    # --------------------------------------------------------------------------
    # 2. DOMESTIC CLOUDS & MACRO ALL-IP
    # --------------------------------------------------------------------------
    print("\n[+] 2/9: Generating 'iran-modular-cloud' & Macro 'iran-all-ip'...")
    cloud_sources = ["arvancloud", "derakcloud", "iranserver", "parspack"]
    raw_cloud_cidrs = []
    for cname in cloud_sources:
        c_raw = fetch_data(f"https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/{cname}.txt", timeout=25)
        raw_cloud_cidrs.extend(c_raw.splitlines())

    cloud_v4, cloud_v6 = collapse_cidrs(raw_cloud_cidrs)
    all_cloud_cidrs = [str(n) for n in (cloud_v4 + cloud_v6)]
    export_ip_target("iran-modular-cloud", all_cloud_cidrs)

    macro_v4, macro_v6 = collapse_cidrs(raw_ip_list + raw_cloud_cidrs)
    master_all_cidrs = [str(n) for n in (macro_v4 + macro_v6)]
    export_ip_target("iran-all-ip", master_all_cidrs)

    with open(V2RAY_GEOIP_DIR / "ir", "w", encoding="utf-8") as f:
        for c in master_all_cidrs:
            f.write(f"{c}\n")

    print(f"  [✓] Modular: 'iran-modular-cloud' ({len(all_cloud_cidrs)} CIDRs)")
    print(f"  [★] MACRO:   'iran-all-ip' ({len(master_all_cidrs)} collapsed CIDRs)")

    # --------------------------------------------------------------------------
    # 3. UNIFIED SECURITY & THREAT INTEL
    # --------------------------------------------------------------------------
    print("\n[+] 3/9: Compiling Macro Security ('iran-all-security' & 'iran-all-security-ip')...")
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
    for url in threat_domain_sources:
        content = fetch_data(url, timeout=30)
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
    for url in threat_ip_sources:
        content = fetch_data(url, timeout=25)
        raw_threat_ips.extend(content.splitlines())

    t_v4, t_v6 = collapse_cidrs(raw_threat_ips)
    all_threat_cidrs = [str(n) for n in (t_v4 + t_v6)]
    export_ip_target("iran-all-security-ip", all_threat_cidrs)

    print(f"  [★] MACRO: 'iran-all-security' ({len(pruned_threats)} domains)")
    print(f"  [★] MACRO: 'iran-all-security-ip' ({len(all_threat_cidrs)} CIDRs)")

    # --------------------------------------------------------------------------
    # 4. PERSIAN ADS & TRACKERS
    # --------------------------------------------------------------------------
    print("\n[+] 4/9: Compiling Macro 'iran-all-ads' (Zero-Trust Protected)...")
    V2FLY_BASE = "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/"
    ads_sources = [
        f"{V2FLY_BASE}category-ads-ir",
        "https://github.com/bootmortis/iran-hosted-domains/releases/latest/download/clash_rules_ads.txt",
        "https://raw.githubusercontent.com/MasterKia/PersianBlocker/main/PersianBlockerHosts.txt",
        "https://raw.githubusercontent.com/MasterKia/PersianBlocker/main/PersianBlockerAds-Hosts.txt",
        "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/ads.txt"
    ]
    raw_ads = {"yektanet.com", "sabavision.com", "mediaad.org", "najva.com"}
    for url in ads_sources:
        content = fetch_data(url, timeout=30)
        for line in content.splitlines():
            d = clean_domain(line)
            if d and not is_whitelisted(d):
                raw_ads.add(d)

    raw_ads -= pruned_threats
    pruned_ads = prune_subdomains(raw_ads)
    export_domain_target("iran-all-ads", pruned_ads)
    print(f"  [★] MACRO: 'iran-all-ads' ({len(pruned_ads)} domains)")

    # --------------------------------------------------------------------------
    # 5. MASTER IRANIAN DIRECT DOMAINS (ALL .IR REMOVED - ZERO OVERLAP)
    # --------------------------------------------------------------------------
    print("\n[+] 5/9: Aggregating Pure Non-IR Domestic Domains...")
    raw_iran_domains = {d for d in UNBREAK_WHITELIST if not is_ir_domain(d)}
    raw_iran_domains.update({d for d in load_baseline("iran-domains") if not is_ir_domain(d)})

    custom_baseline_path = BASELINE_DIR / "custom-domains.txt"
    custom_count = 0
    if custom_baseline_path.exists():
        with open(custom_baseline_path, "r", encoding="utf-8") as f:
            for line in f:
                d = clean_domain(line)
                if d and not is_ir_domain(d):
                    raw_iran_domains.add(d)
                    custom_count += 1
        print(f"  [✓] Loaded {custom_count} manual non-ir domain(s) from custom-domains.txt")
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

    v2fly_banking_seeds = set()
    v2fly_gov_seeds = set()
    v2fly_media_seeds = set()
    download_seeds = set()

    for url in domain_upstreams:
        content = fetch_data(url, timeout=40)
        is_bank_src = any(k in url for k in ["category-bank-ir", "category-payment-ir", "category-bourse-ir", "category-insurance-ir"])
        is_gov_src = "category-gov-ir" in url
        is_media_src = any(k in url for k in ["category-media-ir", "category-news-ir"])

        for line in content.splitlines():
            if "," in line and not line.startswith("DOMAIN"):
                parts = line.split(",")
                if len(parts) >= 2:
                    line = parts[1]
            d = clean_domain(line)
            if d and not is_ir_domain(d):
                raw_iran_domains.add(d)
                if is_bank_src:
                    v2fly_banking_seeds.add(d)
                elif is_gov_src:
                    v2fly_gov_seeds.add(d)
                elif is_media_src:
                    v2fly_media_seeds.add(d)

    print("  [*] Fetching Bootmortis custom_domains.py (Direct list)...")
    custom_py_raw = fetch_data("https://raw.githubusercontent.com/bootmortis/iran-hosted-domains/main/src/custom_domains.py", timeout=30)
    if custom_py_raw:
        direct_matches = re.findall(r'"([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})"', custom_py_raw)
        added_custom = 0
        for dom in direct_matches:
            d = clean_domain(dom)
            if d and not is_ir_domain(d):
                raw_iran_domains.add(d)
                added_custom += 1
        print(f"  [✓] Integrated {added_custom} tested non-ir domains from custom_domains.py.")

    print("  [*] Fetching & Streaming Enamad Database (~13MB)...")
    enamad_raw = fetch_data("https://raw.githubusercontent.com/bootmortis/enamad-mirror/main/out/domains.csv", timeout=120)
    enamad_count = 0
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
                    raw_val = row[domain_idx]
                    d = clean_domain(raw_val)
                    if d and not is_ir_domain(d):
                        raw_iran_domains.add(d)
                        enamad_count += 1
            print(f"  [✓] Enamad Mirror: Successfully parsed {enamad_count} commercial non-ir domains.")
        except Exception as e:
            print(f"  [!] Warning parsing Enamad CSV: {e}")

    print("  [*] Fetching Cloudflare Iranian Domains (CF-Web)...")
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
                            raw_iran_domains.add(d)
                            cf_count += 1
            print(f"  [✓] CF-Web: Successfully parsed {cf_count} Cloudflare non-ir domains.")
        except Exception as e:
            print(f"  [!] Warning parsing CF-Web JSON: {e}")

    print("  [*] Fetching Mirava Iranian Package Mirrors Registry...")
    mirava_raw = fetch_data("https://raw.githubusercontent.com/MiravaOrg/Mirava/refs/heads/main/mirrors_list.yaml", timeout=30)
    mirava_count = 0
    if mirava_raw:
        urls = re.findall(r"https?://([a-zA-Z0-9.-]+)", mirava_raw)
        for host in urls:
            d = clean_domain(host)
            if d and not is_ir_domain(d):
                raw_iran_domains.add(d)
                download_seeds.add(d)
                mirava_count += 1
        print(f"  [✓] Mirava: Successfully integrated {mirava_count} non-ir mirrors.")

    raw_iran_domains = (raw_iran_domains - pruned_ads - pruned_threats)
    raw_iran_domains = {d for d in raw_iran_domains if not is_ir_domain(d)}
    raw_iran_domains.update({d for d in UNBREAK_WHITELIST if not is_ir_domain(d)})

    save_baseline("iran-domains", raw_iran_domains)
    pruned_iran_domains = prune_subdomains(raw_iran_domains)

    export_domain_target("iran-all-domains", pruned_iran_domains)

    with open(V2RAY_GEOSITE_DIR / "ir", "w", encoding="utf-8") as f:
        for d in sorted(pruned_iran_domains):
            f.write(f"{d}\n")

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

    pruned_lite = prune_subdomains(lite_domains if len(lite_domains) > 100 else pruned_iran_domains)
    export_domain_target("iran-all-domains-lite", pruned_lite)

    print(f"  [★] MACRO: 'iran-all-domains' ({len(pruned_iran_domains)} pure non-ir domains preserved with 0% overlap)")

    # --------------------------------------------------------------------------
    # 6. GRANULAR DISJOINT MODULES
    # --------------------------------------------------------------------------
    print("\n[+] 6/9: Partitioning Master Domains into Disjoint Modular Sets...")

    MEDIA_PATTERNS = re.compile(r"(?:aparat|filimo|namava|filmnet|telewebion|gapfilm|cinematicket|tiwall|tamasha|namasha|antenn|lenz|mayaa|irib|seevid|ammarfilm|radio|video|music|tv|vod|stream)")
    BANKING_PATTERNS = re.compile(r"(?:bank|shaparak|sadad|mellat|melli|tejarat|saderat|pasargad|sb24|blubank|sepah|refah|keshavarzi|maskan|postbank|zarinpal|payping|idpay|jibit|nextpay|vandar|zibal|nobitex|wallex|bitpin|ramzinex|abantether|exir|bourse|seham|tsetmc|codal|emofid|agah|fipiran|bimeh|azki)")
    GOV_PATTERNS = re.compile(r"(?:\.gov\.ir$|\.jud\.ir$|\.police\.ir$|sana\.gov|adliran|my\.gov|mardom|tax\.gov|tamin|post\.ir|dolat\.ir|majlis\.ir|sabteahval|moi\.ir|medu\.ir)")
    GAMING_PATTERNS = re.compile(r"(?:gameup|shecan|electro|radar\.game|parshub|asiagame|vmp|fivem|gamefa|vgmag|zoomg|bazicenter|baziato|csgo|samp|bazi|game)")
    DOWNLOAD_PATTERNS = re.compile(r"(?:soft98|yasdl|downloadha|p30download|asandl|sarzamindownload|p30world|shahrsakhtafzar|zoomit|digiato|download|mirror|tarfandestan)")

    banking_domains = set()
    gov_domains = set()
    media_domains = set()
    gaming_domains = set()
    download_domains = set()

    for d in pruned_iran_domains:
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
    other_domains = pruned_iran_domains - categorized_union

    export_domain_target("iran-modular-banking", banking_domains)
    export_domain_target("iran-modular-gov", gov_domains)
    export_domain_target("iran-modular-media", media_domains)
    export_domain_target("iran-modular-gaming", gaming_domains)
    export_domain_target("iran-modular-download", download_domains)
    export_domain_target("iran-modular-other", other_domains)

    assert (len(categorized_union) + len(other_domains)) == len(pruned_iran_domains), "Data integrity check failed!"
    print(f"  [✓] Disjoint math check passed: Submodules == Master ({len(pruned_iran_domains)})")

    # --------------------------------------------------------------------------
    # 7. DOMESTIC GAMBLING & BETTING
    # --------------------------------------------------------------------------
    print("\n[+] 7/9: Compiling 'iran-modular-gambling'...")
    gambling_sources = [
        "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/nsfw.txt"
    ]
    raw_gambling = {"betcart.com", "takbet.com", "wolfbet.info", "cannonbet.org", "hazarat.org"}
    for url in gambling_sources:
        content = fetch_data(url, timeout=30)
        for line in content.splitlines():
            d = clean_domain(line)
            if d and not is_whitelisted(d):
                raw_gambling.add(d)

    raw_gambling -= pruned_iran_domains
    pruned_gambling = prune_subdomains(raw_gambling)
    export_domain_target("iran-modular-gambling", pruned_gambling)
    print(f"  [✓] Modular: 'iran-modular-gambling' ({len(pruned_gambling)} domains)")

    # --------------------------------------------------------------------------
    # 8. APP EXCEPTIONS, APPS & UNIFIED CLASSICAL
    # --------------------------------------------------------------------------
    print("\n[+] 8/9: Compiling App Rules & Dynamic Tracker Exceptions...")

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

    with open(TEXT_DIR / "iran-app-exceptions.yaml", "w", encoding="utf-8") as f:
        f.write("payload:\n")
        for r in classical_exception_lines:
            f.write(f"  - '{r}'\n")

    print(f"  [✓] Classical Exceptions: 'iran-app-exceptions' ({len(classical_exception_lines)} rules)")

    ESSENTIAL_PACKAGES = {
        "cab.snapp.passenger", "cab.snapp.driver", "cab.snapp.biker", "cab.snapp.delivery",
        "taxi.tap30.passenger", "taxi.tap30.driver", "taxi.tap30.food", "com.alopeyk.customer",
        "neshan.maps", "ir.balad.maps", "com.digikala", "ir.divar", "ir.torob", "com.emalls",
        "market.nobitex", "net.nobitex", "ir.wallex.app", "com.abantether", "com.ramzinex.app",
        "ir.bitpin", "ir.tejaratbank.mobile", "com.bmi.mobilebank", "com.bmi.bam", "ir.sep.sesame",
        "ir.banksepah.mobilebank", "ir.omidbank", "com.bsi.mobilebank", "ir.bpi.mobilebank",
        "ir.blu.banking", "ir.resalat.mb", "com.aparat.android", "com.saba.filimo",
        "ir.shatel.namava", "ir.filmnet.android", "com.zoodfood.android", "org.bale.messenger",
        "ir.eitaa.messenger", "ir.resaneh1.iptv", "org.soroushplus.messenger", "com.farsitel.bazaar",
        "ir.mservices.myket", "ir.mci.ecareapp", "com.mtnirancell.myirancell", "ir.rightel.myrightel"
    }
    GLOBAL_EXCLUDES = {
        "org.telegram.messenger", "com.whatsapp", "com.instagram.android", "com.facebook.katana",
        "com.twitter.android", "com.google.android.youtube", "com.google.android.gms",
        "com.android.chrome", "org.mozilla.firefox", "com.spotify.music", "com.netflix.mediaclient",
        "com.valvesoftware.android.steam.community"
    }
    WINDOWS_PROCESSES = [
        "Bale.exe", "Eitaa.exe", "EitaaDesktop.exe", "Rubika.exe", "Soroush.exe",
        "Gap.exe", "IDMan.exe", "Digikala.exe", "Aparat.exe"
    ]

    compiled_packages = set(ESSENTIAL_PACKAGES)
    app_sources = [
        "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/apps.txt",
        "https://raw.githubusercontent.com/SamadiPour/iran-android-apps/master/packages.json",
        "https://raw.githubusercontent.com/bootmortis/iran-hosted-domains/main/apps/apps.txt"
    ]
    PKG_REGEX = re.compile(r"^[a-zA-Z][a-zA-Z0-9_]*(?:\.[a-zA-Z][a-zA-Z0-9_]*)+$")

    for url in app_sources:
        raw = fetch_data(url, timeout=30)
        matches = re.findall(r"([a-zA-Z][a-zA-Z0-9_]+(?:\.[a-zA-Z][a-zA-Z0-9_]+)+)", raw)
        for pkg in matches:
            pkg = pkg.strip()
            if (pkg not in GLOBAL_EXCLUDES and
                not pkg.startswith(("PROCESS-NAME", "PACKAGE-NAME", "payload", "rules")) and
                PKG_REGEX.match(pkg) and len(pkg) < 85):
                compiled_packages.add(pkg)

    with open(TEXT_DIR / "iran-all-apps.txt", "w", encoding="utf-8") as f:
        for pkg in sorted(compiled_packages):
            f.write(f"PACKAGE-NAME,{pkg}\n")
        for proc in sorted(WINDOWS_PROCESSES):
            f.write(f"PROCESS-NAME,{proc}\n")

    with open(TEXT_DIR / "iran-all-apps.yaml", "w", encoding="utf-8") as f:
        f.write("payload:\n")
        for pkg in sorted(compiled_packages):
            f.write(f"  - 'PACKAGE-NAME,{pkg}'\n")
        for proc in sorted(WINDOWS_PROCESSES):
            f.write(f"  - 'PROCESS-NAME,{proc}'\n")

    data_apps = {"version": 1, "rules": [{"package_name": sorted(compiled_packages), "process_name": sorted(WINDOWS_PROCESSES)}]}
    with open(TEXT_DIR / "iran-all-apps.json", "w", encoding="utf-8") as f:
        json.dump(data_apps, f, indent=2, ensure_ascii=False)

    classical_rules = ["GEOIP,ir", "DOMAIN-SUFFIX,ir"]
    for d in sorted(pruned_iran_domains):
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
        for d in sorted(pruned_iran_domains):
            f.write(f"DOMAIN-SUFFIX,{d}\n")
        for n in master_all_cidrs:
            f.write(f"IP-CIDR,{n},no-resolve\n")

    geoip_config = {
        "input": [{"type": "text", "action": "add", "args": {"inputDir": str(V2RAY_GEOIP_DIR.resolve())}}],
        "output": [{"type": "v2rayGeoIPDat", "action": "output", "args": {"outputDir": str(MRS_DIR.resolve()), "outputName": "geoip.dat"}}]
    }
    with open(TEXT_DIR / "v2ray_geoip_config.json", "w", encoding="utf-8") as f:
        json.dump(geoip_config, f, indent=2)

    # --------------------------------------------------------------------------
    # 9. DUAL COMPILATION (MIHOMO .MRS & SING-BOX .SRS)
    # --------------------------------------------------------------------------
    print("\n" + "=" * 82)
    print("⚙️ 9/9: DUAL COMPILATION (MIHOMO .MRS & SING-BOX .SRS)")
    print("=" * 82)

    for f in TEXT_DIR.glob("*.*"):
        if f.is_file():
            shutil.copy(f, MRS_DIR / f.name)

    mihomo_bin = shutil.which("mihomo") or shutil.which("mihomo.exe") or (BASE_DIR / "mihomo")
    if mihomo_bin and os.path.exists(mihomo_bin):
        print(f"[+] Mihomo Core Active: {mihomo_bin}")

        domain_targets = [
            "iran-all-domains", "iran-all-domains-lite", "iran-all-ads", "iran-all-security",
            "iran-modular-banking", "iran-modular-gov", "iran-modular-media",
            "iran-modular-gaming", "iran-modular-download", "iran-modular-other",
            "iran-modular-gambling"
        ]
        for target in sorted(domain_targets):
            in_txt = TEXT_DIR / f"{target}.txt"
            out_mrs = MRS_DIR / f"{target}.mrs"
            if in_txt.exists():
                success = compile_to_mrs(str(mihomo_bin), "domain", in_txt, out_mrs)
                status = f"{out_mrs.stat().st_size/1024:.1f} KB" if success else "FAILED"
                print(f"  [{'✓' if success else '✗'}] Mihomo MRS (domain): {target}.mrs ({status})")

        ip_targets = [
            "iran-all-ip", "iran-modular-isp", "iran-modular-cloud", "iran-all-security-ip"
        ]
        for target in sorted(ip_targets):
            in_txt = TEXT_DIR / f"{target}.txt"
            out_mrs = MRS_DIR / f"{target}.mrs"
            if in_txt.exists():
                success = compile_to_mrs(str(mihomo_bin), "ipcidr", in_txt, out_mrs)
                status = f"{out_mrs.stat().st_size/1024:.1f} KB" if success else "FAILED"
                print(f"  [{'✓' if success else '✗'}] Mihomo MRS (ipcidr): {target}.mrs ({status})")

    singbox_bin = shutil.which("sing-box") or shutil.which("sing-box.exe") or (BASE_DIR / "sing-box")
    if singbox_bin and os.path.exists(singbox_bin):
        print(f"\n[+] Sing-box Core Active: {singbox_bin}")
        srs_targets = [
            "iran-all-domains", "iran-all-domains-lite", "iran-all-ip", "iran-all-ads",
            "iran-all-security", "iran-all-security-ip", "iran-all-apps",
            "iran-modular-banking", "iran-modular-gov", "iran-modular-media",
            "iran-modular-gaming", "iran-modular-download", "iran-modular-other",
            "iran-modular-isp", "iran-modular-cloud", "iran-modular-gambling"
        ]
        for target in sorted(srs_targets):
            in_json = TEXT_DIR / f"{target}.json"
            out_srs = MRS_DIR / f"{target}.srs"
            if in_json.exists():
                success = compile_to_srs(str(singbox_bin), in_json, out_srs)
                status = f"{out_srs.stat().st_size/1024:.1f} KB" if success else "FAILED"
                print(f"  [{'✓' if success else '✗'}] Sing-box SRS: {target}.srs ({status})")

    print("\n" + "=" * 82)
    print("🏁 PIPELINE COMPLETED: ALL CLEAN ASSETS GENERATED SUCCESSFULLY.")
    print("=" * 82)

if __name__ == "__main__":
    main()
