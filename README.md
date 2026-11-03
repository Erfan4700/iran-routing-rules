<div align="center">

# 🇮🇷 Iran Universal Routing & Cyber Defense Suite
### Enterprise Automated Multi-Platform RuleSets & Clean Profile Processors for Mihomo, Sing-box, V2Ray/Xray & Surge

[![Automated Build Pipeline](https://img.shields.io/github/actions/workflow/status/Erfan4700/iran-routing-rules/build-iran.yml?branch=main&label=Build%20Pipeline&style=flat-square&logo=github-actions&logoColor=white)](https://github.com/Erfan4700/iran-routing-rules/actions)
[![Direct Release](https://img.shields.io/badge/Release-GitHub%20Direct%20(Zero--Cache)-blue?style=flat-square&logo=github&logoColor=white)](https://github.com/Erfan4700/iran-routing-rules/releases/latest)
[![Edge CDN Active](https://img.shields.io/badge/CDN-jsDelivr%20Purged-orange?style=flat-square&logo=jsdelivr&logoColor=white)](https://fastly.jsdelivr.net/gh/Erfan4700/iran-routing-rules@release/)
[![Engine Architecture](https://img.shields.io/badge/Architecture-Strict%20Non--IR%20Direct-blueviolet?style=flat-square&logo=checkmarx&logoColor=white)](#-the-strict-non-ir-direct-architecture)
[![Coverage](https://img.shields.io/badge/Coverage-Enamad%20%7C%20CF--Web%20%7C%20Mirava%20%7C%20TCI-success?style=flat-square&logo=internet-explorer&logoColor=white)](#-telemetry-sources--upstream-feeds)
[![HaGeZi Integrated](https://img.shields.io/badge/Threat%20Intel-HaGeZi%20MRS%20Native-purple?style=flat-square&logo=adguard&logoColor=white)](https://github.com/Erfan4700/HaGeZi_BlockLists_mrs_format)
[![Security Specs](https://img.shields.io/badge/Security-Phishing%20%7C%20AdBlock%20%7C%20Zero--Trust-emerald?style=flat-square&logo=shield&logoColor=white)](#-cyber-threat-mitigation--whitelist-integrity)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)](LICENSE)

An industrial-grade routing engine and cyber defense framework compiled natively into optimized binary and classical text rule-sets across **Mihomo (`.mrs`)**, **Sing-box (`.srs`)**, **V2Ray/Xray (`.dat`)**, and **Surge/Shadowrocket (`.list`)**. Powered by **Strict Non-IR Direct supernetting**, mathematical zero-overlap disjoint sets, Mozilla PSL root pruning, dynamic ride-hailing app exceptions, and automated ingestion of the **Enamad database**, **Cloudflare Iranian Web registry (CF-Web)**, **Mirava Linux Mirrors**, and **Telecommunication Company of Iran (TCI ADSL)** feeds.

[Architecture](#-the-strict-non-ir-direct-architecture) • [Merge Scripts](#-clash-verge-merge-scripts-javascript-runtime) • [Catalog & Endpoints](#-ruleset-catalog--distribution-endpoints) • [Client Setup](#-client--platform-integration) • [Telemetry Sources](#-telemetry-sources--upstream-feeds) • [راهنمای جامع فارسی](#-راهنمای-جامع-به-زبان-فارسی)

</div>

---

## 🌐 Multi-Platform Client Matrix

This repository acts as an authoritative, single source of truth, compiling unified network telemetry into native runtime formats:

| Platform / Client Application | Target Core Engine | Native Binary Rule-Set | Classical / Text Source |
| :--- | :--- | :---: | :---: |
| **Clash Verge Rev, Mihomo Party, FlClash** | Mihomo | **`.mrs`** (Radix Tree) | `.txt` / `.yaml` |
| **Hiddify, NekoBox, Karing, Box4Proxy** | Sing-box Core (v1.8+) | **`.srs`** (Compiled Protobuf) | `.json` (Headless Rule-Set) |
| **Marzban, 3X-UI, v2rayN, v2rayNG, V2Box** | Xray-core / V2Fly Core | **`geosite.dat` / `geoip.dat` / `iran.dat`** | — |
| **Shadowrocket, Surge, Loon, Stash, Egern** | Surge Rule Engine | — | **`.list`** |

---

## 📐 The Strict Non-IR Direct Architecture

### Why Regular `.ir` Domains Are Excluded From Direct Rulesets:
In modern routing setups (Clash, Mihomo, Sing-box), all ordinary domestic `.ir` websites are covered with a single, ultra-lightweight rule:
```text
DOMAIN-SUFFIX,ir,DIRECT
```
Including tens of thousands of individual `.ir` domain entries in direct rulesets creates 100% redundant memory bloat. Therefore, this engine enforces a **Strict Non-IR Direct Paradigm**:

1. **Direct Sets (`iran-all-domains` & Modular Sets):** Contain **purely non-`.ir` domestic domains** (`.com`, `.net`, `.org`, `.io`, `.shop`, etc.) sourced from Enamad, CF-Web, Mirava, and TCI.
2. **Threat & Ad Sets (`iran-all-ads`, `iran-all-security`, `iran-modular-gambling`):** **Strictly retain domestic `.ir` threats**. Since security and adblock rules evaluate *before* the general `DOMAIN-SUFFIX,ir,DIRECT` rule, malicious or advertising `.ir` domains are intercepted and rejected (`REJECT`) before they can reach the direct rule!

```text
┌────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                  1. MACRO SUITE (Comprehensive All-In-One)                             │
├────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ • Designed for maximum speed, simplicity, and zero-configuration domestic bypass.                      │
│ • iran-all-domains       : Pure non-.ir Iranian commercial, tech, and cloud domains (+Enamad, CF-Web). │
│ • iran-all-domains-lite  : Curated set of high-traffic non-.ir domestic platforms.                     │
│ • iran-all-ip            : Full aggregated RIPE IPv4/IPv6 country delegations (Supernetted).           │
│ • iran-all-ads           : Unified domestic banner, SDK, and tracker blocking feed (Contains .ir ads). │
│ • iran-all-security      : Domestic phishing, banking trojans, and smishing portals (Contains .ir).    │
│ • iran-all-apps          : Native Android package names and desktop process names.                     │
│ • iran-app-exceptions    : Dedicated classical ruleset allowing domestic app analytics (Metrix, etc.). │
└────────────────────────────────────────────────────────────────────────────────────────────────────────┘

                                                   VS

┌────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                              2. MODULAR SUITE (Zero-Overlap Disjoint Routing)                          │
├────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ • Designed for precision traffic control, granular policy routing, and zero memory redundancy.         │
│ • iran-modular-banking   : Non-.ir banking portals, Shaparak infrastructure, bourse, & crypto.         │
│ • iran-modular-gov       : Non-.ir state portals, municipal, and judicial endpoints.                   │
│ • iran-modular-media     : Non-.ir VOD platforms, Aparat, Filimo, Telewebion, and broadcasters.        │
│ • iran-modular-gaming    : Domestic game matchmaking, Radar Game subnets, and low-latency servers.     │
│ • iran-modular-download  : Non-.ir software mirrors, Soft98, and Mirava Iranian Linux mirrors.         │
│ • iran-modular-cloud     : Domestic cloud datacenters (ArvanCloud, Derak, ParsPack) IP-CIDRs.          │
│ • iran-modular-isp       : Direct domestic ISP infrastructure subnets (MCI, Irancell, Shatel, etc.).   │
│ • iran-modular-gambling  : Domestic online casinos, betting networks, and illegal payment scripts.     │
│ • iran-modular-other     : The mathematical remainder set (+100k Enamad shops, Startups, CF-Web).      │
└────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

### The Disjoint Mathematical Guarantee:
All ruleset layers enforce strict mathematical disjointness:
$$\text{Security} > \text{Ads} > \text{Direct}$$
$$\text{Ads} = \text{Ads} \setminus \text{Security}$$
$$\text{Direct} = (\text{Direct} \setminus \text{Ads} \setminus \text{Security}) \setminus \{ \text{all } .ir \text{ domains} \}$$
$$\text{banking} \cap \text{gov} \cap \text{media} \cap \text{gaming} \cap \text{download} \cap \text{other} = \emptyset$$

> **Zero Leakage & Zero Redundancy:** Direct sets contain 0% ads, 0% security threats, and 0% ordinary `.ir` domains, eliminating radix tree bloat while providing 100% defense coverage.

---

## ⚡ Clash Verge Merge Scripts (JavaScript Runtime)

This repository includes **three specialized production-hardened JavaScript merge processors** in the root directory for **Clash Verge Rev**, **Mihomo Party**, and **FlClash**. All scripts feature native integration with the **[HaGeZi_BlockLists_Compiled_format](https://github.com/Erfan4700/HaGeZi_BlockLists_Compiled_format)**, automated domestic DNS policy injection, zero-latency domestic white-listing, and UDP/QUIC leak suppression.

```text
├── clash-verge-merge-Macro.js       # [Ultra-Light] Full Macro: Iran Macro + HaGeZi Macro Bundles (Lowest RAM/CPU)
├── clash-verge-merge-IranMacro.js   # [Hybrid] Macro Iran (iran-all-*) + Granular Modular HaGeZi Lists
└── clash-verge-merge-modular.js     # [Full Granular] Per-category toggles for Iran (Banking, Media, Gov, etc.)
```

### Key Architectural Upgrades in Runtime Processors:
* **Sniffer Bypass for Domestic Rulesets:** TLS/HTTP sniffing is automatically bypassed for all domestic Iranian domains (`rule-set:iran-all-domains` or modular equivalents). This completely eliminates TLS handshake latency and prevents 403 Forbidden / Cloudflare Captcha loops on Iranian websites.
* **Dual Routing Alignment:** Handled via sequential rule execution:
  * First, `iran-all-security` and `iran-all-ads` intercept threats (including `.ir`).
  * Next, `DOMAIN-SUFFIX,ir,DIRECT` bypasses all `.ir` traffic in a single line.
  * Finally, `iran-all-domains` bypasses all verified non-`.ir` domestic domains.
* **Emergency Slot (`EMERGENCY_MANUAL_DOMAINS`):** A dedicated, zero-delay array at the top of the scripts allowing users to unblock any newly launched domestic domain immediately without waiting for pipeline builds.
* **Decoupled Tracker Routing (`iran-app-exceptions`):** Analytics endpoints utilized by essential domestic transport services (Metrix SDK used by Snapp, Tapsi, SnappFood) are dynamically routed via clean classical rulesets, eliminating ride-hailing crashes when domestic adblockers are active.

---

## 🛡️ Cyber Threat Mitigation & Whitelist Integrity

* **Targeted Threat Elimination (`iran-all-security` & `iran-all-security-ip`):** Intercepts cloned phishing portals mimicking judiciary services (`sana` / `adliran`), fraudulent subsidy pages, card-to-card traps, and malicious C2 IPs.
* **Adblock Isolation (`category-ads-ir` & `clash_rules_ads.txt`):** Domestic ad networks from V2Fly Community and Bootmortis are strictly routed to `iran-all-ads` (`REJECT`) and isolated from bypass datasets.
* **Safety Exclusions (No Broken Rules):** Excludes broken domains, overseas proxies (`animelist.ir`, `gamepass.ir`), speedtest nodes (`ooklaserver.net`), international CDNs (`github.io`, `wordpress.com`, `googleapis.com`, `ubuntu.com`, `eset.com`), and IDN/Punycode (`xn--`) from direct routing.
* **Cloudflare Anycast IP Safety Isolation:** From the `CF-Web` database, **only validated domain names are extracted**. Cloudflare Anycast IP addresses (`104.21.x.x`, `172.67.x.x`) are discarded, ensuring global internet CDN routing remains unpolluted.
* **Deterministic Financial Protection (`UNBREAK_WHITELIST`):** Enforces an immutable exemption layer during Python compilation (`build.py`) for central payment infrastructure (`*.shaparak.ir`), all licensed Payment Service Providers (Behpardakht, Sadad, Asan Pardakht, Saman Kish, Parsian, ZarinPal, etc.), core Iranian banks, crypto platforms (Nobitex, Wallex), and critical SMS notification endpoints (`kavenegar.com`, `ghasedak.me`).

---

## 🔄 Resilience & User Customization (`data/baseline/`)

To prevent build failures, cache corruption, or upstream network disruptions during GitHub Actions execution, the build pipeline incorporates a **Golden Baseline Resilience Database (`data/baseline/`)**:
* **Automated Fallback:** If an upstream source fails or returns insufficient entries, the pipeline automatically falls back to verified local baseline snapshots (`load_baseline`).
* **Manual Additions (`custom-domains.txt`):** Users can manually add unindexed, private, or local enterprise domains to `data/baseline/custom-domains.txt`.
  - Non-`.ir` domains added to this file are automatically deduplicated, pruned against Mozilla PSL, and categorized into both Macro and Modular rulesets.
  - The file is **never overwritten** by automated snapshot bots.
  - Committing to `custom-domains.txt` triggers an automatic, immediate release build via GitHub Actions.

---

## 📦 Ruleset Catalog & Distribution Endpoints

All release assets are rebuilt automatically twice daily (03:00 and 15:00 UTC) or upon manual push via parallelized compilation and distributed via both zero-cache GitHub direct links and purged jsDelivr edge mirrors:

* **Direct GitHub Releases URL (Recommended - Real-time & Zero Cache Lag):**  
  `https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/`
* **Edge CDN URL (Failover):**  
  `https://fastly.jsdelivr.net/gh/Erfan4700/iran-routing-rules@release/`

### 1. Macro Datasets (All-In-One Suite)
| Ruleset Identifier | Scope / Content | Action | Supported Formats |
| :--- | :--- | :---: | :---: |
| **`iran-all-domains`** | Pure non-`.ir` Iranian domains (Enamad, CF-Web, V2Fly, TCI) | `DIRECT` | [mrs](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-domains.mrs) \| [srs](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-domains.srs) \| [txt](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-domains.txt) \| [json](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-domains.json) \| [list](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-domains.list) |
| **`iran-all-domains-lite`** | Essential high-traffic non-`.ir` domestic domains | `DIRECT` | [mrs](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-domains-lite.mrs) \| [srs](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-domains-lite.srs) \| [txt](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-domains-lite.txt) \| [json](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-domains-lite.json) \| [list](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-domains-lite.list) |
| **`iran-all-ip`** | Full supernetted RIPE IPv4/IPv6 subnets | `DIRECT` | [mrs](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-ip.mrs) \| [srs](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-ip.srs) \| [txt](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-ip.txt) \| [json](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-ip.json) \| [list](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-ip.list) |
| **`iran-all-ads`** | Domestic ad servers, SDKs, and trackers (Contains `.ir`) | `REJECT` | [mrs](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-ads.mrs) \| [srs](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-ads.srs) \| [txt](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-ads.txt) \| [json](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-ads.json) \| [list](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-ads.list) |
| **`iran-all-security`** | Phishing portals, fake banks, and malware (Contains `.ir`) | `REJECT` | [mrs](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-security.mrs) \| [srs](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-security.srs) \| [txt](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-security.txt) \| [json](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-security.json) \| [list](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-security.list) |
| **`iran-all-security-ip`**| Malicious IP addresses, C2 nodes, and bots | `REJECT` | [mrs](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-security-ip.mrs) \| [srs](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-security-ip.srs) \| [txt](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-security-ip.txt) \| [json](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-security-ip.json) \| [list](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-security-ip.list) |
| **`iran-app-exceptions`** | Tracker exceptions for Snapp/Tapsi/Metrix | `DIRECT` | [txt](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-app-exceptions.txt) \| [yaml](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-app-exceptions.yaml) |
| **`iran-all-apps`** | Android package IDs & Windows processes | `DIRECT` | [srs](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-apps.srs) \| [txt](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-apps.txt) \| [yaml](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-apps.yaml) \| [json](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-apps.json) |
| **`iran-asn`** | Autonomous System Numbers of Iranian ISPs | `DIRECT` | [txt](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-asn.txt) \| [yaml](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-asn.yaml) |
| **`iran-unified`** | Single classical master file for legacy clients | `DIRECT` | [txt](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-unified.txt) \| [yaml](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-unified.yaml) \| [list](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-unified.list) |

### 2. Modular Datasets (Zero-Overlap Granular Suite)
| Ruleset Identifier | Specific Scope | Action | Supported Formats |
| :--- | :--- | :---: | :---: |
| **`iran-modular-banking`** | Non-`.ir` banks, Shaparak gateways, crypto, bourse, insurance | `DIRECT` | [mrs](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-banking.mrs) \| [srs](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-banking.srs) \| [txt](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-banking.txt) \| [json](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-banking.json) \| [list](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-banking.list) |
| **`iran-modular-gov`** | Non-`.ir` state portals, Sana, judiciary, tax services | `DIRECT` | [mrs](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-gov.mrs) \| [srs](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-gov.srs) \| [txt](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-gov.txt) \| [json](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-gov.json) \| [list](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-gov.list) |
| **`iran-modular-media`** | Non-`.ir` VOD, streaming platforms, Aparat, Filimo, news | `DIRECT` | [mrs](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-media.mrs) \| [srs](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-media.srs) \| [txt](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-media.txt) \| [json](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-media.json) \| [list](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-media.list) |
| **`iran-modular-gaming`** | Domestic game matchmaking & Radar Game | `DIRECT` | [mrs](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-gaming.mrs) \| [srs](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-gaming.srs) \| [txt](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-gaming.txt) \| [json](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-gaming.json) \| [list](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-gaming.list) |
| **`iran-modular-download`** | Non-`.ir` software mirrors, ISOs, Soft98, and Mirava mirrors | `DIRECT` | [mrs](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-download.mrs) \| [srs](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-download.srs) \| [txt](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-download.txt) \| [json](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-download.json) \| [list](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-download.list) |
| **`iran-modular-cloud`** | National cloud CIDRs (Arvan, Derak, ParsPack) | `DIRECT` | [mrs](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-cloud.mrs) \| [srs](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-cloud.srs) \| [txt](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-cloud.txt) \| [json](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-cloud.json) \| [list](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-cloud.list) |
| **`iran-modular-isp`** | Supernetted ISP allocations (IP-CIDR) | `DIRECT` | [mrs](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-isp.mrs) \| [srs](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-isp.srs) \| [txt](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-isp.txt) \| [json](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-isp.json) \| [list](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-isp.list) |
| **`iran-modular-gambling`** | Online gambling portals & betting scripts (Contains `.ir`) | `REJECT` | [mrs](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-gambling.mrs) \| [srs](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-gambling.srs) \| [txt](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-gambling.txt) \| [json](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-gambling.json) \| [list](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-gambling.list) |
| **`iran-modular-other`** | Remainder set (Enamad shops, Startups, CF-Web, TCI) | `DIRECT` | [mrs](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-other.mrs) \| [srs](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-other.srs) \| [txt](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-other.txt) \| [json](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-other.json) \| [list](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-other.list) |

### 3. Unified V2Ray / Xray Protobuf Datasets
* **`geosite.dat`**: Full tags (`geosite:iran-all-domains`, `geosite:iran-modular-banking`, `geosite:iran-modular-gov`, `geosite:iran-modular-media`, `geosite:iran-modular-gaming`, `geosite:iran-modular-download`, `geosite:iran-modular-other`, `geosite:iran-all-ads`, `geosite:iran-all-security`, `geosite:iran-modular-gambling`, `geosite:ir`) ➔ [Download geosite.dat](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/geosite.dat)
* **`geoip.dat`**: Country tags (`geoip:ir`, `geoip:iran-modular-cloud`, `geoip:iran-modular-isp`, `geoip:iran-all-security-ip`) ➔ [Download geoip.dat](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/geoip.dat)
* **`iran.dat`**: Drop-in unified replacement for Marzban and traditional Xray server deployments ➔ [Download iran.dat](https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran.dat)

---

## 🚀 Client & Platform Integration

### 1. Mihomo / Clash Meta (`config.yaml`) - Production Ready Setup

```yaml
rule-providers:
  iran-app-exceptions:
    type: http
    behavior: classical
    format: text
    url: "https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-app-exceptions.txt"
    path: ./ruleset/iran-app-exceptions.txt
    interval: 172800

  iran-all-security:
    type: http
    behavior: domain
    format: mrs
    url: "https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-security.mrs"
    path: ./ruleset/iran-all-security.mrs
    interval: 86400

  iran-all-ads:
    type: http
    behavior: domain
    format: mrs
    url: "https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-ads.mrs"
    path: ./ruleset/iran-all-ads.mrs
    interval: 172800

  iran-modular-banking:
    type: http
    behavior: domain
    format: mrs
    url: "https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-banking.mrs"
    path: ./ruleset/iran-modular-banking.mrs
    interval: 172800

  iran-modular-other:
    type: http
    behavior: domain
    format: mrs
    url: "https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-modular-other.mrs"
    path: ./ruleset/iran-modular-other.mrs
    interval: 172800

  iran-all-ip:
    type: http
    behavior: ipcidr
    format: mrs
    url: "https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-ip.mrs"
    path: ./ruleset/iran-all-ip.mrs
    interval: 172800

rules:
  - GEOIP,private,DIRECT,no-resolve
  - AND,((NETWORK,UDP),(DST-PORT,443)),REJECT
  - RULE-SET,iran-app-exceptions,DIRECT
  - RULE-SET,iran-all-security,REJECT
  - RULE-SET,iran-all-ads,REJECT
  - DOMAIN-SUFFIX,ir,DIRECT
  - RULE-SET,iran-modular-banking,DIRECT
  - RULE-SET,iran-modular-other,DIRECT
  - RULE-SET,iran-all-ip,DIRECT,no-resolve
  - MATCH,PROXY
```

---

### 2. Sing-box Core (`config.json`)

```json
{
  "route": {
    "rule_set": [
      {
        "tag": "iran-all-ads",
        "type": "remote",
        "format": "binary",
        "url": "https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-ads.srs",
        "download_detour": "direct"
      },
      {
        "tag": "iran-all-security",
        "type": "remote",
        "format": "binary",
        "url": "https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-security.srs",
        "download_detour": "direct"
      },
      {
        "tag": "iran-all-domains",
        "type": "remote",
        "format": "binary",
        "url": "https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-domains.srs",
        "download_detour": "direct"
      },
      {
        "tag": "iran-all-ip",
        "type": "remote",
        "format": "binary",
        "url": "https://github.com/Erfan4700/iran-routing-rules/releases/latest/download/iran-all-ip.srs",
        "download_detour": "direct"
      }
    ],
    "rules": [
      { "rule_set": "iran-all-ads", "outbound": "block" },
      { "rule_set": "iran-all-security", "outbound": "block" },
      { "domain_suffix": [".ir"], "outbound": "direct" },
      { "rule_set": "iran-all-domains", "outbound": "direct" },
      { "rule_set": "iran-all-ip", "outbound": "direct" }
    ]
  }
}
```

---

### 3. V2Ray / Xray / Marzban Outbound Server Routing

```json
{
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      {
        "type": "field",
        "outboundTag": "blocked",
        "domain": [
          "ext:iran.dat:iran-all-ads",
          "ext:iran.dat:iran-all-security",
          "ext:iran.dat:iran-modular-gambling"
        ]
      },
      {
        "type": "field",
        "outboundTag": "blocked",
        "domain": [
          "regexp:.*\\.ir$",
          "ext:iran.dat:iran-all-domains"
        ],
        "ip": [
          "geoip:ir"
        ]
      }
    ]
  }
}
```

---

## 📡 Telemetry Sources & Upstream Feeds

The automated pipeline (`build.py`) aggregates telemetry from authorized registries and vetted sources:

### 1. Commercial & E-Commerce Registries (Enamad):
* **Official Enamad Mirror Database:** `@bootmortis/enamad-mirror` (`domains.csv` ~13MB) – Over 100,000 verified commercial Iranian platforms, sanitized to extract strictly non-`.ir` domains.

### 2. Cloudflare-Fronted Domestic Infrastructure:
* **CF-Web Registry:** `@hossein-mohseni/CF-Web` (`domains.json`) – Domestic Iranian websites utilizing Cloudflare edge proxies (non-`.ir` extracted; Cloudflare Anycast IPs discarded).

### 3. Linux & Developer Mirrors (Mirava):
* **Mirava Registry:** `@MiravaOrg/Mirava` (`mirrors_list.yaml`) – Verified domestic mirrors for Ubuntu, Debian, Arch, PyPI, NPM, and Docker in Iran, routed directly to `iran-modular-download`.

### 4. Telecommunication Company of Iran (TCI):
* **ADSL TCI Subsidized Database:** `@bootmortis/iran-hosted-domains` (`src/data/adsl_tci.txt`) – Official half-price intranet portal dataset (all `.ir` removed, non-`.ir` retained).

### 5. Bootmortis Curated Datasets:
* **Bootmortis Release Feeds:** `@bootmortis/iran-hosted-domains`
  - `clash_rules_other.txt`: Non-`.ir` domestic direct services.
  - `clash_rules_ads.txt`: Iranian ads & telemetry services.
  - `src/custom_domains.py`: Tested non-`.ir` direct list + exclusions.
  *(Note: Redundant and generic `domains.txt` and raw TLD files are deliberately omitted to avoid ad leaks and radix bloat).*

### 6. V2Fly Community Categorization:
* **V2Fly Domain Community Feeds:** `@v2fly/domain-list-community` (15 direct categories: `category-bank-ir`, `category-gov-ir`, `category-media-ir`, `category-news-ir`, `category-tech-ir`, `category-bourse-ir`, `category-payment-ir`, `category-shopping-ir`, `category-scholar-ir`, `category-insurance-ir`, etc. + `category-ads-ir` strictly isolated into `iran-all-ads`).

### 7. Official IP & ASN Allocations:
* **RIPE NCC Delegated Statistics:** `ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-latest`.
* **APNIC Mirror Delegation:** `ftp.apnic.net/stats/ripe-ncc/delegated-ripencc-latest`.
* **Domestic Datacenters:** `ygbkm/resources` (`ipv4.txt` & `ipv6.txt`).
* **Meta Rules Datasets:** `MetaCubeX/meta-rules-dat`.
* **Chocolate4U Routing Feeds:** `Chocolate4U/Iran-clash-rules` (`ircidr.txt` & `irasn.txt`).

### 8. Cloud Datacenters:
* Subnets for ArvanCloud (`arvancloud.txt`), Derak (`derakcloud.txt`), Iranserver (`iranserver.txt`), and ParsPack (`parspack.txt`).

### 9. Domestic & Government Domains:
* **Information Technology Organization (ITO):** `@bootmortis/ito-gov-mirror` (`domains.csv`).
* **Domestic Heuristics:** `@ygbkm/clash-rules-iran`.

### 10. Security, Phishing, & Adblocking:
* **PersianBlocker Feeds:** `@MasterKia/PersianBlocker` (`PersianBlockerHosts.txt`, `PersianBlockerAds-Hosts.txt`, `PersianBlockerPhishing.txt`, `PersianBlockerGambling.txt`).
* **Global Phishing Filters:** `@curbengh/phishing-filter`.
* **Threat Intelligence Sets:** `Chocolate4U` (`phishing.txt`, `malware.txt`, `phishing-ip.txt`, `malware-ip.txt`).

### 11. Applications & Processes:
* **Iranian Android Packages:** `@SamadiPour/iran-android-apps` (`packages.json`).
* **Desktop Windows Binaries:** Curated list (`Bale.exe`, `Eitaa.exe`, `Rubika.exe`, `Soroush.exe`, `IDMan.exe`, etc.).

---

## 🇮🇷 راهنمای جامع به زبان فارسی

<details>
<summary><b>برای مطالعه نکات تخصصی، چرایی حذف دامنه‌های ir. از دایرکت و نحوه استفاده کلیک کنید</b></summary>
<br>

### چرا تمام دامنه‌های عادی `.ir` از لیست‌های دایرکت حذف شدند؟
در تنظیمات کلاینت‌های مدرن (کلش، سینگ‌باکس، نکوباکس و...) قانونی به نام `DOMAIN-SUFFIX,ir,DIRECT` وجود دارد. این قانون ساده با مصرف **تنها ۱ سطر حافظه در رم**، تمام دامنه‌های منتهی به `.ir` در کل کشور را دایرکت می‌کند.  
اگر ما صدها هزار دامنه `.ir` را خط‌به‌خط در فایل‌های دایرکت نگه می‌داشتیم، تنها باعث اشغال ده‌ها مگابایت رم اضافه و کندی سیستم می‌شد.  
به همین دلیل:
* **در رول‌ست‌های دایرکت (`iran-all-domains` و ماژول‌ها):** دامنه‌های منتهی به `.ir` کاملاً حذف شده‌اند تا فایل‌ها منحصراً شامل دامنه‌های باارزش غیر `.ir` (مانند `.com`، `.net`، `.org` اینماد و کلودفلر) باشند.
* **در رول‌ست‌های تبلیغات و امنیت (`iran-all-ads` و `iran-all-security`):** دامنه‌های مخرب و تبلیغاتی `.ir` (مانند یکتانت، تپسل یا درگاه‌های فیشینگ) **با دقت حفظ شده‌اند**؛ چرا که این قوانین در کلاینت *قبل* از قانون دایرکت `.ir` اجرا می‌شوند تا تبلیغات و تهدیدات در همان ابتدا مسدود (`REJECT`) گردند.

### چه وب‌سایت‌هایی در رول‌ست‌های دایرکت جدید قرار دارند؟
تمامی وب‌سایت‌ها و پلتفرم‌های ایرانی که دامنه غیر `.ir` دارند از مراجع زیر گردآوری و خالص‌سازی شده‌اند:
* پایگاه عظیم **اینماد (Enamad Mirror با حجم ۱۳ مگابایت)** شامل ده‌ها هزار فروشگاه، صرافی و خدمات آنلاین با دامنه بین‌المللی.
* دیتابیس **CF-Web** شامل سایت‌های ایرانی میزبانی‌شده روی کلودفلر (بدون آی‌پی‌های Anycast).
* پایگاه تخصصی **Mirava** شامل تمامی سرورهای آینه‌ی لینوکس، پایتون (PyPI) و داکر در ایران برای دانلود با حداکثر سرعت.
* سامانه پورتال‌های نیم‌بهای **مخابرات ایران (TCI ADSL)**.

### نحوه افزودن دامنه اختصاصی کاربر (`data/baseline/custom-domains.txt`)
اگر دامنه شرکتی، سازمانی یا نوپایی دارید که هنوز در لیست‌ها نیست:
1. وارد مسیر `data/baseline/` در مخزن گیت‌هاب خود شوید.
2. فایل `custom-domains.txt` را باز کرده و دامنه‌ها را خط‌به‌خط وارد کنید.
3. با زدن دکمه Commit، گیت‌هاب اکشن به‌صورت خودکار اجرا شده، دامنه‌ها را پالایش و کامپایل کرده و نسخه جدید را ریلیز می‌کند. ربات‌های آپدیت روزانه هرگز محتوای این فایل را دستکاری نخواهند کرد.

### چرا اسنیفر (Sniffer) برای دامنه‌های ایران غیرفعال است؟
اسنیفر با باز کردن هدر پکت‌های TLS برای حدس زدن دامنه، بار پردازشی زیادی ایجاد می‌کند. اسکریپت‌های مرج این پروژه با تنظیم هوشمند `skip-domain`، بار اسنیفر را برای ترافیک ایران به صفر می‌رسانند تا لود سایت‌ها با کمترین تأخیر انجام شود و مشکل ارور ۴۰۳ و کپچای کلودفلر رفع گردد.

### راهنمای انتخاب بین ۳ اسکریپت Merge موجود در مخزن:
1. **`clash-verge-merge-Macro.js` (پیشنهادی برای موبایل):**  
   سبک‌ترین حالت ممکن؛ هم ترافیک ایران و هم پکیج‌های هاگزی را به‌صورت ماکروهای تجمیعی لود می‌کند تا مصرف رم به حداقل برسد.
2. **`clash-verge-merge-IranMacro.js` (پیشنهادی برای مصرف عمومی کامپیوتر):**  
   ترافیک ایران به‌صورت ماکرو و دایرکت یکپارچه است، اما سوییچ‌های امنیتی و محتوایی هاگزی ماژولار و قابل انتخاب هستند.
3. **`clash-verge-merge-modular.js` (پیشرفته‌ترین حالت برای کامپیوتر):**  
   تمامی دسته‌بندی‌های ایران (بانک، رسانه، دولت، بازی، ابر، دانلود و سایر) دارای کلیدهای مستقل روشن/خاموش در کنترل‌پنل هستند.

### چرا تپسی، اسنپ و اسنپ‌فود با ادبلاکرها به مشکل نمی‌خورند؟
بسیاری از اپلیکیشن‌های تاکسی و غذا از ترکر `metrix.ir` استفاده می‌کنند. رول‌ست **`iran-app-exceptions`** قبل از قوانین ادبلاکر لود می‌شود و بررسی می‌کند که اگر پکت از سمت اپلیکیشن‌های رسمی نظیر `cab.snapp.passenger` ارسال شد، مستقیماً عبور کند (`DIRECT`) و بقیه ترافیک‌های تبلیغاتی مسدود بمانند.

### نحوه استفاده از اسکریپت‌های ادغام در Clash Verge Rev
1. وارد نرم‌افزار **Clash Verge Rev** شوید.
2. به بخش **Profiles** رفته و روی پروفایل اشتراک فعال خود راست‌کلیک کرده و گزینه **Edit Rules** یا **Merge Scripts** را باز کنید.
3. کد یکی از فایل‌های اسکریپت بالا را کپی کرده و در تب مربوطه جای‌گذاری کنید.
4. تغییرات را ذخیره نموده و پروفایل را فعال کنید.

</details>

---

## 📄 License

This repository is licensed under the **[MIT License](LICENSE)**. Network routing telemetry and domain datasets remain under the intellectual rights of their respective official registries and maintainers.
