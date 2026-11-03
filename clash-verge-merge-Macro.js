// ==============================================================================
// 0. USER CONTROL PANEL (Macro Architecture)
// ==============================================================================

const ENABLE_SAFE_SEARCH = false;       // [Optional] Enforce SafeSearch
const ENABLE_QUIC_BLOCK = true;         // [Recommended] Force TCP fallback to prevent UDP censorship throttling

// Available Tiers: "light" | "normal" | "pro" | "proplus" | "ultimate"
const HAGEZI_TIER = "proplus";

// --- GLOBAL CONTENT & THREAT INTELLIGENCE (Macro Bundles) ---
const ENABLE_HAGEZI_SECURITY_ALL = true; // [Macro] Merges TIF-Mini, Fake, Badware & DynDNS into 1 file
const ENABLE_HAGEZI_SECURITY_IP = true;  // [Macro] Merges TIF-IP & DoH Bypass IPs into 1 file
const ENABLE_HAGEZI_CONTENT_ALL = true;  // [Macro] Merges Adult (NSFW), Gambling & Popups into 1 file

// --- ANTI-PIRACY & COPYRIGHT (Kept Standalone to Prevent Breaking Downloads/Torrents) ---
const ENABLE_ANTI_PIRACY = false;        // [Optional | Standalone] Blocks torrent trackers & warez portals

// --- NATIVE OEM & APP TRACKERS (Device Specific - Lightweight 2KB to 4KB each) ---
// Enable ONLY the brands you or your network devices actually use to prevent RAM bloat:
const ENABLE_TRACKER_SAMSUNG = false;    // Samsung OneUI telemetry
const ENABLE_TRACKER_MICROSOFT = true;   // Windows diagnostic & Cortana telemetry
const ENABLE_TRACKER_XIAOMI = false;     // Xiaomi & HyperOS tracking
const ENABLE_TRACKER_APPLE = false;      // Apple telemetry (Keep false if using iCloud Relay)
const ENABLE_TRACKER_HUAWEI = false;     // Huawei telemetry
const ENABLE_TRACKER_BBK = false;        // Oppo / Realme / Vivo tracking
const ENABLE_TRACKER_AMAZON = false;     // Amazon Echo & FireTV tracking
const ENABLE_TRACKER_LG = false;         // LG Smart TV (webOS) analytics
const ENABLE_TRACKER_ROKU = false;       // Roku streaming media tracking
const ENABLE_TRACKER_TIKTOK = true;      // TikTok analytics & tracker telemetry
const ENABLE_TRACKER_TIKTOK_EXT = false; // Aggressive TikTok tracking (May break app feed)

// Optional Master Switch (If running on a router with dozens of diverse guest devices):
const ENABLE_TRACKER_ALL_OEM = false;    // [Macro] Downloads HageziNativeAll (Not recommended for single phones)

// --- IRAN CORE SUITE (Macro All-In-One) ---
const ENABLE_IRAN_DIRECT = true;         // Master Switch for Domestic Direct Routing
const ENABLE_IRAN_SECURITY = true;       // Iran Phishing, Fake Gateways & Threat IPs
const ENABLE_IRAN_ADS = true;            // Iran Ads & Trackers

const SECURITY_INTERVAL = 36 * 3600;     // 36 Hours update interval for macro threat feeds
const STANDARD_INTERVAL = 72 * 3600;     // 72 Hours update interval for general content & tracker rules

// ==============================================================================
// 1. DATASETS & STATIC ASSETS (PRE-LOADED IN ENGINE MEMORY)
// ==============================================================================

const IRAN_RULES_BASE_URL = "https://github.com/Erfan4700/iran-routing-rules/releases/download/latest/";
const HAGEZI_RAW_URL = "https://github.com/Erfan4700/HaGeZi_BlockLists_Compiled_format/releases/download/latest/";

const HAGEZI_TIERS_MAP = Object.freeze({
  light: "HageziLight",
  normal: "HageziNormal",
  pro: "HageziPro",
  proplus: "HageziProPlus",
  ultimate: "HageziUltimate"
});

const SELECTED_HAGEZI_NAME = HAGEZI_TIERS_MAP[HAGEZI_TIER.toLowerCase()] ?? "HageziProPlus";

// Static Compiled Regular Expressions (Compiled once at script load to prevent CPU re-compilation)
const JUNK_RULES_REGEX = /(?:GEOIP|GEOSITE|RULE-SET),[^,\n]*(?<![a-z0-9])(?:CN|CHINA|RU|RUSSIA)(?![a-z0-9])/i;
const PROXY_KEYWORD_REGEX = /proxy|auto|select|default|fallback|internet|traffic|manual|nodes|نهایی|اینترنت|دستی|انتخاب|🚀|⚡|♻️/i;
const INFO_NODE_REGEX = /(?:مشخصات|باقی\s*مانده|مصرف|حجم|trial|expire|traffic|volume)/i;

const EMERGENCY_MANUAL_DOMAINS = Object.freeze([
  // "custom-local-bank.com",
  // "my-internal-service.ir"
]);

const FROZEN_HOSTS = Object.freeze({
  "forcesafesearch.google.com": "216.239.38.120",
  "www.google.com": "216.239.38.120",
  "google.com": "216.239.38.120",
  "strict.bing.com": "204.79.197.220",
  "www.bing.com": "204.79.197.220",
  "bing.com": "204.79.197.220"
});

const PURE_DOMESTIC_RESOLVERS = Object.freeze([
  "193.186.32.32",
  "217.218.127.127",
  "217.218.155.155"
]);

const UNPOISONED_PROXY_RESOLVERS = Object.freeze([
  "https://223.5.5.5/dns-query",
  "223.5.5.5",
  "119.29.29.29",
  "193.186.32.32"
]);

const HYBRID_BOOTSTRAP_RESOLVERS = Object.freeze([
  "223.5.5.5",
  "119.29.29.29",
  "193.186.32.32"
]);

const DOH_ENDPOINTS = Object.freeze([
  "https://1.1.1.1/dns-query",
  "https://8.8.8.8/dns-query",
  "https://9.9.9.9/dns-query"
]);

// ==============================================================================
// 2. HELPER FUNCTIONS
// ==============================================================================

const makeProvider = (name, behavior, format, url, interval) => ({
  type: "http",
  behavior,
  format,
  url,
  path: `./ruleset/${name}.${format === "mrs" ? "mrs" : format === "yaml" ? "yaml" : "txt"}`,
  interval
});

function resolvePrimaryProxyGroup(groups) {
  if (!Array.isArray(groups) || groups.length === 0) return "PROXIES";

  let matchedSelectGroup = null;
  let fallbackAutoGroup = null;

  for (let i = 0, len = groups.length; i < len; i++) {
    const group = groups[i];
    if (!group) continue;
    const { type, name } = group;

    if (name.toLowerCase() === "reject" || name.toLowerCase().indexOf("direct") !== -1) continue;

    const isMatch = PROXY_KEYWORD_REGEX.test(name);
    if (type === "select" && isMatch) return name;
    if (!matchedSelectGroup && isMatch) matchedSelectGroup = name;
    if (!fallbackAutoGroup && (type === "url-test" || type === "fallback" || type === "load-balance")) {
      fallbackAutoGroup = name;
    }
  }

  return matchedSelectGroup ?? fallbackAutoGroup ?? groups[0]?.name ?? "PROXIES";
}

// Fast string checker for IP rules (Replaces heavy Go Regex engine checks)
function formatUserIpRule(rule) {
  if (rule.indexOf("no-resolve") !== -1) return rule;
  const upper = rule.slice(0, 9).toUpperCase();
  if (
    upper.startsWith("GEOIP,") || upper.startsWith("IP-ASN,") ||
    upper.startsWith("IP-CIDR,") || upper.startsWith("IP-CIDR6,")
  ) {
    return rule + ",no-resolve";
  }
  return rule;
}

// ==============================================================================
// 3. ZERO-COST COMPILATION (MACRO ARCHITECTURE PRE-BUILT AT LOAD TIME)
// ==============================================================================
// Note: Constructing macro objects here outside of main() guarantees near-zero RAM
// allocations and eliminates GC pauses inside the runtime parsing execution.

const BASE_RULE_PROVIDERS = Object.create(null);
const STATIC_RULES_STAGE1 = []; // Local networks, QUIC, Macro Security, Content, Trackers, Ads
const STATIC_RULES_STAGE2 = []; // Domestic whitelist & Iran Macro direct rules

const BASE_SNIFFER_SKIP_DOMAINS = [
  "Mijia Cloud", "+.push.apple.com", "+.apple.com",
  "+.lan", "+.local", "+.home.arpa", "+.ir"
];

const BASE_FAKE_IP_FILTER = [
  "+.ir", "+.lan", "+.local", "+.home.arpa",
  "captive.apple.com", "+.connectivitycheck.gstatic.com",
  "detectportal.firefox.com", "+.msftconnecttest.com", "+.msftncsi.com",
  "time.apple.com", "time.google.com", "time.windows.com", "time.nist.gov",
  "+.pool.ntp.org", "+.ntp.org",
  "+.steamcontent.com", "+.battlenet.com", "+.battle.net", "+.ea.com",
  "stun.*", "*.stun.*", "supl.google.com", "+.supl.google.com",
  "location.services.mozilla.com"
];

const BASE_NS_POLICY = Object.create(null);
BASE_NS_POLICY["+.ir"] = PURE_DOMESTIC_RESOLVERS;
BASE_NS_POLICY["supl.google.com"] = PURE_DOMESTIC_RESOLVERS;
BASE_NS_POLICY["+.supl.google.com"] = PURE_DOMESTIC_RESOLVERS;

for (let i = 0; i < EMERGENCY_MANUAL_DOMAINS.length; i++) {
  const d = EMERGENCY_MANUAL_DOMAINS[i];
  BASE_SNIFFER_SKIP_DOMAINS.push(`+.${d}`);
  BASE_FAKE_IP_FILTER.push(`+.${d}`);
  BASE_NS_POLICY[`+.${d}`] = PURE_DOMESTIC_RESOLVERS;
}

// ------------------------------------------------------------------------------
// Compile Pre-Waze Static Pipeline (Stage 1)
// ------------------------------------------------------------------------------

// 1. Local Network & Private IP Bypass
STATIC_RULES_STAGE1.push(
  "GEOIP,private,DIRECT,no-resolve",
  "DST-PORT,7275,DIRECT",
  "DST-PORT,6881-6889,DIRECT",
  "DST-PORT,51413,DIRECT"
);

// 2. High-Priority QUIC Blocking
if (ENABLE_QUIC_BLOCK) {
  STATIC_RULES_STAGE1.push("AND,((NETWORK,UDP),(DST-PORT,443)),REJECT");
}

function compileFeed(cond, id, behavior, format, url, interval, action, noResolve) {
  if (!cond) return;
  BASE_RULE_PROVIDERS[id] = makeProvider(id, behavior, format, url, interval);
  if (action) {
    STATIC_RULES_STAGE1.push(`RULE-SET,${id},${action}${noResolve ? ",no-resolve" : ""}`);
  }
}

// 3. Global & Domestic Security (Threat Intelligence Bundles)
compileFeed(ENABLE_HAGEZI_SECURITY_ALL, "hagezi-security-all", "domain", "mrs", `${HAGEZI_RAW_URL}HageziSecurityAll.mrs`, SECURITY_INTERVAL, "REJECT", false);
compileFeed(ENABLE_HAGEZI_SECURITY_IP, "hagezi-security-ip", "ipcidr", "mrs", `${HAGEZI_RAW_URL}HageziSecurityIP.mrs`, SECURITY_INTERVAL, "REJECT", true);
compileFeed(ENABLE_IRAN_SECURITY, "iran-all-security", "domain", "mrs", `${IRAN_RULES_BASE_URL}iran-all-security.mrs`, SECURITY_INTERVAL, "REJECT", false);
compileFeed(ENABLE_IRAN_SECURITY, "iran-all-security-ip", "ipcidr", "mrs", `${IRAN_RULES_BASE_URL}iran-all-security-ip.mrs`, SECURITY_INTERVAL, "REJECT", true);

// 4. Content Filtering (NSFW / Gambling / Popups Macro Bundle)
compileFeed(ENABLE_HAGEZI_CONTENT_ALL, "hagezi-content-all", "domain", "mrs", `${HAGEZI_RAW_URL}HageziContentAll.mrs`, STANDARD_INTERVAL, "REJECT", false);

// 5. Standalone Anti-Piracy (Never merged into Content to protect downloads)
compileFeed(ENABLE_ANTI_PIRACY, "hagezi-antipiracy", "domain", "mrs", `${HAGEZI_RAW_URL}HageziAntiPiracy.mrs`, STANDARD_INTERVAL, "REJECT", false);

// 6. Special App Exceptions (Evaluated before general adblocking)
if (ENABLE_IRAN_DIRECT) {
  compileFeed(true, "iran-app-exceptions", "classical", "text", `${IRAN_RULES_BASE_URL}iran-app-exceptions.txt`, STANDARD_INTERVAL, "DIRECT", false);
}

// 7. Base Adblocking & Telemetry
compileFeed(true, "hagezi-main", "domain", "mrs", `${HAGEZI_RAW_URL}${SELECTED_HAGEZI_NAME}.mrs`, STANDARD_INTERVAL, "REJECT", false);
compileFeed(ENABLE_IRAN_ADS, "iran-all-ads", "domain", "mrs", `${IRAN_RULES_BASE_URL}iran-all-ads.mrs`, STANDARD_INTERVAL, "REJECT", false);

// 8. Native OEM Trackers Routing (Macro vs Granular)
if (ENABLE_TRACKER_ALL_OEM) {
  compileFeed(true, "hagezi-native-all", "domain", "mrs", `${HAGEZI_RAW_URL}HageziNativeAll.mrs`, STANDARD_INTERVAL, "REJECT", false);
} else {
  compileFeed(ENABLE_TRACKER_SAMSUNG, "hagezi-native-samsung", "domain", "mrs", `${HAGEZI_RAW_URL}HageziNativeSamsung.mrs`, STANDARD_INTERVAL, "REJECT", false);
  compileFeed(ENABLE_TRACKER_MICROSOFT, "hagezi-native-microsoft", "domain", "mrs", `${HAGEZI_RAW_URL}HageziNativeMicrosoft.mrs`, STANDARD_INTERVAL, "REJECT", false);
  compileFeed(ENABLE_TRACKER_TIKTOK, "hagezi-native-tiktok", "domain", "mrs", `${HAGEZI_RAW_URL}HageziNativeTikTok.mrs`, STANDARD_INTERVAL, "REJECT", false);
  compileFeed(ENABLE_TRACKER_XIAOMI, "hagezi-native-xiaomi", "domain", "mrs", `${HAGEZI_RAW_URL}HageziNativeXiaomi.mrs`, STANDARD_INTERVAL, "REJECT", false);
  compileFeed(ENABLE_TRACKER_APPLE, "hagezi-native-apple", "domain", "mrs", `${HAGEZI_RAW_URL}HageziNativeApple.mrs`, STANDARD_INTERVAL, "REJECT", false);
  compileFeed(ENABLE_TRACKER_HUAWEI, "hagezi-native-huawei", "domain", "mrs", `${HAGEZI_RAW_URL}HageziNativeHuawei.mrs`, STANDARD_INTERVAL, "REJECT", false);
  compileFeed(ENABLE_TRACKER_BBK, "hagezi-native-oppo-realme", "domain", "mrs", `${HAGEZI_RAW_URL}HageziNativeOppoRealme.mrs`, STANDARD_INTERVAL, "REJECT", false);
  compileFeed(ENABLE_TRACKER_AMAZON, "hagezi-native-amazon", "domain", "mrs", `${HAGEZI_RAW_URL}HageziNativeAmazon.mrs`, STANDARD_INTERVAL, "REJECT", false);
  compileFeed(ENABLE_TRACKER_LG, "hagezi-native-lg", "domain", "mrs", `${HAGEZI_RAW_URL}HageziNativeLGWebOS.mrs`, STANDARD_INTERVAL, "REJECT", false);
  compileFeed(ENABLE_TRACKER_ROKU, "hagezi-native-roku", "domain", "mrs", `${HAGEZI_RAW_URL}HageziNativeRoku.mrs`, STANDARD_INTERVAL, "REJECT", false);
  compileFeed(ENABLE_TRACKER_TIKTOK_EXT, "hagezi-native-tiktok-ext", "domain", "mrs", `${HAGEZI_RAW_URL}HageziNativeTikTokExtended.mrs`, STANDARD_INTERVAL, "REJECT", false);
}

// ------------------------------------------------------------------------------
// Compile Post-Waze Domestic Whitelist Pipeline (Stage 2)
// ------------------------------------------------------------------------------

// 9. Manual Zero-Delay Domestic Whitelist
for (let i = 0; i < EMERGENCY_MANUAL_DOMAINS.length; i++) {
  STATIC_RULES_STAGE2.push(`DOMAIN-SUFFIX,${EMERGENCY_MANUAL_DOMAINS[i]},DIRECT`);
}
STATIC_RULES_STAGE2.push("DOMAIN-SUFFIX,ir,DIRECT");

// 10. Iran Macro Direct Routing
if (ENABLE_IRAN_DIRECT) {
  const iranAllTag = "rule-set:iran-all-domains";
  BASE_SNIFFER_SKIP_DOMAINS.push(iranAllTag);
  BASE_FAKE_IP_FILTER.splice(1, 0, iranAllTag);
  BASE_NS_POLICY[iranAllTag] = PURE_DOMESTIC_RESOLVERS;

  BASE_RULE_PROVIDERS["iran-all-apps"] = makeProvider("iran-all-apps", "classical", "text", `${IRAN_RULES_BASE_URL}iran-all-apps.txt`, STANDARD_INTERVAL);
  BASE_RULE_PROVIDERS["iran-all-domains"] = makeProvider("iran-all-domains", "domain", "mrs", `${IRAN_RULES_BASE_URL}iran-all-domains.mrs`, STANDARD_INTERVAL);
  BASE_RULE_PROVIDERS["iran-all-ip"] = makeProvider("iran-all-ip", "ipcidr", "mrs", `${IRAN_RULES_BASE_URL}iran-all-ip.mrs`, STANDARD_INTERVAL);
  BASE_RULE_PROVIDERS["iran-asn"] = makeProvider("iran-asn", "classical", "text", `${IRAN_RULES_BASE_URL}iran-asn.txt`, STANDARD_INTERVAL);

  STATIC_RULES_STAGE2.push(
    "RULE-SET,iran-all-apps,DIRECT,no-resolve",
    "RULE-SET,iran-all-domains,DIRECT",
    "RULE-SET,iran-all-ip,DIRECT,no-resolve",
    "RULE-SET,iran-asn,DIRECT,no-resolve"
  );
}

// Pre-create the Set of base rules for O(1) deduplication against user rules
const PRECOMPILED_BASE_RULES_SET = new Set([...STATIC_RULES_STAGE1, ...STATIC_RULES_STAGE2]);

// ==============================================================================
// 4. MAIN RUNTIME PIPELINE (BLAZING-FAST EXECUTION)
// ==============================================================================

function main(config, profileName) {
  // --------------------------------------------------------------------------
  // [FIX 1]: Single-Pass Proxy Normalization (Strip info nodes, cast ports & extract names)
  // --------------------------------------------------------------------------
  let validProxyNames = null;

  if (Array.isArray(config.proxies)) {
    const raw = config.proxies;
    const filtered = [];
    const names = [];

    for (let i = 0, len = raw.length; i < len; i++) {
      const p = raw[i];
      // Filter out non-functional metadata/informational nodes (traffic balance, expiry, etc.)
      if (!p || !p.name || INFO_NODE_REGEX.test(p.name)) continue;

      // Robust port validation: convert string to integer and ensure a valid port range
      const port = +p.port;
      if (port > 0 && port <= 65535) p.port = port;

      if (p.tls || p["reality-opts"] || p.type === "vless" || p.type === "trojan" || p.type === "hysteria2") {
        p["client-fingerprint"] ??= "chrome";
      }

      filtered.push(p);
      names.push(p.name);
    }
    config.proxies = filtered;
    validProxyNames = names;
  }

  // --------------------------------------------------------------------------
  // [FIX 2]: Auto-generate Proxy Groups if the profile input is empty or raw
  // --------------------------------------------------------------------------
  if (!validProxyNames || validProxyNames.length === 0) {
    validProxyNames = ["DIRECT"];
  }

  if (!Array.isArray(config["proxy-groups"]) || config["proxy-groups"].length === 0) {
    config["proxy-groups"] = [
      {
        name: "PROXIES",
        type: "select",
        proxies: ["AUTO", ...validProxyNames]
      },
      {
        name: "AUTO",
        type: "url-test",
        url: "http://www.gstatic.com/generate_204",
        interval: 300,
        tolerance: 50,
        proxies: [...validProxyNames]
      }
    ];
  } else if (config["proxy-groups"][0]?.proxies?.length === 0) {
    // If the group exists but contains no proxies, link all validated nodes
    config["proxy-groups"][0].proxies = validProxyNames;
  }

  const defaultProxyGroup = resolvePrimaryProxyGroup(config["proxy-groups"]);

  // Core System Kernel Settings
  config["tcp-concurrent"] = true;
  config["unified-delay"] = true;
  config["find-process-mode"] = "strict";

  delete config["global-client-fingerprint"];

  config["geodata-mode"] = false;
  config["geo-auto-update"] = false;

  config["keep-alive-idle"] = 600;
  config["keep-alive-interval"] = 15;

  (config.experimental ??= {})["quic-go-disable-ecn"] = true;

  const profile = (config.profile ??= {});
  profile["store-fake-ip"] = true;
  profile["store-selected"] = true;

  // --------------------------------------------------------------------------
  // [FIX 3]: Zero-Allocation Sniffer Configuration (Prevent Iran Handshake Latency)
  // --------------------------------------------------------------------------
  config.sniffer = {
    enable: true,
    "force-dns-mapping": true,
    "parse-pure-ip": true,
    "override-destination": false,
    sniff: {
      TLS: { ports: [443, 8443, 2053, 2083, 2087, 2096] },
      HTTP: { ports: [80, 8080, 8880] }
    },
    "skip-dst-address": [
      "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
      "224.0.0.0/4", "255.255.255.255/32"
    ],
    "skip-domain": BASE_SNIFFER_SKIP_DOMAINS
  };

  if (ENABLE_SAFE_SEARCH) {
    config.hosts = Object.assign(config.hosts ?? {}, FROZEN_HOSTS);
  }

  // --------------------------------------------------------------------------
  // [FIX 4]: DNS Architecture & Dynamic Nameserver Policy Mapping
  // --------------------------------------------------------------------------
  const dns = (config.dns ??= {});
  dns.enable = true;
  dns["enhanced-mode"] = "fake-ip";
  dns["fake-ip-range"] = "198.18.0.1/16";
  dns["cache-algorithm"] = "arc";
  dns["cache-size"] = 4096;
  dns["respect-rules"] = false;
  dns["direct-nameserver-follow-policy"] = true;
  dns["use-system-hosts"] = true;
  dns["use-hosts"] = true;
  dns.ipv6 = false;
  dns["prefer-h3"] = false;

  dns["default-nameserver"] = HYBRID_BOOTSTRAP_RESOLVERS;
  dns["proxy-server-nameserver"] = UNPOISONED_PROXY_RESOLVERS;
  dns["direct-nameserver"] = PURE_DOMESTIC_RESOLVERS;
  dns["fake-ip-filter"] = BASE_FAKE_IP_FILTER;

  dns.nameserver = DOH_ENDPOINTS.map(url => `${url}#${defaultProxyGroup}`);

  // Guaranteed immunity for domestic Iranian resolvers using clean Spread syntax
  dns["nameserver-policy"] = { ...dns["nameserver-policy"], ...BASE_NS_POLICY };

  // Merge Rule Providers (Instant clone of pre-compiled dictionary)
  config["rule-providers"] = Object.assign({}, BASE_RULE_PROVIDERS, config["rule-providers"]);

  // --------------------------------------------------------------------------
  // [FIX 5]: Rapid User Rules Sanitization & Zero-Copy Concatenation
  // --------------------------------------------------------------------------
  let capturedMatchRule = null;
  const userSanitizedRules = [];
  const seenRules = new Set(PRECOMPILED_BASE_RULES_SET);

  seenRules.add(`DOMAIN-SUFFIX,waze.com,${defaultProxyGroup}`);
  seenRules.add(`DOMAIN-KEYWORD,waze,${defaultProxyGroup}`);

  const rawRules = config.rules;
  if (Array.isArray(rawRules)) {
    for (let i = 0, len = rawRules.length; i < len; i++) {
      const rule = rawRules[i];
      if (typeof rule !== "string") continue;
      const clean = rule.trim();
      if (!clean || JUNK_RULES_REGEX.test(clean)) continue;

      if (clean.slice(0, 5).toUpperCase() === "MATCH") {
        if (!capturedMatchRule && clean.toLowerCase().indexOf("direct") === -1) {
          capturedMatchRule = clean;
        }
        continue;
      }

      const formatted = formatUserIpRule(clean);
      if (!seenRules.has(formatted)) {
        seenRules.add(formatted);
        userSanitizedRules.push(formatted);
      }
    }
  }

  // Final Assembly (Pre-built Static Stages + Special Overrides + Cleaned User Rules + Fallback)
  config.rules = [
    ...STATIC_RULES_STAGE1,
    `DOMAIN-SUFFIX,waze.com,${defaultProxyGroup}`,
    `DOMAIN-KEYWORD,waze,${defaultProxyGroup}`,
    ...STATIC_RULES_STAGE2,
    ...userSanitizedRules,
    capturedMatchRule ?? `MATCH,${defaultProxyGroup}`
  ];

  return config;
}
