import { SocksProxyAgent } from "socks-proxy-agent";
import { HttpsProxyAgent } from "https-proxy-agent";
import fetch from "node-fetch";
import type { Agent } from "node:https";

// ═══════════════════════════════════════════════════
// PROXY LISTS
// ═══════════════════════════════════════════════════
const SOCKS4_PROXIES = [
  "123.231.230.58:31196",
  "43.163.219.10:20000",
  "76.81.6.107:31008",
  "20.57.138.93:1080",
  "138.124.114.113:1080",
  "40.90.195.218:1080",
  "186.190.228.83:4153",
  "50.63.12.101:45801",
  "129.226.152.29:20000",
  "190.144.224.182:44550",
  "134.199.159.23:1080",
  "45.187.76.2:3629",
  "193.233.254.77:1080",
  "185.178.185.100:1080",
  "191.102.82.83:4153",
  "115.69.210.60:1080",
  "36.95.189.165:5678",
  "91.247.250.215:4145",
  "213.165.58.5:1080",
  "181.129.182.138:5678",
  "149.62.186.244:1080",
  "177.85.65.177:4153",
  "95.178.108.189:5678",
  "178.215.163.218:4145",
  "64.227.131.240:1080",
  "41.223.234.116:37259",
  "64.227.76.27:1080",
  "74.179.84.102:1080",
  "194.186.213.206:1080",
  "46.8.104.176:1080",
  "37.238.168.253:5678",
  "213.210.67.186:3629",
  "109.232.106.150:52435",
  "58.235.170.51:5678",
  "181.48.243.194:4153",
  "190.220.25.42:4153",
  "27.147.153.34:10888",
  "144.124.227.90:21074",
  "83.143.24.29:5678",
  "45.87.43.113:1080",
];

const SOCKS5_PROXIES = [
  "138.2.47.198:1080",
  "103.84.95.54:7890",
  "5.75.202.83:10000",
  "212.58.132.5:1080",
  "147.45.240.36:1080",
  "64.227.131.240:1080",
  "66.42.59.155:443",
  "5.42.103.183:1080",
  "206.123.156.220:34007",
  "129.150.55.165:1080",
  "154.94.238.147:50161",
  "206.123.156.188:4364",
  "124.248.177.44:1080",
  "47.243.75.202:58854",
  "154.64.235.206:58367",
  "195.19.50.114:1080",
  "20.64.246.197:1080",
  "206.123.156.208:5180",
  "206.123.156.215:5867",
  "195.19.50.2:1080",
  "195.19.48.233:1080",
  "206.123.156.242:4215",
  "64.227.76.27:1080",
  "121.169.46.116:1090",
  "173.249.5.133:1080",
  "195.19.48.226:1080",
  "123.58.219.171:10808",
  "206.123.156.193:4982",
  "85.208.108.43:2094",
  "194.163.167.32:1080",
  "95.80.103.217:1080",
  "212.33.248.45:1080",
  "206.123.156.193:8349",
  "175.194.61.56:1080",
  "206.123.156.185:4793",
  "206.123.156.202:6492",
  "108.165.20.16:5555",
  "206.123.156.222:4160",
  "206.123.156.196:5626",
  "213.165.58.8:1080",
  "20.120.246.129:1080",
  "206.123.156.208:5237",
  "104.219.236.127:1080",
  "213.165.58.6:1080",
  "195.19.49.8:1080",
  "213.165.58.5:1080",
  "5.255.117.250:1080",
  "206.123.156.221:4017",
  "206.123.156.200:6236",
  "5.255.117.127:1080",
  "5.255.113.177:1080",
];

const HTTP_PROXIES = [
  "43.99.54.236:5555",
  "167.103.115.102:8800",
  "113.160.132.26:8080",
  "147.161.210.140:8800",
  "167.103.34.108:8800",
  "16.78.119.130:443",
  "167.103.31.122:8800",
  "167.103.144.127:8800",
  "35.225.22.61:80",
  "103.123.64.234:3128",
  "193.233.22.29:10808",
  "45.167.124.52:8080",
  "180.250.219.58:53281",
  "116.80.49.159:3172",
  "119.93.87.65:8080",
  "27.147.245.189:7735",
  "103.125.174.151:1111",
  "101.47.73.135:3128",
  "78.186.117.18:1953",
  "181.41.201.85:3128",
  "185.118.51.230:3128",
  "103.166.48.73:57413",
  "167.172.77.49:8080",
  "119.18.147.81:20326",
  "14.225.240.23:8562",
  "154.127.219.242:999",
  "182.53.202.208:8080",
  "64.227.76.27:1080",
  "115.248.66.131:3129",
  "121.126.185.63:25152",
  "103.30.31.202:20326",
  "8.219.97.248:80",
  "116.80.96.103:3172",
  "45.12.151.226:2829",
  "62.113.119.14:8080",
  "116.80.65.76:3172",
  "95.213.217.168:52004",
  "208.87.243.199:7878",
  "34.101.184.164:3128",
  "147.75.34.105:443",
  "195.123.213.129:1080",
  "200.174.198.32:8888",
  "5.104.87.17:8051",
  "170.80.95.10:11211",
  "116.80.65.78:3172",
  "103.3.246.71:3128",
  "212.253.14.173:1953",
  "173.212.246.157:3128",
  "190.121.136.185:999",
  "180.190.202.141:8082",
  "116.80.96.107:3172",
  "116.80.65.80:3172",
  "116.80.49.162:3172",
  "116.80.48.38:7777",
  "160.238.65.7:3128",
  "160.238.65.8:3128",
  "152.70.137.18:8888",
  "116.80.49.156:3172",
  "177.184.195.168:8080",
  "158.160.215.167:8127",
  "103.69.107.91:1111",
  "186.148.180.46:999",
  "104.207.53.141:3129",
  "209.50.189.254:3129",
  "45.3.44.192:3129",
  "209.50.173.210:3129",
  "65.111.23.178:3129",
  "45.3.50.58:3129",
  "104.207.46.215:3129",
  "65.111.21.192:3129",
  "217.181.90.22:3129",
  "65.111.28.140:3129",
  "209.50.186.140:3129",
  "45.3.54.155:3129",
  "104.207.38.242:3129",
  "104.207.35.248:3129",
  "104.207.44.114:3129",
  "65.111.28.198:3129",
  "45.3.53.23:3129",
  "209.50.178.39:3129",
  "65.111.7.216:3129",
  "209.50.189.167:3129",
  "65.111.6.187:3129",
  "216.26.250.38:3129",
  "209.50.189.93:3129",
  "104.207.34.205:3129",
  "45.3.34.132:3129",
  "209.50.174.197:3129",
  "216.26.231.220:3129",
  "216.26.230.159:3129",
  "217.181.91.237:3129",
  "216.26.235.83:3129",
  "65.111.8.194:3129",
  "65.111.12.121:3129",
  "104.207.47.16:3129",
  "104.207.57.57:3129",
  "209.50.164.85:3129",
  "45.3.51.164:3129",
  "45.3.36.160:3129",
  "104.207.55.99:3129",
  "216.26.225.152:3129",
  "209.50.186.53:3129",
  "65.111.8.229:3129",
  "151.123.176.157:3129",
  "65.111.31.133:3129",
  "45.3.47.5:3129",
  "104.207.55.229:3129",
  "45.3.41.228:3129",
  "45.3.54.50:3129",
  "209.50.187.28:3129",
  "209.50.173.166:3129",
  "151.123.177.143:3129",
  "216.26.241.62:3129",
  "216.26.253.197:3129",
  "45.3.43.78:3129",
  "65.111.6.16:3129",
  "216.26.255.186:3129",
  "216.26.232.3:3129",
  "209.50.187.95:3129",
  "45.3.48.7:3129",
  "65.111.0.42:3129",
  "65.111.27.14:3129",
  "45.3.35.178:3129",
  "216.26.244.57:3129",
  "104.207.48.64:3129",
  "216.26.226.123:3129",
  "209.50.162.200:3129",
  "45.3.62.205:3129",
  "216.26.228.124:3129",
  "209.50.160.233:3129",
  "104.207.54.162:3129",
  "104.207.41.55:3129",
  "45.3.49.230:3129",
  "209.50.179.53:3129",
  "65.111.1.81:3129",
  "209.50.177.96:3129",
  "151.123.177.163:3129",
  "209.50.160.34:3129",
  "209.50.188.9:3129",
  "65.111.25.253:3129",
  "209.50.185.240:3129",
  "45.3.48.231:3129",
  "209.50.190.240:3129",
  "209.50.170.213:3129",
  "104.207.52.24:3129",
  "65.111.4.102:3129",
  "104.207.54.140:3129",
  "65.111.23.12:3129",
  "209.50.171.149:3129",
  "209.50.182.26:3129",
  "45.3.34.40:3129",
  "209.50.169.95:3129",
  "209.50.188.129:3129",
  "209.50.163.130:3129",
  "209.50.167.150:3129",
  "209.50.170.204:3129",
  "216.26.235.247:3129",
  "216.26.225.179:3129",
  "193.56.28.241:3129",
  "104.207.41.237:3129",
  "151.123.177.52:3129",
  "104.207.63.112:3129",
];

// ═══════════════════════════════════════════════════
// PROXY TYPES
// ═══════════════════════════════════════════════════
type ProxyType = "socks4" | "socks5" | "http";

export interface ProxyEntry {
  type: ProxyType;
  host: string;
  port: number;
  uri: string;
  label: string;
}

// ═══════════════════════════════════════════════════
// PROXY HEALTH TRACKER
// Theo dõi sức khỏe từng proxy để ưu tiên proxy tốt
// ═══════════════════════════════════════════════════
interface ProxyHealth {
  success: number;
  failure: number;
  lastUsed: number;
  blacklisted: boolean;
  blacklistedAt: number;
}

const proxyHealthMap = new Map<string, ProxyHealth>();

const BLACKLIST_THRESHOLD = 5;       // consecutive failures before blacklist
const BLACKLIST_DURATION_MS = 3 * 60 * 1000; // 3 minutes blacklist
const BLACKLIST_RECOVER_RATE = 10;   // recover if total success > this

function getHealth(uri: string): ProxyHealth {
  if (!proxyHealthMap.has(uri)) {
    proxyHealthMap.set(uri, {
      success: 0,
      failure: 0,
      lastUsed: 0,
      blacklisted: false,
      blacklistedAt: 0,
    });
  }
  return proxyHealthMap.get(uri)!;
}

export function reportProxySuccess(uri: string): void {
  const h = getHealth(uri);
  h.success++;
  h.lastUsed = Date.now();
  // Auto-recover from blacklist if starts succeeding
  if (h.blacklisted && h.success >= BLACKLIST_RECOVER_RATE) {
    h.blacklisted = false;
    h.failure = 0;
  }
}

export function reportProxyFailure(uri: string): void {
  const h = getHealth(uri);
  h.failure++;
  h.lastUsed = Date.now();
  if (h.failure >= BLACKLIST_THRESHOLD) {
    h.blacklisted = true;
    h.blacklistedAt = Date.now();
  }
}

function isBlacklisted(uri: string): boolean {
  const h = proxyHealthMap.get(uri);
  if (!h || !h.blacklisted) return false;
  // Auto-expire blacklist after duration
  if (Date.now() - h.blacklistedAt >= BLACKLIST_DURATION_MS) {
    h.blacklisted = false;
    h.failure = 0;
    return false;
  }
  return true;
}

/** Score: higher = better. Range ~0..200 */
function proxyScore(uri: string): number {
  const h = proxyHealthMap.get(uri);
  if (!h) return 100; // untested proxy gets neutral score
  const total = h.success + h.failure;
  if (total === 0) return 100;
  const rate = h.success / total;
  return Math.round(rate * 200);
}

// ═══════════════════════════════════════════════════
// PROXY CONSTRUCTION HELPERS
// ═══════════════════════════════════════════════════
function makeEntry(type: ProxyType, host: string, port: number, user?: string, pass?: string): ProxyEntry {
  const auth = user && pass ? `${encodeURIComponent(user)}:${encodeURIComponent(pass)}@` : "";
  const uri  = `${type}://${auth}${host}:${port}`;
  const label = user ? `${host}:${port} (auth)` : `${host}:${port}`;
  return { type, host, port, uri, label };
}

export function parseProxyLine(line: string): ProxyEntry | null {
  line = line.trim();
  if (!line || line.startsWith("#")) return null;

  if (/^(https?|socks[45]):\/\//i.test(line)) {
    try {
      const url  = new URL(line);
      const type: ProxyType =
        url.protocol === "socks4:" ? "socks4" :
        url.protocol === "socks5:" ? "socks5" : "http";
      const host = url.hostname;
      const port = parseInt(url.port, 10);
      const user = url.username ? decodeURIComponent(url.username) : undefined;
      const pass = url.password ? decodeURIComponent(url.password) : undefined;
      if (!host || isNaN(port)) return null;
      return makeEntry(type, host, port, user, pass);
    } catch {
      return null;
    }
  }

  const parts = line.split(":");
  if (parts.length === 2) {
    const [host, portStr] = parts;
    const port = parseInt(portStr, 10);
    if (!host || isNaN(port)) return null;
    return makeEntry("http", host, port);
  }
  if (parts.length === 4) {
    const [host, portStr, user, pass] = parts;
    const port = parseInt(portStr, 10);
    if (!host || isNaN(port)) return null;
    return makeEntry("http", host, port, user, pass);
  }

  return null;
}

function buildStaticProxies(list: string[], type: ProxyType): ProxyEntry[] {
  return list.map((line) => {
    const [host, portStr] = line.trim().split(":");
    return makeEntry(type, host, parseInt(portStr, 10));
  });
}

const STATIC_PROXIES: ProxyEntry[] = [
  ...buildStaticProxies(SOCKS4_PROXIES, "socks4"),
  ...buildStaticProxies(SOCKS5_PROXIES, "socks5"),
  ...buildStaticProxies(HTTP_PROXIES,   "http"),
];

const DYNAMIC_PROXIES: ProxyEntry[] = [];

function allProxies(): ProxyEntry[] {
  const combined = DYNAMIC_PROXIES.length > 0
    ? [...DYNAMIC_PROXIES, ...STATIC_PROXIES]
    : STATIC_PROXIES;
  // Filter out currently blacklisted proxies (with fallback if all are blacklisted)
  const active = combined.filter(p => !isBlacklisted(p.uri));
  return active.length > 0 ? active : combined;
}

// ═══════════════════════════════════════════════════
// SMART WEIGHTED PROXY SELECTION
// Proxy có tỷ lệ thành công cao được ưu tiên hơn
// ═══════════════════════════════════════════════════
export function getRandomProxy(): ProxyEntry {
  const pool = allProxies();
  if (pool.length === 0) return STATIC_PROXIES[Math.floor(Math.random() * STATIC_PROXIES.length)];

  // 70% chance: weighted selection by score
  // 30% chance: random (explore untested proxies)
  if (Math.random() < 0.70) {
    const scores = pool.map(p => proxyScore(p.uri));
    const totalScore = scores.reduce((a, b) => a + b, 0);
    let rand = Math.random() * totalScore;
    for (let i = 0; i < pool.length; i++) {
      rand -= scores[i];
      if (rand <= 0) return pool[i];
    }
  }

  return pool[Math.floor(Math.random() * pool.length)];
}

export function buildProxyAgent(proxy: ProxyEntry): Agent {
  if (proxy.type === "socks4" || proxy.type === "socks5") {
    return new SocksProxyAgent(proxy.uri) as unknown as Agent;
  }
  return new HttpsProxyAgent(proxy.uri) as unknown as Agent;
}

export function addProxiesFromText(text: string): { added: number; failed: number } {
  const lines = text.split(/[\n,\s]+/).filter(Boolean);
  let added = 0, failed = 0;
  for (const line of lines) {
    const entry = parseProxyLine(line);
    if (entry) {
      // Avoid duplicates
      const exists = DYNAMIC_PROXIES.some(p => p.uri === entry.uri);
      if (!exists) {
        DYNAMIC_PROXIES.push(entry);
        added++;
      }
    } else {
      failed++;
    }
  }
  return { added, failed };
}

export function clearDynamicProxies(): number {
  const count = DYNAMIC_PROXIES.length;
  DYNAMIC_PROXIES.length = 0;
  return count;
}

export function STATIC_PROXIES_EXPORT(): ProxyEntry[] {
  return STATIC_PROXIES;
}

export function DYNAMIC_PROXIES_EXPORT(): ProxyEntry[] {
  return DYNAMIC_PROXIES;
}

export function resetBlacklist(): number {
  let count = 0;
  for (const [, h] of proxyHealthMap) {
    if (h.blacklisted) {
      h.blacklisted = false;
      h.failure = 0;
      count++;
    }
  }
  return count;
}

export function getProxyStats() {
  const all = [...DYNAMIC_PROXIES, ...STATIC_PROXIES];
  const blacklisted = all.filter(p => isBlacklisted(p.uri)).length;
  const active = all.filter(p => !isBlacklisted(p.uri)).length;

  let totalSuccess = 0, totalFail = 0;
  for (const [, h] of proxyHealthMap) {
    totalSuccess += h.success;
    totalFail += h.failure;
  }

  return {
    total:      all.length,
    active,
    blacklisted,
    dynamic:    DYNAMIC_PROXIES.length,
    static:     STATIC_PROXIES.length,
    socks4:     STATIC_PROXIES.filter(p => p.type === "socks4").length,
    socks5:     STATIC_PROXIES.filter(p => p.type === "socks5").length,
    http:       STATIC_PROXIES.filter(p => p.type === "http").length,
    totalSuccess,
    totalFail,
    overallRate: totalSuccess + totalFail > 0
      ? parseFloat(((totalSuccess / (totalSuccess + totalFail)) * 100).toFixed(1))
      : 0,
  };
}

// ═══════════════════════════════════════════════════
// PROXY HEALTH TEST
// Test một batch proxy đồng thời, trả về kết quả
// ═══════════════════════════════════════════════════
export interface ProxyTestResult {
  proxy: ProxyEntry;
  alive: boolean;
  latencyMs: number;
}

export async function testProxy(proxy: ProxyEntry): Promise<ProxyTestResult> {
  const agent = buildProxyAgent(proxy);
  const start = Date.now();
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 8_000);
    const res = await fetch("https://httpbin.org/ip", {
      agent,
      signal: controller.signal,
    } as Parameters<typeof fetch>[1]);
    clearTimeout(timer);
    const latencyMs = Date.now() - start;
    const alive = res.status === 200;
    if (alive) reportProxySuccess(proxy.uri);
    else reportProxyFailure(proxy.uri);
    return { proxy, alive, latencyMs };
  } catch {
    reportProxyFailure(proxy.uri);
    return { proxy, alive: false, latencyMs: Date.now() - start };
  }
}

export async function testProxiesBatch(
  proxies: ProxyEntry[],
  concurrency = 20,
  onProgress?: (done: number, total: number) => void,
): Promise<{ alive: number; dead: number; results: ProxyTestResult[] }> {
  const results: ProxyTestResult[] = [];
  let done = 0;

  for (let i = 0; i < proxies.length; i += concurrency) {
    const batch = proxies.slice(i, i + concurrency);
    const batchResults = await Promise.all(batch.map(p => testProxy(p)));
    results.push(...batchResults);
    done += batch.length;
    onProgress?.(done, proxies.length);
  }

  const alive = results.filter(r => r.alive).length;
  return { alive, dead: results.length - alive, results };
}

// ═══════════════════════════════════════════════════
// SERVER IP DETECTION
// ═══════════════════════════════════════════════════
let cachedServerIp: string | null = null;

export async function getServerIp(): Promise<string> {
  if (cachedServerIp) return cachedServerIp;
  try {
    const res = await fetch("https://api.ipify.org?format=text", {
      signal: AbortSignal.timeout(5_000),
    });
    cachedServerIp = (await res.text()).trim();
    return cachedServerIp;
  } catch {
    try {
      const res2 = await fetch("https://ifconfig.me/ip", {
        signal: AbortSignal.timeout(5_000),
      });
      cachedServerIp = (await res2.text()).trim();
      return cachedServerIp;
    } catch {
      return "Không lấy được IP";
    }
  }
}
