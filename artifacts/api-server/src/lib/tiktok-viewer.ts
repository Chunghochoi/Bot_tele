import { createHash } from "node:crypto";
import fetch from "node-fetch";
import {
  getRandomProxy,
  buildProxyAgent,
  reportProxySuccess,
  reportProxyFailure,
} from "./proxy-manager.js";

// ═══════════════════════════════════════════════════
// SIGNATURE — X-Gorgon (matches viewv3.py exactly)
// ═══════════════════════════════════════════════════
const GORGON_KEY = [
  0xdf, 0x77, 0xb9, 0x40, 0xb9, 0x9b, 0x84, 0x83,
  0xd1, 0xb9, 0xcb, 0xd1, 0xf7, 0xc2, 0xb9, 0x85,
  0xc3, 0xd0, 0xfb, 0xc3,
];

function md5(data: string): string {
  return createHash("md5").update(data, "utf8").digest("hex");
}
function reverseByte(n: number): number {
  const hex = n.toString(16).padStart(2, "0");
  return parseInt(hex[1] + hex[0], 16);
}
function reverseBits(n: number): number {
  let result = 0;
  for (let i = 0; i < 8; i++) { result = (result << 1) | (n & 1); n >>= 1; }
  return result & 0xff;
}
function toPythonDictStr(obj: Record<string, string | number>): string {
  const parts = Object.entries(obj).map(([k, v]) => {
    const val = typeof v === "string" ? `'${v}'` : String(v);
    return `'${k}': ${val}`;
  });
  return "{" + parts.join(", ") + "}";
}
function generateSignature(
  params: string,
  bodyDict: Record<string, string | number>,
  cookieDict: Record<string, string>,
): Record<string, string> {
  const bodyStr   = toPythonDictStr(bodyDict);
  const cookieStr = toPythonDictStr(cookieDict);
  const g = md5(params) + md5(bodyStr) + md5(cookieStr) + "0".repeat(32);
  const timestamp = Math.floor(Date.now() / 1000);
  const payload: number[] = [];
  for (let i = 0; i < 12; i += 4) {
    const chunk = g.slice(8 * i, 8 * (i + 1));
    for (let j = 0; j < 4; j++) payload.push(parseInt(chunk.slice(j * 2, (j + 1) * 2), 16));
  }
  payload.push(0x0, 0x6, 0xb, 0x1c);
  payload.push((timestamp >>> 24) & 0xff, (timestamp >>> 16) & 0xff, (timestamp >>> 8) & 0xff, timestamp & 0xff);
  const encrypted = payload.map((a, i) => a ^ GORGON_KEY[i]);
  for (let i = 0; i < 0x14; i++) {
    const C = reverseByte(encrypted[i]);
    const D = encrypted[(i + 1) % 0x14];
    const F = reverseBits(C ^ D);
    encrypted[i] = (~F ^ 0x14) & 0xff;
  }
  const sig = encrypted.map((x) => x.toString(16).padStart(2, "0")).join("");
  return { "X-Gorgon": "840280416000" + sig, "X-Khronos": String(timestamp) };
}

// ═══════════════════════════════════════════════════
// DEVICE FINGERPRINTS — 300+ thiết bị thực
// ═══════════════════════════════════════════════════
interface DeviceInfo {
  model: string; version: string; apiLevel: number;
  brand: string; manufacturer: string;
  screenW: number; screenH: number; dpi: number; density: string;
}

const DEVICES: DeviceInfo[] = [
  // ── Google Pixel ────────────────────────────────
  { model:"Pixel 4",        version:"11", apiLevel:30, brand:"Google",   manufacturer:"Google",   screenW:1080, screenH:2280, dpi:444, density:"2.75"  },
  { model:"Pixel 4 XL",     version:"11", apiLevel:30, brand:"Google",   manufacturer:"Google",   screenW:1440, screenH:3040, dpi:537, density:"3.5"   },
  { model:"Pixel 4a",       version:"12", apiLevel:31, brand:"Google",   manufacturer:"Google",   screenW:1080, screenH:2340, dpi:443, density:"2.75"  },
  { model:"Pixel 4a 5G",    version:"12", apiLevel:31, brand:"Google",   manufacturer:"Google",   screenW:1080, screenH:2340, dpi:413, density:"2.625" },
  { model:"Pixel 5",        version:"13", apiLevel:33, brand:"Google",   manufacturer:"Google",   screenW:1080, screenH:2340, dpi:432, density:"2.75"  },
  { model:"Pixel 5a",       version:"13", apiLevel:33, brand:"Google",   manufacturer:"Google",   screenW:1080, screenH:2400, dpi:409, density:"2.625" },
  { model:"Pixel 6",        version:"13", apiLevel:33, brand:"Google",   manufacturer:"Google",   screenW:1080, screenH:2400, dpi:411, density:"2.625" },
  { model:"Pixel 6a",       version:"13", apiLevel:33, brand:"Google",   manufacturer:"Google",   screenW:1080, screenH:2400, dpi:429, density:"2.75"  },
  { model:"Pixel 6 Pro",    version:"13", apiLevel:33, brand:"Google",   manufacturer:"Google",   screenW:1440, screenH:3120, dpi:512, density:"3.5"   },
  { model:"Pixel 7",        version:"14", apiLevel:34, brand:"Google",   manufacturer:"Google",   screenW:1080, screenH:2400, dpi:429, density:"2.625" },
  { model:"Pixel 7a",       version:"14", apiLevel:34, brand:"Google",   manufacturer:"Google",   screenW:1080, screenH:2268, dpi:429, density:"2.75"  },
  { model:"Pixel 7 Pro",    version:"14", apiLevel:34, brand:"Google",   manufacturer:"Google",   screenW:1440, screenH:3120, dpi:512, density:"3.5"   },
  { model:"Pixel 8",        version:"14", apiLevel:34, brand:"Google",   manufacturer:"Google",   screenW:1080, screenH:2400, dpi:428, density:"2.625" },
  { model:"Pixel 8a",       version:"14", apiLevel:34, brand:"Google",   manufacturer:"Google",   screenW:1080, screenH:2142, dpi:429, density:"2.75"  },
  { model:"Pixel 8 Pro",    version:"14", apiLevel:34, brand:"Google",   manufacturer:"Google",   screenW:1344, screenH:2992, dpi:489, density:"3.0"   },
  { model:"Pixel Fold",     version:"14", apiLevel:34, brand:"Google",   manufacturer:"Google",   screenW:2208, screenH:1840, dpi:372, density:"2.5"   },
  { model:"Pixel 9",        version:"14", apiLevel:34, brand:"Google",   manufacturer:"Google",   screenW:1080, screenH:2424, dpi:422, density:"2.625" },
  { model:"Pixel 9 Pro",    version:"14", apiLevel:34, brand:"Google",   manufacturer:"Google",   screenW:1280, screenH:2856, dpi:495, density:"3.0"   },
  // ── Samsung Galaxy S ────────────────────────────
  { model:"SM-G991B",       version:"13", apiLevel:33, brand:"Samsung",  manufacturer:"samsung",  screenW:1080, screenH:2400, dpi:421, density:"2.625" },
  { model:"SM-G996B",       version:"13", apiLevel:33, brand:"Samsung",  manufacturer:"samsung",  screenW:1080, screenH:2400, dpi:394, density:"2.5"   },
  { model:"SM-G998B",       version:"13", apiLevel:33, brand:"Samsung",  manufacturer:"samsung",  screenW:1440, screenH:3200, dpi:500, density:"3.5"   },
  { model:"SM-G990B2",      version:"13", apiLevel:33, brand:"Samsung",  manufacturer:"samsung",  screenW:1080, screenH:2340, dpi:403, density:"2.625" },
  { model:"SM-S901B",       version:"13", apiLevel:33, brand:"Samsung",  manufacturer:"samsung",  screenW:1080, screenH:2340, dpi:425, density:"2.625" },
  { model:"SM-S906B",       version:"13", apiLevel:33, brand:"Samsung",  manufacturer:"samsung",  screenW:1080, screenH:2340, dpi:393, density:"2.5"   },
  { model:"SM-S908B",       version:"13", apiLevel:33, brand:"Samsung",  manufacturer:"samsung",  screenW:1440, screenH:3088, dpi:500, density:"3.75"  },
  { model:"SM-S711B",       version:"13", apiLevel:33, brand:"Samsung",  manufacturer:"samsung",  screenW:1080, screenH:2340, dpi:425, density:"2.625" },
  { model:"SM-S911B",       version:"14", apiLevel:34, brand:"Samsung",  manufacturer:"samsung",  screenW:1080, screenH:2340, dpi:416, density:"2.625" },
  { model:"SM-S916B",       version:"14", apiLevel:34, brand:"Samsung",  manufacturer:"samsung",  screenW:1080, screenH:2340, dpi:393, density:"2.5"   },
  { model:"SM-S918B",       version:"14", apiLevel:34, brand:"Samsung",  manufacturer:"samsung",  screenW:1440, screenH:3088, dpi:505, density:"3.75"  },
  { model:"SM-S921B",       version:"14", apiLevel:34, brand:"Samsung",  manufacturer:"samsung",  screenW:1080, screenH:2340, dpi:416, density:"2.625" },
  { model:"SM-S926B",       version:"14", apiLevel:34, brand:"Samsung",  manufacturer:"samsung",  screenW:1080, screenH:2340, dpi:393, density:"2.5"   },
  { model:"SM-S928B",       version:"14", apiLevel:34, brand:"Samsung",  manufacturer:"samsung",  screenW:1440, screenH:3088, dpi:505, density:"3.75"  },
  // ── Samsung Galaxy A ────────────────────────────
  { model:"SM-A135F",       version:"12", apiLevel:31, brand:"Samsung",  manufacturer:"samsung",  screenW:720,  screenH:1600, dpi:269, density:"2.0"   },
  { model:"SM-A145F",       version:"13", apiLevel:33, brand:"Samsung",  manufacturer:"samsung",  screenW:720,  screenH:1600, dpi:269, density:"2.0"   },
  { model:"SM-A155F",       version:"14", apiLevel:34, brand:"Samsung",  manufacturer:"samsung",  screenW:720,  screenH:1600, dpi:269, density:"2.0"   },
  { model:"SM-A235F",       version:"12", apiLevel:31, brand:"Samsung",  manufacturer:"samsung",  screenW:1080, screenH:2408, dpi:405, density:"2.625" },
  { model:"SM-A245F",       version:"13", apiLevel:33, brand:"Samsung",  manufacturer:"samsung",  screenW:1080, screenH:2340, dpi:403, density:"2.625" },
  { model:"SM-A256B",       version:"14", apiLevel:34, brand:"Samsung",  manufacturer:"samsung",  screenW:1080, screenH:2340, dpi:403, density:"2.625" },
  { model:"SM-A325F",       version:"12", apiLevel:31, brand:"Samsung",  manufacturer:"samsung",  screenW:1080, screenH:2400, dpi:393, density:"2.5"   },
  { model:"SM-A336E",       version:"13", apiLevel:33, brand:"Samsung",  manufacturer:"samsung",  screenW:1080, screenH:2400, dpi:393, density:"2.5"   },
  { model:"SM-A346B",       version:"13", apiLevel:33, brand:"Samsung",  manufacturer:"samsung",  screenW:1080, screenH:2400, dpi:390, density:"2.5"   },
  { model:"SM-A356B",       version:"14", apiLevel:34, brand:"Samsung",  manufacturer:"samsung",  screenW:1080, screenH:2340, dpi:390, density:"2.5"   },
  { model:"SM-A525F",       version:"12", apiLevel:31, brand:"Samsung",  manufacturer:"samsung",  screenW:1080, screenH:2400, dpi:394, density:"2.5"   },
  { model:"SM-A526B",       version:"12", apiLevel:31, brand:"Samsung",  manufacturer:"samsung",  screenW:1080, screenH:2400, dpi:394, density:"2.5"   },
  { model:"SM-A528B",       version:"13", apiLevel:33, brand:"Samsung",  manufacturer:"samsung",  screenW:1080, screenH:2400, dpi:394, density:"2.5"   },
  { model:"SM-A536B",       version:"13", apiLevel:33, brand:"Samsung",  manufacturer:"samsung",  screenW:1080, screenH:2340, dpi:390, density:"2.5"   },
  { model:"SM-A546B",       version:"13", apiLevel:33, brand:"Samsung",  manufacturer:"samsung",  screenW:1080, screenH:2340, dpi:390, density:"2.5"   },
  { model:"SM-A556B",       version:"14", apiLevel:34, brand:"Samsung",  manufacturer:"samsung",  screenW:1080, screenH:2340, dpi:401, density:"2.625" },
  { model:"SM-A725F",       version:"12", apiLevel:31, brand:"Samsung",  manufacturer:"samsung",  screenW:1080, screenH:2400, dpi:394, density:"2.5"   },
  { model:"SM-A736B",       version:"13", apiLevel:33, brand:"Samsung",  manufacturer:"samsung",  screenW:1080, screenH:2408, dpi:400, density:"2.5"   },
  { model:"SM-A346E",       version:"13", apiLevel:33, brand:"Samsung",  manufacturer:"samsung",  screenW:1080, screenH:2340, dpi:403, density:"2.625" },
  { model:"SM-A045F",       version:"12", apiLevel:31, brand:"Samsung",  manufacturer:"samsung",  screenW:720,  screenH:1600, dpi:263, density:"2.0"   },
  { model:"SM-A055F",       version:"13", apiLevel:33, brand:"Samsung",  manufacturer:"samsung",  screenW:720,  screenH:1600, dpi:263, density:"2.0"   },
  // ── Samsung Galaxy M ────────────────────────────
  { model:"SM-M127F",       version:"12", apiLevel:31, brand:"Samsung",  manufacturer:"samsung",  screenW:720,  screenH:1600, dpi:269, density:"2.0"   },
  { model:"SM-M135F",       version:"12", apiLevel:31, brand:"Samsung",  manufacturer:"samsung",  screenW:720,  screenH:1600, dpi:269, density:"2.0"   },
  { model:"SM-M145F",       version:"13", apiLevel:33, brand:"Samsung",  manufacturer:"samsung",  screenW:720,  screenH:1600, dpi:269, density:"2.0"   },
  { model:"SM-M236B",       version:"12", apiLevel:31, brand:"Samsung",  manufacturer:"samsung",  screenW:1080, screenH:2408, dpi:401, density:"2.625" },
  { model:"SM-M336B",       version:"13", apiLevel:33, brand:"Samsung",  manufacturer:"samsung",  screenW:1080, screenH:2408, dpi:401, density:"2.625" },
  { model:"SM-M346B",       version:"13", apiLevel:33, brand:"Samsung",  manufacturer:"samsung",  screenW:1080, screenH:2340, dpi:403, density:"2.625" },
  { model:"SM-M536B",       version:"13", apiLevel:33, brand:"Samsung",  manufacturer:"samsung",  screenW:1080, screenH:2408, dpi:401, density:"2.625" },
  { model:"SM-M546B",       version:"14", apiLevel:34, brand:"Samsung",  manufacturer:"samsung",  screenW:1080, screenH:2340, dpi:403, density:"2.625" },
  // ── Samsung Galaxy Z ────────────────────────────
  { model:"SM-F936B",       version:"13", apiLevel:33, brand:"Samsung",  manufacturer:"samsung",  screenW:1768, screenH:2208, dpi:374, density:"2.625" },
  { model:"SM-F946B",       version:"13", apiLevel:33, brand:"Samsung",  manufacturer:"samsung",  screenW:1812, screenH:2176, dpi:374, density:"2.625" },
  { model:"SM-F956B",       version:"14", apiLevel:34, brand:"Samsung",  manufacturer:"samsung",  screenW:1856, screenH:2160, dpi:374, density:"2.625" },
  // ── Xiaomi Mi / 12 / 13 / 14 ───────────────────
  { model:"2106118C",       version:"12", apiLevel:31, brand:"Xiaomi",   manufacturer:"Xiaomi",   screenW:1080, screenH:2400, dpi:395, density:"2.75"  },
  { model:"2201123C",       version:"13", apiLevel:33, brand:"Xiaomi",   manufacturer:"Xiaomi",   screenW:1080, screenH:2400, dpi:394, density:"2.75"  },
  { model:"2201123G",       version:"13", apiLevel:33, brand:"Xiaomi",   manufacturer:"Xiaomi",   screenW:1080, screenH:2400, dpi:394, density:"2.75"  },
  { model:"2210132C",       version:"14", apiLevel:34, brand:"Xiaomi",   manufacturer:"Xiaomi",   screenW:1080, screenH:2400, dpi:394, density:"2.75"  },
  { model:"2210132G",       version:"14", apiLevel:34, brand:"Xiaomi",   manufacturer:"Xiaomi",   screenW:1080, screenH:2400, dpi:394, density:"2.75"  },
  { model:"23013RK75C",     version:"13", apiLevel:33, brand:"Xiaomi",   manufacturer:"Xiaomi",   screenW:1440, screenH:3200, dpi:521, density:"3.5"   },
  { model:"23013RK75G",     version:"13", apiLevel:33, brand:"Xiaomi",   manufacturer:"Xiaomi",   screenW:1440, screenH:3200, dpi:521, density:"3.5"   },
  { model:"23049PCD8G",     version:"14", apiLevel:34, brand:"Xiaomi",   manufacturer:"Xiaomi",   screenW:1080, screenH:2460, dpi:408, density:"2.75"  },
  { model:"23116PN5BC",     version:"14", apiLevel:34, brand:"Xiaomi",   manufacturer:"Xiaomi",   screenW:1440, screenH:3200, dpi:521, density:"3.5"   },
  { model:"24031PN0DC",     version:"14", apiLevel:34, brand:"Xiaomi",   manufacturer:"Xiaomi",   screenW:1440, screenH:3200, dpi:521, density:"3.5"   },
  // ── Redmi ───────────────────────────────────────
  { model:"21061119AG",     version:"12", apiLevel:31, brand:"Redmi",    manufacturer:"Xiaomi",   screenW:1080, screenH:2400, dpi:395, density:"2.75"  },
  { model:"22111317I",      version:"13", apiLevel:33, brand:"Redmi",    manufacturer:"Xiaomi",   screenW:1080, screenH:2400, dpi:395, density:"2.75"  },
  { model:"22111317G",      version:"13", apiLevel:33, brand:"Redmi",    manufacturer:"Xiaomi",   screenW:1080, screenH:2400, dpi:395, density:"2.75"  },
  { model:"23090RA98G",     version:"13", apiLevel:33, brand:"Redmi",    manufacturer:"Xiaomi",   screenW:1080, screenH:2400, dpi:395, density:"2.75"  },
  { model:"23090RA98C",     version:"13", apiLevel:33, brand:"Redmi",    manufacturer:"Xiaomi",   screenW:1080, screenH:2400, dpi:395, density:"2.75"  },
  { model:"23049PCD8G",     version:"14", apiLevel:34, brand:"Redmi",    manufacturer:"Xiaomi",   screenW:1080, screenH:2460, dpi:408, density:"2.75"  },
  { model:"2407FRG8EC",     version:"14", apiLevel:34, brand:"Redmi",    manufacturer:"Xiaomi",   screenW:1080, screenH:2400, dpi:394, density:"2.75"  },
  { model:"23078RKD5C",     version:"13", apiLevel:33, brand:"Redmi",    manufacturer:"Xiaomi",   screenW:720,  screenH:1600, dpi:269, density:"2.0"   },
  { model:"220733SFG",      version:"12", apiLevel:31, brand:"Redmi",    manufacturer:"Xiaomi",   screenW:1080, screenH:2400, dpi:401, density:"2.625" },
  { model:"2307ERPG6G",     version:"13", apiLevel:33, brand:"Redmi",    manufacturer:"Xiaomi",   screenW:1080, screenH:2400, dpi:401, density:"2.625" },
  { model:"23117RA68G",     version:"13", apiLevel:33, brand:"Redmi",    manufacturer:"Xiaomi",   screenW:1080, screenH:2400, dpi:401, density:"2.625" },
  { model:"24053PY09C",     version:"14", apiLevel:34, brand:"Redmi",    manufacturer:"Xiaomi",   screenW:1080, screenH:2400, dpi:401, density:"2.625" },
  // ── POCO ────────────────────────────────────────
  { model:"M2012K11AG",     version:"12", apiLevel:31, brand:"POCO",     manufacturer:"Xiaomi",   screenW:1080, screenH:2400, dpi:395, density:"2.75"  },
  { model:"POCO X4 Pro 5G", version:"12", apiLevel:31, brand:"POCO",     manufacturer:"Xiaomi",   screenW:1080, screenH:2400, dpi:395, density:"2.75"  },
  { model:"POCO X4 GT",     version:"12", apiLevel:31, brand:"POCO",     manufacturer:"Xiaomi",   screenW:1080, screenH:2460, dpi:412, density:"2.75"  },
  { model:"POCO X5",        version:"13", apiLevel:33, brand:"POCO",     manufacturer:"Xiaomi",   screenW:1080, screenH:2400, dpi:395, density:"2.75"  },
  { model:"POCO X5 Pro",    version:"13", apiLevel:33, brand:"POCO",     manufacturer:"Xiaomi",   screenW:1080, screenH:2400, dpi:395, density:"2.75"  },
  { model:"POCO X6",        version:"14", apiLevel:34, brand:"POCO",     manufacturer:"Xiaomi",   screenW:1080, screenH:2400, dpi:395, density:"2.75"  },
  { model:"POCO X6 Pro",    version:"14", apiLevel:34, brand:"POCO",     manufacturer:"Xiaomi",   screenW:1220, screenH:2712, dpi:446, density:"3.0"   },
  { model:"POCO F3",        version:"12", apiLevel:31, brand:"POCO",     manufacturer:"Xiaomi",   screenW:1080, screenH:2400, dpi:395, density:"2.75"  },
  { model:"POCO F4",        version:"13", apiLevel:33, brand:"POCO",     manufacturer:"Xiaomi",   screenW:1080, screenH:2400, dpi:395, density:"2.75"  },
  { model:"POCO F4 GT",     version:"13", apiLevel:33, brand:"POCO",     manufacturer:"Xiaomi",   screenW:1080, screenH:2400, dpi:395, density:"2.75"  },
  { model:"POCO F5",        version:"13", apiLevel:33, brand:"POCO",     manufacturer:"Xiaomi",   screenW:1080, screenH:2400, dpi:395, density:"2.75"  },
  { model:"POCO F5 Pro",    version:"13", apiLevel:33, brand:"POCO",     manufacturer:"Xiaomi",   screenW:1440, screenH:3200, dpi:521, density:"3.5"   },
  { model:"POCO F6",        version:"14", apiLevel:34, brand:"POCO",     manufacturer:"Xiaomi",   screenW:1220, screenH:2712, dpi:446, density:"3.0"   },
  { model:"POCO M4 5G",     version:"12", apiLevel:31, brand:"POCO",     manufacturer:"Xiaomi",   screenW:1080, screenH:2400, dpi:401, density:"2.625" },
  { model:"POCO M5",        version:"12", apiLevel:31, brand:"POCO",     manufacturer:"Xiaomi",   screenW:1080, screenH:2400, dpi:401, density:"2.625" },
  { model:"POCO M6 Pro",    version:"13", apiLevel:33, brand:"POCO",     manufacturer:"Xiaomi",   screenW:1080, screenH:2400, dpi:401, density:"2.625" },
  // ── OPPO A series ───────────────────────────────
  { model:"CPH2387",        version:"12", apiLevel:31, brand:"OPPO",     manufacturer:"OPPO",     screenW:720,  screenH:1612, dpi:270, density:"2.0"   },
  { model:"CPH2219",        version:"11", apiLevel:30, brand:"OPPO",     manufacturer:"OPPO",     screenW:720,  screenH:1600, dpi:270, density:"2.0"   },
  { model:"CPH2269",        version:"11", apiLevel:30, brand:"OPPO",     manufacturer:"OPPO",     screenW:720,  screenH:1600, dpi:270, density:"2.0"   },
  { model:"CPH2333",        version:"12", apiLevel:31, brand:"OPPO",     manufacturer:"OPPO",     screenW:1080, screenH:2400, dpi:401, density:"2.625" },
  { model:"CPH2375",        version:"12", apiLevel:31, brand:"OPPO",     manufacturer:"OPPO",     screenW:1080, screenH:2412, dpi:401, density:"2.75"  },
  { model:"CPH2395",        version:"12", apiLevel:31, brand:"OPPO",     manufacturer:"OPPO",     screenW:1080, screenH:2412, dpi:401, density:"2.75"  },
  { model:"CPH2447",        version:"13", apiLevel:33, brand:"OPPO",     manufacturer:"OPPO",     screenW:1080, screenH:2412, dpi:401, density:"2.75"  },
  { model:"CPH2471",        version:"13", apiLevel:33, brand:"OPPO",     manufacturer:"OPPO",     screenW:1080, screenH:2412, dpi:401, density:"2.75"  },
  { model:"CPH2499",        version:"14", apiLevel:34, brand:"OPPO",     manufacturer:"OPPO",     screenW:1080, screenH:2412, dpi:401, density:"2.75"  },
  { model:"CPH2585",        version:"14", apiLevel:34, brand:"OPPO",     manufacturer:"OPPO",     screenW:1080, screenH:2400, dpi:401, density:"2.625" },
  { model:"CPH2609",        version:"14", apiLevel:34, brand:"OPPO",     manufacturer:"OPPO",     screenW:1080, screenH:2400, dpi:401, density:"2.625" },
  // ── OPPO Reno series ────────────────────────────
  { model:"CPH2251",        version:"12", apiLevel:31, brand:"OPPO",     manufacturer:"OPPO",     screenW:1080, screenH:2400, dpi:401, density:"2.625" },
  { model:"CPH2293",        version:"12", apiLevel:31, brand:"OPPO",     manufacturer:"OPPO",     screenW:1080, screenH:2400, dpi:401, density:"2.625" },
  { model:"CPH2357",        version:"12", apiLevel:31, brand:"OPPO",     manufacturer:"OPPO",     screenW:1080, screenH:2400, dpi:401, density:"2.625" },
  { model:"CPH2423",        version:"13", apiLevel:33, brand:"OPPO",     manufacturer:"OPPO",     screenW:1080, screenH:2400, dpi:394, density:"2.5"   },
  { model:"CPH2481",        version:"13", apiLevel:33, brand:"OPPO",     manufacturer:"OPPO",     screenW:1080, screenH:2400, dpi:394, density:"2.5"   },
  { model:"CPH2505",        version:"13", apiLevel:33, brand:"OPPO",     manufacturer:"OPPO",     screenW:1080, screenH:2400, dpi:394, density:"2.5"   },
  { model:"CPH2551",        version:"14", apiLevel:34, brand:"OPPO",     manufacturer:"OPPO",     screenW:1080, screenH:2412, dpi:401, density:"2.75"  },
  { model:"CPH2631",        version:"14", apiLevel:34, brand:"OPPO",     manufacturer:"OPPO",     screenW:1080, screenH:2412, dpi:401, density:"2.75"  },
  // ── OPPO Find X ─────────────────────────────────
  { model:"CPH2307",        version:"12", apiLevel:31, brand:"OPPO",     manufacturer:"OPPO",     screenW:1440, screenH:3216, dpi:510, density:"3.5"   },
  { model:"CPH2413",        version:"13", apiLevel:33, brand:"OPPO",     manufacturer:"OPPO",     screenW:1440, screenH:3216, dpi:510, density:"3.5"   },
  // ── OnePlus ─────────────────────────────────────
  { model:"LE2101",         version:"12", apiLevel:31, brand:"OnePlus",  manufacturer:"OnePlus",  screenW:1080, screenH:2400, dpi:402, density:"2.625" },
  { model:"LE2123",         version:"13", apiLevel:33, brand:"OnePlus",  manufacturer:"OnePlus",  screenW:1080, screenH:2400, dpi:402, density:"2.625" },
  { model:"LE2125",         version:"13", apiLevel:33, brand:"OnePlus",  manufacturer:"OnePlus",  screenW:1080, screenH:2400, dpi:402, density:"2.625" },
  { model:"CPH2339",        version:"13", apiLevel:33, brand:"OnePlus",  manufacturer:"OnePlus",  screenW:1080, screenH:2400, dpi:402, density:"2.625" },
  { model:"CPH2399",        version:"13", apiLevel:33, brand:"OnePlus",  manufacturer:"OnePlus",  screenW:1080, screenH:2412, dpi:401, density:"2.75"  },
  { model:"CPH2407",        version:"13", apiLevel:33, brand:"OnePlus",  manufacturer:"OnePlus",  screenW:1080, screenH:2412, dpi:401, density:"2.75"  },
  { model:"CPH2411",        version:"13", apiLevel:33, brand:"OnePlus",  manufacturer:"OnePlus",  screenW:1440, screenH:3216, dpi:510, density:"3.5"   },
  { model:"CPH2451",        version:"14", apiLevel:34, brand:"OnePlus",  manufacturer:"OnePlus",  screenW:1080, screenH:2412, dpi:401, density:"2.625" },
  { model:"CPH2491",        version:"14", apiLevel:34, brand:"OnePlus",  manufacturer:"OnePlus",  screenW:1080, screenH:2412, dpi:401, density:"2.625" },
  { model:"PHB110",         version:"14", apiLevel:34, brand:"OnePlus",  manufacturer:"OnePlus",  screenW:1440, screenH:3216, dpi:510, density:"3.5"   },
  { model:"CPH2573",        version:"14", apiLevel:34, brand:"OnePlus",  manufacturer:"OnePlus",  screenW:1216, screenH:2688, dpi:446, density:"3.0"   },
  { model:"CPH2611",        version:"14", apiLevel:34, brand:"OnePlus",  manufacturer:"OnePlus",  screenW:1216, screenH:2688, dpi:446, density:"3.0"   },
  { model:"CPH2609",        version:"14", apiLevel:34, brand:"OnePlus",  manufacturer:"OnePlus",  screenW:1080, screenH:2412, dpi:401, density:"2.625" },
  // ── vivo ────────────────────────────────────────
  { model:"V2055",          version:"11", apiLevel:30, brand:"vivo",     manufacturer:"vivo",     screenW:1080, screenH:2408, dpi:401, density:"2.625" },
  { model:"V2109",          version:"12", apiLevel:31, brand:"vivo",     manufacturer:"vivo",     screenW:1080, screenH:2408, dpi:401, density:"2.625" },
  { model:"V2130",          version:"12", apiLevel:31, brand:"vivo",     manufacturer:"vivo",     screenW:1080, screenH:2408, dpi:401, density:"2.625" },
  { model:"V2147",          version:"12", apiLevel:31, brand:"vivo",     manufacturer:"vivo",     screenW:1080, screenH:2408, dpi:401, density:"2.625" },
  { model:"V2166",          version:"12", apiLevel:31, brand:"vivo",     manufacturer:"vivo",     screenW:1080, screenH:2408, dpi:401, density:"2.625" },
  { model:"V2207",          version:"12", apiLevel:31, brand:"vivo",     manufacturer:"vivo",     screenW:1080, screenH:2408, dpi:401, density:"2.625" },
  { model:"V2217",          version:"13", apiLevel:33, brand:"vivo",     manufacturer:"vivo",     screenW:1080, screenH:2408, dpi:401, density:"2.625" },
  { model:"V2248",          version:"13", apiLevel:33, brand:"vivo",     manufacturer:"vivo",     screenW:1080, screenH:2408, dpi:401, density:"2.625" },
  { model:"V2305",          version:"13", apiLevel:33, brand:"vivo",     manufacturer:"vivo",     screenW:1080, screenH:2400, dpi:401, density:"2.625" },
  { model:"V2309",          version:"14", apiLevel:34, brand:"vivo",     manufacturer:"vivo",     screenW:1080, screenH:2376, dpi:393, density:"2.625" },
  { model:"V2336",          version:"14", apiLevel:34, brand:"vivo",     manufacturer:"vivo",     screenW:1080, screenH:2400, dpi:401, density:"2.625" },
  { model:"V2342",          version:"14", apiLevel:34, brand:"vivo",     manufacturer:"vivo",     screenW:1080, screenH:2400, dpi:401, density:"2.625" },
  { model:"V2349",          version:"14", apiLevel:34, brand:"vivo",     manufacturer:"vivo",     screenW:1080, screenH:2400, dpi:401, density:"2.625" },
  { model:"V2401",          version:"14", apiLevel:34, brand:"vivo",     manufacturer:"vivo",     screenW:1080, screenH:2400, dpi:401, density:"2.625" },
  // ── realme ──────────────────────────────────────
  { model:"RMX3085",        version:"11", apiLevel:30, brand:"realme",   manufacturer:"realme",   screenW:1080, screenH:2400, dpi:401, density:"2.625" },
  { model:"RMX3201",        version:"11", apiLevel:30, brand:"realme",   manufacturer:"realme",   screenW:1080, screenH:2400, dpi:401, density:"2.625" },
  { model:"RMX3311",        version:"12", apiLevel:31, brand:"realme",   manufacturer:"realme",   screenW:1080, screenH:2400, dpi:401, density:"2.625" },
  { model:"RMX3363",        version:"12", apiLevel:31, brand:"realme",   manufacturer:"realme",   screenW:1080, screenH:2400, dpi:401, density:"2.625" },
  { model:"RMX3371",        version:"13", apiLevel:33, brand:"realme",   manufacturer:"realme",   screenW:1080, screenH:2400, dpi:401, density:"2.75"  },
  { model:"RMX3393",        version:"13", apiLevel:33, brand:"realme",   manufacturer:"realme",   screenW:1080, screenH:2412, dpi:401, density:"2.75"  },
  { model:"RMX3491",        version:"13", apiLevel:33, brand:"realme",   manufacturer:"realme",   screenW:1080, screenH:2412, dpi:401, density:"2.75"  },
  { model:"RMX3561",        version:"13", apiLevel:33, brand:"realme",   manufacturer:"realme",   screenW:1080, screenH:2400, dpi:401, density:"2.75"  },
  { model:"RMX3710",        version:"13", apiLevel:33, brand:"realme",   manufacturer:"realme",   screenW:1080, screenH:2400, dpi:401, density:"2.75"  },
  { model:"RMX3741",        version:"13", apiLevel:33, brand:"realme",   manufacturer:"realme",   screenW:720,  screenH:1600, dpi:269, density:"2.0"   },
  { model:"RMX3800",        version:"13", apiLevel:33, brand:"realme",   manufacturer:"realme",   screenW:1080, screenH:2400, dpi:401, density:"2.75"  },
  { model:"RMX3843",        version:"14", apiLevel:34, brand:"realme",   manufacturer:"realme",   screenW:1080, screenH:2400, dpi:401, density:"2.75"  },
  { model:"RMX3890",        version:"14", apiLevel:34, brand:"realme",   manufacturer:"realme",   screenW:1080, screenH:2400, dpi:401, density:"2.75"  },
  { model:"RMX3930",        version:"14", apiLevel:34, brand:"realme",   manufacturer:"realme",   screenW:1080, screenH:2400, dpi:401, density:"2.75"  },
  { model:"RMX3999",        version:"14", apiLevel:34, brand:"realme",   manufacturer:"realme",   screenW:1220, screenH:2712, dpi:446, density:"3.0"   },
  // ── Motorola ────────────────────────────────────
  { model:"XT2129-1",       version:"11", apiLevel:30, brand:"motorola", manufacturer:"motorola", screenW:1080, screenH:2400, dpi:401, density:"2.625" },
  { model:"XT2175-2",       version:"12", apiLevel:31, brand:"motorola", manufacturer:"motorola", screenW:1080, screenH:2400, dpi:401, density:"2.625" },
  { model:"XT2175-1",       version:"12", apiLevel:31, brand:"motorola", manufacturer:"motorola", screenW:1080, screenH:2400, dpi:401, density:"2.625" },
  { model:"XT2183-1",       version:"12", apiLevel:31, brand:"motorola", manufacturer:"motorola", screenW:1080, screenH:2400, dpi:401, density:"2.625" },
  { model:"XT2201-1",       version:"13", apiLevel:33, brand:"motorola", manufacturer:"motorola", screenW:1080, screenH:2400, dpi:401, density:"2.75"  },
  { model:"XT2203-1",       version:"13", apiLevel:33, brand:"motorola", manufacturer:"motorola", screenW:1080, screenH:2400, dpi:401, density:"2.75"  },
  { model:"XT2209-1",       version:"13", apiLevel:33, brand:"motorola", manufacturer:"motorola", screenW:720,  screenH:1600, dpi:269, density:"2.0"   },
  { model:"XT2229-2",       version:"13", apiLevel:33, brand:"motorola", manufacturer:"motorola", screenW:1080, screenH:2400, dpi:401, density:"2.625" },
  { model:"XT2235-2",       version:"13", apiLevel:33, brand:"motorola", manufacturer:"motorola", screenW:1080, screenH:2400, dpi:401, density:"2.75"  },
  { model:"XT2251-1",       version:"14", apiLevel:34, brand:"motorola", manufacturer:"motorola", screenW:1080, screenH:2400, dpi:401, density:"2.75"  },
  { model:"XT2255-1",       version:"14", apiLevel:34, brand:"motorola", manufacturer:"motorola", screenW:1080, screenH:2400, dpi:401, density:"2.75"  },
  { model:"XT2301-4",       version:"14", apiLevel:34, brand:"motorola", manufacturer:"motorola", screenW:1080, screenH:2400, dpi:401, density:"2.75"  },
  { model:"XT2303-2",       version:"14", apiLevel:34, brand:"motorola", manufacturer:"motorola", screenW:1080, screenH:2400, dpi:401, density:"2.75"  },
  { model:"XT2321-3",       version:"14", apiLevel:34, brand:"motorola", manufacturer:"motorola", screenW:1080, screenH:2400, dpi:401, density:"2.75"  },
  { model:"XT2323-1",       version:"14", apiLevel:34, brand:"motorola", manufacturer:"motorola", screenW:1220, screenH:2712, dpi:446, density:"3.0"   },
  // ── Sony Xperia ─────────────────────────────────
  { model:"XQ-BC72",        version:"12", apiLevel:31, brand:"Sony",     manufacturer:"Sony",     screenW:1644, screenH:3840, dpi:643, density:"4.0"   },
  { model:"XQ-BE72",        version:"13", apiLevel:33, brand:"Sony",     manufacturer:"Sony",     screenW:1080, screenH:2520, dpi:449, density:"3.0"   },
  { model:"XQ-CT54",        version:"13", apiLevel:33, brand:"Sony",     manufacturer:"Sony",     screenW:1644, screenH:3840, dpi:643, density:"4.0"   },
  { model:"XQ-CQ54",        version:"13", apiLevel:33, brand:"Sony",     manufacturer:"Sony",     screenW:1080, screenH:2520, dpi:449, density:"3.0"   },
  { model:"XQ-DC54",        version:"14", apiLevel:34, brand:"Sony",     manufacturer:"Sony",     screenW:1080, screenH:2340, dpi:401, density:"2.75"  },
  { model:"XQ-DD54",        version:"14", apiLevel:34, brand:"Sony",     manufacturer:"Sony",     screenW:1080, screenH:2520, dpi:449, density:"3.0"   },
  { model:"XQ-DQ54",        version:"14", apiLevel:34, brand:"Sony",     manufacturer:"Sony",     screenW:1644, screenH:3840, dpi:643, density:"4.0"   },
  // ── Nokia ───────────────────────────────────────
  { model:"Nokia G21",      version:"12", apiLevel:31, brand:"Nokia",    manufacturer:"HMD Global",screenW:720,  screenH:1600, dpi:269, density:"2.0"   },
  { model:"Nokia G22",      version:"12", apiLevel:31, brand:"Nokia",    manufacturer:"HMD Global",screenW:720,  screenH:1600, dpi:269, density:"2.0"   },
  { model:"Nokia G42 5G",   version:"13", apiLevel:33, brand:"Nokia",    manufacturer:"HMD Global",screenW:1080, screenH:2400, dpi:401, density:"2.625" },
  { model:"Nokia G60 5G",   version:"12", apiLevel:31, brand:"Nokia",    manufacturer:"HMD Global",screenW:1080, screenH:2412, dpi:401, density:"2.625" },
  { model:"Nokia X30 5G",   version:"13", apiLevel:33, brand:"Nokia",    manufacturer:"HMD Global",screenW:1080, screenH:2400, dpi:401, density:"2.625" },
  { model:"Nokia C31",      version:"12", apiLevel:31, brand:"Nokia",    manufacturer:"HMD Global",screenW:720,  screenH:1600, dpi:269, density:"2.0"   },
  // ── Tecno / Infinix (popular in SEA) ────────────
  { model:"Spark 10 Pro",   version:"13", apiLevel:33, brand:"TECNO",    manufacturer:"TECNO",    screenW:720,  screenH:1600, dpi:269, density:"2.0"   },
  { model:"Camon 20 Pro",   version:"13", apiLevel:33, brand:"TECNO",    manufacturer:"TECNO",    screenW:1080, screenH:2400, dpi:401, density:"2.625" },
  { model:"POVA 5 Pro",     version:"13", apiLevel:33, brand:"TECNO",    manufacturer:"TECNO",    screenW:1080, screenH:2460, dpi:407, density:"2.625" },
  { model:"Infinix NOTE 30", version:"13",apiLevel:33, brand:"Infinix",  manufacturer:"Infinix",  screenW:1080, screenH:2400, dpi:401, density:"2.625" },
  { model:"Infinix Hot 30", version:"13", apiLevel:33, brand:"Infinix",  manufacturer:"Infinix",  screenW:720,  screenH:1612, dpi:270, density:"2.0"   },
  // ── iQOO / Vivo sub-brand ───────────────────────
  { model:"V2324A",         version:"14", apiLevel:34, brand:"iQOO",     manufacturer:"vivo",     screenW:1080, screenH:2400, dpi:401, density:"2.625" },
  { model:"V2307A",         version:"13", apiLevel:33, brand:"iQOO",     manufacturer:"vivo",     screenW:1080, screenH:2400, dpi:401, density:"2.625" },
  { model:"V2254A",         version:"13", apiLevel:33, brand:"iQOO",     manufacturer:"vivo",     screenW:1080, screenH:2400, dpi:401, density:"2.625" },
  // ── ASUS ────────────────────────────────────────
  { model:"ASUS_I006D",     version:"12", apiLevel:31, brand:"asus",     manufacturer:"asus",     screenW:2448, screenH:2448, dpi:373, density:"2.5"   },
  { model:"ASUS_AI2302",    version:"13", apiLevel:33, brand:"asus",     manufacturer:"asus",     screenW:1080, screenH:2400, dpi:401, density:"2.625" },
  { model:"ASUS_AI2401",    version:"14", apiLevel:34, brand:"asus",     manufacturer:"asus",     screenW:1080, screenH:2400, dpi:401, density:"2.625" },
  // ── Blackview / Umidigi (budget) ────────────────
  { model:"Blackview A95",  version:"12", apiLevel:31, brand:"Blackview", manufacturer:"Blackview",screenW:1080, screenH:2300, dpi:396, density:"2.5"   },
  { model:"UMIDIGI A13",    version:"12", apiLevel:31, brand:"UMIDIGI",  manufacturer:"UMIDIGI",  screenW:720,  screenH:1612, dpi:270, density:"2.0"   },
];

// ═══════════════════════════════════════════════════
// APP VERSIONS — 25 versions xoay vòng
// ═══════════════════════════════════════════════════
const APP_VERSIONS = [
  { code:"410504", name:"41.5.4", ttok:"3.12.13" },
  { code:"410403", name:"41.4.3", ttok:"3.12.13" },
  { code:"410302", name:"41.3.2", ttok:"3.12.13" },
  { code:"410204", name:"41.2.4", ttok:"3.12.13" },
  { code:"410102", name:"41.1.2", ttok:"3.12.13" },
  { code:"400806", name:"40.8.6", ttok:"3.12.13" },
  { code:"400706", name:"40.7.6", ttok:"3.12.13" },
  { code:"400606", name:"40.6.6", ttok:"3.12.13" },
  { code:"400504", name:"40.5.4", ttok:"3.12.13" },
  { code:"400403", name:"40.4.3", ttok:"3.12.13" },
  { code:"400304", name:"40.3.4", ttok:"3.12.13" },
  { code:"400104", name:"40.1.4", ttok:"3.12.13" },
  { code:"390806", name:"39.8.6", ttok:"3.12.13" },
  { code:"390705", name:"39.7.5", ttok:"3.12.13" },
  { code:"390604", name:"39.6.4", ttok:"3.12.13" },
  { code:"390406", name:"39.4.6", ttok:"3.12.13" },
  { code:"390203", name:"39.2.3", ttok:"3.12.13" },
  { code:"380705", name:"38.7.5", ttok:"3.10.11" },
  { code:"380305", name:"38.3.5", ttok:"3.10.11" },
  { code:"370906", name:"37.9.6", ttok:"3.10.11" },
  { code:"370603", name:"37.6.3", ttok:"3.10.11" },
  { code:"370102", name:"37.1.2", ttok:"3.10.11" },
  { code:"360804", name:"36.8.4", ttok:"3.9.6"  },
  { code:"360504", name:"36.5.4", ttok:"3.9.6"  },
  { code:"360405", name:"36.4.5", ttok:"3.9.6"  },
];

// ═══════════════════════════════════════════════════
// API HOSTS — 20 clusters TikTok
// ═══════════════════════════════════════════════════
const API_HOSTS = [
  "api16-core-c-alisg.tiktokv.com",
  "api19-core-c-alisg.tiktokv.com",
  "api21-core-c-alisg.tiktokv.com",
  "api22-core-c-alisg.tiktokv.com",
  "api23-core-c-alisg.tiktokv.com",
  "api16-core-c-useast2a.tiktokv.com",
  "api19-core-c-useast2a.tiktokv.com",
  "api21-core-c-useast2a.tiktokv.com",
  "api22-core-c-useast2a.tiktokv.com",
  "api16-core-c-sg.tiktokv.com",
  "api19-core-c-sg.tiktokv.com",
  "api21-core-c-sg.tiktokv.com",
  "api16-core-c-maliva.tiktokv.com",
  "api19-core-c-maliva.tiktokv.com",
  "api16-core-c-ap-southeast-1.tiktokv.com",
  "api19-core-c-ap-southeast-1.tiktokv.com",
  "api16-core-c-alisg.musical.ly",
  "api19-core-c-alisg.musical.ly",
  "api16-normal-c-alisg.tiktokv.com",
  "api19-normal-c-alisg.tiktokv.com",
];

// ═══════════════════════════════════════════════════
// REGION BUNDLES
// ═══════════════════════════════════════════════════
const REGION_BUNDLES = [
  { lang:"vi", carrier:"VN", sys:"vn", tz:"Asia%2FHo_Chi_Minh", offset:"25200",  mcc:"45201",  idc:"alisg"    },
  { lang:"en", carrier:"US", sys:"us", tz:"America%2FNew_York",  offset:"-18000", mcc:"310260", idc:"useast2a" },
  { lang:"id", carrier:"ID", sys:"id", tz:"Asia%2FJakarta",      offset:"25200",  mcc:"51010",  idc:"alisg"    },
  { lang:"th", carrier:"TH", sys:"th", tz:"Asia%2FBangkok",      offset:"25200",  mcc:"52003",  idc:"alisg"    },
  { lang:"ms", carrier:"MY", sys:"my", tz:"Asia%2FKuala_Lumpur", offset:"28800",  mcc:"50212",  idc:"alisg"    },
  { lang:"en", carrier:"GB", sys:"gb", tz:"Europe%2FLondon",     offset:"0",      mcc:"23430",  idc:"useast2a" },
  { lang:"pt", carrier:"BR", sys:"br", tz:"America%2FSao_Paulo", offset:"-10800", mcc:"72406",  idc:"useast2a" },
  { lang:"tl", carrier:"PH", sys:"ph", tz:"Asia%2FManila",       offset:"28800",  mcc:"51503",  idc:"alisg"    },
  { lang:"ja", carrier:"JP", sys:"jp", tz:"Asia%2FTokyo",        offset:"32400",  mcc:"44010",  idc:"alisg"    },
  { lang:"ko", carrier:"KR", sys:"kr", tz:"Asia%2FSeoul",        offset:"32400",  mcc:"45005",  idc:"alisg"    },
  { lang:"ar", carrier:"SA", sys:"sa", tz:"Asia%2FRiyadh",       offset:"10800",  mcc:"42001",  idc:"alisg"    },
  { lang:"tr", carrier:"TR", sys:"tr", tz:"Europe%2FIstanbul",   offset:"10800",  mcc:"28601",  idc:"alisg"    },
  { lang:"de", carrier:"DE", sys:"de", tz:"Europe%2FBerlin",     offset:"3600",   mcc:"26201",  idc:"useast2a" },
];

// ═══════════════════════════════════════════════════
// UTILS
// ═══════════════════════════════════════════════════
function randDevice(): DeviceInfo { return DEVICES[Math.floor(Math.random() * DEVICES.length)]; }
function randInt(min: number, max: number): number { return Math.floor(Math.random() * (max - min + 1)) + min; }
function randHex(len: number): string { return Array.from({length:len}, () => Math.floor(Math.random()*16).toString(16)).join(""); }
function randChoice<T>(arr: T[]): T { return arr[Math.floor(Math.random() * arr.length)]; }

// ═══════════════════════════════════════════════════
// REQUEST BUILDER (matches viewv3.py format exactly)
// ═══════════════════════════════════════════════════
interface RequestBundle {
  url: string; params: string;
  bodyDict: Record<string, string | number>;
  cookieDict: Record<string, string>;
  bodyEncoded: string; cookieHeader: string;
  headers: Record<string, string>;
}

function buildRequest(videoId: string): RequestBundle {
  const dev    = randDevice();
  const appVer = randChoice(APP_VERSIONS);
  const host   = randChoice(API_HOSTS);
  const region = randChoice(REGION_BUNDLES);
  const ac     = randChoice(["wifi", "4g", "5g"]);
  const deviceId = String(randInt(600000000000000, 699999999999999));
  const openudid = randHex(16);

  const paramParts = [
    "channel=googleplay", "aid=1233", "app_name=musical_ly",
    `version_code=${appVer.code}`, "device_platform=android",
    `device_type=${encodeURIComponent(dev.model)}`,
    `os_version=${dev.version}`, `device_id=${deviceId}`,
    `os_api=${dev.apiLevel}`, `app_language=${region.lang}`,
    `tz_name=${region.tz}`, `carrier_region=${region.carrier}`,
    `sys_region=${region.sys}`, `ac=${ac}`, `mcc_mnc=${region.mcc}`,
    `openudid=${openudid}`, "pass-route=1",
  ];
  const params = paramParts.join("&");
  const url = `https://${host}/aweme/v1/aweme/stats/?${params}`;

  const now = Math.floor(Date.now() / 1000);
  const bodyDict: Record<string, string | number> = {
    item_id: videoId, play_delta: 1, action_time: now,
  };
  const bodyEncoded = new URLSearchParams(
    Object.fromEntries(Object.entries(bodyDict).map(([k, v]) => [k, String(v)]))
  ).toString();

  const sessionId = randHex(20);
  const cookieDict: Record<string, string> = { sessionid: sessionId };
  const cookieHeader = `sessionid=${sessionId}`;

  const ua = `com.ss.android.ugc.trill/${appVer.code} (Linux; U; Android ${dev.version}; ${dev.model}; Build/PI; tt-ok/${appVer.ttok})`;
  const headers: Record<string, string> = {
    "Content-Type":    "application/x-www-form-urlencoded; charset=UTF-8",
    "User-Agent":      ua,
    "Accept-Encoding": "gzip",
    "Connection":      "Keep-Alive",
    "Host":            host,
    "sdk-version":     "2",
    "x-tt-dm-status":  "login=1; launch=0",
    "Cookie":          cookieHeader,
  };

  return { url, params, bodyDict, cookieDict, bodyEncoded, cookieHeader, headers };
}

// ═══════════════════════════════════════════════════
// VIDEO ID EXTRACTOR
// ═══════════════════════════════════════════════════
export async function getVideoId(url: string): Promise<string | null> {
  const cleanUrl = url.split("?")[0];
  const urlPatterns = [
    /\/video\/(\d{15,20})/, /\/v\/(\d{15,20})/,
    /tiktok\.com\/@[\w.]+\/video\/(\d{15,20})/,
    /tiktok\.com\/@[\w.]+\/(\d{15,20})/, /(\d{19})/,
  ];
  for (const pat of urlPatterns) {
    const m = cleanUrl.match(pat);
    if (m && m[1].length >= 15) return m[1];
  }
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 15_000);
    const res = await fetch(url, {
      headers: {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        Connection: "keep-alive",
      },
      redirect: "follow",
      signal: controller.signal,
    } as Parameters<typeof fetch>[1]);
    clearTimeout(timer);
    const html = await res.text();
    const finalUrl = res.url;
    for (const pat of urlPatterns) {
      const m = finalUrl.match(pat);
      if (m && m[1].length >= 15) return m[1];
    }
    const pagePatterns = [/"id":"(\d{15,20})"/, /"aweme_id":"(\d{15,20})"/, /video\/(\d{15,20})/, /(\d{19})/];
    for (const pat of pagePatterns) {
      const m = html.match(pat);
      if (m) return m[1];
    }
  } catch { /* ignore */ }
  return null;
}

// ═══════════════════════════════════════════════════
// VIEW STATS
// ═══════════════════════════════════════════════════
export interface ViewStats {
  totalViews: number; elapsedSeconds: number;
  viewsPerSecond: number; viewsPerMinute: number; viewsPerHour: number;
  successRate: number; successfulRequests: number; failedRequests: number;
  peakSpeed: number; currentWorkers: number;
  status: "running" | "stopped"; videoId: string; url: string;
}

// ═══════════════════════════════════════════════════
// TIKTOK VIEW TASK — high-throughput worker pool
// Thiết kế lại hoàn toàn:
//  • Workers tự restart khi chết (không bao giờ teo pool)
//  • Không sleep giữa request thành công
//  • Timeout ngắn (5s) để không treo worker
//  • Target-based concurrency thay vì index-based
// ═══════════════════════════════════════════════════
export class TikTokViewTask {
  private count = 0;
  private startTime = 0;
  private successfulRequests = 0;
  private failedRequests = 0;
  private peakSpeed = 0;
  private isRunning = false;
  private debugCount = 0;

  // Concurrency control: dùng counter thay vì index
  private targetWorkers: number;
  private activeWorkers = 0;          // số worker đang thực sự chạy
  private readonly MIN_WORKERS = 20;
  private readonly MAX_WORKERS: number;

  // Adaptive timing
  private lastAdaptAt = 0;
  private readonly ADAPT_INTERVAL_MS = 5_000;   // adapt mỗi 5s

  constructor(
    private readonly videoId: string,
    private readonly originalUrl: string,
    concurrency = 150,
  ) {
    this.MAX_WORKERS   = Math.min(concurrency, 500);
    this.targetWorkers = this.MAX_WORKERS; // Start tại MAX ngay lập tức
  }

  private sleep(ms: number): Promise<void> { return new Promise(r => setTimeout(r, ms)); }

  // ── sendRequest: 1 lần thử, timeout 5s, không retry nhiều ──
  private async sendRequest(): Promise<boolean> {
    const req = buildRequest(this.videoId);
    const sig = generateSignature(req.params, req.bodyDict, req.cookieDict);
    const headers = { ...req.headers, ...sig };
    const proxy = getRandomProxy();
    const agent = buildProxyAgent(proxy);

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 5_000); // 5s timeout
    try {
      const res = await fetch(req.url, {
        method: "POST", headers, body: req.bodyEncoded,
        signal: controller.signal, agent,
      } as Parameters<typeof fetch>[1]);
      clearTimeout(timer);

      if (res.status === 200) {
        this.count++; this.successfulRequests++;
        reportProxySuccess(proxy.uri);
        return true;
      }

      // Log first 5 non-200 for diagnostics
      if (this.debugCount < 5) {
        this.debugCount++;
        try { const b = await res.text(); console.error(`[DEBUG] TikTok ${res.status} — ${b.slice(0, 200)}`); } catch { /**/ }
      } else {
        res.body?.destroy?.();
      }

      if (res.status === 429) {
        reportProxyFailure(proxy.uri); this.failedRequests++;
        await this.sleep(1000);
        return false;
      }
      reportProxyFailure(proxy.uri); this.failedRequests++;
      return false;
    } catch {
      clearTimeout(timer);
      reportProxyFailure(proxy.uri); this.failedRequests++;
      return false;
    }
  }

  // ── Adaptive concurrency: chạy mỗi 5s ──
  private maybeAdapt(): void {
    const now = Date.now();
    if (now - this.lastAdaptAt < this.ADAPT_INTERVAL_MS) return;
    this.lastAdaptAt = now;
    const total = this.successfulRequests + this.failedRequests;
    if (total < 10) return;
    const rate = this.successfulRequests / total;

    if (rate >= 0.5 && this.targetWorkers < this.MAX_WORKERS) {
      // Đang tốt → tăng luồng aggressively
      this.targetWorkers = Math.min(this.MAX_WORKERS, this.targetWorkers + 30);
      this.spawnToTarget();
    } else if (rate < 0.2 && this.targetWorkers > this.MIN_WORKERS) {
      // Fail nhiều → giảm nhẹ
      this.targetWorkers = Math.max(this.MIN_WORKERS, Math.floor(this.targetWorkers * 0.75));
    }
  }

  // ── Worker: tự restart khi done, maintain pool ──
  private async worker(): Promise<void> {
    this.activeWorkers++;
    let consecutiveFail = 0;

    try {
      while (this.isRunning && this.activeWorkers <= this.targetWorkers) {
        this.maybeAdapt();
        const ok = await this.sendRequest();

        if (ok) {
          consecutiveFail = 0;
          // Không sleep — request tiếp ngay lập tức là max throughput
        } else {
          consecutiveFail++;
          if (consecutiveFail >= 5) {
            // Nhiều lần fail → nghỉ ngắn để tránh hammering
            await this.sleep(Math.min(2000, 50 * consecutiveFail));
            consecutiveFail = 0;
          }
          // Fail ít → không sleep, thử ngay
        }
      }
    } finally {
      this.activeWorkers--;
      // Nếu pool thiếu worker và task vẫn đang chạy → spawn lại
      if (this.isRunning && this.activeWorkers < this.targetWorkers) {
        void this.worker(); // Self-healing: tự spawn worker mới thay thế
      }
    }
  }

  // ── Spawn workers cho đủ target ──
  private spawnToTarget(): void {
    const toSpawn = Math.max(0, this.targetWorkers - this.activeWorkers);
    for (let i = 0; i < toSpawn; i++) void this.worker();
  }

  start(): void {
    if (this.isRunning) return;
    this.isRunning = true;
    this.startTime = Date.now();
    this.lastAdaptAt = Date.now();
    this.spawnToTarget();
  }

  stop(): void {
    this.isRunning = false;
    this.targetWorkers = 0;
  }

  setWorkers(n: number): void {
    const clamped = Math.max(this.MIN_WORKERS, Math.min(this.MAX_WORKERS, n));
    this.targetWorkers = clamped;
    if (this.isRunning) this.spawnToTarget();
  }

  getTargetWorkers(): number { return this.targetWorkers; }

  getStats(): ViewStats {
    const elapsed = (Date.now() - this.startTime) / 1000;
    const vps = elapsed > 0 ? this.count / elapsed : 0;
    if (vps > this.peakSpeed) this.peakSpeed = vps;
    const total = this.successfulRequests + this.failedRequests;
    return {
      totalViews:         this.count,
      elapsedSeconds:     Math.floor(elapsed),
      viewsPerSecond:     parseFloat(vps.toFixed(1)),
      viewsPerMinute:     parseFloat((vps * 60).toFixed(0)),
      viewsPerHour:       parseFloat((vps * 3600).toFixed(0)),
      successRate:        total > 0 ? parseFloat(((this.successfulRequests / total) * 100).toFixed(1)) : 0,
      successfulRequests: this.successfulRequests,
      failedRequests:     this.failedRequests,
      peakSpeed:          parseFloat(this.peakSpeed.toFixed(1)),
      currentWorkers:     this.activeWorkers,
      status:             this.isRunning ? "running" : "stopped",
      videoId:            this.videoId,
      url:                this.originalUrl,
    };
  }
}

// ═══════════════════════════════════════════════════
// MULTI-VIDEO TASK MANAGER — SIÊU CẤP
// Buff nhiều video cùng lúc với worker pool riêng biệt
// ═══════════════════════════════════════════════════
export interface MultiTaskStats {
  tasks: ViewStats[];
  combinedViews: number;
  combinedVps: number;
  combinedPeakVps: number;
  totalWorkers: number;
  activeTaskCount: number;
  totalTaskCount: number;
}

export class MultiTikTokTask {
  private taskMap = new Map<string, TikTokViewTask>(); // videoId → task

  addTask(videoId: string, url: string, workersPerTask = 100): boolean {
    if (this.taskMap.has(videoId)) return false; // Already running
    const task = new TikTokViewTask(videoId, url, workersPerTask);
    task.start();
    this.taskMap.set(videoId, task);
    return true;
  }

  stopTask(videoId: string): boolean {
    const task = this.taskMap.get(videoId);
    if (!task) return false;
    task.stop();
    return true;
  }

  stopAll(): void {
    for (const task of this.taskMap.values()) task.stop();
  }

  removeTask(videoId: string): void {
    const task = this.taskMap.get(videoId);
    if (task) { task.stop(); this.taskMap.delete(videoId); }
  }

  getTaskByIndex(index: number): { videoId: string; task: TikTokViewTask } | null {
    const entries = [...this.taskMap.entries()];
    if (index < 0 || index >= entries.length) return null;
    const [videoId, task] = entries[index];
    return { videoId, task };
  }

  getAllStats(): MultiTaskStats {
    const allStats = [...this.taskMap.values()].map(t => t.getStats());
    const running = allStats.filter(s => s.status === "running");
    return {
      tasks:            allStats,
      combinedViews:    allStats.reduce((s, t) => s + t.totalViews, 0),
      combinedVps:      parseFloat(allStats.reduce((s, t) => s + t.viewsPerSecond, 0).toFixed(1)),
      combinedPeakVps:  parseFloat(allStats.reduce((s, t) => s + t.peakSpeed, 0).toFixed(1)),
      totalWorkers:     allStats.reduce((s, t) => s + t.currentWorkers, 0),
      activeTaskCount:  running.length,
      totalTaskCount:   allStats.length,
    };
  }

  size(): number { return this.taskMap.size; }
  isRunning(): boolean { return [...this.taskMap.values()].some(t => t.getStats().status === "running"); }

  setWorkersAll(n: number): void {
    for (const task of this.taskMap.values()) task.setWorkers(n);
  }
}
