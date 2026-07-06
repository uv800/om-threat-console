/* ============================================================================
 * OM // ENRICHMENT ENGINE  (server-side only — holds API keys)
 * ----------------------------------------------------------------------------
 * enrichIndicator(indicator) detects the indicator type (ip / domain / hash /
 * url), fans out to VirusTotal + AbuseIPDB + Shodan in parallel, correlates the
 * results into a single verdict, and returns a normalized report.
 *
 * Zero-setup: with no API keys configured it returns clearly-flagged demo data
 * (report.demo === true) so the console works out of the box. Add keys in .env
 * to light up real lookups.
 *
 * Keys (server-side, NO VITE_ prefix):
 *   VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY, SHODAN_API_KEY
 * ==========================================================================*/

const KEYS = {
  vt: process.env.VIRUSTOTAL_API_KEY,
  abuse: process.env.ABUSEIPDB_API_KEY,
  shodan: process.env.SHODAN_API_KEY,
};

const IPV4 = /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/;
const HASH = /^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/;
const DOMAIN = /^(?=.{1,253}$)(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,}$/;

export function detectType(raw) {
  const s = String(raw || "").trim();
  if (!s) return "unknown";
  if (IPV4.test(s)) return "ip";
  if (HASH.test(s)) return "hash";
  if (/^https?:\/\//i.test(s)) return "url";
  if (DOMAIN.test(s)) return "domain";
  return "unknown";
}

/* ---------------------------- VirusTotal -------------------------- */
async function queryVT(indicator, type) {
  if (!KEYS.vt) return { available: false, reason: "no_key" };
  let path;
  if (type === "ip") path = `ip_addresses/${indicator}`;
  else if (type === "domain") path = `domains/${indicator}`;
  else if (type === "hash") path = `files/${indicator}`;
  else if (type === "url") path = `urls/${b64url(indicator)}`;
  else return { available: false, reason: "unsupported_type" };

  const res = await fetch(`https://www.virustotal.com/api/v3/${path}`, {
    headers: { "x-apikey": KEYS.vt },
  });
  if (res.status === 404) return { available: true, found: false };
  if (!res.ok) return { available: false, reason: `http_${res.status}` };
  const j = await res.json();
  const a = j.data?.attributes || {};
  const st = a.last_analysis_stats || {};
  return {
    available: true, found: true,
    malicious: st.malicious || 0,
    suspicious: st.suspicious || 0,
    harmless: st.harmless || 0,
    undetected: st.undetected || 0,
    reputation: a.reputation ?? 0,
    country: a.country,
    asOwner: a.as_owner,
    tags: a.tags || [],
    names: a.names?.slice(0, 3),
    link: `https://www.virustotal.com/gui/search/${encodeURIComponent(indicator)}`,
  };
}

/* ---------------------------- AbuseIPDB --------------------------- */
async function queryAbuse(indicator, type) {
  if (type !== "ip") return { available: false, reason: "ip_only" };
  if (!KEYS.abuse) return { available: false, reason: "no_key" };
  const url = `https://api.abuseipdb.com/api/v2/check?ipAddress=${indicator}&maxAgeInDays=90`;
  const res = await fetch(url, { headers: { Key: KEYS.abuse, Accept: "application/json" } });
  if (!res.ok) return { available: false, reason: `http_${res.status}` };
  const d = (await res.json()).data || {};
  return {
    available: true,
    confidence: d.abuseConfidenceScore ?? 0,
    totalReports: d.totalReports ?? 0,
    country: d.countryCode,
    isp: d.isp,
    domain: d.domain,
    usageType: d.usageType,
    isTor: d.isTor,
    lastReported: d.lastReportedAt,
  };
}

/* ------------------------------ Shodan ---------------------------- */
async function queryShodan(indicator, type) {
  if (type !== "ip") return { available: false, reason: "ip_only" };
  if (!KEYS.shodan) return { available: false, reason: "no_key" };
  const res = await fetch(`https://api.shodan.io/shodan/host/${indicator}?key=${KEYS.shodan}`);
  if (res.status === 404) return { available: true, found: false };
  if (!res.ok) return { available: false, reason: `http_${res.status}` };
  const d = await res.json();
  return {
    available: true, found: true,
    ports: (d.ports || []).slice(0, 20),
    org: d.org, os: d.os,
    hostnames: (d.hostnames || []).slice(0, 5),
    tags: d.tags || [],
    vulns: (d.vulns || []).slice(0, 15),
    country: d.country_name,
  };
}

/* --------------------------- correlation -------------------------- */
function verdictFrom(sources) {
  let score = 0;
  const vt = sources.virustotal, ab = sources.abuseipdb, sh = sources.shodan;
  if (vt?.found) score += Math.min(60, (vt.malicious || 0) * 8 + (vt.suspicious || 0) * 3);
  if (ab?.available) score += Math.round((ab.confidence || 0) * 0.35);
  if (sh?.vulns?.length) score += Math.min(15, sh.vulns.length * 2);
  if (ab?.isTor) score += 8;
  score = Math.min(100, score);
  const level = score >= 65 ? "MALICIOUS" : score >= 30 ? "SUSPICIOUS" : score > 0 ? "LOW-RISK" : "CLEAN";
  const bits = [];
  if (vt?.found) bits.push(`VT ${vt.malicious}/${(vt.malicious || 0) + (vt.harmless || 0) + (vt.undetected || 0)} malicious`);
  if (ab?.available) bits.push(`AbuseIPDB ${ab.confidence}% (${ab.totalReports} reports)`);
  if (sh?.vulns?.length) bits.push(`${sh.vulns.length} known CVEs on host`);
  return { level, score, summary: bits.join(" · ") || "No corroborating signals." };
}

/* ------------------------------ main ------------------------------ */
export async function enrichIndicator(indicator) {
  const type = detectType(indicator);
  if (type === "unknown") return { indicator, type, error: "Unrecognized indicator format." };

  const anyKey = KEYS.vt || KEYS.abuse || KEYS.shodan;
  if (!anyKey) return { ...demoReport(indicator, type), demo: true, ts: Date.now() };

  const [virustotal, abuseipdb, shodan] = await Promise.all([
    queryVT(indicator, type).catch((e) => ({ available: false, reason: String(e) })),
    queryAbuse(indicator, type).catch((e) => ({ available: false, reason: String(e) })),
    queryShodan(indicator, type).catch((e) => ({ available: false, reason: String(e) })),
  ]);
  const sources = { virustotal, abuseipdb, shodan };
  return { indicator, type, verdict: verdictFrom(sources), sources, demo: false, ts: Date.now() };
}

/* --------------------------- demo output -------------------------- */
function demoReport(indicator, type) {
  const seed = [...String(indicator)].reduce((a, c) => a + c.charCodeAt(0), 0);
  const mal = seed % 17;
  const conf = (seed * 7) % 100;
  const sources = {
    virustotal: { available: true, found: true, malicious: mal, suspicious: seed % 4, harmless: 40, undetected: 30, reputation: -mal * 3, asOwner: "AS DEMO-NET", country: "—", link: `https://www.virustotal.com/gui/search/${encodeURIComponent(indicator)}`, demo: true },
    abuseipdb: type === "ip" ? { available: true, confidence: conf, totalReports: seed % 240, country: "—", isp: "Demo ISP", usageType: "Data Center/Hosting", isTor: seed % 5 === 0, demo: true } : { available: false, reason: "ip_only" },
    shodan: type === "ip" ? { available: true, found: true, ports: [22, 80, 443, (seed % 9000) + 1000], org: "Demo Hosting Ltd", vulns: mal > 8 ? ["CVE-2026-1042", "CVE-2026-2288"] : [], hostnames: [`host-${seed % 999}.demo.net`], demo: true } : { available: false, reason: "ip_only" },
  };
  return { indicator, type, verdict: verdictFrom(sources), sources };
}

function b64url(s) {
  return Buffer.from(s).toString("base64").replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
}
