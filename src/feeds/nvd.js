/* ----------------------------------------------------------------------------
 * NVD (NIST) + CISA KEV connector
 * Docs: https://nvd.nist.gov/developers/vulnerabilities
 *       https://www.cisa.gov/known-exploited-vulnerabilities-catalog
 *
 * NOTE: NVD and CISA are not in this sandbox's allowlist and browsers hit CORS
 * on NVD, so in production route these through your own backend (see server.js
 * for the pattern) rather than calling them from the browser.
 * --------------------------------------------------------------------------*/
import { normalizeCve } from "./normalize.js";

const NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const KEV_JSON =
  "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

export async function fetchNvdKev() {
  // 1) Pull the CISA KEV catalog (known-exploited flag + priority).
  const kevRes = await fetch(KEV_JSON);
  const kev = await kevRes.json();
  const kevSet = new Set((kev.vulnerabilities || []).map((v) => v.cveID));

  // 2) Pull recent CVEs from NVD (last 24h window keeps payloads small).
  const end = new Date().toISOString();
  const start = new Date(Date.now() - 24 * 3600 * 1000).toISOString();
  const url = `${NVD_API}?pubStartDate=${start}&pubEndDate=${end}&resultsPerPage=40`;
  const headers = {};
  if (import.meta.env.VITE_NVD_API_KEY) headers.apiKey = import.meta.env.VITE_NVD_API_KEY;

  const res = await fetch(url, { headers });
  const data = await res.json();

  return (data.vulnerabilities || [])
    .map((v) => normalizeCve({ ...v.cve, kev: kevSet.has(v.cve.id) }))
    .sort((a, b) => Number(b.cvss) - Number(a.cvss));
}
