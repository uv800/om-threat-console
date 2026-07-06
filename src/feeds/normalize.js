/* Normalization helpers — keep every connector emitting the same shapes. */

export function sevFromCvss(score) {
  const s = Number(score) || 0;
  if (s >= 9.0) return "CRITICAL";
  if (s >= 7.0) return "HIGH";
  if (s >= 4.0) return "MEDIUM";
  return "LOW";
}

export function normalizeCve(raw) {
  // Map an NVD-style record → the UI's vuln row shape.
  const cvss =
    raw?.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore ??
    raw?.cvss ?? 0;
  const cwe =
    raw?.weaknesses?.[0]?.description?.[0]?.value ??
    raw?.cwe ?? "CWE-Unknown";
  const vendor =
    raw?.configurations?.[0]?.nodes?.[0]?.cpeMatch?.[0]?.criteria?.split(":")?.[3] ??
    raw?.vendor ?? "unknown";
  return {
    id: raw.id ?? raw.cveID ?? "CVE-UNKNOWN",
    vendor: String(vendor).replace(/_/g, " "),
    cwe,
    sev: sevFromCvss(cvss),
    cvss: Number(cvss).toFixed(1),
    kev: Boolean(raw.kev),
    epss: raw.epss != null ? Number(raw.epss).toFixed(2) : "0.00",
    t: raw.t ?? (Date.parse(raw.published ?? "") || Date.now()),
  };
}
