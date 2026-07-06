/* ----------------------------------------------------------------------------
 * CISA ICS-CERT advisories connector
 * Source: https://www.cisa.gov/news-events/cybersecurity-advisories?f%5B0%5D=advisory_type%3A95
 * There is no first-party JSON API; teams typically ingest the RSS/Atom feed
 * or scrape the advisory index on a backend, then normalize to the shape below.
 *
 * Return shape: { id, vendor, prod, sev, cvss, proto, vec }
 * --------------------------------------------------------------------------*/
import { sevFromCvss } from "./normalize.js";

const ICS_RSS = "https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml";

export async function fetchIcsAdvisories() {
  // TODO: fetch ICS_RSS on your backend, parse each <item>, and extract vendor,
  // product, CVSS, affected protocol, and vector from the advisory body.
  const res = await fetch(ICS_RSS);
  const xml = await res.text();
  const items = parseRss(xml);

  return items.map((it) => ({
    id: it.id,
    vendor: it.vendor,
    prod: it.product,
    cvss: Number(it.cvss).toFixed(1),
    sev: sevFromCvss(it.cvss),
    proto: it.protocol || "—",
    vec: it.summary || "",
  }));
}

// Minimal RSS shim — replace with a real parser (fast-xml-parser) on the backend.
function parseRss(_xml) {
  return [];
}
