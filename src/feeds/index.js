/* ============================================================================
 * OM // FEED CONNECTORS
 * ----------------------------------------------------------------------------
 * The console ships with realistic SIMULATED data so it runs with zero setup.
 * This module is where you plug in LIVE intelligence sources.
 *
 * Enable live feeds by setting in your .env:
 *     VITE_USE_LIVE_FEEDS=true
 *
 * Each connector returns data already normalized to the shape the UI expects
 * (see src/feeds/normalize.js). Wire more panels by following loadLiveVulnFeed
 * as the template — the mock generators in App.jsx define the target shapes.
 * ==========================================================================*/

import { fetchNvdKev } from "./nvd.js";
import { fetchIcsAdvisories } from "./icscert.js";
import { fetchExposedOt } from "./shodan.js";
import { fetchThreatEvents } from "./misp.js";

export const LIVE_FEEDS_ENABLED = import.meta.env.VITE_USE_LIVE_FEEDS === "true";

/** Real-time vulnerability feed → array of { id, vendor, cwe, sev, cvss, kev, epss, t } */
export async function loadLiveVulnFeed() {
  return fetchNvdKev();
}

/** OT/ICS advisories → array of { id, vendor, prod, sev, cvss, proto, vec } */
export async function loadLiveIcsFeed() {
  return fetchIcsAdvisories();
}

/** Exposed OT surface → array of { proto, count } */
export async function loadLiveExposedOt() {
  return fetchExposedOt();
}

/** Threat events / attack telemetry → array of { id, src, tgt, sev, ts } */
export async function loadLiveThreatEvents() {
  return fetchThreatEvents();
}
