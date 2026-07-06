/* ----------------------------------------------------------------------------
 * MISP connector — threat events / attack telemetry for the GEOINT map + wire
 * Docs: https://www.misp-project.org/openapi/  (POST /events/restSearch)
 * Requires a MISP instance URL + auth key. Proxy through your backend.
 *
 * Return shape: [{ id, src, tgt, sev, ts, info }]
 * --------------------------------------------------------------------------*/

export async function fetchThreatEvents() {
  const base = import.meta.env.VITE_MISP_URL;
  const key = import.meta.env.VITE_MISP_KEY;
  if (!base || !key) throw new Error("MISP_URL / MISP_KEY not set");

  const res = await fetch(`${base}/events/restSearch`, {
    method: "POST",
    headers: { Authorization: key, Accept: "application/json", "Content-Type": "application/json" },
    body: JSON.stringify({ limit: 50, published: true, order: "Event.date desc" }),
  });
  const data = await res.json();

  return (data.response || []).map((e) => ({
    id: e.Event?.uuid,
    info: e.Event?.info,
    sev: mapThreatLevel(e.Event?.threat_level_id),
    ts: Number(e.Event?.timestamp) * 1000,
    src: e.Event?.Orgc?.name,
    tgt: e.Event?.Org?.name,
  }));
}

function mapThreatLevel(id) {
  return { "1": "CRITICAL", "2": "HIGH", "3": "MEDIUM", "4": "LOW" }[String(id)] || "MEDIUM";
}
