/* ----------------------------------------------------------------------------
 * Shodan connector — exposed OT/ICS surface counts
 * Docs: https://developer.shodan.io/api  (endpoint: /shodan/host/count)
 * Requires SHODAN_API_KEY. Call from a backend to keep the key off the client.
 *
 * Return shape: [{ proto, count }]
 * --------------------------------------------------------------------------*/

const PROTOCOLS = [
  { proto: "Modbus/TCP", query: "port:502" },
  { proto: "DNP3", query: "port:20000 source" },
  { proto: "EtherNet/IP", query: "port:44818" },
  { proto: "BACnet", query: "port:47808" },
];

export async function fetchExposedOt() {
  const key = import.meta.env.VITE_SHODAN_API_KEY;
  if (!key) throw new Error("SHODAN_API_KEY not set");

  const out = [];
  for (const p of PROTOCOLS) {
    const url = `https://api.shodan.io/shodan/host/count?key=${key}&query=${encodeURIComponent(p.query)}`;
    const res = await fetch(url);
    const data = await res.json();
    out.push({ proto: p.proto, count: data.total ?? 0 });
  }
  return out;
}
