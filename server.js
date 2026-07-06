/* ----------------------------------------------------------------------------
 * OM proxy + investigation backend
 *  POST /api/enrich  { indicator }   -> VT + AbuseIPDB + Shodan, correlated
 *  POST /api/om      { system, messages } -> Anthropic, with an enrich tool OM
 *                                            can call to investigate indicators
 *
 * The Anthropic key and all intel keys stay server-side. Run:
 *   ANTHROPIC_API_KEY=sk-ant-... node server.js
 *   (or set keys in .env and use `npm start`)
 * --------------------------------------------------------------------------*/
import express from "express";
import { enrichIndicator, detectType } from "./enrich.js";

const PORT = process.env.OM_PORT || 8787;
const MODEL = process.env.OM_MODEL || "claude-sonnet-4-6";
const KEY = process.env.ANTHROPIC_API_KEY;

const app = express();
app.use(express.json({ limit: "1mb" }));

app.get("/api/health", (_req, res) =>
  res.json({ ok: true, model: MODEL, keyed: Boolean(KEY) })
);

/* ---- indicator enrichment (also used directly by the Investigate panel) ---- */
app.post("/api/enrich", async (req, res) => {
  const indicator = String(req.body?.indicator || "").trim();
  if (!indicator) return res.status(400).json({ error: "indicator required" });
  try {
    res.json(await enrichIndicator(indicator));
  } catch (e) {
    res.status(502).json({ error: "enrich_failed", detail: String(e) });
  }
});

/* ---- the tool OM is allowed to call ---------------------------------------- */
const OM_TOOLS = [
  {
    name: "enrich_indicator",
    description:
      "Investigate an IOC (IPv4, domain, file hash, or URL) across VirusTotal, AbuseIPDB, and Shodan and return a correlated threat verdict. Call this whenever the user asks to investigate, look up, check, or triage an indicator.",
    input_schema: {
      type: "object",
      properties: { indicator: { type: "string", description: "The IP, domain, hash, or URL to investigate." } },
      required: ["indicator"],
    },
  },
];

async function callAnthropic(system, messages) {
  const r = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: { "content-type": "application/json", "x-api-key": KEY, "anthropic-version": "2023-06-01" },
    body: JSON.stringify({ model: MODEL, max_tokens: 1200, system, messages, tools: OM_TOOLS }),
  });
  return r.json();
}

app.post("/api/om", async (req, res) => {
  if (!KEY) return res.status(500).json({ error: "ANTHROPIC_API_KEY not set on server" });
  try {
    const { system, messages } = req.body;
    let convo = [...messages];
    let data = await callAnthropic(system, convo);

    // Tool-use loop: let OM call enrich_indicator and reason over the results.
    for (let i = 0; i < 4 && data.stop_reason === "tool_use"; i++) {
      const toolUses = (data.content || []).filter((c) => c.type === "tool_use");
      const results = [];
      for (const tu of toolUses) {
        let out;
        try { out = await enrichIndicator(tu.input?.indicator); }
        catch (e) { out = { error: String(e) }; }
        results.push({ type: "tool_result", tool_use_id: tu.id, content: JSON.stringify(out) });
      }
      convo.push({ role: "assistant", content: data.content });
      convo.push({ role: "user", content: results });
      data = await callAnthropic(system, convo);
    }
    res.status(200).json(data);
  } catch (e) {
    res.status(502).json({ error: "upstream_failed", detail: String(e) });
  }
});

app.listen(PORT, () =>
  console.log(`OM backend on http://localhost:${PORT} (model: ${MODEL}, keyed: ${Boolean(KEY)})`)
);
