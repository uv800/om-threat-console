import React, { useState, useEffect, useRef, useMemo } from "react";
import { loadLiveVulnFeed, LIVE_FEEDS_ENABLED } from "./feeds/index.js";
import {
  BarChart, Bar, XAxis, YAxis, Cell, ResponsiveContainer, Tooltip,
  RadialBarChart, RadialBar, PolarAngleAxis, AreaChart, Area, CartesianGrid,
} from "recharts";

/* ------------------------------------------------------------------ *
 *  OM // UNIFIED THREAT INTELLIGENCE CONSOLE
 *  Military-tactical OSINT / cyber theme. All feeds are simulated for
 *  demonstration except OM, which calls a live model when available.
 * ------------------------------------------------------------------ */

const T = {
  bg: "#0A0C07",
  bg2: "#0D1009",
  panel: "#14170E",
  panel2: "#191D12",
  line: "#262A1B",
  lineHot: "#3A4126",
  olive: "#A6B24E",     // primary accent (the "OSINT COURSE" khaki-green)
  oliveDim: "#6B7538",
  amber: "#D6A93B",
  red: "#C0453B",
  redHot: "#E5584B",
  bone: "#E9E6D8",
  mute: "#7A825F",
  muteDim: "#565C41",
  cyan: "#5FA8A0",
};

const SEV = {
  CRITICAL: T.red,
  HIGH: T.amber,
  MEDIUM: T.olive,
  LOW: T.cyan,
};

/* ----------------------------- fonts ------------------------------ */
const FontInject = () => (
  <style>{`
    @import url('https://fonts.googleapis.com/css2?family=Oswald:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;700&family=Barlow+Condensed:wght@400;500;600&display=swap');
    * { box-sizing: border-box; }
    ::-webkit-scrollbar { width: 8px; height: 8px; }
    ::-webkit-scrollbar-track { background: ${T.bg}; }
    ::-webkit-scrollbar-thumb { background: ${T.lineHot}; border-radius: 0; }
    @keyframes blink { 0%,49%{opacity:1} 50%,100%{opacity:.25} }
    @keyframes scan { 0%{transform:translateY(-100%)} 100%{transform:translateY(2000%)} }
    @keyframes dash { to { stroke-dashoffset: -1000; } }
    @keyframes pulseNode { 0%{r:2.4;opacity:1} 100%{r:9;opacity:0} }
    @keyframes fadeUp { from{opacity:0;transform:translateY(6px)} to{opacity:1;transform:none} }
    @media (prefers-reduced-motion: reduce) {
      *{animation-duration:.001ms !important; animation-iteration-count:1 !important;}
    }
  `}</style>
);

/* --------------------------- primitives --------------------------- */
function Bracket({ children, label, right, glow, style }) {
  return (
    <div style={{ position: "relative", background: T.panel, border: `1px solid ${T.line}`, ...style }}>
      {["tl", "tr", "bl", "br"].map((c) => (
        <span key={c} style={{
          position: "absolute", width: 9, height: 9, pointerEvents: "none",
          borderColor: glow ? T.olive : T.oliveDim,
          top: c[0] === "t" ? -1 : "auto", bottom: c[0] === "b" ? -1 : "auto",
          left: c[1] === "l" ? -1 : "auto", right: c[1] === "r" ? -1 : "auto",
          borderTop: c[0] === "t" ? "1.5px solid" : "none",
          borderBottom: c[0] === "b" ? "1.5px solid" : "none",
          borderLeft: c[1] === "l" ? "1.5px solid" : "none",
          borderRight: c[1] === "r" ? "1.5px solid" : "none",
        }} />
      ))}
      {(label || right) && (
        <div style={{
          display: "flex", justifyContent: "space-between", alignItems: "center",
          padding: "8px 12px", borderBottom: `1px solid ${T.line}`,
        }}>
          <span style={{
            fontFamily: "Oswald", fontWeight: 600, letterSpacing: "0.14em",
            fontSize: 11, color: T.olive, textTransform: "uppercase",
          }}>{label}</span>
          <span style={{ fontFamily: "JetBrains Mono", fontSize: 10, color: T.mute }}>{right}</span>
        </div>
      )}
      {children}
    </div>
  );
}

const SevTag = ({ s }) => (
  <span style={{
    fontFamily: "JetBrains Mono", fontSize: 9.5, fontWeight: 700, letterSpacing: ".08em",
    color: SEV[s], border: `1px solid ${SEV[s]}55`, background: `${SEV[s]}15`,
    padding: "1px 6px", whiteSpace: "nowrap",
  }}>{s}</span>
);

/* ---------------------------- mock data --------------------------- */
const VENDORS = ["Fortinet", "Cisco IOS", "Palo Alto", "Ivanti", "VMware", "Citrix", "Apache", "Microsoft", "Adobe", "Atlassian", "GitLab", "SonicWall", "Zimbra", "MOVEit", "Juniper"];
const CWE = ["CWE-78 OS Cmd Inj", "CWE-89 SQLi", "CWE-416 Use-After-Free", "CWE-502 Deserialization", "CWE-22 Path Traversal", "CWE-287 Auth Bypass", "CWE-434 File Upload", "CWE-798 Hardcoded Creds"];
const rnd = (a) => a[Math.floor(Math.random() * a.length)];
const pad = (n, l = 4) => String(n).padStart(l, "0");

function makeCVE(i) {
  const roll = Math.random();
  const sev = roll > 0.82 ? "CRITICAL" : roll > 0.5 ? "HIGH" : roll > 0.22 ? "MEDIUM" : "LOW";
  const cvss = sev === "CRITICAL" ? (9 + Math.random()).toFixed(1)
    : sev === "HIGH" ? (7 + Math.random() * 2).toFixed(1)
    : sev === "MEDIUM" ? (4 + Math.random() * 3).toFixed(1)
    : (0.1 + Math.random() * 3.8).toFixed(1);
  return {
    id: `CVE-2026-${pad(1000 + Math.floor(Math.random() * 8999))}`,
    vendor: rnd(VENDORS), cwe: rnd(CWE), sev, cvss,
    kev: Math.random() > 0.72,
    epss: (Math.random()).toFixed(2),
    t: Date.now() - i * 41000,
  };
}

const ICS_ADV = [
  { id: "ICSA-26-041-02", vendor: "Siemens", prod: "SIMATIC S7-1500 PLC", sev: "CRITICAL", cvss: "9.8", proto: "PROFINET", vec: "Unauth RCE via web server" },
  { id: "ICSA-26-039-01", vendor: "Schneider Electric", prod: "EcoStruxure Modicon M340", sev: "HIGH", cvss: "8.6", proto: "Modbus/TCP", vec: "Improper access control" },
  { id: "ICSA-26-037-04", vendor: "Rockwell", prod: "ControlLogix 1756-EN2T", sev: "CRITICAL", cvss: "9.1", proto: "CIP / EtherNet-IP", vec: "Denial of control state" },
  { id: "ICSA-26-034-03", vendor: "GE Vernova", prod: "iFIX SCADA HMI", sev: "HIGH", cvss: "7.8", proto: "OPC-UA", vec: "Privilege escalation" },
  { id: "ICSA-26-031-01", vendor: "Emerson", prod: "DeltaV DCS Controller", sev: "MEDIUM", cvss: "6.4", proto: "Proprietary", vec: "Hardcoded credentials" },
  { id: "ICSA-26-029-02", vendor: "Honeywell", prod: "Experion PKS Server", sev: "CRITICAL", cvss: "9.4", proto: "DNP3", vec: "Path traversal → RCE" },
  { id: "ICSA-26-026-01", vendor: "ABB", prod: "800xA Aspect Server", sev: "HIGH", cvss: "8.1", proto: "IEC 61850", vec: "Unauth config change" },
  { id: "ICSA-26-022-05", vendor: "Mitsubishi", prod: "MELSEC iQ-R Series", sev: "MEDIUM", cvss: "5.9", proto: "SLMP", vec: "Resource exhaustion DoS" },
];

const SECTORS = [
  { name: "Healthcare",    breaches: 47, records: "18.4M", trend: +12, sev: "CRITICAL", note: "Ransomware on EHR + imaging systems" },
  { name: "Power Grid",    breaches: 23, records: "OT",    trend: +31, sev: "CRITICAL", note: "ICS intrusions, RTU manipulation" },
  { name: "Financial",     breaches: 39, records: "9.1M",  trend: -4,  sev: "HIGH",     note: "Credential theft, wire fraud" },
  { name: "Manufacturing", breaches: 34, records: "OT",    trend: +18, sev: "HIGH",     note: "PLC lockouts, IP exfiltration" },
  { name: "Government",    breaches: 28, records: "6.7M",  trend: +7,  sev: "HIGH",     note: "APT espionage campaigns" },
  { name: "Telecom",       breaches: 19, records: "22.0M", trend: +9,  sev: "MEDIUM",   note: "Signaling + subscriber DB access" },
  { name: "Water & Util.", breaches: 14, records: "OT",    trend: +26, sev: "CRITICAL", note: "SCADA HMI exposed to internet" },
  { name: "Transport",     breaches: 11, records: "3.2M",  trend: -2,  sev: "MEDIUM",   note: "Logistics + rail signaling probes" },
];

const NEWS = [
  { src: "SECTOR-CERT", t: "0h", tag: "POWER GRID", sev: "CRITICAL", h: "Threat actor manipulates substation RTUs across two regional operators; load-shed averted", note: "Attribution: state-nexus, ICS-focused" },
  { src: "HEALTH-ISAC", t: "2h", tag: "HEALTHCARE", sev: "CRITICAL", h: "Ransomware crew claims 18M patient records from hospital network; imaging systems offline", note: "Data-leak site countdown active" },
  { src: "OSINT/TELE", t: "4h", tag: "OT/ICS", sev: "HIGH", h: "New wiper variant targeting Modbus + DNP3 devices observed in the wild", note: "IOCs circulating on closed channels" },
  { src: "FIN-CERT", t: "6h", tag: "FINANCIAL", sev: "HIGH", h: "Supply-chain compromise of payment SDK pushes credential stealer to 400+ apps", note: "Package registry pulled 12 builds" },
  { src: "NVD/KEV", t: "7h", tag: "VULN", sev: "CRITICAL", h: "Edge VPN zero-day added to KEV; mass exploitation, patch within 24h mandated", note: "EPSS 0.94 — active scanning" },
  { src: "GOV-SOC", t: "9h", tag: "GOVERNMENT", sev: "MEDIUM", h: "Spear-phishing wave impersonates procurement portal to harvest ministry credentials", note: "Lookalike domains sinkholed" },
  { src: "WATER-ISAC", t: "11h", tag: "WATER", sev: "HIGH", h: "Internet-exposed HMI at treatment plant probed 900+ times in 24h", note: "Setpoints unchanged, access blocked" },
];

/* threat nodes (lon, lat) → projected on the dotted world map */
const NODES = [
  { id: "RU", city: "Moscow", lon: 37.6, lat: 55.7, role: "src" },
  { id: "CN", city: "Beijing", lon: 116.4, lat: 39.9, role: "src" },
  { id: "IR", city: "Tehran", lon: 51.3, lat: 35.6, role: "src" },
  { id: "KP", city: "Pyongyang", lon: 125.7, lat: 39.0, role: "src" },
  { id: "BR", city: "São Paulo", lon: -46.6, lat: -23.5, role: "src" },
  { id: "NG", city: "Lagos", lon: 3.3, lat: 6.5, role: "src" },
  { id: "US", city: "Washington", lon: -77.0, lat: 38.9, role: "tgt" },
  { id: "DE", city: "Frankfurt", lon: 8.6, lat: 50.1, role: "tgt" },
  { id: "IN", city: "Mumbai", lon: 72.8, lat: 19.0, role: "tgt" },
  { id: "SG", city: "Singapore", lon: 103.8, lat: 1.3, role: "tgt" },
  { id: "AU", city: "Sydney", lon: 151.2, lat: -33.8, role: "tgt" },
  { id: "GB", city: "London", lon: -0.1, lat: 51.5, role: "tgt" },
];

/* ---------------- procedural satellite / GEOINT terrain ----------- */
function mulberry32(a) {
  return function () {
    a |= 0; a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
function buildTerrain(W, H) {
  const rng = mulberry32(20260706);
  const roadsX = [], roadsY = [];
  let x = 0; while (x < W) { x += 40 + rng() * 52; roadsX.push(x); }
  let y = 0; while (y < H) { y += 36 + rng() * 44; roadsY.push(y); }
  const xs = [0, ...roadsX, W], ys = [0, ...roadsY, H];
  const bldgs = [];
  for (let i = 0; i < xs.length - 1; i++) {
    for (let j = 0; j < ys.length - 1; j++) {
      const bx = xs[i] + 3, by = ys[j] + 3, bw = xs[i + 1] - xs[i] - 6, bh = ys[j + 1] - ys[j] - 6;
      if (bw < 9 || bh < 9) continue;
      const cols = 1 + Math.floor(rng() * 3), rows = 1 + Math.floor(rng() * 3);
      const cw = bw / cols, ch = bh / rows;
      for (let c = 0; c < cols; c++) for (let r = 0; r < rows; r++) {
        if (rng() < 0.14) continue;
        const p = 1 + rng() * 2;
        bldgs.push({ x: bx + c * cw + p, y: by + r * ch + p, w: Math.max(2, cw - p * 2), h: Math.max(2, ch - p * 2), s: rng() });
      }
    }
  }
  const ry = H * 0.28 + rng() * H * 0.25;
  const river = `M -20 ${ry.toFixed(0)} C ${W * 0.25} ${ry - 70}, ${W * 0.42} ${ry + 100}, ${W * 0.6} ${ry + 20} S ${W * 0.9} ${ry - 50}, ${W + 20} ${ry + 40}`;
  return { roadsX, roadsY, bldgs, river };
}
const shadeOf = (s) => (s < 0.5 ? "#161a10" : s < 0.75 ? "#1d2214" : s < 0.9 ? "#262c1a" : "#333a22");

/* tracked contacts on the GEOINT feed */
const TRACKS = [
  { id: "TRK-01", xf: 0.29, yf: 0.32, status: "LOCKED",    type: "HOSTILE", desig: "C2 NODE",  mgrs: "38S MC 4471 8823" },
  { id: "TRK-02", xf: 0.67, yf: 0.50, status: "ACQUIRING", type: "UNKNOWN", desig: "BEACON",   mgrs: "38S MC 5188 7402" },
  { id: "TRK-03", xf: 0.47, yf: 0.74, status: "TRACKING",  type: "ASSET",   desig: "FRIENDLY", mgrs: "38S MC 4903 6217" },
];
const trackCol = (t) => (t === "HOSTILE" ? T.red : t === "UNKNOWN" ? T.amber : T.olive);

/* ------------------ GEOINT SATELLITE TACTICAL MAP ----------------- */
function ThreatMap({ compact }) {
  const W = 960, H = 500;
  const terr = useMemo(() => buildTerrain(W, H), []);
  const cx = W * 0.5, cy = H * 0.5, R = Math.hypot(W, H);
  const sweep = useMemo(() => {
    const a = (18 * Math.PI) / 180;
    const p2 = [cx + R * Math.cos(-a), cy + R * Math.sin(-a)];
    const p3 = [cx + R * Math.cos(a), cy + R * Math.sin(a)];
    return { d: `M${cx} ${cy} L${p2[0].toFixed(0)} ${p2[1].toFixed(0)} A${R} ${R} 0 0 1 ${p3[0].toFixed(0)} ${p3[1].toFixed(0)} Z`, edge: p3 };
  }, []);

  const [hud, setHud] = useState({ lat: "34.7182", lon: "44.3861", hdg: "073", frame: 4021 });
  useEffect(() => {
    const id = setInterval(() => setHud((h) => ({
      lat: (34.7182 + (Math.random() - 0.5) * 0.005).toFixed(4),
      lon: (44.3861 + (Math.random() - 0.5) * 0.005).toFixed(4),
      hdg: String(70 + Math.floor(Math.random() * 9)).padStart(3, "0"),
      frame: h.frame + Math.floor(Math.random() * 6 + 22),
    })), 1000);
    return () => clearInterval(id);
  }, []);

  const cornerBox = (X, Y, S, L) => [
    `M${X - S} ${Y - S + L} V${Y - S} H${X - S + L}`,
    `M${X + S - L} ${Y - S} H${X + S} V${Y - S + L}`,
    `M${X + S} ${Y + S - L} V${Y + S} H${X + S - L}`,
    `M${X - S + L} ${Y + S} H${X - S} V${Y + S - L}`,
  ];

  return (
    <div style={{ position: "relative", width: "100%", background: "#0B0E08", overflow: "hidden" }}>
      <style>{`
        @keyframes radar{to{transform:rotate(360deg)}}
        @keyframes spin{to{transform:rotate(360deg)}}
        @keyframes geoscan{0%{top:-4%}100%{top:104%}}
      `}</style>
      <svg viewBox={`0 0 ${W} ${H}`} style={{ width: "100%", display: "block" }} preserveAspectRatio="xMidYMid slice">
        <defs>
          <radialGradient id="sweepGrad" cx={cx} cy={cy} r={R} gradientUnits="userSpaceOnUse">
            <stop offset="0" stopColor={T.olive} stopOpacity="0.30" />
            <stop offset="0.5" stopColor={T.olive} stopOpacity="0.06" />
            <stop offset="1" stopColor={T.olive} stopOpacity="0" />
          </radialGradient>
          <radialGradient id="vign" cx="50%" cy="50%" r="72%">
            <stop offset="60%" stopColor="#000" stopOpacity="0" />
            <stop offset="100%" stopColor="#000" stopOpacity="0.55" />
          </radialGradient>
        </defs>

        {/* satellite terrain: dark ground */}
        <rect x="0" y="0" width={W} height={H} fill="#0D110A" />
        {/* building footprints */}
        <g>
          {terr.bldgs.map((b, i) => (
            <rect key={i} x={b.x} y={b.y} width={b.w} height={b.h} fill={shadeOf(b.s)} />
          ))}
        </g>
        {/* river */}
        <path d={terr.river} fill="none" stroke="#12211f" strokeWidth="16" opacity="0.8" />
        <path d={terr.river} fill="none" stroke="#1c3330" strokeWidth="6" opacity="0.6" />
        {/* roads */}
        <g stroke="#080a05" strokeWidth="4" opacity="0.85">
          {terr.roadsX.map((rx, i) => <line key={"rx" + i} x1={rx} y1={0} x2={rx} y2={H} />)}
          {terr.roadsY.map((ry, i) => <line key={"ry" + i} x1={0} y1={ry} x2={W} y2={ry} />)}
        </g>

        {/* radar sweep */}
        <g style={{ transformOrigin: `${cx}px ${cy}px`, animation: "radar 6s linear infinite" }}>
          <path d={sweep.d} fill="url(#sweepGrad)" />
          <line x1={cx} y1={cy} x2={sweep.edge[0]} y2={sweep.edge[1]} stroke={T.olive} strokeWidth="1.4" opacity="0.7" />
        </g>

        {/* MGRS coordinate grid */}
        <g stroke={T.olive} strokeWidth="0.5" opacity="0.18">
          {[...Array(9)].map((_, i) => <line key={"gv" + i} x1={(W / 8) * i} y1={0} x2={(W / 8) * i} y2={H} />)}
          {[...Array(7)].map((_, i) => <line key={"gh" + i} x1={0} y1={(H / 6) * i} x2={W} y2={(H / 6) * i} />)}
        </g>
        {!compact && (
          <g fontFamily="JetBrains Mono" fontSize="9" fill={T.oliveDim} opacity="0.85">
            {[...Array(8)].map((_, i) => <text key={"lx" + i} x={(W / 8) * i + 4} y={13}>{`0${44 + i}°E`}</text>)}
            {[...Array(6)].map((_, i) => <text key={"ly" + i} x={4} y={(H / 6) * i + 26}>{`${35 - i}°N`}</text>)}
          </g>
        )}

        {/* range rings + boresight crosshair at sensor center */}
        <g stroke={T.olive} fill="none" opacity="0.22">
          {[70, 140, 210].map((r) => <circle key={r} cx={cx} cy={cy} r={r} strokeWidth="0.8" />)}
        </g>
        <g stroke={T.olive} strokeWidth="1">
          <line x1={cx - 16} y1={cy} x2={cx + 16} y2={cy} />
          <line x1={cx} y1={cy - 16} x2={cx} y2={cy + 16} />
        </g>

        {/* moving UAV contact with tracking gate */}
        <g>
          <g>
            <animateMotion dur="20s" repeatCount="indefinite" path={`M120 ${H * 0.9} Q ${W * 0.5} ${H * 0.55} ${W - 90} ${H * 0.82}`} />
            {cornerBox(0, 0, 13, 5).map((d, i) => <path key={i} d={d} fill="none" stroke={T.amber} strokeWidth="1.3" />)}
            <path d="M0 -6 L4 5 L0 2 L-4 5 Z" fill={T.amber} />
            <text x="18" y="3" fill={T.amber} fontFamily="JetBrains Mono" fontSize="8">UAV-07</text>
          </g>
        </g>

        {/* target-lock reticles */}
        {TRACKS.map((t) => {
          const X = t.xf * W, Y = t.yf * H, col = trackCol(t.type), S = 20, L = 7;
          return (
            <g key={t.id}>
              <circle cx={X} cy={Y} r={S} fill="none" stroke={col} strokeWidth="1" opacity="0.6">
                <animate attributeName="r" values={`${S};${S + 18}`} dur="2.4s" repeatCount="indefinite" />
                <animate attributeName="opacity" values="0.55;0" dur="2.4s" repeatCount="indefinite" />
              </circle>
              {t.status === "ACQUIRING" && (
                <circle cx={X} cy={Y} r={S + 5} fill="none" stroke={col} strokeWidth="1" strokeDasharray="3 5"
                  style={{ transformOrigin: `${X}px ${Y}px`, animation: "spin 4s linear infinite" }} opacity="0.8" />
              )}
              {cornerBox(X, Y, S, L).map((d, i) => <path key={i} d={d} fill="none" stroke={col} strokeWidth="1.5" />)}
              <line x1={X - S} y1={Y} x2={X - S + 6} y2={Y} stroke={col} strokeWidth="1.2" />
              <line x1={X + S - 6} y1={Y} x2={X + S} y2={Y} stroke={col} strokeWidth="1.2" />
              <line x1={X} y1={Y - S} x2={X} y2={Y - S + 6} stroke={col} strokeWidth="1.2" />
              <line x1={X} y1={Y + S - 6} x2={X} y2={Y + S} stroke={col} strokeWidth="1.2" />
              <circle cx={X} cy={Y} r="1.8" fill={col} />
              {!compact && (
                <g fontFamily="JetBrains Mono">
                  <line x1={X + S} y1={Y - S} x2={X + S + 14} y2={Y - S - 8} stroke={col} strokeWidth="0.8" opacity="0.7" />
                  <text x={X + S + 16} y={Y - S - 10} fill={col} fontSize="10" fontWeight="700">{t.id} · {t.type}</text>
                  <text x={X + S + 16} y={Y - S + 2} fill={col} fontSize="8.5" opacity="0.85">{t.status} // {t.desig}</text>
                  <text x={X + S + 16} y={Y - S + 13} fill={T.mute} fontSize="8">{t.mgrs}</text>
                </g>
              )}
            </g>
          );
        })}

        {/* passive sensor blips */}
        <g fill={T.olive} opacity="0.5">
          {[[0.13,0.6],[0.83,0.28],[0.58,0.2],[0.22,0.85],[0.75,0.68],[0.4,0.45]].map(([fx,fy],i)=>(
            <circle key={i} cx={fx*W} cy={fy*H} r="1.6"><animate attributeName="opacity" values="0.15;0.7;0.15" dur={`${2+i*0.4}s`} repeatCount="indefinite"/></circle>
          ))}
        </g>

        <rect x="0" y="0" width={W} height={H} fill="url(#vign)" pointerEvents="none" />
        {/* frame corner brackets */}
        <g stroke={T.olive} strokeWidth="1.5" fill="none">
          <path d="M14 34 V14 H34" /><path d={`M${W-34} 14 H${W-14} V34`} />
          <path d={`M14 ${H-34} V${H-14} H34`} /><path d={`M${W-34} ${H-14} H${W-14} V${H-34}`} />
        </g>
      </svg>

      {/* moving sensor scan bar */}
      <div style={{ position: "absolute", left: 0, right: 0, height: 2, background: `${T.olive}55`,
        boxShadow: `0 0 12px ${T.olive}`, animation: "geoscan 4.5s linear infinite", pointerEvents: "none" }} />

      {/* HUD overlays */}
      <div style={{ position: "absolute", inset: 0, pointerEvents: "none", fontFamily: "JetBrains Mono" }}>
        <div style={{ position: "absolute", top: 10, left: 14, display: "flex", flexDirection: "column", gap: 6 }}>
          <span style={{ fontSize: 9.5, color: T.amber, border: `1px solid ${T.amber}`, background: `${T.amber}14`, padding: "2px 7px", letterSpacing: ".12em" }}>
            UNCLAS // GEOINT-DEMO
          </span>
          {!compact && <span style={{ fontSize: 9.5, color: T.olive, letterSpacing: ".08em" }}>EO/IR FMV · SLANT RANGE 6.2KM</span>}
        </div>
        <div style={{ position: "absolute", top: 10, right: 14, textAlign: "right", display: "flex", flexDirection: "column", gap: 3 }}>
          <span style={{ display: "flex", alignItems: "center", gap: 6, justifyContent: "flex-end", fontSize: 10, color: T.red }}>
            <span style={{ width: 7, height: 7, borderRadius: 7, background: T.red, animation: "blink 1s infinite" }} />REC · LIVE
          </span>
          <span style={{ fontSize: 10, color: T.bone }}>LAT {hud.lat}°N</span>
          <span style={{ fontSize: 10, color: T.bone }}>LON {hud.lon}°E</span>
          <span style={{ fontSize: 10, color: T.olive }}>HDG {hud.hdg}° · FRM {hud.frame}</span>
        </div>
        {!compact && (
          <>
            <div style={{ position: "absolute", bottom: 34, left: 14, fontSize: 9.5, color: T.olive, opacity: 0.9 }}>
              SENSOR: MX-25D · ALT 22,000FT · ZOOM ×8 · GIMBAL AUTO
            </div>
            <div style={{ position: "absolute", bottom: 10, left: 14, display: "flex", gap: 16 }}>
              {[["HOSTILE", T.red], ["UNKNOWN", T.amber], ["FRIENDLY", T.olive]].map(([l, c]) => (
                <span key={l} style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 9, color: T.mute }}>
                  <span style={{ width: 8, height: 8, border: `1.5px solid ${c}`, display: "inline-block" }} /> {l}
                </span>
              ))}
            </div>
            <div style={{ position: "absolute", bottom: 10, right: 14, fontSize: 9.5, color: T.mute }}>
              TRACKS: {TRACKS.length} · SWEEP 60RPM · LINK ●
            </div>
          </>
        )}
      </div>
    </div>
  );
}

/* --------------------------- STAT TILE ---------------------------- */
function Stat({ label, value, sub, accent = T.olive, blink }) {
  return (
    <Bracket style={{ padding: 0 }}>
      <div style={{ padding: "13px 15px" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 6 }}>
          {blink && <span style={{ width: 6, height: 6, borderRadius: 6, background: accent, animation: "blink 1.4s infinite" }} />}
          <span style={{ fontFamily: "Barlow Condensed", fontSize: 12, letterSpacing: ".18em", color: T.mute, textTransform: "uppercase" }}>{label}</span>
        </div>
        <div style={{ fontFamily: "Oswald", fontWeight: 700, fontSize: 30, lineHeight: 1, color: accent }}>{value}</div>
        <div style={{ fontFamily: "JetBrains Mono", fontSize: 10, color: T.mute, marginTop: 6 }}>{sub}</div>
      </div>
    </Bracket>
  );
}

/* ============================ OM AGENT ============================ */
const OM_SYSTEM = `You are OM, an AI intelligence analyst embedded in a unified cyber threat-intelligence console used by a SOC / threat-hunting team. You are precise, calm, and tactical. Domains you cover: threat hunting, investigation, incident response (IR), OSINT, and malware sandbox analysis.

Formatting rules:
- Lead with a one-line tactical read.
- Then give concrete, actionable steps as short lines. Use hunt hypotheses, MITRE ATT&CK technique IDs (e.g. T1059), KQL/SPL/Sigma pointers, or IR phase (Prepare/Identify/Contain/Eradicate/Recover) where relevant.
- Reference specific tools/log sources when useful (EDR, Sysmon event IDs, Zeek, Suricata, VirusTotal, Shodan, Censys, urlscan, MISP, Cuckoo/CAPE/Joe Sandbox, MaxMind).
- Keep it under ~180 words. No fluff, no disclaimers. You assist defenders only.

TOOL: You have an enrich_indicator tool that runs a LIVE lookup on an IP, domain, hash, or URL across VirusTotal, AbuseIPDB, and Shodan. When the user asks you to investigate / look up / check / triage an indicator, CALL the tool first, then base your verdict on the returned data — never guess reputation from memory. Cite the concrete numbers it returns (VT detections, AbuseIPDB confidence, open ports, CVEs) and give the analyst a clear next step.`;

const OM_FALLBACK = (q) => {
  const l = q.toLowerCase();
  if (/incident|ir|respon|contain|breach/.test(l))
    return "TACTICAL READ — treat as active until scoped.\n\n1. IDENTIFY: pull EDR timeline for patient-zero, isolate host at network layer (keep powered for memory).\n2. SCOPE: hunt the same IOC/TTP across the fleet — parent-child process anomalies, T1059 script exec, T1055 injection.\n3. CONTAIN: block C2 at egress, disable compromised creds, rotate service accounts.\n4. ERADICATE: remove persistence (T1547 run keys, scheduled tasks, WMI subs).\n5. RECOVER: rebuild from known-good, validate with a hunt sweep before reconnect.\n\n[OM fallback mode — live model unavailable]";
  if (/hunt|detect|sigma|kql|spl/.test(l))
    return "TACTICAL READ — start from a hypothesis, not a tool.\n\n• Hypothesis: adversary uses living-off-the-land binaries.\n• Data: Sysmon EID 1 (proc create), EID 3 (net conn), EID 11 (file).\n• Hunt: rare parent→child pairs, encoded PowerShell (T1059.001), rundll32/regsvr32 spawning net conns.\n• Pivot: LOLBAS against outbound to new ASNs; enrich with GeoIP + passive DNS.\n• Codify wins into a Sigma rule and push to detection pipeline.\n\n[OM fallback mode — live model unavailable]";
  if (/osint|shodan|recon|attribut/.test(l))
    return "TACTICAL READ — collect, verify, then attribute cautiously.\n\n• Infra: Shodan/Censys for exposed services, TLS cert pivots, favicon hashes.\n• Domains: passive DNS, WHOIS history, urlscan for lookalikes.\n• Actor: map TTPs to MITRE, cross-ref MISP/OTX feeds — never attribute on infra alone.\n• Exposure: check your own org surface the same way an adversary would.\n\n[OM fallback mode — live model unavailable]";
  if (/sandbox|malware|detonat|sample|hash/.test(l))
    return "TACTICAL READ — detonate isolated, capture everything.\n\n• Submit hash to VirusTotal first (don't burn the sample if already public).\n• Detonate in CAPE/Cuckoo/Joe with network sim; capture proc tree, dropped files, registry, C2 beacons.\n• Extract: mutexes, C2 domains/IPs, config; classify by family.\n• Output IOCs to MISP, generate Sigma/YARA, distribute to detection.\n\n[OM fallback mode — live model unavailable]";
  return "TACTICAL READ — I cover threat hunting, investigation, incident response, OSINT, and sandbox analysis. Give me an IOC, a host, an alert, or a hypothesis and I'll build the play.\n\n[OM fallback mode — live model unavailable]";
};

function OMChat() {
  const [msgs, setMsgs] = useState([
    { r: "om", t: "OM online. Threat-intel context loaded. Ask me about threat hunting, investigation, incident response, OSINT, or sandbox analysis — or drop an IOC and I'll build the play." },
  ]);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const endRef = useRef(null);
  useEffect(() => { endRef.current?.scrollIntoView({ behavior: "smooth" }); }, [msgs, busy]);

  const send = async (text) => {
    const q = (text ?? input).trim();
    if (!q || busy) return;
    setInput("");
    const history = [...msgs, { r: "user", t: q }];
    setMsgs(history);
    setBusy(true);
    try {
      // Calls the local OM proxy (server.js), which injects the Anthropic API
      // key server-side. If the proxy is not running, we fall back to the
      // built-in playbook below so the console always responds.
      const endpoint = import.meta.env.VITE_OM_ENDPOINT || "/api/om";
      const res = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          system: OM_SYSTEM,
          messages: history.map((m) => ({ role: m.r === "user" ? "user" : "assistant", content: m.t })),
        }),
      });
      if (!res.ok) throw new Error("api");
      const data = await res.json();
      const out = (data.content || []).filter((c) => c.type === "text").map((c) => c.text).join("\n").trim();
      setMsgs((m) => [...m, { r: "om", t: out || OM_FALLBACK(q) }]);
    } catch {
      setMsgs((m) => [...m, { r: "om", t: OM_FALLBACK(q) }]);
    } finally {
      setBusy(false);
    }
  };

  const chips = ["Investigate 185.220.101.44", "Build a hunt for LOLBAS abuse", "IR steps for ransomware on EHR", "Sandbox this dropper safely"];

  return (
    <Bracket label="OM // AI Intelligence Analyst" right="CTX: THREAT-INTEL" glow style={{ display: "flex", flexDirection: "column", height: "100%" }}>
      <div style={{ flex: 1, overflowY: "auto", padding: 14, display: "flex", flexDirection: "column", gap: 12, minHeight: 260 }}>
        {msgs.map((m, i) => (
          <div key={i} style={{ animation: "fadeUp .25s ease", alignSelf: m.r === "user" ? "flex-end" : "flex-start", maxWidth: "88%" }}>
            <div style={{ fontFamily: "JetBrains Mono", fontSize: 9, letterSpacing: ".1em", color: m.r === "user" ? T.mute : T.olive, marginBottom: 4 }}>
              {m.r === "user" ? "ANALYST" : "◆ OM"}
            </div>
            <div style={{
              fontFamily: m.r === "user" ? "Barlow Condensed" : "JetBrains Mono",
              fontSize: m.r === "user" ? 15 : 12.5, lineHeight: 1.55, whiteSpace: "pre-wrap",
              color: m.r === "user" ? T.bone : "#CFD3B8",
              background: m.r === "user" ? T.panel2 : "#10130B",
              border: `1px solid ${m.r === "user" ? T.line : T.lineHot}`,
              padding: "9px 12px",
            }}>{m.t}</div>
          </div>
        ))}
        {busy && (
          <div style={{ fontFamily: "JetBrains Mono", fontSize: 11, color: T.olive }}>
            ◆ OM analyzing<span style={{ animation: "blink 1s infinite" }}>_</span>
          </div>
        )}
        <div ref={endRef} />
      </div>
      <div style={{ display: "flex", gap: 6, flexWrap: "wrap", padding: "0 14px 10px" }}>
        {chips.map((c) => (
          <button key={c} onClick={() => send(c)} disabled={busy} style={{
            fontFamily: "Barlow Condensed", fontSize: 12, color: T.olive, background: "transparent",
            border: `1px solid ${T.lineHot}`, padding: "4px 9px", cursor: "pointer", letterSpacing: ".03em",
          }}>{c}</button>
        ))}
      </div>
      <div style={{ display: "flex", borderTop: `1px solid ${T.line}` }}>
        <input
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && send()}
          placeholder="Query OM — IOC, host, alert, or hypothesis…"
          style={{
            flex: 1, background: T.bg, border: "none", outline: "none", color: T.bone,
            fontFamily: "JetBrains Mono", fontSize: 12.5, padding: "12px 14px",
          }}
        />
        <button onClick={() => send()} disabled={busy} style={{
          fontFamily: "Oswald", fontWeight: 600, letterSpacing: ".1em", fontSize: 12,
          background: T.olive, color: T.bg, border: "none", padding: "0 20px", cursor: "pointer",
        }}>SEND</button>
      </div>
    </Bracket>
  );
}

/* --------------------------- VULN FEED ---------------------------- */
function VulnFeed({ rows }) {
  return (
    <Bracket label="Real-Time Vulnerability Feed" right={`${rows.length} TRACKED · NVD/KEV`} style={{ height: "100%" }}>
      <div style={{ maxHeight: 520, overflowY: "auto" }}>
        {rows.map((v, i) => (
          <div key={v.id + i} style={{
            display: "grid", gridTemplateColumns: "1.3fr 1.5fr 0.9fr auto", gap: 10, alignItems: "center",
            padding: "10px 14px", borderBottom: `1px solid ${T.line}`,
            animation: i === 0 ? "fadeUp .4s ease" : "none",
          }}>
            <div>
              <div style={{ fontFamily: "JetBrains Mono", fontSize: 12, color: T.bone }}>{v.id}</div>
              <div style={{ fontFamily: "Barlow Condensed", fontSize: 12, color: T.mute }}>{v.vendor}</div>
            </div>
            <div style={{ fontFamily: "JetBrains Mono", fontSize: 11, color: T.muteDim }}>
              {v.cwe}
              <div style={{ color: T.mute, marginTop: 2 }}>EPSS {v.epss}</div>
            </div>
            <div style={{ display: "flex", flexDirection: "column", gap: 4, alignItems: "flex-start" }}>
              <SevTag s={v.sev} />
              {v.kev && <span style={{ fontFamily: "JetBrains Mono", fontSize: 9, color: T.red, letterSpacing: ".08em" }}>▲ KEV EXPLOITED</span>}
            </div>
            <div style={{ fontFamily: "Oswald", fontWeight: 700, fontSize: 22, color: SEV[v.sev], minWidth: 44, textAlign: "right" }}>{v.cvss}</div>
          </div>
        ))}
      </div>
    </Bracket>
  );
}

/* ---------------------------- OT / ICS ---------------------------- */
function OTICS() {
  const chartData = ["Siemens", "Schneider", "Rockwell", "GE", "Honeywell", "ABB", "Mitsubishi"].map((v) => ({
    v, n: 2 + Math.floor(Math.random() * 8),
  }));
  return (
    <div style={{ display: "grid", gridTemplateColumns: "1.6fr 1fr", gap: 16 }}>
      <Bracket label="OT / ICS Vulnerability Advisories" right="ICS-CERT MIRROR">
        <div style={{ maxHeight: 520, overflowY: "auto" }}>
          {ICS_ADV.map((a) => (
            <div key={a.id} style={{ padding: "12px 14px", borderBottom: `1px solid ${T.line}` }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <span style={{ fontFamily: "JetBrains Mono", fontSize: 12, color: T.bone }}>{a.id}</span>
                <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                  <SevTag s={a.sev} />
                  <span style={{ fontFamily: "Oswald", fontWeight: 700, fontSize: 18, color: SEV[a.sev] }}>{a.cvss}</span>
                </div>
              </div>
              <div style={{ fontFamily: "Barlow Condensed", fontSize: 15, color: T.olive, marginTop: 3, letterSpacing: ".02em" }}>
                {a.vendor} — {a.prod}
              </div>
              <div style={{ display: "flex", gap: 14, marginTop: 5, fontFamily: "JetBrains Mono", fontSize: 10.5, color: T.mute }}>
                <span>PROTO: {a.proto}</span>
                <span style={{ color: T.muteDim }}>│</span>
                <span>{a.vec}</span>
              </div>
            </div>
          ))}
        </div>
      </Bracket>
      <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
        <Bracket label="Advisories by Vendor" right="LAST 90D">
          <div style={{ padding: "10px 8px 4px", height: 240 }}>
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={chartData} layout="vertical" margin={{ left: 8, right: 18 }}>
                <XAxis type="number" hide />
                <YAxis type="category" dataKey="v" width={72} tick={{ fill: T.mute, fontSize: 11, fontFamily: "Barlow Condensed" }} axisLine={false} tickLine={false} />
                <Tooltip cursor={{ fill: "#ffffff08" }} contentStyle={{ background: T.panel, border: `1px solid ${T.lineHot}`, fontFamily: "JetBrains Mono", fontSize: 11 }} />
                <Bar dataKey="n" barSize={13}>
                  {chartData.map((_, i) => <Cell key={i} fill={i < 2 ? T.amber : T.oliveDim} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Bracket>
        <Bracket label="Exposed OT Surface" right="SHODAN SNAPSHOT">
          <div style={{ padding: 14, display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
            {[["Modbus/TCP", "1,284", T.red], ["DNP3", "612", T.amber], ["EtherNet/IP", "938", T.amber], ["BACnet", "2,077", T.olive]].map(([p, n, c]) => (
              <div key={p} style={{ border: `1px solid ${T.line}`, padding: "10px 12px" }}>
                <div style={{ fontFamily: "Oswald", fontWeight: 700, fontSize: 22, color: c }}>{n}</div>
                <div style={{ fontFamily: "JetBrains Mono", fontSize: 10, color: T.mute }}>{p} exposed</div>
              </div>
            ))}
          </div>
        </Bracket>
      </div>
    </div>
  );
}

/* ------------------------- SECTOR BREACH -------------------------- */
function SectorBreach() {
  const chart = SECTORS.map((s) => ({ name: s.name, n: s.breaches, sev: s.sev }));
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill,minmax(230px,1fr))", gap: 12 }}>
        {SECTORS.map((s) => (
          <Bracket key={s.name} glow={s.sev === "CRITICAL"} style={{ padding: 0 }}>
            <div style={{ height: 3, background: SEV[s.sev] }} />
            <div style={{ padding: "12px 14px" }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
                <span style={{ fontFamily: "Oswald", fontWeight: 600, fontSize: 16, color: T.bone, letterSpacing: ".02em" }}>{s.name}</span>
                <SevTag s={s.sev} />
              </div>
              <div style={{ display: "flex", alignItems: "baseline", gap: 8, marginTop: 8 }}>
                <span style={{ fontFamily: "Oswald", fontWeight: 700, fontSize: 34, color: SEV[s.sev], lineHeight: 1 }}>{s.breaches}</span>
                <span style={{ fontFamily: "Barlow Condensed", fontSize: 13, color: T.mute }}>incidents</span>
                <span style={{
                  marginLeft: "auto", fontFamily: "JetBrains Mono", fontSize: 11,
                  color: s.trend >= 0 ? T.red : T.olive,
                }}>{s.trend >= 0 ? "▲" : "▼"}{Math.abs(s.trend)}%</span>
              </div>
              <div style={{ fontFamily: "JetBrains Mono", fontSize: 10, color: T.mute, marginTop: 8 }}>
                RECORDS: <span style={{ color: T.amber }}>{s.records}</span>
              </div>
              <div style={{ fontFamily: "Barlow Condensed", fontSize: 12.5, color: T.muteDim, marginTop: 6, lineHeight: 1.35 }}>{s.note}</div>
            </div>
          </Bracket>
        ))}
      </div>
      <Bracket label="Breach Volume by Sector" right="ROLLING 30 DAYS">
        <div style={{ padding: "14px 10px 4px", height: 280 }}>
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={chart} margin={{ top: 8, right: 14, left: -8 }}>
              <CartesianGrid stroke={T.line} vertical={false} />
              <XAxis dataKey="name" tick={{ fill: T.mute, fontSize: 10, fontFamily: "Barlow Condensed" }} axisLine={{ stroke: T.line }} tickLine={false} interval={0} angle={-18} textAnchor="end" height={54} />
              <YAxis tick={{ fill: T.mute, fontSize: 10, fontFamily: "JetBrains Mono" }} axisLine={false} tickLine={false} />
              <Tooltip cursor={{ fill: "#ffffff08" }} contentStyle={{ background: T.panel, border: `1px solid ${T.lineHot}`, fontFamily: "JetBrains Mono", fontSize: 11 }} />
              <Bar dataKey="n" barSize={26}>
                {chart.map((c, i) => <Cell key={i} fill={SEV[c.sev]} />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </Bracket>
    </div>
  );
}

/* ----------------------------- NEWS ------------------------------- */
function NewsFeed() {
  return (
    <Bracket label="Cyber Attack Intelligence Wire" right="MULTI-SOURCE · OSINT">
      <div>
        {NEWS.map((n, i) => (
          <div key={i} style={{ display: "grid", gridTemplateColumns: "auto 1fr auto", gap: 14, padding: "14px 16px", borderBottom: `1px solid ${T.line}`, alignItems: "start" }}>
            <div style={{ width: 4, alignSelf: "stretch", background: SEV[n.sev] }} />
            <div>
              <div style={{ display: "flex", gap: 10, alignItems: "center", marginBottom: 5, flexWrap: "wrap" }}>
                <span style={{ fontFamily: "JetBrains Mono", fontSize: 9.5, color: T.olive, border: `1px solid ${T.lineHot}`, padding: "1px 6px", letterSpacing: ".06em" }}>{n.tag}</span>
                <SevTag s={n.sev} />
                <span style={{ fontFamily: "JetBrains Mono", fontSize: 10, color: T.mute }}>{n.src}</span>
              </div>
              <div style={{ fontFamily: "Barlow Condensed", fontSize: 16.5, color: T.bone, lineHeight: 1.3, letterSpacing: ".01em" }}>{n.h}</div>
              <div style={{ fontFamily: "JetBrains Mono", fontSize: 10.5, color: T.muteDim, marginTop: 4 }}>▸ {n.note}</div>
            </div>
            <span style={{ fontFamily: "JetBrains Mono", fontSize: 11, color: T.mute, whiteSpace: "nowrap" }}>{n.t} ago</span>
          </div>
        ))}
      </div>
    </Bracket>
  );
}

/* ------------------------- INVESTIGATE PANEL ---------------------- */
const verdictColor = (l) =>
  l === "MALICIOUS" ? T.red : l === "SUSPICIOUS" ? T.amber : l === "LOW-RISK" ? T.cyan : T.olive;

function SrcRow({ k, v }) {
  return (
    <div style={{ display: "flex", justifyContent: "space-between", gap: 12, padding: "5px 0", borderBottom: `1px solid ${T.line}` }}>
      <span style={{ fontFamily: "JetBrains Mono", fontSize: 10.5, color: T.mute }}>{k}</span>
      <span style={{ fontFamily: "JetBrains Mono", fontSize: 11, color: T.bone, textAlign: "right", wordBreak: "break-word" }}>{v}</span>
    </div>
  );
}

function InvestigatePanel() {
  const [ind, setInd] = useState("");
  const [busy, setBusy] = useState(false);
  const [rep, setRep] = useState(null);
  const [err, setErr] = useState("");

  const run = async (val) => {
    const q = (val ?? ind).trim();
    if (!q || busy) return;
    setInd(q); setBusy(true); setErr(""); setRep(null);
    try {
      const endpoint = import.meta.env.VITE_ENRICH_ENDPOINT || "/api/enrich";
      const res = await fetch(endpoint, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ indicator: q }),
      });
      const data = await res.json();
      if (data.error) setErr(data.error);
      else setRep(data);
    } catch {
      setErr("Backend unreachable. Start the enrichment server (npm start) to run live lookups.");
    } finally { setBusy(false); }
  };

  const vt = rep?.sources?.virustotal, ab = rep?.sources?.abuseipdb, sh = rep?.sources?.shodan;

  return (
    <div style={{ display: "grid", gridTemplateColumns: "1fr", gap: 16 }}>
      <Bracket label="Indicator Investigation" right="VT · ABUSEIPDB · SHODAN" glow>
        <div style={{ padding: 16 }}>
          <div style={{ display: "flex", gap: 8 }}>
            <input
              value={ind}
              onChange={(e) => setInd(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && run()}
              placeholder="Enter an IP, domain, hash, or URL…"
              style={{ flex: 1, background: T.bg, border: `1px solid ${T.lineHot}`, outline: "none", color: T.bone, fontFamily: "JetBrains Mono", fontSize: 13, padding: "12px 14px" }}
            />
            <button onClick={() => run()} disabled={busy} style={{ fontFamily: "Oswald", fontWeight: 700, letterSpacing: ".1em", fontSize: 13, background: T.olive, color: T.bg, border: "none", padding: "0 22px", cursor: "pointer" }}>
              {busy ? "RUNNING…" : "INVESTIGATE"}
            </button>
          </div>
          <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginTop: 10 }}>
            {["185.220.101.44", "google.com", "44d88612fea8a8f36de82e1278abb02f"].map((s) => (
              <button key={s} onClick={() => run(s)} disabled={busy} style={{ fontFamily: "JetBrains Mono", fontSize: 11, color: T.mute, background: "transparent", border: `1px solid ${T.line}`, padding: "3px 8px", cursor: "pointer" }}>{s}</button>
            ))}
          </div>
          {err && <div style={{ fontFamily: "JetBrains Mono", fontSize: 12, color: T.red, marginTop: 12 }}>▲ {err}</div>}
        </div>
      </Bracket>

      {rep && (
        <>
          <Bracket label="Correlated Verdict" right={`TYPE: ${rep.type?.toUpperCase()} · ${new Date(rep.ts).toISOString().slice(11, 19)}Z`}>
            <div style={{ padding: 16, display: "flex", alignItems: "center", gap: 20, flexWrap: "wrap" }}>
              <div style={{ border: `2px solid ${verdictColor(rep.verdict.level)}`, padding: "10px 20px", minWidth: 160 }}>
                <div style={{ fontFamily: "Barlow Condensed", fontSize: 12, letterSpacing: ".18em", color: T.mute }}>ASSESSMENT</div>
                <div style={{ fontFamily: "Oswald", fontWeight: 700, fontSize: 30, color: verdictColor(rep.verdict.level), lineHeight: 1 }}>{rep.verdict.level}</div>
                <div style={{ fontFamily: "JetBrains Mono", fontSize: 11, color: T.mute, marginTop: 4 }}>risk score {rep.verdict.score}/100</div>
              </div>
              <div style={{ flex: 1, minWidth: 220 }}>
                <div style={{ fontFamily: "JetBrains Mono", fontSize: 12.5, color: T.bone, lineHeight: 1.6 }}>{rep.indicator}</div>
                <div style={{ fontFamily: "Barlow Condensed", fontSize: 15, color: T.mute, marginTop: 4 }}>{rep.verdict.summary}</div>
              </div>
              {rep.demo && (
                <span style={{ fontFamily: "JetBrains Mono", fontSize: 10, color: T.amber, border: `1px solid ${T.amber}`, padding: "3px 8px", letterSpacing: ".08em" }}>DEMO DATA — add API keys for live</span>
              )}
            </div>
          </Bracket>

          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(280px,1fr))", gap: 16 }}>
            <Bracket label="VirusTotal" right={vt?.found ? "MATCH" : vt?.available ? "NO RECORD" : "OFFLINE"}>
              <div style={{ padding: 14 }}>
                {vt?.found ? (<>
                  <div style={{ display: "flex", gap: 8, marginBottom: 10 }}>
                    <span style={{ fontFamily: "Oswald", fontWeight: 700, fontSize: 26, color: vt.malicious > 0 ? T.red : T.olive }}>{vt.malicious}</span>
                    <span style={{ fontFamily: "Barlow Condensed", fontSize: 13, color: T.mute, alignSelf: "flex-end" }}>engines flagged malicious · {vt.suspicious} suspicious</span>
                  </div>
                  <SrcRow k="reputation" v={vt.reputation} />
                  {vt.asOwner && <SrcRow k="AS owner" v={vt.asOwner} />}
                  {vt.country && <SrcRow k="country" v={vt.country} />}
                  {vt.tags?.length ? <SrcRow k="tags" v={vt.tags.join(", ")} /> : null}
                </>) : (
                  <div style={{ fontFamily: "JetBrains Mono", fontSize: 11, color: T.mute }}>
                    {vt?.available ? "No record found." : `Not queried (${vt?.reason || "no key"}).`}
                  </div>
                )}
              </div>
            </Bracket>

            <Bracket label="AbuseIPDB" right={ab?.available ? "MATCH" : "N/A"}>
              <div style={{ padding: 14 }}>
                {ab?.available ? (<>
                  <div style={{ display: "flex", gap: 8, marginBottom: 10 }}>
                    <span style={{ fontFamily: "Oswald", fontWeight: 700, fontSize: 26, color: ab.confidence > 50 ? T.red : ab.confidence > 20 ? T.amber : T.olive }}>{ab.confidence}%</span>
                    <span style={{ fontFamily: "Barlow Condensed", fontSize: 13, color: T.mute, alignSelf: "flex-end" }}>abuse confidence · {ab.totalReports} reports</span>
                  </div>
                  {ab.isp && <SrcRow k="ISP" v={ab.isp} />}
                  {ab.usageType && <SrcRow k="usage" v={ab.usageType} />}
                  {ab.country && <SrcRow k="country" v={ab.country} />}
                  <SrcRow k="tor exit" v={ab.isTor ? "yes" : "no"} />
                </>) : (
                  <div style={{ fontFamily: "JetBrains Mono", fontSize: 11, color: T.mute }}>{ab?.reason === "ip_only" ? "IP indicators only." : `Not queried (${ab?.reason || "no key"}).`}</div>
                )}
              </div>
            </Bracket>

            <Bracket label="Shodan" right={sh?.found ? "HOST FOUND" : sh?.available ? "NO HOST" : "N/A"}>
              <div style={{ padding: 14 }}>
                {sh?.found ? (<>
                  {sh.org && <SrcRow k="org" v={sh.org} />}
                  <SrcRow k="open ports" v={sh.ports?.join(", ") || "—"} />
                  {sh.hostnames?.length ? <SrcRow k="hostnames" v={sh.hostnames.join(", ")} /> : null}
                  <SrcRow k="known CVEs" v={sh.vulns?.length ? sh.vulns.join(", ") : "none"} />
                </>) : (
                  <div style={{ fontFamily: "JetBrains Mono", fontSize: 11, color: T.mute }}>{sh?.reason === "ip_only" ? "IP indicators only." : sh?.available ? "No host record." : `Not queried (${sh?.reason || "no key"}).`}</div>
                )}
              </div>
            </Bracket>
          </div>
          <div style={{ fontFamily: "JetBrains Mono", fontSize: 10.5, color: T.muteDim, letterSpacing: ".06em" }}>
            ▸ OM can run this same investigation from chat — try "Investigate {rep.indicator}" on the OM Analyst tab.
          </div>
        </>
      )}
    </div>
  );
}

/* ============================== APP ============================== */
const TABS = ["OVERVIEW", "THREAT MAP", "VULN FEED", "OT / ICS", "INVESTIGATE", "SECTOR BREACH", "WIRE", "OM ANALYST"];

export default function App() {
  const [tab, setTab] = useState("OVERVIEW");
  const [clock, setClock] = useState("");
  const [cves, setCves] = useState(() => Array.from({ length: 14 }, (_, i) => makeCVE(i)));
  const [defcon] = useState(2);

  useEffect(() => {
    const t = setInterval(() => setClock(new Date().toISOString().replace("T", " ").slice(0, 19) + "Z"), 1000);
    return () => clearInterval(t);
  }, []);
  useEffect(() => {
    const t = setInterval(() => setCves((c) => [{ ...makeCVE(0), id: `CVE-2026-${pad(1000 + Math.floor(Math.random() * 8999))}` }, ...c].slice(0, 20)), 4200);
    return () => clearInterval(t);
  }, []);

  // OPTIONAL LIVE FEEDS — when VITE_USE_LIVE_FEEDS=true, pull real CVE/KEV data
  // from src/feeds/. Wrapped in try/catch so the demo never breaks if a feed
  // is unreachable. See src/feeds/index.js to wire the other panels the same way.
  useEffect(() => {
    if (!LIVE_FEEDS_ENABLED) return;
    let alive = true;
    const pull = async () => {
      try {
        const rows = await loadLiveVulnFeed();
        if (alive && rows?.length) setCves(rows.slice(0, 20));
      } catch (e) { console.warn("[feeds] live vuln feed unavailable, using demo data:", e.message); }
    };
    pull();
    const t = setInterval(pull, 60000);
    return () => { alive = false; clearInterval(t); };
  }, []);

  const critCount = cves.filter((c) => c.sev === "CRITICAL").length;
  const kevCount = cves.filter((c) => c.kev).length;

  return (
    <div style={{ background: T.bg, minHeight: "100vh", color: T.bone, fontFamily: "Barlow Condensed, sans-serif", position: "relative", overflow: "hidden" }}>
      <FontInject />
      {/* scanline atmosphere */}
      <div style={{ position: "fixed", inset: 0, pointerEvents: "none", zIndex: 50,
        background: `repeating-linear-gradient(0deg, transparent 0 3px, ${T.bg}22 3px 4px)`, mixBlendMode: "overlay" }} />
      <div style={{ position: "fixed", left: 0, right: 0, height: 60, pointerEvents: "none", zIndex: 40,
        background: `linear-gradient(${T.olive}0c, transparent)`, animation: "scan 9s linear infinite" }} />

      {/* HEADER */}
      <header style={{ borderBottom: `1px solid ${T.lineHot}`, background: T.bg2, position: "sticky", top: 0, zIndex: 30 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 16, padding: "12px 20px", flexWrap: "wrap" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            <div style={{ position: "relative", width: 38, height: 38, border: `1.5px solid ${T.olive}`, display: "grid", placeItems: "center" }}>
              <span style={{ fontFamily: "Oswald", fontWeight: 700, fontSize: 19, color: T.olive }}>OM</span>
              <span style={{ position: "absolute", inset: -4, border: `1px solid ${T.oliveDim}`, opacity: .4 }} />
            </div>
            <div>
              <div style={{ fontFamily: "Oswald", fontWeight: 700, fontSize: 19, letterSpacing: ".08em", lineHeight: 1 }}>
                UNIFIED THREAT <span style={{ color: T.olive }}>INTELLIGENCE</span>
              </div>
              <div style={{ fontFamily: "JetBrains Mono", fontSize: 9.5, color: T.mute, letterSpacing: ".22em", marginTop: 3 }}>
                INFORMATION IS POWER · OSINT TURNS DATA INTO INTELLIGENCE
              </div>
            </div>
          </div>
          <div style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 18 }}>
            <div style={{ textAlign: "right" }}>
              <div style={{ fontFamily: "JetBrains Mono", fontSize: 12, color: T.bone }}>{clock}</div>
              <div style={{ fontFamily: "JetBrains Mono", fontSize: 9, color: T.mute, letterSpacing: ".15em" }}>SYSTEM TIME · UTC</div>
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 8, border: `1px solid ${T.red}`, padding: "5px 12px", background: `${T.red}12` }}>
              <span style={{ width: 8, height: 8, borderRadius: 8, background: T.red, animation: "blink 1.2s infinite" }} />
              <span style={{ fontFamily: "Oswald", fontWeight: 700, fontSize: 13, color: T.red, letterSpacing: ".1em" }}>DEFCON {defcon}</span>
            </div>
          </div>
        </div>
        {/* ticker */}
        <div style={{ borderTop: `1px solid ${T.line}`, overflow: "hidden", background: T.bg }}>
          <div style={{ display: "flex", whiteSpace: "nowrap", fontFamily: "JetBrains Mono", fontSize: 11, color: T.mute, padding: "6px 0", animation: "scan 0s" }}>
            <div style={{ display: "inline-block", animation: "ticker 34s linear infinite", paddingLeft: "100%" }}>
              <style>{`@keyframes ticker{from{transform:translateX(0)}to{transform:translateX(-100%)}}`}</style>
              {["▲ KEV: edge-VPN 0day mass-exploited (EPSS 0.94)", "⚠ POWER GRID: RTU manipulation across 2 operators", "◆ HEALTHCARE: 18M records claimed on leak site", "▲ OT wiper targeting Modbus + DNP3 in-the-wild", "⚠ SUPPLY-CHAIN: payment SDK pushes stealer to 400+ apps"].map((s, i) => (
                <span key={i} style={{ marginRight: 46, color: s[0] === "▲" ? T.red : s[0] === "⚠" ? T.amber : T.olive }}>{s}</span>
              ))}
            </div>
          </div>
        </div>
        {/* tabs */}
        <nav style={{ display: "flex", gap: 0, overflowX: "auto", borderTop: `1px solid ${T.line}` }}>
          {TABS.map((tb) => (
            <button key={tb} onClick={() => setTab(tb)} style={{
              fontFamily: "Oswald", fontWeight: 600, fontSize: 13, letterSpacing: ".1em",
              padding: "11px 18px", background: tab === tb ? T.panel : "transparent",
              color: tab === tb ? T.olive : T.mute, border: "none",
              borderBottom: tab === tb ? `2px solid ${T.olive}` : "2px solid transparent",
              cursor: "pointer", whiteSpace: "nowrap", textTransform: "uppercase",
            }}>{tb}</button>
          ))}
        </nav>
      </header>

      {/* MAIN */}
      <main style={{ padding: 20, maxWidth: 1440, margin: "0 auto", position: "relative", zIndex: 1 }}>
        {tab === "OVERVIEW" && (
          <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill,minmax(180px,1fr))", gap: 12 }}>
              <Stat label="Active CVEs" value={cves.length} sub="LIVE · NVD stream" accent={T.olive} blink />
              <Stat label="Critical" value={critCount} sub="CVSS ≥ 9.0" accent={T.red} blink />
              <Stat label="KEV Exploited" value={kevCount} sub="known-exploited" accent={T.amber} />
              <Stat label="OT/ICS Advisories" value={ICS_ADV.length} sub="ICS-CERT mirror" accent={T.olive} />
              <Stat label="Sector Breaches" value={SECTORS.reduce((a, b) => a + b.breaches, 0)} sub="rolling 30d" accent={T.red} />
              <Stat label="Exposed OT Hosts" value="4.9K" sub="Shodan snapshot" accent={T.amber} />
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "1.55fr 1fr", gap: 16 }}>
              <Bracket label="Global Threat Map" right="LIVE ATTACK TELEMETRY" glow>
                <ThreatMap />
              </Bracket>
              <VulnFeed rows={cves.slice(0, 8)} />
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
              <div style={{ height: 440 }}><OMChat /></div>
              <NewsFeed />
            </div>
          </div>
        )}
        {tab === "THREAT MAP" && (
          <Bracket label="Global Threat Map" right="LIVE ATTACK TELEMETRY · SIMULATED" glow>
            <ThreatMap />
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill,minmax(150px,1fr))", gap: 10, padding: 14, borderTop: `1px solid ${T.line}` }}>
              {NODES.filter(n => n.role === "src").map((n) => (
                <div key={n.id} style={{ border: `1px solid ${T.line}`, padding: "9px 11px" }}>
                  <div style={{ fontFamily: "Oswald", fontWeight: 700, color: T.red, fontSize: 17 }}>{n.id} · {n.city}</div>
                  <div style={{ fontFamily: "JetBrains Mono", fontSize: 10, color: T.mute }}>{(200 + Math.floor(Math.random() * 900))} events/min</div>
                </div>
              ))}
            </div>
          </Bracket>
        )}
        {tab === "VULN FEED" && (
          <div style={{ display: "grid", gridTemplateColumns: "1.4fr 1fr", gap: 16 }}>
            <VulnFeed rows={cves} />
            <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
              <Bracket label="Severity Distribution" right="CURRENT WINDOW">
                <div style={{ padding: 16, display: "flex", flexDirection: "column", gap: 12 }}>
                  {["CRITICAL", "HIGH", "MEDIUM", "LOW"].map((s) => {
                    const n = cves.filter((c) => c.sev === s).length;
                    const pct = Math.round((n / cves.length) * 100) || 0;
                    return (
                      <div key={s}>
                        <div style={{ display: "flex", justifyContent: "space-between", fontFamily: "JetBrains Mono", fontSize: 11, marginBottom: 4 }}>
                          <span style={{ color: SEV[s] }}>{s}</span><span style={{ color: T.mute }}>{n} · {pct}%</span>
                        </div>
                        <div style={{ height: 8, background: T.bg, border: `1px solid ${T.line}` }}>
                          <div style={{ width: `${pct}%`, height: "100%", background: SEV[s] }} />
                        </div>
                      </div>
                    );
                  })}
                </div>
              </Bracket>
              <Bracket label="KEV Priority Actions" right="PATCH SLA">
                <div style={{ padding: 14, display: "flex", flexDirection: "column", gap: 10 }}>
                  {cves.filter(c => c.kev).slice(0, 5).map((v) => (
                    <div key={v.id} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", borderLeft: `3px solid ${T.red}`, paddingLeft: 10 }}>
                      <div>
                        <div style={{ fontFamily: "JetBrains Mono", fontSize: 11.5, color: T.bone }}>{v.id}</div>
                        <div style={{ fontFamily: "Barlow Condensed", fontSize: 12, color: T.mute }}>{v.vendor} · patch ≤ 24h</div>
                      </div>
                      <span style={{ fontFamily: "Oswald", fontWeight: 700, color: T.red, fontSize: 18 }}>{v.cvss}</span>
                    </div>
                  ))}
                </div>
              </Bracket>
            </div>
          </div>
        )}
        {tab === "OT / ICS" && <OTICS />}
        {tab === "INVESTIGATE" && <InvestigatePanel />}
        {tab === "SECTOR BREACH" && <SectorBreach />}
        {tab === "WIRE" && <NewsFeed />}
        {tab === "OM ANALYST" && (
          <div style={{ display: "grid", gridTemplateColumns: "1.4fr 1fr", gap: 16 }}>
            <div style={{ height: 620 }}><OMChat /></div>
            <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
              <Bracket label="OM Capabilities" right="CONTEXT MODULES">
                <div style={{ padding: 14, display: "flex", flexDirection: "column", gap: 2 }}>
                  {[
                    ["THREAT HUNTING", "Hypothesis-driven hunts, Sigma/KQL/SPL, MITRE ATT&CK mapping"],
                    ["INVESTIGATION", "Timeline reconstruction, IOC pivoting, root-cause analysis"],
                    ["INCIDENT RESPONSE", "IR phases, containment, eradication, recovery playbooks"],
                    ["OSINT", "Shodan/Censys, passive DNS, infra pivots, exposure mapping"],
                    ["SANDBOX", "Detonation strategy, IOC extraction, YARA/Sigma generation"],
                  ].map(([t, d]) => (
                    <div key={t} style={{ padding: "10px 0", borderBottom: `1px solid ${T.line}` }}>
                      <div style={{ fontFamily: "Oswald", fontWeight: 600, fontSize: 14, color: T.olive, letterSpacing: ".06em" }}>◆ {t}</div>
                      <div style={{ fontFamily: "Barlow Condensed", fontSize: 13.5, color: T.mute, marginTop: 2 }}>{d}</div>
                    </div>
                  ))}
                </div>
              </Bracket>
              <Bracket label="Engagement Posture" right="DEFENSIVE-ONLY">
                <div style={{ padding: 14, fontFamily: "JetBrains Mono", fontSize: 11, color: T.mute, lineHeight: 1.7 }}>
                  OM assists blue-team / defensive operations only. Outputs are analyst-grade playbooks and pointers — validate against your own environment and authorization before action.
                </div>
              </Bracket>
            </div>
          </div>
        )}
      </main>

      <footer style={{ borderTop: `1px solid ${T.line}`, padding: "14px 20px", textAlign: "center", fontFamily: "JetBrains Mono", fontSize: 10, color: T.muteDim, letterSpacing: ".1em" }}>
        OM UNIFIED THREAT INTELLIGENCE CONSOLE · DEMONSTRATION BUILD · FEEDS SIMULATED — WIRE TO NVD / KEV / ICS-CERT / SHODAN / MISP FOR PRODUCTION
      </footer>
    </div>
  );
}
