"""Build threat-pulse.svg: a small card with this week's threat activity from public sources.

Runs inside GitHub Actions every few hours (.github/workflows/threat-pulse.yml).
Sources (all free, no API key):
  * Ransomware.live API v2   - ransomware victims claimed on leak sites, last 7 days
                               (only counts, countries and group names are shown:
                               victim names come from the attackers' leak sites and are never republished)
  * SANS ISC / DShield       - most scanned ports worldwide (firewall logs from DShield sensors)
  * CISA KEV catalog         - vulnerabilities newly confirmed as exploited in the wild
Each source is independent: if one is down, its panel says so and the others still update.
If every source fails, the existing card is kept as it is.
No third-party Python packages are needed.
"""
import datetime as dt
import json
import os
import time
import urllib.request
from collections import Counter

UA = "PARTSI14-profile-threat-pulse/1.0 (+https://github.com/PARTSI14)"
RW_BASE = "https://api.ransomware.live/v2"
ISC_TOPPORTS = "https://isc.sans.edu/api/topports/records/10?json"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
OUT = "threat-pulse.svg"
DAYS = 7

COUNTRIES = {
    "US": "United States", "CA": "Canada", "GB": "United Kingdom", "DE": "Germany", "FR": "France",
    "IT": "Italy", "ES": "Spain", "BR": "Brazil", "AU": "Australia", "IN": "India", "JP": "Japan",
    "MX": "Mexico", "NL": "Netherlands", "BE": "Belgium", "CH": "Switzerland", "AT": "Austria",
    "SE": "Sweden", "TR": "Turkey", "GR": "Greece", "CY": "Cyprus", "PL": "Poland", "PT": "Portugal",
    "AR": "Argentina", "CO": "Colombia", "CL": "Chile", "PE": "Peru", "ZA": "South Africa",
    "AE": "UAE", "SA": "Saudi Arabia", "IL": "Israel", "SG": "Singapore", "KR": "South Korea",
    "TW": "Taiwan", "TH": "Thailand", "MY": "Malaysia", "ID": "Indonesia", "PH": "Philippines",
    "VN": "Vietnam", "CN": "China", "HK": "Hong Kong", "NZ": "New Zealand", "IE": "Ireland",
    "DK": "Denmark", "NO": "Norway", "FI": "Finland", "CZ": "Czechia", "RO": "Romania", "EG": "Egypt",
}
PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 81: "HTTP alt", 110: "POP3",
    123: "NTP", 135: "MS RPC", 137: "NetBIOS", 139: "NetBIOS", 143: "IMAP", 161: "SNMP", 443: "HTTPS",
    445: "SMB", 1433: "MS SQL", 1723: "PPTP", 2222: "SSH alt", 2323: "Telnet alt", 3306: "MySQL",
    3389: "RDP", 5060: "SIP", 5555: "Android ADB", 5900: "VNC", 6379: "Redis", 7547: "TR-069",
    8000: "HTTP alt", 8080: "HTTP proxy", 8443: "HTTPS alt", 8728: "MikroTik API", 9200: "Elasticsearch",
    37215: "Huawei router", 52869: "UPnP",
}


def fetch(url, as_json=True, retries=2):
    for attempt in range(retries + 1):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=60) as r:
                data = r.read().decode("utf-8", errors="replace")
            return json.loads(data) if as_json else data
        except Exception as e:  # noqa: BLE001
            if attempt == retries:
                raise
            print(f"retry {url}: {e}")
            time.sleep(65)  # Ransomware.live allows about one call per minute per endpoint


def parse_date(value):
    if not value:
        return None
    s = str(value).strip().replace("T", " ")
    for fmt, length in (("%Y-%m-%d %H:%M:%S", 19), ("%Y-%m-%d %H:%M", 16), ("%Y-%m-%d", 10)):
        try:
            return dt.datetime.strptime(s[:length], fmt)
        except ValueError:
            continue
    return None


# ---------------------------------------------------------------- sources

def ransomware(now):
    """Victims claimed in the last DAYS days: total, top countries, Greece, top groups."""
    since = now - dt.timedelta(days=DAYS)
    months = [(now.year, now.month)]
    if since.month != now.month:
        months.append((since.year, since.month))
    records = []
    for i, (y, m) in enumerate(months):
        if i:
            time.sleep(65)
        data = fetch(f"{RW_BASE}/victims/{y}/{m:02d}")
        records += data if isinstance(data, list) else data.get("victims", [])
    seen, countries, groups = set(), Counter(), Counter()
    for r in records:
        when = parse_date(r.get("discovered") or r.get("attackdate"))
        if not when or not (since <= when <= now + dt.timedelta(days=1)):
            continue
        key = (str(r.get("victim", "")).lower(), str(r.get("group", "")).lower())
        if key in seen:
            continue
        seen.add(key)
        countries[(r.get("country") or "??").upper()] += 1
        if r.get("group"):
            groups[str(r["group"]).lower()] += 1
    return {"total": len(seen), "countries": countries, "groups": groups}


def top_ports():
    data = fetch(ISC_TOPPORTS)
    rows = list(data.values()) if isinstance(data, dict) else list(data)
    out = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        port = row.get("targetport", row.get("port"))
        try:
            port = int(port)
        except (TypeError, ValueError):
            continue
        reports = row.get("records", row.get("reports", 0)) or 0
        out.append((int(row.get("rank", len(out) + 1)), port, int(reports)))
    out.sort()
    return out[:5]


def kev(now):
    data = fetch(KEV_URL)
    vulns = data.get("vulnerabilities", [])
    vulns.sort(key=lambda v: (v.get("dateAdded", ""), v.get("cveID", "")), reverse=True)
    since = (now - dt.timedelta(days=DAYS)).date().isoformat()
    recent = [v for v in vulns if v.get("dateAdded", "") >= since]
    ransomware_use = sum(1 for v in recent if str(v.get("knownRansomwareCampaignUse", "")).lower() == "known")
    return {"total": len(vulns), "week": len(recent), "ransomware": ransomware_use, "latest": vulns[:3]}


# ---------------------------------------------------------------- drawing

def esc(s):
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def clip(s, n):
    s = str(s)
    return s if len(s) <= n else s[: n - 1] + "…"


def render(rw, ports, kv, now):
    W, H = 1200, 470
    font = 'font-family="Segoe UI, Helvetica, Arial, sans-serif"'
    cyan, grey, soft, white = "#22d3ee", "#94a3b8", "#cbd5e1", "#ffffff"
    stamp = now.strftime("%d %b %Y, %H:%M UTC")
    o = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}" role="img" aria-label="Threat pulse: ransomware victims, most scanned ports and newly exploited vulnerabilities in the last {DAYS} days">',
         '<defs><linearGradient id="tpg" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#06122b"/><stop offset="1" stop-color="#0b2a5c"/></linearGradient></defs>',
         f'<rect width="{W}" height="{H}" rx="18" fill="url(#tpg)"/>',
         f'<circle cx="48" cy="45" r="7" fill="#ef4444"><animate attributeName="opacity" values="1;0.25;1" dur="1.6s" repeatCount="indefinite"/></circle>',
         f'<text x="66" y="52" {font} font-size="26" font-weight="700" fill="{white}">Threat pulse</text>',
         f'<text x="232" y="52" {font} font-size="16" fill="{grey}">last {DAYS} days · updated {stamp} · refreshes every 6 hours</text>']

    def panel(x, w, title):
        o.append(f'<rect x="{x}" y="78" width="{w}" height="330" rx="12" fill="#0b1a3a" stroke="{cyan}" stroke-opacity="0.35" stroke-width="1.2"/>')
        o.append(f'<text x="{x + 20}" y="106" {font} font-size="13" font-weight="700" letter-spacing="2" fill="#38bdf8">{title}</text>')

    def unavailable(x):
        o.append(f'<text x="{x + 20}" y="160" {font} font-size="15" fill="{grey}">Source unavailable in this run.</text>')
        o.append(f'<text x="{x + 20}" y="182" {font} font-size="15" fill="{grey}">It will retry in a few hours.</text>')

    # --- ransomware panel
    x, w = 30, 420
    panel(x, w, "RANSOMWARE LEAK-SITE CLAIMS")
    if rw:
        o.append(f'<text x="{x + 20}" y="158" {font} font-size="44" font-weight="700" fill="{cyan}">{rw["total"]}</text>')
        o.append(f'<text x="{x + 20 + 30 * len(str(rw["total"])) + 12}" y="158" {font} font-size="15" fill="{soft}">victims claimed this week</text>')
        top = [(c, n) for c, n in rw["countries"].most_common() if c != "??"][:5]
        peak = max([1] + [n for _, n in top])
        for i, (code, n) in enumerate(top):
            y = 186 + i * 27
            o.append(f'<text x="{x + 20}" y="{y + 13}" {font} font-size="14" fill="{soft}">{esc(COUNTRIES.get(code, code))}</text>')
            bw = max(4, int(170 * n / peak))
            o.append(f'<rect x="{x + 170}" y="{y + 1}" width="170" height="14" rx="4" fill="#0f1d3d"/>')
            o.append(f'<rect x="{x + 170}" y="{y + 1}" width="{bw}" height="14" rx="4" fill="{cyan}" fill-opacity="0.8"/>')
            o.append(f'<text x="{x + 350}" y="{y + 13}" {font} font-size="13" font-weight="600" fill="{white}">{n}</text>')
        gr = rw["countries"].get("GR", 0)
        o.append(f'<text x="{x + 20}" y="342" {font} font-size="14" fill="{soft}">Greece: <tspan font-weight="700" fill="{white}">{gr}</tspan></text>')
        groups = ", ".join(clip(g, 14) for g, _ in rw["groups"].most_common(3))
        o.append(f'<text x="{x + 20}" y="368" {font} font-size="14" fill="{soft}">Most active: <tspan font-weight="600" fill="{white}">{esc(groups) or "–"}</tspan></text>')
        o.append(f'<text x="{x + 20}" y="392" {font} font-size="11" fill="#64748b">Counts only. Victim names are not republished.</text>')
    else:
        unavailable(x)

    # --- ports panel
    x, w = 465, 300
    panel(x, w, "MOST SCANNED PORTS")
    if ports:
        peak = max([1] + [r for _, _, r in ports])
        for i, (_, port, reports) in enumerate(ports):
            y = 128 + i * 52
            o.append(f'<text x="{x + 20}" y="{y + 18}" {font} font-size="22" font-weight="700" fill="{white}">{port}</text>')
            o.append(f'<text x="{x + 100}" y="{y + 17}" {font} font-size="14" fill="{soft}">{esc(PORTS.get(port, "other"))}</text>')
            bw = max(4, int(240 * reports / peak))
            o.append(f'<rect x="{x + 20}" y="{y + 26}" width="260" height="8" rx="4" fill="#0f1d3d"/>')
            o.append(f'<rect x="{x + 20}" y="{y + 26}" width="{bw}" height="8" rx="4" fill="{cyan}" fill-opacity="0.8"/>')
        o.append(f'<text x="{x + 20}" y="392" {font} font-size="11" fill="#64748b">By reports from DShield sensors, latest day.</text>')
    else:
        unavailable(x)

    # --- KEV panel
    x, w = 780, 390
    panel(x, w, "NEWLY EXPLOITED (CISA KEV)")
    if kv:
        o.append(f'<text x="{x + 20}" y="158" {font} font-size="44" font-weight="700" fill="{cyan}">{kv["week"]}</text>')
        o.append(f'<text x="{x + 20 + 30 * len(str(kv["week"])) + 12}" y="146" {font} font-size="15" fill="{soft}">added this week</text>')
        o.append(f'<text x="{x + 20 + 30 * len(str(kv["week"])) + 12}" y="166" {font} font-size="13" fill="{grey}">{kv["ransomware"]} used by ransomware · {kv["total"]} in catalog</text>')
        for i, v in enumerate(kv["latest"]):
            y = 196 + i * 62
            o.append(f'<text x="{x + 20}" y="{y + 14}" {font} font-size="15" font-weight="700" fill="{white}">{esc(v.get("cveID", ""))}</text>')
            o.append(f'<text x="{x + 370}" y="{y + 14}" {font} font-size="12" fill="{grey}" text-anchor="end">{esc(v.get("dateAdded", ""))}</text>')
            prod = f'{v.get("vendorProject", "")} {v.get("product", "")}'.strip()
            o.append(f'<text x="{x + 20}" y="{y + 34}" {font} font-size="13" fill="{soft}">{esc(clip(prod, 44))}</text>')
        o.append(f'<text x="{x + 20}" y="392" {font} font-size="11" fill="#64748b">Vulnerabilities confirmed as exploited in the wild.</text>')
    else:
        unavailable(x)

    o.append(f'<text x="30" y="{H - 24}" {font} font-size="12" fill="#64748b">Sources: Ransomware.live · SANS Technology Institute, Internet Storm Center (isc.sans.edu) · CISA Known Exploited Vulnerabilities. Leak-site claims are unverified by nature.</text>')
    o.append("</svg>")
    return "\n".join(o)


def main(now=None, sources=None):
    now = now or dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)
    results = {}
    for name, func in (sources or {"rw": lambda: ransomware(now), "ports": top_ports, "kev": lambda: kev(now)}).items():
        try:
            results[name] = func()
        except Exception as e:  # noqa: BLE001 - one broken source must not break the card
            print(f"{name} failed: {e}")
            results[name] = None
    if not any(results.values()):
        print("All sources failed, keeping the existing card")
        return
    svg = render(results["rw"], results["ports"], results["kev"], now)
    with open(OUT, "w", encoding="utf-8") as fh:
        fh.write(svg)
    print(f"{OUT} written: ransomware={bool(results['rw'])} ports={bool(results['ports'])} kev={bool(results['kev'])}")


if __name__ == "__main__":
    main()
