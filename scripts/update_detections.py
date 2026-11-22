"""Build detections.svg: an inventory of the detection rules published across all public project repos.

Runs inside GitHub Actions after update_coverage.py. For every public repo (same filter as the
project table) it reads:
  * Sigma rules      - *.yml / *.yaml files with a `detection:` or `correlation:` section
                       (multi-document files are counted per rule; correlation rules separately)
  * KQL queries      - *.kql files
  * Splunk searches  - *.spl files and ```spl code blocks inside Markdown files
ATT&CK technique IDs are taken from Sigma `attack.tXXXX` tags and from T-numbers written in
KQL / SPL comments, then mapped to tactics with data/attack-tactics.json.
No third-party Python packages are needed.
"""
import datetime
import json
import os
import re
import urllib.request

from update_readme import SKIP, TOKEN, USER, fetch_repos

TECH_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
SIGMA_TAG_RE = re.compile(r"attack\.(t\d{4}(?:\.\d{3})?)\b", re.I)
SPL_BLOCK_RE = re.compile(r"```spl\s*\n(.*?)```", re.S | re.I)
LEVELS = ["critical", "high", "medium", "low", "informational"]
PRETTY = {"windows": "Windows", "linux": "Linux", "macos": "macOS", "waf": "WAF", "php": "PHP", "apache": "Apache",
          "nginx": "Nginx", "webserver": "Web server", "azure": "Azure", "aws": "AWS", "gcp": "GCP", "m365": "Microsoft 365",
          "okta": "Okta", "vmware": "VMware", "zeek": "Zeek", "dns": "DNS", "firewall": "Firewall", "proxy": "Proxy"}


def http(url, as_json=True):
    req = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json", "User-Agent": "profile-detections"})
    if TOKEN and "api.github.com" in url:
        req.add_header("Authorization", f"Bearer {TOKEN}")
    with urllib.request.urlopen(req) as r:
        data = r.read().decode("utf-8", errors="replace")
    return json.loads(data) if as_json else data


def repo_files(repo):
    """Yield (path, raw_url) for candidate detection files in the repo."""
    branch = repo.get("default_branch", "main")
    tree = http(f"https://api.github.com/repos/{USER}/{repo['name']}/git/trees/{branch}?recursive=1")
    for item in tree.get("tree", []):
        p = item["path"]
        low = p.lower()
        if item["type"] != "blob" or low.startswith(".github/"):
            continue
        if low.endswith((".yml", ".yaml", ".kql", ".spl", ".md")):
            yield p, f"https://raw.githubusercontent.com/{USER}/{repo['name']}/{branch}/{p}"


def analyse(files):
    """files: iterable of (repo_name, path, text). Returns the inventory dict."""
    inv = {"sigma": 0, "correlation": 0, "kql": 0, "spl": 0, "techniques": set(),
           "levels": {l: 0 for l in LEVELS}, "platforms": {}, "repos": set()}

    def platform(name):
        inv["platforms"][name] = inv["platforms"].get(name, 0) + 1

    for repo, path, text in files:
        low = path.lower()
        if low.endswith((".yml", ".yaml")):
            for doc in re.split(r"(?m)^---\s*$", text):
                if not re.search(r"(?m)^title:", doc):
                    continue
                if re.search(r"(?m)^correlation:", doc):
                    inv["correlation"] += 1
                elif re.search(r"(?m)^detection:", doc) and re.search(r"(?m)^logsource:", doc):
                    inv["sigma"] += 1
                    m = re.search(r"(?m)^\s+product:\s*([\w-]+)", doc)
                    c = re.search(r"(?m)^\s+category:\s*([\w-]+)", doc)
                    key = (m.group(1) if m else (c.group(1) if c else "other")).lower()
                    platform(PRETTY.get(key, key.capitalize()))
                else:
                    continue
                inv["repos"].add(repo)
                lvl = re.search(r"(?m)^level:\s*(\w+)", doc)
                if lvl and lvl.group(1).lower() in inv["levels"]:
                    inv["levels"][lvl.group(1).lower()] += 1
                inv["techniques"] |= {t.upper() for t in SIGMA_TAG_RE.findall(doc)}
        elif low.endswith(".kql"):
            inv["kql"] += 1
            inv["repos"].add(repo)
            platform("Microsoft Sentinel")
            inv["techniques"] |= set(TECH_RE.findall(text))
        elif low.endswith(".spl"):
            inv["spl"] += 1
            inv["repos"].add(repo)
            inv["techniques"] |= set(TECH_RE.findall(text))
        elif low.endswith(".md"):
            blocks = SPL_BLOCK_RE.findall(text)
            if blocks:
                inv["spl"] += len(blocks)
                inv["repos"].add(repo)
    return inv


def collect(repos):
    for repo in repos:
        if repo.get("fork") or repo.get("private") or repo.get("archived") or repo["name"].lower() in SKIP:
            continue
        try:
            for path, url in repo_files(repo):
                try:
                    yield repo["name"], path, http(url, as_json=False)
                except Exception as e:
                    print(f"skip {url}: {e}")
        except Exception as e:
            print(f"skip {repo['name']}: {e}")


def esc(s):
    return s.replace("&", "&amp;").replace("<", "&lt;")


def render(inv, mapping):
    W, H = 1200, 530
    font = 'font-family="Segoe UI, Helvetica, Arial, sans-serif"'
    today = datetime.date.today().isoformat()
    techmap = mapping["enterprise"]["techniques"]
    tactics = mapping["enterprise"]["tactics"]
    counts = {t[0]: 0 for t in tactics}
    for tid in inv["techniques"]:
        for tac in techmap.get(tid, []):
            counts[tac] += 1
    total_rules = inv["sigma"] + inv["correlation"] + inv["kql"]

    o = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}" role="img" aria-label="Detection library">',
         '<defs><linearGradient id="dbg" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#06122b"/><stop offset="1" stop-color="#0b2a5c"/></linearGradient></defs>',
         f'<rect width="{W}" height="{H}" rx="18" fill="url(#dbg)"/>',
         f'<text x="40" y="52" {font} font-size="26" font-weight="700" fill="#ffffff">Detection library</text>',
         f'<text x="40" y="84" {font} font-size="16" fill="#94a3b8">{total_rules} detection rules · {len(inv["techniques"])} ATT&amp;CK techniques · {len(inv["repos"])} projects · auto-updated {today}</text>']

    # stat tiles
    tiles = [("Sigma rules", inv["sigma"], f'+{inv["correlation"]} correlation' if inv["correlation"] else "vendor-neutral"),
             ("KQL queries", inv["kql"], "Microsoft Sentinel"),
             ("Splunk searches", inv["spl"], "SPL"),
             ("ATT&amp;CK techniques", len(inv["techniques"]), "detected")]
    for i, (label, value, sub) in enumerate(tiles):
        x, y = 40 + (i % 2) * 270, 112 + (i // 2) * 116
        o.append(f'<rect x="{x}" y="{y}" width="255" height="102" rx="12" fill="#0b1a3a" stroke="#22d3ee" stroke-opacity="0.45" stroke-width="1.5"/>')
        o.append(f'<text x="{x + 20}" y="{y + 52}" {font} font-size="40" font-weight="700" fill="#22d3ee">{value}</text>')
        o.append(f'<text x="{x + 20}" y="{y + 76}" {font} font-size="15" font-weight="600" fill="#e2e8f0">{label}</text>')
        o.append(f'<text x="{x + 20}" y="{y + 93}" {font} font-size="12" fill="#94a3b8">{sub}</text>')

    # severity + platforms
    y0 = 360
    o.append(f'<text x="40" y="{y0}" {font} font-size="13" font-weight="700" letter-spacing="2" fill="#38bdf8">SIGMA SEVERITY</text>')
    sev_cols = {"critical": "#ef4444", "high": "#f97316", "medium": "#f59e0b", "low": "#22c55e", "informational": "#64748b"}
    x = 40
    for lvl in LEVELS:
        n = inv["levels"][lvl]
        if not n:
            continue
        label = f"{lvl.capitalize()} {n}"
        w = len(label) * 8 + 28
        o.append(f'<rect x="{x}" y="{y0 + 12}" width="{w}" height="26" rx="13" fill="{sev_cols[lvl]}" fill-opacity="0.18" stroke="{sev_cols[lvl]}" stroke-width="1.2"/>')
        o.append(f'<text x="{x + w / 2}" y="{y0 + 30}" {font} font-size="13" font-weight="600" fill="{sev_cols[lvl]}" text-anchor="middle">{label}</text>')
        x += w + 8
    o.append(f'<text x="40" y="{y0 + 66}" {font} font-size="13" font-weight="700" letter-spacing="2" fill="#38bdf8">PLATFORMS</text>')
    # wrap the platform list so it never runs into the tactic bars on the right (max ~62 chars per line)
    items = [f"{k} {v}" for k, v in sorted(inv["platforms"].items(), key=lambda kv: -kv[1])]
    lines, cur = [], ""
    for it in items:
        cand = f"{cur} · {it}" if cur else it
        if len(cand) > 62 and cur:
            lines.append(cur)
            cur = it
        else:
            cur = cand
    if cur:
        lines.append(cur)
    for j, line in enumerate(lines[:3]):
        o.append(f'<text x="40" y="{y0 + 88 + j * 20}" {font} font-size="14" fill="#cbd5e1">{esc(line)}</text>')

    # tactic bars
    x0, top, row, label_w, bar_max = 620, 126, 21, 190, 300
    o.append(f'<text x="{x0}" y="{top - 14}" {font} font-size="13" font-weight="700" letter-spacing="2" fill="#38bdf8">TECHNIQUES DETECTED BY TACTIC</text>')
    peak = max([1] + list(counts.values()))
    for i, (short, name) in enumerate(tactics):
        y = top + i * row
        v = counts[short]
        w = 0 if v == 0 else max(6, int(bar_max * v / peak))
        o.append(f'<text x="{x0}" y="{y + 14}" {font} font-size="13" fill="#cbd5e1">{esc(name)}</text>')
        o.append(f'<rect x="{x0 + label_w}" y="{y + 3}" width="{bar_max}" height="14" rx="4" fill="#0f1d3d"/>')
        if w:
            o.append(f'<rect x="{x0 + label_w}" y="{y + 3}" width="{w}" height="14" rx="4" fill="#22d3ee" fill-opacity="{0.45 + 0.55 * v / peak:.2f}"/>')
        o.append(f'<text x="{x0 + label_w + bar_max + 10}" y="{y + 15}" {font} font-size="12" font-weight="600" fill="{"#e2e8f0" if v else "#475569"}">{v}</text>')
    o.append(f'<text x="40" y="{H - 18}" {font} font-size="12" fill="#64748b">Splunk searches are mostly Sigma rules converted with pySigma, so they are not added to the rule total. Rules are published for defensive use; test before production.</text>')
    o.append("</svg>")
    return "\n".join(o)


def main(files=None):
    mapping = json.load(open(os.path.join(os.path.dirname(__file__), "..", "data", "attack-tactics.json"), encoding="utf-8"))
    inv = analyse(files if files is not None else collect(fetch_repos()))
    svg = render(inv, mapping)
    old = open("detections.svg", encoding="utf-8").read() if os.path.exists("detections.svg") else ""
    strip = lambda s: "\n".join(l for l in s.splitlines() if "auto-updated" not in l)
    if strip(old) != strip(svg):
        open("detections.svg", "w", encoding="utf-8").write(svg)
        print("detections.svg updated")
    else:
        print("No detection changes")


if __name__ == "__main__":
    main()
