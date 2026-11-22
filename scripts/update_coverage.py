"""Build attack-coverage.svg: MITRE ATT&CK techniques mapped across all public project repos.

Runs inside GitHub Actions after update_readme.py. For every public repo (same filter as the
project table) it looks for ATT&CK Navigator layer files (*.json inside a folder called "layers"),
reads the techniques, maps them to tactics with data/attack-tactics.json (ATT&CK v20.1) and draws
one bar per tactic. SPARTA layers and other non-ATT&CK files are ignored.
"""
import datetime
import json
import os
import urllib.request

from update_readme import SKIP, TOKEN, USER, fetch_repos

DOMAINS = {"enterprise-attack": "enterprise", "ics-attack": "ics"}


def get_json(url):
    req = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json", "User-Agent": "profile-coverage"})
    if TOKEN and "api.github.com" in url:
        req.add_header("Authorization", f"Bearer {TOKEN}")
    with urllib.request.urlopen(req) as r:
        return json.load(r)


def layer_files(repo):
    branch = repo.get("default_branch", "main")
    tree = get_json(f"https://api.github.com/repos/{USER}/{repo['name']}/git/trees/{branch}?recursive=1")
    for item in tree.get("tree", []):
        p = item["path"]
        if item["type"] == "blob" and p.endswith(".json") and "layers/" in f"/{p}":
            yield f"https://raw.githubusercontent.com/{USER}/{repo['name']}/{branch}/{p}"


def collect(repos):
    found = {"enterprise": set(), "ics": set()}
    projects = set()
    for repo in repos:
        if repo.get("fork") or repo.get("private") or repo.get("archived") or repo["name"].lower() in SKIP:
            continue
        try:
            urls = list(layer_files(repo))
        except Exception as e:  # empty repo, API hiccup
            print(f"skip {repo['name']}: {e}")
            continue
        for url in urls:
            try:
                layer = get_json(url)
            except Exception as e:
                print(f"skip {url}: {e}")
                continue
            dom = DOMAINS.get(layer.get("domain")) if isinstance(layer, dict) else None
            if not dom:
                continue  # SPARTA or other format
            ids = {t["techniqueID"] for t in layer.get("techniques", []) if t.get("enabled", True) and t.get("techniqueID")}
            if ids:
                found[dom] |= ids
                projects.add(repo["name"])
    return found, projects


def esc(s):
    return s.replace("&", "&amp;").replace("<", "&lt;")


def render(found, projects, mapping):
    W, ROW, TOP = 1200, 25, 150
    font = 'font-family="Segoe UI, Helvetica, Arial, sans-serif"'
    cols = []
    for dom, x0, title in (("enterprise", 40, "Enterprise"), ("ics", 640, "ICS")):
        tactics = mapping[dom]["tactics"]
        techmap = mapping[dom]["techniques"]
        counts = {t[0]: 0 for t in tactics}
        for tid in found[dom]:
            for tac in techmap.get(tid, []):
                if tac in counts:
                    counts[tac] += 1
        cols.append((dom, x0, title, tactics, counts))
    rows = max(len(c[3]) for c in cols)
    H = TOP + rows * ROW + 60
    total = len(found["enterprise"]) + len(found["ics"])
    today = datetime.date.today().isoformat()

    out = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}" role="img" aria-label="MITRE ATT&amp;CK coverage">',
           '<defs><linearGradient id="cbg" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#06122b"/><stop offset="1" stop-color="#0b2a5c"/></linearGradient></defs>',
           f'<rect width="{W}" height="{H}" rx="18" fill="url(#cbg)"/>',
           f'<text x="40" y="52" {font} font-size="26" font-weight="700" fill="#ffffff">MITRE ATT&amp;CK coverage across my projects</text>',
           f'<text x="40" y="84" {font} font-size="16" fill="#94a3b8">{total} unique techniques and sub-techniques · {len(projects)} projects · ATT&amp;CK v{mapping["attack_version"]} · auto-updated {today}</text>']
    for dom, x0, title, tactics, counts in cols:
        n = len(found[dom])
        peak = max([1] + list(counts.values()))
        out.append(f'<text x="{x0}" y="{TOP - 22}" {font} font-size="15" font-weight="700" letter-spacing="3" fill="#38bdf8">{title.upper()} · {n} TECHNIQUES</text>')
        label_w, bar_max = 210, 330
        for i, (short, name) in enumerate(tactics):
            y = TOP + i * ROW
            v = counts[short]
            w = 0 if v == 0 else max(6, int(bar_max * v / peak))
            shade = "#1e3a8a" if v == 0 else ("#2563eb" if v < peak * 0.34 else "#3b82f6" if v < peak * 0.67 else "#60a5fa")
            out.append(f'<text x="{x0}" y="{y + 15}" {font} font-size="14" fill="#cbd5e1">{esc(name)}</text>')
            out.append(f'<rect x="{x0 + label_w}" y="{y + 3}" width="{bar_max}" height="16" rx="4" fill="#0f1d3d"/>')
            if w:
                out.append(f'<rect x="{x0 + label_w}" y="{y + 3}" width="{w}" height="16" rx="4" fill="{shade}"/>')
            out.append(f'<text x="{x0 + label_w + bar_max + 10}" y="{y + 16}" {font} font-size="13" font-weight="600" fill="{"#e2e8f0" if v else "#475569"}">{v}</text>')
    out.append(f'<text x="40" y="{H - 24}" {font} font-size="12" fill="#64748b">A technique listed under several tactics is counted in each. Source: ATT&amp;CK Navigator layers in each project repository. MITRE ATT&amp;CK® is a trademark of The MITRE Corporation.</text>')
    out.append("</svg>")
    return "\n".join(out)


def main(repos=None):
    mapping = json.load(open(os.path.join(os.path.dirname(__file__), "..", "data", "attack-tactics.json"), encoding="utf-8"))
    found, projects = collect(repos if repos is not None else fetch_repos())
    svg = render(found, projects, mapping)
    old = open("attack-coverage.svg", encoding="utf-8").read() if os.path.exists("attack-coverage.svg") else ""
    # ignore the date when deciding whether anything changed
    strip = lambda s: "\n".join(l for l in s.splitlines() if "auto-updated" not in l)
    if strip(old) != strip(svg):
        open("attack-coverage.svg", "w", encoding="utf-8").write(svg)
        print("attack-coverage.svg updated")
    else:
        print("No coverage changes")


if __name__ == "__main__":
    main()
