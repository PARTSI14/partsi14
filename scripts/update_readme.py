"""Rebuild the project cards in the profile README from the user's public GitHub repositories.

Runs inside GitHub Actions. Reads repos with the GitHub REST API, draws one SVG card per project
into cards/<repo>.svg (category colour taken from the repo topics) and replaces the text between
<!-- PROJECTS:START --> and <!-- PROJECTS:END --> in README.md with a two-column grid of linked cards.
No third-party packages are needed.
"""
import datetime
import json
import os
import re
import urllib.request

USER = os.environ.get("GH_USER", "PARTSI14")
TOKEN = os.environ.get("GITHUB_TOKEN", "")
START, END = "<!-- PROJECTS:START -->", "<!-- PROJECTS:END -->"
SKIP = {USER.lower(), "dga_classification.ipynb", "dga-edited-notebook", "fix_notebook.py", "iforest-and-ecod", "anomaly_detection.ipynb-lab", "lab-stelios"}  # profile repo + old labs (lower case)

# (category label, colour, topics that select it) - first match wins, so order matters
CATEGORIES = [
    ("Education", "#22c55e", {"cs50", "harvard", "course"}),
    ("Space Security", "#60a5fa", {"satellite", "space-security", "sparta"}),
    ("ICS / OT Security", "#f97316", {"ics-security", "ot-security", "mitre-attack-ics", "scada"}),
    ("Incident Response", "#ef4444", {"nis2", "playbook"}),
    ("Detection Engineering", "#22d3ee", {"detection-engineering", "sigma", "kql", "splunk"}),
    ("Threat Intelligence", "#a78bfa", {"threat-intelligence", "cti", "ai-security"}),
]
DEFAULT_CATEGORY = ("Security Research", "#94a3b8")
HIDDEN_TOPICS = {"cybersecurity"}  # too generic to show on a card


def fetch_repos():
    repos, page = [], 1
    while True:
        url = f"https://api.github.com/users/{USER}/repos?type=owner&sort=created&direction=desc&per_page=100&page={page}"
        req = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json", "User-Agent": "profile-readme-updater"})
        if TOKEN:
            req.add_header("Authorization", f"Bearer {TOKEN}")
        with urllib.request.urlopen(req) as r:
            batch = json.load(r)
        if not batch:
            return repos
        repos += batch
        page += 1


def visible(repos):
    return [r for r in repos if not (r.get("fork") or r.get("private") or r.get("archived") or r["name"].lower() in SKIP)]


def category(topics):
    t = set(topics)
    for label, colour, keys in CATEGORIES:
        if t & keys:
            return label, colour
    return DEFAULT_CATEGORY


def esc(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def wrap(text, width, max_lines):
    words, lines, cur = text.split(), [], ""
    for w in words:
        cand = f"{cur} {w}".strip()
        if len(cand) > width and cur:
            lines.append(cur)
            cur = w
        else:
            cur = cand
    if cur:
        lines.append(cur)
    if len(lines) > max_lines:
        lines = lines[:max_lines]
        lines[-1] = lines[-1][: width - 1].rstrip(" ,.;:") + "…"
    return lines


def card_svg(repo):
    label, colour = category(repo.get("topics", []))
    font = 'font-family="Segoe UI, Helvetica, Arial, sans-serif"'
    W, H = 600, 210
    created = repo.get("created_at", "")[:10]
    try:
        date = datetime.date.fromisoformat(created).strftime("%b %Y")
    except ValueError:
        date = ""
    o = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}" role="img" aria-label="{esc(repo["name"])}">',
         '<defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#06122b"/><stop offset="1" stop-color="#0b2a5c"/></linearGradient></defs>',
         f'<clipPath id="c"><rect x="1" y="1" width="{W - 2}" height="{H - 2}" rx="16"/></clipPath>',
         f'<rect x="1" y="1" width="{W - 2}" height="{H - 2}" rx="16" fill="url(#g)"/>',
         f'<rect x="1" y="1" width="9" height="{H - 2}" fill="{colour}" clip-path="url(#c)"/>',
         f'<rect x="1" y="1" width="{W - 2}" height="{H - 2}" rx="16" fill="none" stroke="{colour}" stroke-opacity="0.55" stroke-width="1.5"/>']
    # category pill + date
    pw = len(label) * 7.4 + 26
    o.append(f'<rect x="26" y="20" width="{pw:.0f}" height="24" rx="12" fill="{colour}" fill-opacity="0.18" stroke="{colour}" stroke-width="1"/>')
    o.append(f'<text x="{26 + pw / 2:.0f}" y="36.5" {font} font-size="12" font-weight="700" letter-spacing="0.5" fill="{colour}" text-anchor="middle">{esc(label.upper())}</text>')
    if date:
        o.append(f'<text x="{W - 24}" y="37" {font} font-size="13" fill="#94a3b8" text-anchor="end">{date}</text>')
    # title
    title = repo["name"]
    size = 21 if len(title) <= 38 else 18
    o.append(f'<text x="26" y="76" {font} font-size="{size}" font-weight="700" fill="#ffffff">{esc(title)}</text>')
    # description
    for i, line in enumerate(wrap(repo.get("description") or "", 74, 3)):
        o.append(f'<text x="26" y="{104 + i * 20}" {font} font-size="14" fill="#cbd5e1">{esc(line)}</text>')
    # topics
    x = 26
    for t in [t for t in repo.get("topics", []) if t not in HIDDEN_TOPICS]:
        w = len(t) * 7 + 18
        if x + w > W - 24:
            break
        o.append(f'<rect x="{x}" y="{H - 40}" width="{w}" height="22" rx="11" fill="#0f2a5a" stroke="#3b82f6" stroke-opacity="0.6" stroke-width="1"/>')
        o.append(f'<text x="{x + w / 2:.0f}" y="{H - 25}" {font} font-size="12" fill="#bfdbfe" text-anchor="middle">{esc(t)}</text>')
        x += w + 6
    o.append("</svg>")
    return "\n".join(o)


def build_grid(repos):
    os.makedirs("cards", exist_ok=True)
    wanted = set()
    cells = []
    for r in repos:
        fn = f"cards/{r['name']}.svg"
        wanted.add(fn)
        svg = card_svg(r)
        old = open(fn, encoding="utf-8").read() if os.path.exists(fn) else ""
        if old != svg:
            open(fn, "w", encoding="utf-8").write(svg)
        alt = esc(f"{r['name']}: {r.get('description') or ''}")
        cells.append(f'<a href="{r["html_url"]}"><img src="{fn}" width="49%" alt="{alt}"></a>')
    # remove cards of repos that are gone, hidden or renamed
    for f in os.listdir("cards"):
        if f"cards/{f}" not in wanted and f.endswith(".svg"):
            os.remove(f"cards/{f}")
    return "<p>\n" + "\n".join(cells) + "\n</p>"


def main(repos=None):
    readme = open("README.md", encoding="utf-8").read()
    if START not in readme or END not in readme:
        raise SystemExit("Markers not found in README.md")
    grid = build_grid(visible(repos if repos is not None else fetch_repos()))
    new = re.sub(re.escape(START) + r".*?" + re.escape(END), lambda m: f"{START}\n{grid}\n{END}", readme, flags=re.S)
    if new != readme:
        open("README.md", "w", encoding="utf-8").write(new)
        print("README updated")
    else:
        print("No README changes")


if __name__ == "__main__":
    main()
