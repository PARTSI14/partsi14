"""Rebuild the project table in the profile README from the user's public GitHub repositories.

Runs inside GitHub Actions. Reads repos with the GitHub REST API and replaces the text
between <!-- PROJECTS:START --> and <!-- PROJECTS:END --> in README.md.
"""
import json
import os
import re
import urllib.request

USER = os.environ.get("GH_USER", "PARTSI14")
TOKEN = os.environ.get("GITHUB_TOKEN", "")
START, END = "<!-- PROJECTS:START -->", "<!-- PROJECTS:END -->"
SKIP = {USER.lower(), "dga_classification.ipynb", "dga-edited-notebook", "fix_notebook.py", "iforest-and-ecod", "anomaly_detection.ipynb-lab", "lab-stelios"}


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


def pretty(name):
    return name


def build_table(repos):
    rows = ["| Project | Description | Topics |", "|---|---|---|"]
    for r in repos:
        if r.get("fork") or r.get("private") or r.get("archived") or r["name"].lower() in SKIP:
            continue
        desc = (r.get("description") or "").replace("|", "\\|")
        topics = " ".join(f"`{t}`" for t in r.get("topics", [])[:6])
        rows.append(f"| [{pretty(r['name'])}]({r['html_url']}) | {desc} | {topics} |")
    return "\n".join(rows)


def main():
    readme = open("README.md", encoding="utf-8").read()
    if START not in readme or END not in readme:
        raise SystemExit("Markers not found in README.md")
    table = build_table(fetch_repos())
    new = re.sub(re.escape(START) + r".*?" + re.escape(END), f"{START}\n{table}\n{END}", readme, flags=re.S)
    if new != readme:
        open("README.md", "w", encoding="utf-8").write(new)
        print("README updated")
    else:
        print("No changes")


if __name__ == "__main__":
    main()
