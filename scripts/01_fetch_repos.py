"""
01_fetch_repos.py
Recupera los N repositorios públicos más populares (por estrellas) de una
organización de GitHub. Por defecto trae los top 5.
"""

import os
import json
import time
import argparse
from datetime import datetime, timezone
import requests

GITHUB_API = "https://api.github.com"


def get_headers(token: str | None = None) -> dict:
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def fetch_top_repos(org: str, token: str | None, top_n: int = 5) -> list[dict]:
    """
    Devuelve los top_n repositorios públicos de la organización
    ordenados por número de estrellas (descendente).
    """
    all_repos = []
    page = 1
    print(f"[*] Buscando repos en '{org}' ordenados por estrellas...")

    while True:
        url = f"{GITHUB_API}/orgs/{org}/repos"
        params = {
            "type": "public",
            "sort": "stars",
            "direction": "desc",
            "per_page": 100,
            "page": page,
        }
        r = requests.get(url, headers=get_headers(token), params=params, timeout=30)

        if r.status_code == 403:
            reset = int(r.headers.get("X-RateLimit-Reset", time.time() + 60))
            wait = max(reset - int(time.time()), 1)
            print(f"    Rate-limit. Esperando {wait}s...")
            time.sleep(wait)
            continue
        r.raise_for_status()

        batch = r.json()
        if not batch:
            break

        for repo in batch:
            if repo.get("archived") or repo.get("disabled") or repo.get("fork"):
                continue
            all_repos.append({
                "name": repo["name"],
                "full_name": repo["full_name"],
                "clone_url": repo["clone_url"],
                "html_url": repo["html_url"],
                "pushed_at": repo.get("pushed_at", ""),
                "language": repo.get("language"),
                "size_kb": repo.get("size", 0),
                "default_branch": repo.get("default_branch", "main"),
                "topics": repo.get("topics", []),
                "stargazers_count": repo.get("stargazers_count", 0),
                "forks_count": repo.get("forks_count", 0),
                "open_issues_count": repo.get("open_issues_count", 0),
            })

        # Como están ordenados por estrellas desc, si ya tenemos top_n podemos parar
        if len(all_repos) >= top_n:
            break

        page += 1

    # Ordenar por estrellas y tomar los top_n
    all_repos.sort(key=lambda x: x["stargazers_count"], reverse=True)
    return all_repos[:top_n]


def main():
    parser = argparse.ArgumentParser(description="Fetch top repos de una org de GitHub por estrellas")
    parser.add_argument("org", help="Nombre de la organización en GitHub")
    parser.add_argument("--token", default=os.getenv("GITHUB_TOKEN"), help="GitHub token (o GITHUB_TOKEN env)")
    parser.add_argument("--top", type=int, default=5, help="Cantidad de repos top a recuperar (default: 5)")
    parser.add_argument("--output", default="repos.json")
    args = parser.parse_args()

    repos = fetch_top_repos(args.org, args.token, args.top)
    out_path = os.path.join(os.path.dirname(__file__), "..", "reports", args.output)
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w") as f:
        json.dump({
            "org": args.org,
            "fetched_at": datetime.now(timezone.utc).isoformat(),
            "repos": repos
        }, f, indent=2)

    print(f"\n[✓] Top {len(repos)} repositorios guardados en {out_path}")
    for r in repos:
        print(f"    • {r['full_name']} ({r['language']}) — ⭐ {r['stargazers_count']:,}")


if __name__ == "__main__":
    main()
