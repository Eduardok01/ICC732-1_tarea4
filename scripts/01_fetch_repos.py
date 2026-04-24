"""
01_fetch_repos.py
Recupera repositorios públicos activos de una organización de GitHub.
Activos = último commit dentro de los últimos 30 días.
"""

import os
import json
import time
import argparse
from datetime import datetime, timedelta, timezone
import requests

GITHUB_API = "https://api.github.com"


def get_headers(token: str | None = None) -> dict:
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def fetch_repos(org: str, token: str | None, max_repos: int = 50) -> list[dict]:
    """Devuelve repositorios públicos con push reciente (≤30 días)."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=30)
    repos = []
    page = 1
    print(f"[*] Buscando repos en '{org}' (máx {max_repos})...")

    while len(repos) < max_repos:
        url = f"{GITHUB_API}/orgs/{org}/repos"
        params = {
            "type": "public",
            "sort": "pushed",
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
            pushed = repo.get("pushed_at")
            if not pushed:
                continue
            pushed_dt = datetime.fromisoformat(pushed.replace("Z", "+00:00"))
            if pushed_dt < cutoff:
                # Repos ordenados por pushed desc; si ya pasó el corte → terminamos
                print(f"    Repo '{repo['name']}' fuera del rango de 30 días. Deteniendo.")
                return repos
            if repo.get("archived") or repo.get("disabled") or repo.get("fork"):
                continue
            repos.append(
                {
                    "name": repo["name"],
                    "full_name": repo["full_name"],
                    "clone_url": repo["clone_url"],
                    "html_url": repo["html_url"],
                    "pushed_at": pushed,
                    "language": repo.get("language"),
                    "size_kb": repo.get("size", 0),
                    "default_branch": repo.get("default_branch", "main"),
                    "topics": repo.get("topics", []),
                    "stargazers_count": repo.get("stargazers_count", 0),
                }
            )
            if len(repos) >= max_repos:
                break

        page += 1

    return repos


def main():
    parser = argparse.ArgumentParser(description="Fetch GitHub org repos")
    parser.add_argument("org", help="Nombre de la organización en GitHub")
    parser.add_argument("--token", default=os.getenv("GITHUB_TOKEN"), help="GitHub token (o GITHUB_TOKEN env)")
    parser.add_argument("--max-repos", type=int, default=50)
    parser.add_argument("--output", default="repos.json")
    args = parser.parse_args()

    repos = fetch_repos(args.org, args.token, args.max_repos)
    out_path = os.path.join(os.path.dirname(__file__), "..", "reports", args.output)
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w") as f:
        json.dump({"org": args.org, "fetched_at": datetime.now(timezone.utc).isoformat(), "repos": repos}, f, indent=2)

    print(f"\n[✓] {len(repos)} repositorios activos guardados en {out_path}")
    for r in repos:
        print(f"    • {r['full_name']} ({r['language']}) — push: {r['pushed_at'][:10]}")


if __name__ == "__main__":
    main()
