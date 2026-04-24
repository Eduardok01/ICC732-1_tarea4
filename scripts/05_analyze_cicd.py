"""
05_analyze_cicd.py
Analiza los workflows de GitHub Actions de cada repositorio buscando
configuraciones riesgosas: permisos excesivos, uso de pull_request_target,
secrets expuestos, actions sin versión fija, etc.
"""

import os
import json
import re
import requests
import time
import argparse
from pathlib import Path
from datetime import datetime, timezone

GITHUB_API = "https://api.github.com"
REPORTS_DIR = Path(__file__).parent.parent / "reports"

# Patrones de riesgo a buscar en los workflows
RISK_PATTERNS = [
    {
        "id": "permissions_write_all",
        "description": "Permisos write-all otorgados al workflow",
        "pattern": r"permissions:\s*write-all",
        "severity": "HIGH",
    },
    {
        "id": "pull_request_target",
        "description": "Uso de pull_request_target (puede exponer secrets a PRs externos)",
        "pattern": r"on:\s*.*pull_request_target",
        "severity": "HIGH",
    },
    {
        "id": "secret_in_run",
        "description": "Secret potencialmente expuesto en bloque run",
        "pattern": r"run:.*\$\{\{\s*secrets\.",
        "severity": "MEDIUM",
    },
    {
        "id": "action_no_version",
        "description": "Action usada sin versión fija (usa rama flotante como @main o @master)",
        "pattern": r"uses:\s+\S+@(main|master|HEAD)",
        "severity": "MEDIUM",
    },
    {
        "id": "action_no_pin",
        "description": "Action usada con tag de versión en vez de commit hash (puede ser modificada)",
        "pattern": r"uses:\s+\S+@v\d",
        "severity": "LOW",
    },
    {
        "id": "env_secret_exposure",
        "description": "Secret asignado a variable de entorno (puede aparecer en logs)",
        "pattern": r"env:[\s\S]*?\$\{\{\s*secrets\.",
        "severity": "MEDIUM",
    },
    {
        "id": "curl_pipe_sh",
        "description": "Descarga y ejecución directa de script remoto (curl | sh)",
        "pattern": r"curl.*\|.*sh",
        "severity": "HIGH",
    },
    {
        "id": "sudo_usage",
        "description": "Uso de sudo en workflow",
        "pattern": r"\bsudo\b",
        "severity": "LOW",
    },
    {
        "id": "github_token_exposed",
        "description": "GITHUB_TOKEN usado con permisos potencialmente amplios",
        "pattern": r"\$\{\{\s*secrets\.GITHUB_TOKEN\s*\}\}",
        "severity": "INFO",
    },
]


def get_headers(token: str | None = None) -> dict:
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def get_workflows(org: str, repo: str, token: str | None) -> list[dict]:
    """Obtiene la lista de archivos workflow del repositorio vía API."""
    url = f"{GITHUB_API}/repos/{org}/{repo}/contents/.github/workflows"
    r = requests.get(url, headers=get_headers(token), timeout=30)
    if r.status_code == 404:
        return []  # No tiene workflows
    if r.status_code == 403:
        time.sleep(60)
        return get_workflows(org, repo, token)
    if not r.ok:
        return []
    return [f for f in r.json() if f.get("name", "").endswith((".yml", ".yaml"))]


def get_workflow_content(download_url: str, token: str | None) -> str | None:
    """Descarga el contenido de un archivo workflow."""
    r = requests.get(download_url, headers=get_headers(token), timeout=30)
    if r.ok:
        return r.text
    return None


def analyze_workflow(content: str, filename: str) -> list[dict]:
    """Aplica los patrones de riesgo sobre el contenido del workflow."""
    findings = []
    for pattern in RISK_PATTERNS:
        matches = re.findall(pattern["pattern"], content, re.IGNORECASE | re.MULTILINE)
        if matches:
            # Encontrar líneas donde aparece
            lines = []
            for i, line in enumerate(content.splitlines(), 1):
                if re.search(pattern["pattern"], line, re.IGNORECASE):
                    lines.append(i)

            findings.append({
                "rule_id":     pattern["id"],
                "description": pattern["description"],
                "severity":    pattern["severity"],
                "file":        filename,
                "lines":       lines[:5],  # máximo 5 líneas
                "match_count": len(matches),
            })
    return findings


def analyze_repo_cicd(org: str, repo_name: str, token: str | None) -> dict:
    """Analiza todos los workflows de un repositorio."""
    workflows = get_workflows(org, repo_name, token)

    if not workflows:
        return {
            "repo": repo_name,
            "workflow_count": 0,
            "total_findings": 0,
            "severity_counts": {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
            "findings": [],
            "workflows_analyzed": [],
        }

    all_findings = []
    workflows_analyzed = []

    for wf in workflows:
        filename = wf["name"]
        content = get_workflow_content(wf["download_url"], token)
        if not content:
            continue
        findings = analyze_workflow(content, filename)
        all_findings.extend(findings)
        workflows_analyzed.append(filename)

    severity_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in all_findings:
        sev = f["severity"]
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    return {
        "repo": repo_name,
        "workflow_count": len(workflows),
        "workflows_analyzed": workflows_analyzed,
        "total_findings": len(all_findings),
        "severity_counts": severity_counts,
        "findings": all_findings,
        "analyzed_at": datetime.now(timezone.utc).isoformat(),
    }


def main():
    parser = argparse.ArgumentParser(description="Análisis de CI/CD workflows")
    parser.add_argument("--repos-file", default=str(REPORTS_DIR / "repos.json"))
    parser.add_argument("--reports-dir", default=str(REPORTS_DIR))
    parser.add_argument("--token", default=os.getenv("GITHUB_TOKEN"))
    args = parser.parse_args()

    with open(args.repos_file) as f:
        data = json.load(f)

    org = data["org"]
    repos = data["repos"]
    reports_dir = Path(args.reports_dir)
    reports_dir.mkdir(parents=True, exist_ok=True)

    print(f"[*] Analizando workflows CI/CD de {len(repos)} repositorios...\n")

    all_results = []
    for i, repo in enumerate(repos, 1):
        name = repo["name"]
        print(f"[{i}/{len(repos)}] {repo['full_name']}")
        result = analyze_repo_cicd(org, name, args.token)
        all_results.append(result)
        sc = result["severity_counts"]
        print(f"    [✓] Workflows: {result['workflow_count']} | Findings: {result['total_findings']} | HIGH: {sc['HIGH']} | MEDIUM: {sc['MEDIUM']} | LOW: {sc['LOW']}")

    output_path = reports_dir / "cicd_report.json"
    with open(output_path, "w") as f:
        json.dump({
            "analyzed_at": datetime.now(timezone.utc).isoformat(),
            "org": org,
            "results": all_results,
        }, f, indent=2)

    total_findings = sum(r["total_findings"] for r in all_results)
    total_high = sum(r["severity_counts"]["HIGH"] for r in all_results)
    print(f"\n[✓] Análisis CI/CD completado")
    print(f"    Total findings: {total_findings} | HIGH: {total_high}")
    print(f"    Reporte guardado en: {output_path}")


if __name__ == "__main__":
    main()
