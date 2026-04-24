"""
04_analyze_code.py
Analiza el código fuente de cada repositorio con Semgrep (análisis estático).
Requiere: semgrep, git
"""

import os
import json
import subprocess
import shutil
import tempfile
import argparse
from pathlib import Path
from datetime import datetime, timezone

REPORTS_DIR = Path(__file__).parent.parent / "reports"


def check_tool(name: str):
    if not shutil.which(name):
        raise RuntimeError(f"Herramienta '{name}' no encontrada. Instala con: pip install semgrep")


def clone_repo(clone_url: str, dest: Path) -> bool:
    cmd = ["git", "clone", "--depth", "1", "--quiet", clone_url, str(dest)]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    if result.returncode != 0:
        print(f"    [!] Error clonando: {result.stderr.strip()[:200]}")
        return False
    return True


def run_semgrep(repo_path: Path) -> dict | None:
    """
    Ejecuta Semgrep con reglas de seguridad sobre el repo clonado.
    Usa los rulesets: p/security-audit, p/secrets, p/owasp-top-ten
    """
    cmd = [
        "semgrep",
        "--config", "p/security-audit",
        "--config", "p/secrets",
        "--config", "p/owasp-top-ten",
        "--json",
        "--quiet",
        str(repo_path),
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)

    # Semgrep retorna 0 (sin findings) o 1 (con findings), ambos válidos
    if result.returncode not in (0, 1):
        print(f"    [!] Semgrep error (rc={result.returncode}): {result.stderr.strip()[:300]}")
        return None

    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as e:
        print(f"    [!] No se pudo parsear salida de Semgrep: {e}")
        return None


def summarize_semgrep(data: dict, repo_name: str) -> dict:
    """Extrae métricas relevantes del resultado de Semgrep."""
    results = data.get("results", [])

    severity_counts = {"ERROR": 0, "WARNING": 0, "INFO": 0}
    categories = {}
    findings = []

    for r in results:
        severity = r.get("extra", {}).get("severity", "INFO")
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

        metadata = r.get("extra", {}).get("metadata", {})
        category = metadata.get("category", "unknown")
        categories[category] = categories.get(category, 0) + 1

        findings.append({
            "rule_id":   r.get("check_id", ""),
            "severity":  severity,
            "category":  category,
            "file":      r.get("path", "").replace(str(r.get("path", "")), ""),
            "path":      r.get("path", ""),
            "line":      r.get("start", {}).get("line", 0),
            "message":   r.get("extra", {}).get("message", "")[:300],
            "cwe":       metadata.get("cwe", []),
            "owasp":     metadata.get("owasp", []),
        })

    return {
        "repo": repo_name,
        "total_findings": len(results),
        "severity_counts": severity_counts,
        "categories": categories,
        "findings": findings,
        "analyzed_at": datetime.now(timezone.utc).isoformat(),
    }


def main():
    parser = argparse.ArgumentParser(description="Análisis estático con Semgrep")
    parser.add_argument("--repos-file", default=str(REPORTS_DIR / "repos.json"))
    parser.add_argument("--reports-dir", default=str(REPORTS_DIR))
    parser.add_argument("--keep-clones", action="store_true")
    args = parser.parse_args()

    check_tool("semgrep")

    with open(args.repos_file) as f:
        data = json.load(f)

    repos = data["repos"]
    reports_dir = Path(args.reports_dir)
    semgrep_dir = reports_dir / "semgrep_raw"
    semgrep_dir.mkdir(parents=True, exist_ok=True)

    tmpdir = Path(tempfile.mkdtemp(prefix="semgrep_clones_"))
    print(f"[*] Analizando {len(repos)} repositorios con Semgrep...\n")

    all_results = []

    try:
        for i, repo in enumerate(repos, 1):
            name = repo["name"]
            print(f"[{i}/{len(repos)}] {repo['full_name']}")

            raw_path = semgrep_dir / f"{name}_semgrep.json"

            if raw_path.exists():
                print(f"    [→] Resultado ya existe, usando cache.")
                with open(raw_path) as f:
                    semgrep_data = json.load(f)
            else:
                clone_dest = tmpdir / name
                print(f"    Clonando...")
                if not clone_repo(repo["clone_url"], clone_dest):
                    all_results.append({"repo": name, "error": "clone_failed"})
                    continue

                print(f"    Ejecutando Semgrep (puede tardar varios minutos)...")
                semgrep_data = run_semgrep(clone_dest)

                if not args.keep_clones:
                    shutil.rmtree(clone_dest, ignore_errors=True)

                if semgrep_data is None:
                    all_results.append({"repo": name, "error": "semgrep_failed"})
                    continue

                with open(raw_path, "w") as f:
                    json.dump(semgrep_data, f, indent=2)

            summary = summarize_semgrep(semgrep_data, name)
            all_results.append(summary)
            sc = summary["severity_counts"]
            print(f"    [✓] Findings: {summary['total_findings']} | ERROR: {sc.get('ERROR',0)} | WARNING: {sc.get('WARNING',0)} | INFO: {sc.get('INFO',0)}")

    finally:
        if not args.keep_clones:
            shutil.rmtree(tmpdir, ignore_errors=True)

    output_path = reports_dir / "code_analysis_report.json"
    with open(output_path, "w") as f:
        json.dump({
            "analyzed_at": datetime.now(timezone.utc).isoformat(),
            "total_repos": len(all_results),
            "results": all_results,
        }, f, indent=2)

    successful = [r for r in all_results if "error" not in r]
    total_findings = sum(r["total_findings"] for r in successful)
    print(f"\n[✓] Análisis completado: {len(successful)}/{len(all_results)} repos")
    print(f"    Total findings: {total_findings}")
    print(f"    Reporte guardado en: {output_path}")


if __name__ == "__main__":
    main()
