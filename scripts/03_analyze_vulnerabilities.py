"""
03_analyze_vulnerabilities.py
Analiza cada SBOM con Grype y consolida los resultados en un archivo JSON.
Requiere: grype (instalado en PATH)
"""

import os
import json
import subprocess
import shutil
import argparse
from pathlib import Path
from datetime import datetime, timezone

REPORTS_DIR = Path(__file__).parent.parent / "reports"
SBOMS_DIR = Path(__file__).parent.parent / "sboms"


def check_tool(name: str):
    if not shutil.which(name):
        raise RuntimeError(
            f"Herramienta '{name}' no encontrada.\n"
            f"  Instala con: curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin"
        )


SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Negligible": 4, "Unknown": 5}


def run_grype(sbom_path: Path) -> dict | None:
    """
    Ejecuta Grype sobre un SBOM y devuelve el resultado parseado.
    """
    cmd = [
        "grype",
        f"sbom:{sbom_path}",
        "--output", "json",
        "--quiet",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

    if result.returncode not in (0, 1):  # 0=sin vulns, 1=con vulns
        print(f"    [!] Grype error (rc={result.returncode}): {result.stderr.strip()[:300]}")
        return None

    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as e:
        print(f"    [!] No se pudo parsear salida de Grype: {e}")
        return None


def summarize_grype(grype_data: dict, repo_name: str) -> dict:
    """Extrae métricas relevantes del resultado de Grype."""
    matches = grype_data.get("matches", [])

    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Negligible": 0, "Unknown": 0}
    cves = []
    packages_affected = set()

    for match in matches:
        vuln = match.get("vulnerability", {})
        severity = vuln.get("severity", "Unknown")
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

        cve_id = vuln.get("id", "")
        artifact = match.get("artifact", {})
        pkg_name = artifact.get("name", "unknown")
        pkg_version = artifact.get("version", "?")
        pkg_type = artifact.get("type", "unknown")
        packages_affected.add(pkg_name)

        cves.append({
            "id": cve_id,
            "severity": severity,
            "cvss": vuln.get("cvss", []),
            "fix_versions": vuln.get("fix", {}).get("versions", []),
            "fix_state": vuln.get("fix", {}).get("state", "unknown"),
            "package": pkg_name,
            "package_version": pkg_version,
            "package_type": pkg_type,
            "description": vuln.get("description", "")[:300],
            "urls": vuln.get("urls", [])[:3],
        })

    # Calcular CVSS score máximo si está disponible
    max_cvss = 0.0
    for cve in cves:
        for score_entry in cve.get("cvss", []):
            score = score_entry.get("metrics", {}).get("baseScore", 0)
            if score > max_cvss:
                max_cvss = score

    return {
        "repo": repo_name,
        "total_vulnerabilities": len(matches),
        "severity_counts": severity_counts,
        "packages_affected_count": len(packages_affected),
        "max_cvss_score": max_cvss,
        "fixable": sum(1 for c in cves if c["fix_state"] == "fixed"),
        "vulnerabilities": cves,
        "analyzed_at": datetime.now(timezone.utc).isoformat(),
    }


def main():
    parser = argparse.ArgumentParser(description="Analiza vulnerabilidades con Grype")
    parser.add_argument("--sboms-dir", default=str(SBOMS_DIR))
    parser.add_argument("--reports-dir", default=str(REPORTS_DIR))
    args = parser.parse_args()

    check_tool("grype")

    sboms_dir = Path(args.sboms_dir)
    reports_dir = Path(args.reports_dir)
    reports_dir.mkdir(parents=True, exist_ok=True)

    sbom_files = sorted(sboms_dir.glob("*.cdx.json"))
    if not sbom_files:
        print(f"[!] No se encontraron SBOMs en {sboms_dir}")
        return

    print(f"[*] Analizando {len(sbom_files)} SBOMs con Grype...\n")

    all_results = []
    vuln_reports_dir = reports_dir / "grype_raw"
    vuln_reports_dir.mkdir(exist_ok=True)

    for i, sbom_path in enumerate(sbom_files, 1):
        repo_name = sbom_path.stem.replace(".cdx", "")
        print(f"[{i}/{len(sbom_files)}] {repo_name}")

        raw_path = vuln_reports_dir / f"{repo_name}_grype.json"

        # Usar cache si existe
        if raw_path.exists():
            print(f"    [→] Resultado Grype ya existe, usando cache.")
            with open(raw_path) as f:
                grype_data = json.load(f)
        else:
            grype_data = run_grype(sbom_path)
            if grype_data is None:
                all_results.append({"repo": repo_name, "error": "grype_failed"})
                continue
            # Guardar raw
            with open(raw_path, "w") as f:
                json.dump(grype_data, f, indent=2)

        summary = summarize_grype(grype_data, repo_name)
        all_results.append(summary)

        sc = summary["severity_counts"]
        print(
            f"    [✓] Total: {summary['total_vulnerabilities']} | "
            f"Critical: {sc['Critical']} | High: {sc['High']} | "
            f"Medium: {sc['Medium']} | Low: {sc['Low']} | "
            f"Fixable: {summary['fixable']}"
        )

    # Guardar resumen consolidado
    output_path = reports_dir / "vulnerability_report.json"
    with open(output_path, "w") as f:
        json.dump(
            {
                "analyzed_at": datetime.now(timezone.utc).isoformat(),
                "total_repos": len(all_results),
                "results": all_results,
            },
            f,
            indent=2,
        )

    # Estadísticas globales
    successful = [r for r in all_results if "error" not in r]
    total_vulns = sum(r["total_vulnerabilities"] for r in successful)
    total_critical = sum(r["severity_counts"].get("Critical", 0) for r in successful)
    total_high = sum(r["severity_counts"].get("High", 0) for r in successful)

    print(f"\n{'='*50}")
    print(f"[✓] Análisis completado")
    print(f"    Repos analizados: {len(successful)}/{len(all_results)}")
    print(f"    Total vulnerabilidades: {total_vulns}")
    print(f"    Critical: {total_critical} | High: {total_high}")
    print(f"    Reporte guardado en: {output_path}")


if __name__ == "__main__":
    main()
