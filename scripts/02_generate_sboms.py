"""
02_generate_sboms.py
Clona cada repositorio activo y genera su SBOM en formato CycloneDX JSON usando Syft.
Requiere: git, syft (instalado en PATH)
"""

import os
import json
import subprocess
import shutil
import argparse
import tempfile
from pathlib import Path
from datetime import datetime, timezone

REPORTS_DIR = Path(__file__).parent.parent / "reports"
SBOMS_DIR = Path(__file__).parent.parent / "sboms"


def check_tool(name: str):
    if not shutil.which(name):
        raise RuntimeError(f"Herramienta '{name}' no encontrada. Instálala y vuelve a intentar.")


def clone_repo(clone_url: str, dest: Path, depth: int = 1) -> bool:
    """Clona un repo de forma superficial. Devuelve True si tuvo éxito."""
    cmd = ["git", "clone", "--depth", str(depth), "--quiet", clone_url, str(dest)]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    if result.returncode != 0:
        print(f"    [!] Error clonando: {result.stderr.strip()[:200]}")
        return False
    return True


def generate_sbom(repo_path: Path, output_path: Path, repo_name: str) -> dict | None:
    """
    Ejecuta Syft sobre el directorio clonado y guarda el SBOM en CycloneDX JSON.
    Devuelve un dict de resumen o None si falló.
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        "syft",
        str(repo_path),
        "--output", f"cyclonedx-json={output_path}",
        "--quiet",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

    if result.returncode != 0:
        print(f"    [!] Syft falló: {result.stderr.strip()[:300]}")
        return None

    # Parsear SBOM para obtener métricas básicas
    try:
        with open(output_path) as f:
            sbom = json.load(f)
        components = sbom.get("components", [])
        ecosystems = {}
        for c in components:
            ptype = c.get("purl", "").split(":")[1].split("/")[0] if "purl" in c else "unknown"
            ecosystems[ptype] = ecosystems.get(ptype, 0) + 1

        return {
            "repo": repo_name,
            "sbom_path": str(output_path),
            "component_count": len(components),
            "ecosystems": ecosystems,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }
    except Exception as e:
        print(f"    [!] No se pudo parsear SBOM: {e}")
        return {"repo": repo_name, "sbom_path": str(output_path), "component_count": 0, "ecosystems": {}}


def main():
    parser = argparse.ArgumentParser(description="Genera SBOMs con Syft")
    parser.add_argument("--repos-file", default=str(REPORTS_DIR / "repos.json"))
    parser.add_argument("--sboms-dir", default=str(SBOMS_DIR))
    parser.add_argument("--keep-clones", action="store_true", help="No eliminar clones después de procesar")
    args = parser.parse_args()

    check_tool("git")
    check_tool("syft")

    with open(args.repos_file) as f:
        data = json.load(f)

    repos = data["repos"]
    sboms_dir = Path(args.sboms_dir)
    sboms_dir.mkdir(parents=True, exist_ok=True)

    summary = []
    tmpdir = Path(tempfile.mkdtemp(prefix="sbom_clones_"))
    print(f"[*] Clones temporales en: {tmpdir}")
    print(f"[*] Procesando {len(repos)} repositorios...\n")

    try:
        for i, repo in enumerate(repos, 1):
            name = repo["name"]
            full_name = repo["full_name"]
            clone_url = repo["clone_url"]
            sbom_path = sboms_dir / f"{name}.cdx.json"

            print(f"[{i}/{len(repos)}] {full_name}")

            # Si el SBOM ya existe, saltar
            if sbom_path.exists():
                print(f"    [→] SBOM ya existe, saltando.")
                # Igual lo incluimos en el resumen
                with open(sbom_path) as f:
                    sbom = json.load(f)
                components = sbom.get("components", [])
                summary.append({
                    "repo": name,
                    "sbom_path": str(sbom_path),
                    "component_count": len(components),
                    "ecosystems": {},
                    "skipped": True,
                })
                continue

            clone_dest = tmpdir / name
            print(f"    Clonando {clone_url}...")
            if not clone_repo(clone_url, clone_dest):
                summary.append({"repo": name, "error": "clone_failed"})
                continue

            print(f"    Generando SBOM...")
            result = generate_sbom(clone_dest, sbom_path, name)
            if result:
                summary.append(result)
                print(f"    [✓] {result['component_count']} componentes | ecosystems: {result['ecosystems']}")
            else:
                summary.append({"repo": name, "error": "syft_failed"})

            # Limpiar clon para ahorrar espacio
            if not args.keep_clones:
                shutil.rmtree(clone_dest, ignore_errors=True)

    finally:
        if not args.keep_clones:
            shutil.rmtree(tmpdir, ignore_errors=True)
            print(f"\n[*] Clones temporales eliminados.")

    # Guardar resumen
    summary_path = REPORTS_DIR / "sbom_summary.json"
    with open(summary_path, "w") as f:
        json.dump({"generated_at": datetime.now(timezone.utc).isoformat(), "sboms": summary}, f, indent=2)

    print(f"\n[✓] SBOMs generados: {sum(1 for s in summary if 'error' not in s)}/{len(repos)}")
    print(f"[✓] Resumen guardado en {summary_path}")


if __name__ == "__main__":
    main()
