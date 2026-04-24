# Análisis de Seguridad — Organización Apache

Análisis de seguridad de los 5 repositorios más populares de la organización `apache` en GitHub.
Cubre tres dimensiones: dependencias (SBOM), código fuente (análisis estático) y configuración CI/CD.

## Estructura del proyecto

```
sbom-project/
├── scripts/
│   ├── 01_fetch_repos.py           # Recupera top 5 repos por estrellas
│   ├── 02_generate_sboms.py        # Genera SBOMs con Syft
│   ├── 03_analyze_vulnerabilities.py  # Analiza dependencias con Grype
│   ├── 04_analyze_code.py          # Análisis estático con Semgrep
│   └── 05_analyze_cicd.py          # Analiza workflows de GitHub Actions
├── notebooks/
│   └── analysis.ipynb              # Análisis cuantitativo y cualitativo
├── sboms/                          # SBOMs generados (.cdx.json por repo)
├── reports/                        # Reportes JSON y gráficas
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

## Instrucciones

### 1. Construir la imagen
```bash
docker compose build --no-cache
```

### 2. Entrar al contenedor
```bash
docker compose run --rm pipeline
```

### 3. Ejecutar el pipeline (dentro del contenedor)
```bash
python scripts/01_fetch_repos.py apache --top 5
python scripts/02_generate_sboms.py
python scripts/03_analyze_vulnerabilities.py
python scripts/04_analyze_code.py
python scripts/05_analyze_cicd.py
```

### 4. Salir del contenedor
```bash
exit
```

### 5. Levantar Jupyter
```bash
docker compose up jupyter
```

Abre **http://localhost:8888** en el navegador, abre `analysis.ipynb` y ejecuta `Kernel → Restart & Run All`.
