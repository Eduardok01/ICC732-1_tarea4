# SBOM + Vulnerabilidades

## Estructura del proyecto

```
sbom-project/
├── scripts/
│   ├── 01_fetch_repos.py
│   ├── 02_generate_sboms.py
│   └── 03_analyze_vulnerabilities.py
├── notebooks/
│   └── analysis.ipynb
├── sboms/
├── reports/
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
python scripts/01_fetch_repos.py <ORGANIZACIÓN> --max-repos 50
python scripts/02_generate_sboms.py
python scripts/03_analyze_vulnerabilities.py
```

Reemplaza `<ORGANIZACIÓN>` por el nombre de la organización en GitHub, por ejemplo `pallets`.  
Para una prueba rápida usa `--max-repos 1`.

### 4. Salir del contenedor
```bash
exit
```

### 5. Levantar Jupyter
```bash
docker compose up jupyter
```

Abre **http://localhost:8888** en el navegador, abre `analysis.ipynb` y ejecuta `Kernel → Restart & Run All`.
