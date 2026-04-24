FROM python:3.11-slim

# ── Sistema base ─────────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# ── Syft ─────────────────────────────────────────────────────────────────────
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh \
    | sh -s -- -b /usr/local/bin

# ── Grype ────────────────────────────────────────────────────────────────────
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh \
    | sh -s -- -b /usr/local/bin

# Pre-descargar la base de datos de vulnerabilidades de Grype
# (así no lo hace en el primer análisis y ahorra tiempo)
RUN grype db update

# ── Dependencias Python ───────────────────────────────────────────────────────
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ── Código del proyecto ───────────────────────────────────────────────────────
COPY scripts/ ./scripts/

# Crear carpetas de salida (notebooks se monta como volumen desde el host)
RUN mkdir -p notebooks reports sboms reports/grype_raw reports/semgrep_raw

# Puerto para Jupyter
EXPOSE 8888

# Entrypoint por defecto: bash interactivo
CMD ["bash"]
