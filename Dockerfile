# Utiliser une image Python officielle comme base
FROM python:3.10-slim

# Définir les variables d'environnement
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Créer et définir le répertoire de travail
WORKDIR /app

# Installer les dépendances système
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    git \
    libmagic1 \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Copier les fichiers de dépendances
COPY requirements.txt .
COPY pyproject.toml .
COPY setup.py .

# Installer les dépendances Python
RUN pip install --no-cache-dir -r requirements.txt

# Copier le code source
COPY . .

# Créer les répertoires nécessaires
RUN mkdir -p /app/data /app/logs /app/certs

# Définir les permissions
RUN chown -R nobody:nogroup /app

# Passer à l'utilisateur non-root
USER nobody

# Exposer les ports
EXPOSE 8000 8001 8002

# Définir le point d'entrée
ENTRYPOINT ["python", "-m", "osiris.hive.server"] 