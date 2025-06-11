# Création des répertoires nécessaires
New-Item -ItemType Directory -Force -Path "data"
New-Item -ItemType Directory -Force -Path "logs"
New-Item -ItemType Directory -Force -Path "certificates"
New-Item -ItemType Directory -Force -Path "web/static"
New-Item -ItemType Directory -Force -Path "web/templates"

# Création de l'environnement virtuel Python
python -m venv .venv

# Activation de l'environnement virtuel
.\.venv\Scripts\Activate.ps1

# Installation des dépendances
pip install -r requirements.txt

# Installation du package en mode développement
pip install -e .

# Initialisation de la base de données
python hive/init_db.py

Write-Host "Environnement initialisé avec succès !"
Write-Host "Pour démarrer Osiris, exécutez : docker-compose up -d" 