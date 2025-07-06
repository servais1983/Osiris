# Makefile pour Osiris
# Simplifie les commandes courantes du projet

.PHONY: help build up down logs clean test install docs

# Variables
DOCKER_COMPOSE = docker-compose
PYTHON = python3
PIP = pip3

# Aide
help:
	@echo "🚀 Osiris - Makefile"
	@echo "=================="
	@echo ""
	@echo "Commandes disponibles:"
	@echo "  build          - Construire les images Docker"
	@echo "  up             - Démarrer les services"
	@echo "  down           - Arrêter les services"
	@echo "  logs           - Afficher les logs"
	@echo "  clean          - Nettoyer les conteneurs et images"
	@echo "  test           - Exécuter les tests"
	@echo "  test-linux     - Tester les collecteurs Linux"
	@echo "  install        - Installer les dépendances Python"
	@echo "  docs           - Générer la documentation"
	@echo "  proto          - Compiler les protobufs"
	@echo "  certs          - Générer les certificats mTLS"
	@echo "  db-init        - Initialiser la base de données"
	@echo "  db-migrate     - Migrer la base de données"
	@echo ""

# Docker
build:
	@echo "🔨 Construction des images Docker..."
	$(DOCKER_COMPOSE) build

up:
	@echo "🚀 Démarrage des services..."
	$(DOCKER_COMPOSE) up -d

down:
	@echo "🛑 Arrêt des services..."
	$(DOCKER_COMPOSE) down

logs:
	@echo "📋 Affichage des logs..."
	$(DOCKER_COMPOSE) logs -f

clean:
	@echo "🧹 Nettoyage des conteneurs et images..."
	$(DOCKER_COMPOSE) down -v --rmi all
	docker system prune -f

# Tests
test:
	@echo "🧪 Exécution des tests..."
	$(PYTHON) -m pytest tests/ -v --cov=agent --cov=hive --cov-report=term-missing

test-linux:
	@echo "🧪 Test des collecteurs Linux..."
	$(PYTHON) test_linux_collectors.py

# Installation
install:
	@echo "📦 Installation des dépendances Python..."
	$(PIP) install -r requirements.txt
	$(PIP) install -e .

# Documentation
docs:
	@echo "📚 Génération de la documentation..."
	$(PYTHON) -m pydoc -w agent/
	$(PYTHON) -m pydoc -w hive/
	@echo "Documentation générée dans le répertoire courant"

# Protobuf
proto:
	@echo "🔧 Compilation des protobufs..."
	$(PYTHON) scripts/compile_protos.py

# Certificats
certs:
	@echo "🔐 Génération des certificats mTLS..."
	$(PYTHON) scripts/generate_certs.py

# Base de données
db-init:
	@echo "🗄️  Initialisation de la base de données..."
	$(PYTHON) hive/init_db.py

db-migrate:
	@echo "🔄 Migration de la base de données..."
	$(PYTHON) scripts/migrate_database.py

# Développement
dev-setup: install proto certs db-init
	@echo "✅ Configuration de développement terminée"

dev-start: build up
	@echo "✅ Environnement de développement démarré"

dev-stop: down
	@echo "✅ Environnement de développement arrêté"

# Production
prod-setup: install proto certs db-init
	@echo "✅ Configuration de production terminée"

prod-start: build up
	@echo "✅ Environnement de production démarré"

prod-stop: down
	@echo "✅ Environnement de production arrêté"

# Utilitaires
status:
	@echo "📊 Statut des services..."
	$(DOCKER_COMPOSE) ps

restart:
	@echo "🔄 Redémarrage des services..."
	$(DOCKER_COMPOSE) restart

pull:
	@echo "⬇️  Mise à jour des images..."
	$(DOCKER_COMPOSE) pull

# Nettoyage avancé
clean-all: clean
	@echo "🧹 Nettoyage complet..."
	docker system prune -a -f
	docker volume prune -f
	docker network prune -f

# Vérification
check:
	@echo "🔍 Vérification de l'environnement..."
	@echo "Python: $(shell $(PYTHON) --version)"
	@echo "Docker: $(shell docker --version)"
	@echo "Docker Compose: $(shell $(DOCKER_COMPOSE) --version)"
	@echo "Pip: $(shell $(PIP) --version)"

# Déploiement
deploy: prod-setup prod-start
	@echo "🚀 Déploiement terminé"

undeploy: prod-stop clean
	@echo "🛑 Déploiement supprimé"

# Monitoring
monitor:
	@echo "📈 Monitoring des services..."
	$(DOCKER_COMPOSE) top

# Sauvegarde
backup:
	@echo "💾 Sauvegarde des données..."
	$(DOCKER_COMPOSE) exec -T postgres pg_dump -U osiris > backup_$(shell date +%Y%m%d_%H%M%S).sql

# Restauration
restore:
	@echo "📥 Restauration des données..."
	@read -p "Nom du fichier de sauvegarde: " file; \
	$(DOCKER_COMPOSE) exec -T postgres psql -U osiris < $$file

# Par défaut
.DEFAULT_GOAL := help 