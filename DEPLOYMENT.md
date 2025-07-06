# 🚀 Guide de Déploiement Osiris

Ce guide détaille le processus de déploiement d'Osiris en environnement de développement et de production.

## 📋 Prérequis

### Système
- **OS** : Linux (Ubuntu 20.04+), macOS (10.15+), ou Windows 10/11
- **RAM** : Minimum 4GB, recommandé 8GB+
- **Stockage** : Minimum 10GB d'espace libre
- **CPU** : 2 cœurs minimum, 4 cœurs recommandés

### Logiciels
- **Docker** : Version 20.10+
- **Docker Compose** : Version 2.0+
- **Python** : Version 3.8+
- **Git** : Version 2.25+

### Vérification des prérequis

```bash
# Vérifier Docker
docker --version
docker-compose --version

# Vérifier Python
python3 --version
pip3 --version

# Vérifier Git
git --version
```

## 🔧 Installation

### 1. Cloner le dépôt

```bash
git clone https://github.com/votre-org/osiris.git
cd osiris
```

### 2. Configuration initiale

```bash
# Utiliser le Makefile pour la configuration automatique
make dev-setup
```

Cette commande exécute automatiquement :
- Installation des dépendances Python
- Compilation des protobufs
- Génération des certificats mTLS
- Initialisation de la base de données

## 🐳 Déploiement avec Docker

### Démarrage rapide

```bash
# Démarrer tous les services
make up

# Vérifier le statut
make status

# Afficher les logs
make logs
```

### Services inclus

- **Osiris Hive** : Serveur central (port 8080)
- **PostgreSQL** : Base de données principale (port 5432)
- **ClickHouse** : Base de données analytique (port 8123)
- **Redis** : Cache et sessions (port 6379)
- **Nginx** : Proxy inverse (port 80/443)

### Configuration Docker

Le fichier `docker-compose.yml` définit tous les services :

```yaml
version: '3.8'
services:
  hive:
    build: .
    ports:
      - "8080:8080"
    environment:
      - DATABASE_URL=postgresql://osiris:password@postgres:5432/osiris
      - REDIS_URL=redis://redis:6379
    depends_on:
      - postgres
      - redis
      - clickhouse

  postgres:
    image: postgres:13
    environment:
      - POSTGRES_DB=osiris
      - POSTGRES_USER=osiris
      - POSTGRES_PASSWORD=password
    volumes:
      - postgres_data:/var/lib/postgresql/data

  clickhouse:
    image: clickhouse/clickhouse-server:latest
    ports:
      - "8123:8123"
    volumes:
      - clickhouse_data:/var/lib/clickhouse

  redis:
    image: redis:6-alpine
    volumes:
      - redis_data:/data

volumes:
  postgres_data:
  clickhouse_data:
  redis_data:
```

## 🔐 Configuration de la Sécurité

### Certificats mTLS

Osiris utilise une authentification mutuelle TLS (mTLS) pour sécuriser les communications entre agents et serveur.

```bash
# Générer les certificats
make certs
```

Les certificats générés :
- `certs/ca.crt` : Autorité de certification
- `certs/hive.crt` : Certificat du serveur Hive
- `certs/hive.key` : Clé privée du serveur Hive
- `certs/agent.crt` : Certificat des agents
- `certs/agent.key` : Clé privée des agents

### Variables d'environnement

Créer un fichier `.env` à la racine du projet :

```env
# Base de données
DATABASE_URL=postgresql://osiris:password@localhost:5432/osiris
CLICKHOUSE_URL=http://localhost:8123

# Redis
REDIS_URL=redis://localhost:6379

# Sécurité
JWT_SECRET=votre-secret-jwt-super-securise
MTLS_CA_CERT=./certs/ca.crt
MTLS_SERVER_CERT=./certs/hive.crt
MTLS_SERVER_KEY=./certs/hive.key

# Logging
LOG_LEVEL=INFO
LOG_FILE=./logs/osiris.log

# Interface web
WEB_HOST=0.0.0.0
WEB_PORT=8080
WEB_DEBUG=false

# Agents
AGENT_HEARTBEAT_INTERVAL=30
AGENT_TIMEOUT=300
```

## 🧪 Tests et Validation

### Tests unitaires

```bash
# Exécuter tous les tests
make test

# Tests spécifiques
pytest tests/test_windows_collectors.py -v
pytest tests/test_integration.py -v
```

### Tests des collecteurs Linux

```bash
# Tester les collecteurs Linux (nécessite un système Linux)
make test-linux
```

### Validation du déploiement

```bash
# Vérifier l'état des services
make status

# Tester l'API
curl -k https://localhost:8080/api/health

# Vérifier les logs
make logs
```

## 📊 Monitoring et Maintenance

### Logs

```bash
# Logs en temps réel
make logs

# Logs d'un service spécifique
docker-compose logs -f hive

# Logs avec filtrage
docker-compose logs --tail=100 hive | grep ERROR
```

### Sauvegarde

```bash
# Sauvegarde de la base de données
make backup

# Restauration
make restore
```

### Mise à jour

```bash
# Arrêter les services
make down

# Mettre à jour le code
git pull origin main

# Reconstruire et redémarrer
make build
make up
```

## 🔧 Déploiement en Production

### Préparation

1. **Sécuriser l'environnement**
   ```bash
   # Changer les mots de passe par défaut
   # Configurer le firewall
   # Activer HTTPS
   ```

2. **Configuration de production**
   ```bash
   # Utiliser la configuration de production
   make prod-setup
   ```

3. **Déploiement**
   ```bash
   # Déployer
   make deploy
   ```

### Configuration avancée

#### Nginx (Proxy inverse)

```nginx
server {
    listen 80;
    server_name osiris.votre-domaine.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name osiris.votre-domaine.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://localhost:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

#### Systemd (Service)

```ini
[Unit]
Description=Osiris Hive
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/opt/osiris
ExecStart=/usr/bin/docker-compose up -d
ExecStop=/usr/bin/docker-compose down
TimeoutStartSec=0

[Install]
WantedBy=multi-user.target
```

## 🐛 Dépannage

### Problèmes courants

#### 1. Ports déjà utilisés

```bash
# Vérifier les ports utilisés
netstat -tulpn | grep :8080

# Changer les ports dans docker-compose.yml
```

#### 2. Problèmes de certificats

```bash
# Régénérer les certificats
make certs

# Vérifier les permissions
chmod 600 certs/*.key
```

#### 3. Problèmes de base de données

```bash
# Redémarrer PostgreSQL
docker-compose restart postgres

# Vérifier les logs
docker-compose logs postgres
```

#### 4. Problèmes de mémoire

```bash
# Augmenter la mémoire Docker
# Éditer /etc/docker/daemon.json
{
  "default-shm-size": "2G"
}
```

### Logs de débogage

```bash
# Mode debug
export LOG_LEVEL=DEBUG
make up

# Logs détaillés
docker-compose logs -f --tail=1000
```

## 📈 Performance

### Optimisations recommandées

1. **Base de données**
   - Ajuster les paramètres PostgreSQL
   - Configurer les index appropriés
   - Utiliser le partitionnement pour les grandes tables

2. **Réseau**
   - Utiliser un réseau dédié pour les agents
   - Configurer la QoS pour les communications critiques

3. **Stockage**
   - Utiliser des SSD pour les bases de données
   - Configurer le RAID pour la redondance

### Monitoring

```bash
# Statistiques des conteneurs
docker stats

# Utilisation des ressources
docker-compose top

# Métriques de base de données
docker-compose exec postgres psql -U osiris -c "SELECT * FROM pg_stat_database;"
```

## 🔄 Mise à jour et Maintenance

### Mise à jour automatique

```bash
# Script de mise à jour
#!/bin/bash
cd /opt/osiris
git pull origin main
make down
make build
make up
make backup
```

### Maintenance planifiée

1. **Sauvegarde avant maintenance**
   ```bash
   make backup
   ```

2. **Maintenance**
   ```bash
   make down
   # Effectuer les tâches de maintenance
   make up
   ```

3. **Vérification post-maintenance**
   ```bash
   make test
   curl -k https://localhost:8080/api/health
   ```

## 📞 Support

### Ressources utiles

- **Documentation** : `docs/`
- **Issues** : GitHub Issues
- **Wiki** : GitHub Wiki
- **Discussions** : GitHub Discussions

### Logs de support

```bash
# Collecter les logs pour le support
docker-compose logs > osiris_logs_$(date +%Y%m%d_%H%M%S).txt
docker system info > system_info_$(date +%Y%m%d_%H%M%S).txt
```

---

**Note** : Ce guide est en constante évolution. Consultez régulièrement la documentation officielle pour les dernières mises à jour. 